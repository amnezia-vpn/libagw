package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Resolver resolves a host name to IP addresses. *net.Resolver satisfies it.
// A custom implementation must be comparable (a pointer), because clients that
// share one resolver also share its DNS cache and connection pool.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

const (
	dnsTTL          = 5 * time.Minute
	dnsStaleMax     = 24 * time.Hour
	dnsNegativeTTL  = 5 * time.Second
	dialStagger     = 300 * time.Millisecond
	resolutionDelay = 50 * time.Millisecond
	dialTimeout     = 10 * time.Second

	lkgMaxHosts  = 64
	lkgMaxAddrs  = 4
	lkgMaxAge    = 30 * 24 * time.Hour
	lkgDNSWait   = 300 * time.Millisecond
	lkgDayLayout = "2006-01-02"
)

type netstack struct {
	res       Resolver
	transport *http.Transport

	mu  sync.Mutex
	dns map[string]*dnsEntry
	lkg map[string]*lkgEntry
}

type lkgEntry struct {
	addrs   []netip.Addr
	seen    time.Time
	touched time.Time
}

type dnsEntry struct {
	addrs      []netip.Addr
	err        error
	expires    time.Time
	staleUntil time.Time
	inflight   chan struct{}
}

var (
	stacksMu sync.Mutex
	stacks   = map[Resolver]*netstack{}
)

func stackFor(res Resolver) *netstack {
	if res == nil {
		res = net.DefaultResolver
	}
	stacksMu.Lock()
	defer stacksMu.Unlock()
	if s, ok := stacks[res]; ok {
		return s
	}
	s := &netstack{res: res, dns: map[string]*dnsEntry{}, lkg: map[string]*lkgEntry{}}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = s.dialContext
	tr.DialTLSContext = chromeTLSDialer(s.dialContext, transportRoots(tr))
	s.transport = tr
	stacks[res] = s
	return s
}

func isIPLiteral(host string) bool {
	_, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil
}

func (s *netstack) startLookupLocked(host string, e *dnsEntry, timeout time.Duration) {
	done := make(chan struct{})
	e.inflight = done
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		type answer struct {
			addrs []netip.Addr
			err   error
		}
		answers := make(chan answer, 2)
		for _, network := range []string{"ip4", "ip6"} {
			go func() {
				addrs, err := s.res.LookupNetIP(ctx, network, host)
				answers <- answer{addrs, err}
			}()
		}

		var addrs []netip.Addr
		var errs []error
		var grace <-chan time.Time
		pending := 2
	collect:
		for pending > 0 {
			select {
			case a := <-answers:
				pending--
				if a.err == nil && len(a.addrs) > 0 {
					addrs = appendUnique(addrs, a.addrs)
					if grace == nil {
						grace = time.After(resolutionDelay)
					}
				} else {
					errs = append(errs, a.err)
				}
			case <-grace:
				break collect
			}
		}

		s.mu.Lock()
		s.storeLocked(host, e, addrs, lookupError(host, errs))
		e.inflight = nil
		s.mu.Unlock()
		close(done)

		if pending == 0 {
			cancel()
			return
		}
		a := <-answers
		cancel()
		if a.err != nil || len(a.addrs) == 0 {
			return
		}
		s.mu.Lock()
		if e.err == nil && len(e.addrs) > 0 {
			e.addrs = appendUnique(slices.Clone(e.addrs), a.addrs)
		}
		s.mu.Unlock()
	}()
}

func (s *netstack) storeLocked(host string, e *dnsEntry, addrs []netip.Addr, err error) {
	now := time.Now()
	switch {
	case len(addrs) > 0:
		e.addrs, e.err = addrs, nil
		e.expires, e.staleUntil = now.Add(dnsTTL), now.Add(dnsStaleMax)
	case len(e.addrs) > 0 && now.Before(e.staleUntil):
	default:
		e.addrs, e.err = nil, err
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			e.expires = now.Add(dnsNegativeTTL)
		} else {
			e.expires = now
		}
	}
}

func lookupError(host string, errs []error) error {
	var notFound error
	for _, err := range errs {
		var dnsErr *net.DNSError
		switch {
		case err == nil:
		case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
			notFound = err
		default:
			return err
		}
	}
	if notFound != nil {
		return notFound
	}
	return &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func appendUnique(dst, src []netip.Addr) []netip.Addr {
	for _, a := range src {
		if !slices.Contains(dst, a) {
			dst = append(dst, a)
		}
	}
	return dst
}

func (s *netstack) prefetch(hosts []string, timeout time.Duration) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, host := range hosts {
		if host == "" || isIPLiteral(host) {
			continue
		}
		e := s.dns[host]
		if e == nil {
			e = &dnsEntry{}
			s.dns[host] = e
		}
		if e.inflight != nil || (e.err == nil && len(e.addrs) > 0 && now.Before(e.expires)) {
			continue
		}
		s.startLookupLocked(host, e, timeout)
	}
}

func (s *netstack) resolve(ctx context.Context, host string, timeout time.Duration) ([]netip.Addr, error) {
	now := time.Now()
	s.mu.Lock()
	e := s.dns[host]
	if e == nil {
		e = &dnsEntry{}
		s.dns[host] = e
	}
	if e.inflight == nil {
		switch {
		case e.err == nil && len(e.addrs) > 0 && now.Before(e.expires):
			addrs := e.addrs
			s.mu.Unlock()
			return addrs, nil
		case e.err == nil && len(e.addrs) > 0 && now.Before(e.staleUntil):
			addrs := e.addrs
			s.startLookupLocked(host, e, timeout)
			s.mu.Unlock()
			return addrs, nil
		case e.err != nil && now.Before(e.expires):
			err := e.err
			s.mu.Unlock()
			return nil, err
		}
		s.startLookupLocked(host, e, timeout)
	}
	done := e.inflight
	s.mu.Unlock()

	select {
	case <-done:
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(e.addrs) > 0 {
			return e.addrs, nil
		}
		return nil, e.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *netstack) peek(host string) []netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.dns[host]; e != nil && e.err == nil && len(e.addrs) > 0 && time.Now().Before(e.staleUntil) {
		return slices.Clone(e.addrs)
	}
	return nil
}

func today() time.Time { return time.Now().UTC().Truncate(24 * time.Hour) }

func (s *netstack) lastKnown(host string) []netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.lkg[host]
	if e == nil || today().Sub(e.seen) > lkgMaxAge {
		return nil
	}
	return slices.Clone(e.addrs)
}

func (s *netstack) isLastKnownOnly(host string, addr netip.Addr) bool {
	return addr.IsValid() && slices.Contains(s.lastKnown(host), addr) && !slices.Contains(s.peek(host), addr)
}

func (s *netstack) remember(host string, addr netip.Addr) {
	if !addr.IsValid() || host == "" || isIPLiteral(host) {
		return
	}
	addr = addr.Unmap()
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.lkg[host]
	if e == nil {
		e = &lkgEntry{}
		s.lkg[host] = e
	}
	e.addrs = slices.DeleteFunc(e.addrs, func(a netip.Addr) bool { return a == addr })
	e.addrs = append([]netip.Addr{addr}, e.addrs...)
	if len(e.addrs) > lkgMaxAddrs {
		e.addrs = e.addrs[:lkgMaxAddrs]
	}
	e.seen, e.touched = today(), time.Now()
	s.trimLocked()
}

func (s *netstack) forget(host string, addr netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.lkg[host]
	if e == nil {
		return
	}
	e.addrs = slices.DeleteFunc(e.addrs, func(a netip.Addr) bool { return a == addr.Unmap() })
	if len(e.addrs) == 0 {
		delete(s.lkg, host)
	}
}

func (s *netstack) trimLocked() {
	day := today()
	hosts := make([]string, 0, len(s.lkg))
	for host, e := range s.lkg {
		if day.Sub(e.seen) > lkgMaxAge || len(e.addrs) == 0 {
			delete(s.lkg, host)
			continue
		}
		hosts = append(hosts, host)
	}
	if len(hosts) <= lkgMaxHosts {
		return
	}
	sort.Slice(hosts, func(i, j int) bool {
		a, b := s.lkg[hosts[i]], s.lkg[hosts[j]]
		if !a.touched.Equal(b.touched) {
			return a.touched.After(b.touched)
		}
		return hosts[i] < hosts[j]
	})
	for _, host := range hosts[lkgMaxHosts:] {
		delete(s.lkg, host)
	}
}

type persistedHost struct {
	Addrs []string `json:"addrs"`
	Seen  string   `json:"seen"`
}

func (s *netstack) exportHosts() map[string]persistedHost {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trimLocked()
	if len(s.lkg) == 0 {
		return nil
	}
	out := make(map[string]persistedHost, len(s.lkg))
	for host, e := range s.lkg {
		addrs := make([]string, 0, len(e.addrs))
		for _, a := range e.addrs {
			addrs = append(addrs, a.String())
		}
		sort.Strings(addrs)
		out[host] = persistedHost{Addrs: addrs, Seen: e.seen.Format(lkgDayLayout)}
	}
	return out
}

func (s *netstack) importHosts(hosts map[string]persistedHost) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for host, ph := range hosts {
		seen, err := time.Parse(lkgDayLayout, ph.Seen)
		if err != nil || host == "" || isIPLiteral(host) {
			continue
		}
		var addrs []netip.Addr
		for _, raw := range ph.Addrs {
			if a, err := netip.ParseAddr(raw); err == nil && !slices.Contains(addrs, a.Unmap()) {
				addrs = append(addrs, a.Unmap())
			}
		}
		if len(addrs) == 0 {
			continue
		}
		if len(addrs) > lkgMaxAddrs {
			addrs = addrs[:lkgMaxAddrs]
		}
		if cur := s.lkg[host]; cur != nil && !seen.After(cur.seen) {
			continue
		}
		s.lkg[host] = &lkgEntry{addrs: addrs, seen: seen, touched: seen}
	}
	s.trimLocked()
}

type dialRecord struct {
	mu   sync.Mutex
	addr netip.Addr
}

type dialRecordKey struct{}

func (r *dialRecord) set(addr netip.Addr) {
	r.mu.Lock()
	r.addr = addr
	r.mu.Unlock()
}

func (r *dialRecord) get() netip.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.addr
}

func connAddr(c net.Conn) netip.Addr {
	if tcp, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return tcp.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

func filterFamily(network string, addrs []netip.Addr) []netip.Addr {
	switch network {
	case "tcp4":
		return slicesFilter(addrs, func(a netip.Addr) bool { return a.Unmap().Is4() })
	case "tcp6":
		return slicesFilter(addrs, func(a netip.Addr) bool { return !a.Unmap().Is4() })
	}
	return addrs
}

func slicesFilter(addrs []netip.Addr, keep func(netip.Addr) bool) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if keep(a) {
			out = append(out, a)
		}
	}
	return out
}

func (s *netstack) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	if isIPLiteral(host) {
		return dialer.DialContext(ctx, network, address)
	}
	var addrs []netip.Addr
	if lkg := s.lastKnown(host); len(lkg) > 0 {
		addrs = s.peek(host)
		for _, a := range lkg {
			if !slices.Contains(addrs, a) {
				addrs = append(addrs, a)
			}
		}
	} else {
		var err error
		if addrs, err = s.resolve(ctx, host, defaultDNSTimeout); err != nil {
			return nil, err
		}
	}
	addrs = filterFamily(network, addrs)
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no suitable address", Name: host}
	}
	conn, err := raceDial(ctx, dialer, network, addrs, port)
	if rec, ok := ctx.Value(dialRecordKey{}).(*dialRecord); ok && err == nil {
		rec.set(connAddr(conn))
	}
	return conn, err
}

func raceDial(ctx context.Context, dialer *net.Dialer, network string, addrs []netip.Addr, port string) (net.Conn, error) {
	if len(addrs) == 1 {
		return dialer.DialContext(ctx, network, net.JoinHostPort(addrs[0].String(), port))
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, len(addrs))
	failed := make(chan struct{}, len(addrs))
	launch := func(a netip.Addr) {
		go func() {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
			if err != nil {
				failed <- struct{}{}
			}
			results <- result{conn, err}
		}()
	}

	launch(addrs[0])
	next := 1
	timer := time.NewTimer(dialStagger)
	defer timer.Stop()
	var firstErr error
	done := ctx.Done()
	for pending := 1; pending > 0; {
		select {
		case r := <-results:
			pending--
			if r.err == nil {
				cancel()
				go func(left int) {
					for ; left > 0; left-- {
						if late := <-results; late.conn != nil {
							late.conn.Close()
						}
					}
				}(pending)
				return r.conn, nil
			}
			if firstErr == nil {
				firstErr = r.err
			}
		case <-failed:
			if next < len(addrs) {
				launch(addrs[next])
				next++
				pending++
				timer.Reset(dialStagger)
			}
		case <-timer.C:
			if next < len(addrs) {
				launch(addrs[next])
				next++
				pending++
				timer.Reset(dialStagger)
			}
		case <-done:
			done = nil
			next = len(addrs)
			if firstErr == nil {
				firstErr = ctx.Err()
			}
		}
	}
	return nil, firstErr
}
