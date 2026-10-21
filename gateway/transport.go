package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Doer abstracts the HTTP transport so hosts can inject their own client
// (custom TLS/uTLS dialer, platform networking, tests).
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

type transportErrorKind int

const (
	transportOK transportErrorKind = iota
	transportTimeout
	transportCancelled
	transportConnError
)

type sendResult struct {
	kind    transportErrorKind
	ssl     bool
	err     error
	status  int
	body    []byte // raw, still encrypted
	phase   string
	elapsed time.Duration
	dnsWait time.Duration
	remote netip.Addr
	lastKnown bool
}

func (sr sendResult) notes() string {
	var out string
	if sr.phase != phaseDNS && sr.dnsWait >= 100*time.Millisecond {
		out = fmt.Sprintf("; dns %s", sr.dnsWait.Round(100*time.Millisecond))
	}
	if sr.lastKnown {
		out += "; last known address"
	}
	return out
}

const phaseDNS = "dns lookup"

var phaseNames = []string{"tcp connect", "dns lookup", "tcp connect", "tls handshake", "waiting for response", "reading response"}

type phaseTracker struct {
	current atomic.Int32

	mu     sync.Mutex
	remote netip.Addr
}

func (p *phaseTracker) gotConn(info httptrace.GotConnInfo) {
	if info.Conn == nil {
		return
	}
	addr := connAddr(info.Conn)
	p.mu.Lock()
	p.remote = addr
	p.mu.Unlock()
}

func (p *phaseTracker) remoteAddr() netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.remote
}

func (p *phaseTracker) set(i int32) { p.current.Store(i) }

func (p *phaseTracker) name() string { return phaseNames[p.current.Load()] }

func (p *phaseTracker) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { p.set(1) },
		DNSDone: func(info httptrace.DNSDoneInfo) {
			if info.Err == nil {
				p.set(2)
			}
		},
		ConnectStart:         func(string, string) { p.set(2) },
		GotConn:              p.gotConn,
		TLSHandshakeStart:    func() { p.set(3) },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { p.set(4) },
		WroteRequest:         func(httptrace.WroteRequestInfo) { p.set(4) },
		GotFirstResponseByte: func() { p.set(5) },
	}
}

const maxResponseBytes = 32 << 20

func (c *Client) send(ctx context.Context, method, target string, body []byte, timeout time.Duration, requestID string) sendResult {
	if c.cfg.OnBeforeRequest != nil {
		if u, err := url.Parse(target); err == nil {
			c.cfg.OnBeforeRequest(u.Hostname())
		}
	}

	dnsWait, failed := c.resolveTarget(ctx, target)
	if failed != nil {
		return *failed
	}

	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var phase phaseTracker
	rec := &dialRecord{}
	started := time.Now()
	rctx := context.WithValue(httptrace.WithClientTrace(tctx, phase.clientTrace()), dialRecordKey{}, rec)
	req, err := http.NewRequestWithContext(rctx, method, target, bytes.NewReader(body))
	if err != nil {
		return sendResult{kind: transportConnError, err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	if requestID != "" {
		req.Header.Set("X-Client-Request-ID", requestID)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		out := sendResult{kind: classifyTransportError(ctx, err), ssl: isTLSError(err), err: err, phase: phase.name(), elapsed: time.Since(started), dnsWait: dnsWait}
		c.noteRemote(target, &out, rec.get())
		return out
	}
	defer resp.Body.Close()

	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	out := sendResult{status: resp.StatusCode, body: data, phase: phase.name(), elapsed: time.Since(started), dnsWait: dnsWait}
	if readErr != nil {
		out.kind = classifyTransportError(ctx, readErr)
		out.err = readErr
	}
	remote := phase.remoteAddr()
	if !remote.IsValid() {
		remote = rec.get()
	}
	c.noteRemote(target, &out, remote)
	return out
}

func (c *Client) noteRemote(target string, sr *sendResult, remote netip.Addr) {
	host := c.lastKnownHost(target)
	if host == "" || !remote.IsValid() {
		return
	}
	sr.remote = remote
	sr.lastKnown = c.net.isLastKnownOnly(host, remote)
	if sr.ssl && slices.Contains(c.net.lastKnown(host), remote) {
		c.net.forget(host, remote)
	}
}

func (c *Client) confirm(target string, sr sendResult) {
	if host := c.lastKnownHost(target); host != "" {
		c.net.remember(host, sr.remote)
	}
}

func (c *Client) lastKnownHost(target string) string {
	if c.net == nil || usesEnvironmentProxy(target) {
		return ""
	}
	u, err := url.Parse(target)
	if err != nil || isIPLiteral(u.Hostname()) {
		return ""
	}
	return u.Hostname()
}

func (c *Client) resolveTarget(ctx context.Context, target string) (time.Duration, *sendResult) {
	if c.net == nil {
		return 0, nil
	}
	u, err := url.Parse(target)
	if err != nil {
		return 0, nil
	}
	host := u.Hostname()
	if host == "" || isIPLiteral(host) || usesEnvironmentProxy(target) {
		return 0, nil
	}

	budget := c.cfg.DNSTimeout
	fallback := len(c.net.lastKnown(host)) > 0
	if fallback {
		budget = min(budget, lkgDNSWait)
	}
	started := time.Now()
	rctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	_, err = c.net.resolve(rctx, host, c.cfg.DNSTimeout)
	waited := time.Since(started)
	if err == nil || (fallback && ctx.Err() == nil) {
		return waited, nil
	}

	out := sendResult{err: err, phase: phaseDNS, elapsed: waited, dnsWait: waited}
	var dnsErr *net.DNSError
	switch {
	case ctx.Err() != nil:
		out.kind = classifyTransportError(ctx, ctx.Err())
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &dnsErr) && dnsErr.IsTimeout:
		out.kind = transportTimeout
	default:
		out.kind = transportConnError
		if !errors.As(err, &dnsErr) {
			out.err = &net.DNSError{Err: err.Error(), Name: host}
		}
	}
	return waited, &out
}

func usesEnvironmentProxy(target string) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	proxy, err := http.ProxyFromEnvironment(&http.Request{URL: u})
	return err == nil && proxy != nil
}

func classifyTransportError(parent context.Context, err error) transportErrorKind {
	switch {
	case parent.Err() != nil && context.Cause(parent) == errPostDeadline:
		return transportTimeout
	case parent.Err() != nil:
		return transportCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return transportTimeout
	default:
		var netErr interface{ Timeout() bool }
		if errors.As(err, &netErr) && netErr.Timeout() {
			return transportTimeout
		}
		return transportConnError
	}
}

func isTLSError(err error) bool {
	var (
		verifyErr   *tls.CertificateVerificationError
		recordErr   tls.RecordHeaderError
		unknownAuth x509.UnknownAuthorityError
		hostnameErr x509.HostnameError
		invalidCert x509.CertificateInvalidError
	)
	return errors.As(err, &verifyErr) || errors.As(err, &recordErr) ||
		errors.As(err, &unknownAuth) || errors.As(err, &hostnameErr) ||
		errors.As(err, &invalidCert)
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func joinURL(base, path string) string {
	b := strings.TrimRight(base, "/")
	p := strings.TrimLeft(path, "/")
	if p == "" {
		return b
	}
	return b + "/" + p
}
