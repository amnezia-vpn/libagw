package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func okGateway(t *testing.T) (*httptest.Server, []byte) {
	t.Helper()
	priv, pubPEM := newTestKeyPair(t)
	srv := httptest.NewServer(gatewayHandler(priv, nil, func([]byte) []byte { return []byte(`{"ok":true}`) }))
	t.Cleanup(srv.Close)
	return srv, pubPEM
}

func hangingServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSlowDNSDoesNotEatTheAttemptBudget(t *testing.T) {
	srv, pubPEM := okGateway(t)
	res := newFakeResolver()
	res.set("gw.test", 600*time.Millisecond)

	c := New(Config{
		GatewayEndpoint: named(srv.URL, "gw.test"),
		PublicKeyPEM:    pubPEM,
		RequestTimeout:  400 * time.Millisecond,
		Resolver:        res,
	})
	resp, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if err != nil {
		t.Fatalf("%v\n%s", err, traceOf(err))
	}
	if len(resp.Trace) != 2 || !strings.HasPrefix(resp.Trace[1], "direct: http 200, ") || !strings.HasSuffix(resp.Trace[1], ", accepted; dns 600ms; ipv4; address 127.0.0.1") {
		t.Fatalf("trace:\n%s", resp.Trace)
	}
}

func TestDNSTimeoutBoundsTheLookup(t *testing.T) {
	srv, pubPEM := okGateway(t)
	res := newFakeResolver()
	res.set("gw.test", 3*time.Second)

	c := New(Config{
		GatewayEndpoint: named(srv.URL, "gw.test"),
		PublicKeyPEM:    pubPEM,
		DNSTimeout:      200 * time.Millisecond,
		Resolver:        res,
	})
	started := time.Now()
	_, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if code := errCodeOf(t, err); code != TimeoutError {
		t.Fatalf("code %d, want %d", code, TimeoutError)
	}
	if took := time.Since(started); took > 1500*time.Millisecond {
		t.Fatalf("post took %s", took)
	}
	if tr := traceOf(err); !strings.Contains(tr, "direct: timeout after 200ms in dns lookup, suspicious") {
		t.Fatalf("trace:\n%s", tr)
	}
}

func TestUnknownHostIsAConnectFailure(t *testing.T) {
	_, pubPEM := newTestKeyPair(t)
	res := newFakeResolver()
	res.fail["gw.test"] = &net.DNSError{Err: "no such host", Name: "gw.test", IsNotFound: true}

	c := New(Config{GatewayEndpoint: "http://gw.test:1", PublicKeyPEM: pubPEM, Resolver: res})
	_, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if code := errCodeOf(t, err); code != NetworkError {
		t.Fatalf("code %d, want %d", code, NetworkError)
	}
	if tr := traceOf(err); !strings.Contains(tr, "direct: connect failed: dns lookup failed: no such host, in dns lookup, suspicious") {
		t.Fatalf("trace:\n%s", tr)
	}
}

func TestHealthBudgetExcludesDNS(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>blocked</html>"))
	}))
	t.Cleanup(blocked.Close)
	proxy, _ := proxyServer(t, priv, func([]byte) []byte { return []byte(`{"ok":true}`) })
	storageBody := encryptStorageList(t, pubPEM, []string{named(proxy.URL, "proxy.test")})
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(storageBody) }))
	t.Cleanup(storage.Close)

	res := newFakeResolver()
	res.set("proxy.test", 400*time.Millisecond)
	c := New(Config{
		GatewayEndpoint:    blocked.URL,
		PublicKeyPEM:       pubPEM,
		S3PrimaryEndpoints: []string{storage.URL},
		ProxyHealthTimeout: 200 * time.Millisecond,
		Resolver:           res,
	})
	resp, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if err != nil {
		t.Fatalf("%v\n%s", err, traceOf(err))
	}
	joined := resp.Trace.String()
	if !strings.Contains(joined, "health 1/1: ok; dns 400ms") || !strings.Contains(joined, "proxy 1/1: http 200") {
		t.Fatalf("trace:\n%s", joined)
	}
	if strings.Contains(joined, ".test") || strings.Contains(joined, "127.0.0.1") {
		t.Fatalf("trace leaks a host:\n%s", joined)
	}
}

func TestDNSCacheIsSharedAcrossClients(t *testing.T) {
	srv, pubPEM := okGateway(t)
	res := newFakeResolver()
	for i := 0; i < 3; i++ {
		c := New(Config{GatewayEndpoint: named(srv.URL, "gw.test"), PublicKeyPEM: pubPEM, Resolver: res})
		if _, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if n := res.callsFor("gw.test"); n != 1 {
		t.Fatalf("%d lookups, want 1", n)
	}
}

func TestLookupOutlivesTheAttemptThatStartedIt(t *testing.T) {
	res := newFakeResolver()
	res.set("slow.test", 300*time.Millisecond)
	s := stackFor(res)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := s.resolve(ctx, "slow.test", time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first resolve: %v", err)
	}
	started := time.Now()
	addrs, err := s.resolve(context.Background(), "slow.test", time.Second)
	if err != nil || len(addrs) != 1 {
		t.Fatalf("second resolve: %v %v", addrs, err)
	}
	if took := time.Since(started); took > 280*time.Millisecond {
		t.Fatalf("second resolve took %s: it did not join the running lookup", took)
	}
	if n := res.callsFor("slow.test"); n != 1 {
		t.Fatalf("%d lookups, want 1", n)
	}
}

func TestStaleAnswerIsServedWhenTheRefreshFails(t *testing.T) {
	res := newFakeResolver()
	s := stackFor(res)
	if _, err := s.resolve(context.Background(), "gw.test", time.Second); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.dns["gw.test"].expires = time.Now().Add(-time.Second)
	s.mu.Unlock()
	res.mu.Lock()
	res.fail["gw.test"] = &net.DNSError{Err: "server misbehaving", Name: "gw.test"}
	res.mu.Unlock()

	for i := 0; i < 2; i++ {
		addrs, err := s.resolve(context.Background(), "gw.test", time.Second)
		if err != nil || len(addrs) != 1 {
			t.Fatalf("resolve %d: %v %v", i, addrs, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestPrefetchResolvesFailoverHostsTogether(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>blocked</html>"))
	}))
	t.Cleanup(blocked.Close)
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(broken.Close)
	proxy, _ := proxyServer(t, priv, func([]byte) []byte { return []byte(`{"ok":true}`) })
	storageBody := encryptStorageList(t, pubPEM, []string{proxy.URL})
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(storageBody) }))
	t.Cleanup(storage.Close)

	res := newFakeResolver()
	for _, host := range []string{"gw.test", "s1.test", "s2.test"} {
		res.set(host, 300*time.Millisecond)
	}
	c := New(Config{
		GatewayEndpoint:     named(blocked.URL, "gw.test"),
		PublicKeyPEM:        pubPEM,
		S3PrimaryEndpoints:  []string{named(broken.URL, "s1.test")},
		S3FallbackEndpoints: []string{named(storage.URL, "s2.test")},
		Resolver:            res,
	})
	started := time.Now()
	if _, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{}); err != nil {
		t.Fatalf("%v\n%s", err, traceOf(err))
	}
	if n := res.maxConcurrent(); n < 3 {
		t.Fatalf("at most %d lookups ran together, want 3", n)
	}
	if took := time.Since(started); took > 800*time.Millisecond {
		t.Fatalf("post took %s: lookups ran one after another", took)
	}
}

func TestHealthChecksRunInParallel(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>blocked</html>"))
	}))
	t.Cleanup(blocked.Close)
	good, _ := proxyServer(t, priv, func([]byte) []byte { return []byte(`{"ok":true}`) })
	list := []string{good.URL}
	for i := 0; i < 3; i++ {
		list = append(list, hangingServer(t).URL)
	}
	storageBody := encryptStorageList(t, pubPEM, list)
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(storageBody) }))
	t.Cleanup(storage.Close)

	c := New(Config{
		GatewayEndpoint:    blocked.URL,
		PublicKeyPEM:       pubPEM,
		S3PrimaryEndpoints: []string{storage.URL},
		ProxyHealthTimeout: 800 * time.Millisecond,
	})
	for i := 0; i < 5; i++ {
		c.setWorkingProxy("")
		started := time.Now()
		resp, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
		if err != nil {
			t.Fatalf("%v\n%s", err, traceOf(err))
		}
		if took := time.Since(started); took > 600*time.Millisecond {
			t.Fatalf("post took %s: health checks waited for each other\n%s", took, resp.Trace)
		}
		health := 0
		for _, line := range resp.Trace {
			if strings.HasPrefix(line, "health ") {
				health++
				if !strings.HasSuffix(line, ": ok") {
					t.Fatalf("a cancelled check made it to the trace:\n%s", resp.Trace)
				}
			}
		}
		if health != 1 {
			t.Fatalf("%d health lines, want 1:\n%s", health, resp.Trace)
		}
	}
}

func TestSweepReachesAProxyWhoseHealthCheckFailed(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>blocked</html>"))
	}))
	t.Cleanup(blocked.Close)

	refused := httptest.NewServer(http.HandlerFunc(http.NotFound))
	refused.Close()
	proxy, hits := proxyServer(t, priv, func([]byte) []byte { return []byte(`{"ok":true}`) })
	slowHealth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, healthPath) {
			time.Sleep(400 * time.Millisecond)
			w.Write([]byte("ok"))
			return
		}
		proxy.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(slowHealth.Close)

	storageBody := encryptStorageList(t, pubPEM, []string{refused.URL, slowHealth.URL})
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(storageBody) }))
	t.Cleanup(storage.Close)

	c := New(Config{
		GatewayEndpoint:    blocked.URL,
		PublicKeyPEM:       pubPEM,
		S3PrimaryEndpoints: []string{storage.URL},
		ProxyHealthTimeout: 100 * time.Millisecond,
	})
	resp, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if err != nil {
		t.Fatalf("%v\n%s", err, traceOf(err))
	}
	if hits.Load() != 1 {
		t.Fatalf("working proxy got %d requests, want 1", hits.Load())
	}
	if last := resp.Trace[len(resp.Trace)-1]; !strings.HasPrefix(last, "proxy ") || !strings.Contains(last, ", accepted") {
		t.Fatalf("trace:\n%s", resp.Trace)
	}
}

func traceOf(err error) string {
	var gwErr *Error
	if errors.As(err, &gwErr) {
		return gwErr.Trace.String()
	}
	var cancelled *CancelledError
	if errors.As(err, &cancelled) {
		return cancelled.Trace.String()
	}
	return ""
}

func TestSlowIPv6AnswerDoesNotHoldTheLookup(t *testing.T) {
	res := newFakeResolver()
	res.set("gw.test", 100*time.Millisecond)
	res.delay6["gw.test"] = 3 * time.Second
	s := stackFor(res)

	started := time.Now()
	addrs, err := s.resolve(context.Background(), "gw.test", 5*time.Second)
	if err != nil || len(addrs) != 1 || !addrs[0].Is4() {
		t.Fatalf("resolve: %v %v", addrs, err)
	}
	if took := time.Since(started); took > time.Second {
		t.Fatalf("resolve took %s: it waited for the IPv6 answer", took)
	}
}

func TestIPv6AnswerAloneIsEnough(t *testing.T) {
	res := newFakeResolver()
	res.set("gw.test", 3*time.Second)
	res.delay6["gw.test"] = 50 * time.Millisecond
	res.addr6["gw.test"] = netip.MustParseAddr("::1")
	s := stackFor(res)

	started := time.Now()
	addrs, err := s.resolve(context.Background(), "gw.test", 5*time.Second)
	if err != nil || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("::1") {
		t.Fatalf("resolve: %v %v", addrs, err)
	}
	if took := time.Since(started); took > time.Second {
		t.Fatalf("resolve took %s", took)
	}
}

func TestLateFamilyJoinsTheCachedAnswer(t *testing.T) {
	res := newFakeResolver()
	res.delay6["gw.test"] = 200 * time.Millisecond
	res.addr6["gw.test"] = netip.MustParseAddr("::1")
	s := stackFor(res)

	addrs, err := s.resolve(context.Background(), "gw.test", 5*time.Second)
	if err != nil || len(addrs) != 1 {
		t.Fatalf("resolve: %v %v", addrs, err)
	}
	time.Sleep(400 * time.Millisecond)
	if got := s.peek("gw.test"); len(got) != 2 || !slices.Contains(got, netip.MustParseAddr("::1")) {
		t.Fatalf("cached %v, want both families", got)
	}
}

func TestTimeoutInOneFamilyIsNotCachedAsUnknownHost(t *testing.T) {
	res := newFakeResolver()
	res.set("gw.test", 3*time.Second)
	res.delay6["gw.test"] = 0
	s := stackFor(res)

	_, err := s.resolve(context.Background(), "gw.test", 200*time.Millisecond)
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || dnsErr.IsNotFound {
		t.Fatalf("err %v, want a timeout", err)
	}
	res.set("gw.test", 0)
	if addrs, err := s.resolve(context.Background(), "gw.test", time.Second); err != nil || len(addrs) != 1 {
		t.Fatalf("second resolve: %v %v (the timeout was cached)", addrs, err)
	}
}
