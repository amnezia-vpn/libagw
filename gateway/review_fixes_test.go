package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// A saved proxy that fails TLS must not stick: the request goes through
// failover, which replaces the proxy.
func TestPostSavedProxyTLSErrorRunsFailover(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)

	// Self-signed certificate the default client does not trust.
	var badHits atomic.Int32
	badProxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		badHits.Add(1)
	}))
	t.Cleanup(badProxy.Close)

	goodProxy, goodHits := proxyServer(t, priv, func([]byte) []byte {
		return []byte(`{"services":["via-good-proxy"]}`)
	})
	storageBody := encryptStorageList(t, pubPEM, []string{goodProxy.URL})
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(storageBody)
	}))
	t.Cleanup(storage.Close)

	c := newTestClient(t, Config{
		GatewayEndpoint:    "http://127.0.0.1:1",
		PublicKeyPEM:       pubPEM,
		S3PrimaryEndpoints: []string{storage.URL},
	})
	state, _ := json.Marshal(persistedState{Version: stateVersion, WorkingProxy: badProxy.URL})
	if err := c.ImportState(state); err != nil {
		t.Fatal(err)
	}

	resp, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if err != nil {
		t.Fatalf("want failover past the TLS-broken proxy, got %v", err)
	}
	if string(resp.Body) != `{"services":["via-good-proxy"]}` {
		t.Fatalf("body: %s", resp.Body)
	}
	if goodHits.Load() == 0 {
		t.Fatal("good proxy never reached")
	}
	if got := c.getWorkingProxy(); got != goodProxy.URL {
		t.Fatal("working proxy not replaced")
	}
}

// When failover finds nothing, the TLS-broken proxy is still dropped, so the
// next request tries the gateway directly instead of failing the same way.
func TestPostSavedProxyTLSErrorDropsProxy(t *testing.T) {
	_, pubPEM := newTestKeyPair(t)
	badProxy := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(badProxy.Close)

	c := newTestClient(t, Config{GatewayEndpoint: "http://127.0.0.1:1", PublicKeyPEM: pubPEM})
	state, _ := json.Marshal(persistedState{Version: stateVersion, WorkingProxy: badProxy.URL})
	if err := c.ImportState(state); err != nil {
		t.Fatal(err)
	}

	_, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if code := errCodeOf(t, err); code != SSLError {
		t.Fatalf("code %d, want %d", code, SSLError)
	}
	if got := c.getWorkingProxy(); got != "" {
		t.Fatal("TLS-broken proxy kept as the working proxy")
	}
}

// A TLS error on the direct gateway path still ends the request without
// failover, as in the Qt client.
func TestPostDirectTLSErrorNoFailover(t *testing.T) {
	_, pubPEM := newTestKeyPair(t)
	gw := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(gw.Close)

	var storageHits atomic.Int32
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		storageHits.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(storage.Close)

	c := newTestClient(t, Config{GatewayEndpoint: gw.URL, PublicKeyPEM: pubPEM, S3PrimaryEndpoints: []string{storage.URL}})
	_, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if code := errCodeOf(t, err); code != SSLError {
		t.Fatalf("code %d, want %d", code, SSLError)
	}
	if storageHits.Load() != 0 {
		t.Fatal("direct TLS error must not trigger failover")
	}
}

// The proxy picked by the health check is not tried a second time in the
// sweep.
func TestPickedProxyNotRetriedInSweep(t *testing.T) {
	_, pubPEM := newTestKeyPair(t)
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>denied</html>"))
	}))
	t.Cleanup(blocked.Close)

	var posts atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, healthPath) {
			w.Write([]byte("ok"))
			return
		}
		posts.Add(1)
		w.Write([]byte("<html>also denied</html>"))
	}))
	t.Cleanup(proxy.Close)
	storageBody := encryptStorageList(t, pubPEM, []string{proxy.URL})
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(storageBody) }))
	t.Cleanup(storage.Close)

	c := newTestClient(t, Config{GatewayEndpoint: blocked.URL, PublicKeyPEM: pubPEM, S3PrimaryEndpoints: []string{storage.URL}})
	c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if posts.Load() != 1 {
		t.Fatalf("picked proxy got %d POSTs, want 1", posts.Load())
	}
}

// A request through the saved proxy is logged as such, not as a direct attempt.
func TestLogTellsSavedProxyFromDirect(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)
	proxy, _ := proxyServer(t, priv, func([]byte) []byte { return []byte(`{}`) })

	var mu sync.Mutex
	var lines []string
	c := newTestClient(t, Config{
		GatewayEndpoint: "http://127.0.0.1:1",
		PublicKeyPEM:    pubPEM,
		Logger: func(_ LogLevel, msg string) {
			mu.Lock()
			lines = append(lines, msg)
			mu.Unlock()
		},
	})
	state, _ := json.Marshal(persistedState{Version: stateVersion, WorkingProxy: proxy.URL})
	if err := c.ImportState(state); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(lines) == 0 || lines[0] != "saved proxy attempt" {
		t.Fatalf("first log line %v, want \"saved proxy attempt\"", lines)
	}
}
