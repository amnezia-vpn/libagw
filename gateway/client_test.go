package gateway

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testEndpoint = "v1/services"

func gatewayHandler(priv *rsa.PrivateKey, hits *atomic.Int32, respond func(payload []byte) []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		body := make([]byte, 0, 4096)
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			body = append(body, buf[:n]...)
			if err != nil {
				break
			}
		}
		payload, key, iv, err := openEnvelopeErr(priv, body)
		if err != nil {
			http.Error(w, "bad envelope: "+err.Error(), http.StatusInternalServerError)
			return
		}
		ct, err := aesEncryptCBC(respond(payload), key, iv)
		if err != nil {
			http.Error(w, "encrypt failed", http.StatusInternalServerError)
			return
		}
		w.Write(ct)
	}
}

func proxyServer(t *testing.T, priv *rsa.PrivateKey, respond func(payload []byte) []byte) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	gw := gatewayHandler(priv, &hits, respond)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, healthPath) {
			w.Write([]byte("ok"))
			return
		}
		gw(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func newTestClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 5 * time.Second
	}
	if cfg.ProxyStorageTimeout == 0 {
		cfg.ProxyStorageTimeout = 2 * time.Second
	}
	if cfg.ProxyHealthTimeout == 0 {
		cfg.ProxyHealthTimeout = 2 * time.Second
	}
	return New(cfg)
}

func errCodeOf(t *testing.T, err error) ErrorCode {
	t.Helper()
	var gwErr *Error
	if !errors.As(err, &gwErr) {
		t.Fatalf("want *gateway.Error, got %v", err)
	}
	return gwErr.Code
}

func TestPostDirectSuccess(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)

	var gotPayload []byte
	srv := httptest.NewServer(gatewayHandler(priv, nil, func(payload []byte) []byte {
		gotPayload = payload
		return []byte(`{"services":["ok"]}`)
	}))
	t.Cleanup(srv.Close)

	c := newTestClient(t, Config{GatewayEndpoint: srv.URL, PublicKeyPEM: pubPEM})
	resp, err := c.Post(context.Background(), testEndpoint, []byte(`{"app_version":"4.8"}`), PostOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != `{"services":["ok"]}` {
		t.Fatalf("body: %s", resp.Body)
	}
	if string(gotPayload) != `{"app_version":"4.8"}` {
		t.Fatalf("server saw payload: %s", gotPayload)
	}
}

func TestPostFailoverThroughProxy(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)

	var directHits atomic.Int32
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directHits.Add(1)
		w.Write([]byte("<html>access denied</html>"))
	}))
	t.Cleanup(blocked.Close)

	proxy, proxyHits := proxyServer(t, priv, func([]byte) []byte {
		return []byte(`{"services":["via-proxy"]}`)
	})

	var storageHits atomic.Int32
	storageBody := encryptStorageList(t, pubPEM, []string{proxy.URL})
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		storageHits.Add(1)
		w.Write(storageBody)
	}))
	t.Cleanup(storage.Close)

	c := newTestClient(t, Config{
		GatewayEndpoint:    blocked.URL,
		PublicKeyPEM:       pubPEM,
		S3PrimaryEndpoints: []string{storage.URL},
	})

	opts := PostOptions{ServiceType: "amnezia-free", UserCountryCode: "ru"}
	resp, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), opts)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != `{"services":["via-proxy"]}` {
		t.Fatalf("body: %s", resp.Body)
	}
	if storageHits.Load() == 0 {
		t.Fatal("storage was never queried")
	}

	// The working proxy must be remembered: the second call goes straight to
	// the proxy without touching the blocked endpoint again.
	if _, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), opts); err != nil {
		t.Fatal(err)
	}
	if directHits.Load() != 1 {
		t.Fatalf("blocked endpoint hit %d times, want 1", directHits.Load())
	}
	if proxyHits.Load() < 2 {
		t.Fatalf("proxy hit %d times, want >= 2", proxyHits.Load())
	}
}

func TestPostCaptchaNoFailover(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)

	srv := httptest.NewServer(gatewayHandler(priv, nil, func([]byte) []byte {
		return []byte(`{"http_status":402,"captcha_id":"abc","captcha_image":"xyz"}`)
	}))
	t.Cleanup(srv.Close)

	var storageHits atomic.Int32
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		storageHits.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(storage.Close)

	c := newTestClient(t, Config{
		GatewayEndpoint:    srv.URL,
		PublicKeyPEM:       pubPEM,
		S3PrimaryEndpoints: []string{storage.URL},
	})
	resp, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if code := errCodeOf(t, err); code != ApiCaptchaRequiredError {
		t.Fatalf("code %d, want %d", code, ApiCaptchaRequiredError)
	}
	var doc map[string]any
	if json.Unmarshal(resp.Body, &doc) != nil || doc["captcha_id"] != "abc" {
		t.Fatalf("captcha body must be passed through, got: %s", resp.Body)
	}
	if storageHits.Load() != 0 {
		t.Fatal("business errors must not trigger proxy failover")
	}
}

func TestPostAllPathsBlocked(t *testing.T) {
	_, pubPEM := newTestKeyPair(t)

	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>denied</html>"))
	}))
	t.Cleanup(blocked.Close)
	storage := httptest.NewServer(http.HandlerFunc(http.NotFound))
	t.Cleanup(storage.Close)

	c := newTestClient(t, Config{
		GatewayEndpoint:    blocked.URL,
		PublicKeyPEM:       pubPEM,
		S3PrimaryEndpoints: []string{storage.URL},
	})
	_, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	// Parity with the Qt client: an undecryptable 200 response maps to a
	// decryption error, not a download error.
	if code := errCodeOf(t, err); code != ApiConfigDecryptionError {
		t.Fatalf("code %d, want %d", code, ApiConfigDecryptionError)
	}
}

func TestPostUsesCachedProxyListWhenStoragesDown(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)

	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>denied</html>"))
	}))
	t.Cleanup(blocked.Close)
	storage := httptest.NewServer(http.HandlerFunc(http.NotFound))
	t.Cleanup(storage.Close)
	proxy, _ := proxyServer(t, priv, func([]byte) []byte { return []byte(`{"ok":true}`) })

	c := newTestClient(t, Config{
		GatewayEndpoint:    blocked.URL,
		PublicKeyPEM:       pubPEM,
		S3PrimaryEndpoints: []string{storage.URL},
	})

	opts := PostOptions{ServiceType: "svc", UserCountryCode: "de"}
	state, _ := json.Marshal(persistedState{
		Version:    stateVersion,
		ProxyLists: map[string][]string{proxyListKey("svc", "de"): {proxy.URL}},
	})
	if err := c.ImportState(state); err != nil {
		t.Fatal(err)
	}

	resp, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), opts)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != `{"ok":true}` {
		t.Fatalf("body: %s", resp.Body)
	}
}

func TestPostContextCancel(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		gatewayHandler(priv, nil, func([]byte) []byte { return []byte(`{}`) })(w, r)
	}))
	t.Cleanup(srv.Close)

	c := newTestClient(t, Config{GatewayEndpoint: srv.URL, PublicKeyPEM: pubPEM})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := c.Post(ctx, testEndpoint, []byte(`{}`), PostOptions{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want context error, got %v", err)
	}
}

func TestStateRoundTrip(t *testing.T) {
	_, pubPEM := newTestKeyPair(t)
	c := newTestClient(t, Config{GatewayEndpoint: "https://gw", PublicKeyPEM: pubPEM})
	c.setWorkingProxy("https://proxy.example.com/")
	c.mu.Lock()
	c.proxyLists["service_a_country_b"] = []string{"https://p1/", "https://p2/"}
	c.mu.Unlock()

	blob := c.ExportState()

	c2 := newTestClient(t, Config{GatewayEndpoint: "https://gw", PublicKeyPEM: pubPEM})
	if err := c2.ImportState(blob); err != nil {
		t.Fatal(err)
	}
	if c2.getWorkingProxy() != "https://proxy.example.com/" {
		t.Fatal("working proxy lost")
	}
	c2.mu.Lock()
	defer c2.mu.Unlock()
	if len(c2.proxyLists["service_a_country_b"]) != 2 {
		t.Fatal("proxy lists lost")
	}
}

func TestImportStateRejectsGarbage(t *testing.T) {
	_, pubPEM := newTestKeyPair(t)
	c := newTestClient(t, Config{GatewayEndpoint: "https://gw", PublicKeyPEM: pubPEM})
	if err := c.ImportState([]byte("not json")); err == nil {
		t.Fatal("garbage state must be rejected")
	}
	if err := c.ImportState([]byte(`{"version":99}`)); err == nil {
		t.Fatal("unknown version must be rejected")
	}
}

func TestPostMissingPublicKey(t *testing.T) {
	c := newTestClient(t, Config{GatewayEndpoint: "https://gw"})
	_, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if code := errCodeOf(t, err); code != ApiMissingAgwPublicKey {
		t.Fatalf("code %d, want %d", code, ApiMissingAgwPublicKey)
	}
}

// Log messages must not carry endpoint addresses: hosts route them into
// application logs that users export and share.
func TestLogsCarryNoEndpointAddresses(t *testing.T) {
	_, pubPEM := newTestKeyPair(t)

	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>denied</html>"))
	}))
	t.Cleanup(blocked.Close)
	storage := httptest.NewServer(http.HandlerFunc(http.NotFound))
	t.Cleanup(storage.Close)
	proxy := httptest.NewServer(http.HandlerFunc(http.NotFound))
	t.Cleanup(proxy.Close)

	var lines []string
	c := newTestClient(t, Config{
		GatewayEndpoint:    blocked.URL,
		PublicKeyPEM:       pubPEM,
		S3PrimaryEndpoints: []string{storage.URL},
		Logger: func(_ LogLevel, msg string) {
			lines = append(lines, msg)
		},
	})
	state, _ := json.Marshal(persistedState{
		Version:    stateVersion,
		ProxyLists: map[string][]string{proxyListKey("svc", "de"): {proxy.URL}},
	})
	if err := c.ImportState(state); err != nil {
		t.Fatal(err)
	}

	c.Post(context.Background(), testEndpoint, []byte(`{}`),
		PostOptions{ServiceType: "svc", UserCountryCode: "de"})

	if len(lines) == 0 {
		t.Fatal("expected progress messages")
	}
	for _, host := range []string{blocked.URL, storage.URL, proxy.URL} {
		bare := strings.TrimPrefix(host, "http://")
		for _, line := range lines {
			if strings.Contains(line, host) || strings.Contains(line, bare) {
				t.Errorf("log line leaks an endpoint address: %q", line)
			}
		}
	}
}
