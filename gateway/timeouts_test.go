package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProxyRequestTimeoutDefaultsToRequestTimeout(t *testing.T) {
	if got := New(Config{}).cfg.ProxyRequestTimeout; got != defaultRequestTimeout {
		t.Fatalf("default proxy timeout %s, want %s", got, defaultRequestTimeout)
	}
	if got := New(Config{RequestTimeout: 7 * time.Second}).cfg.ProxyRequestTimeout; got != 7*time.Second {
		t.Fatalf("proxy timeout %s, want the request timeout", got)
	}
	if got := New(Config{RequestTimeout: 7 * time.Second, ProxyRequestTimeout: 3 * time.Second}).cfg.ProxyRequestTimeout; got != 3*time.Second {
		t.Fatalf("proxy timeout %s, want 3s", got)
	}
}

func TestProxyAttemptsUseTheProxyTimeout(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)

	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>blocked</html>"))
	}))
	t.Cleanup(blocked.Close)
	answer := gatewayHandler(priv, nil, func([]byte) []byte { return []byte(`{"ok":true}`) })
	slowProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, healthPath) {
			w.Write([]byte("ok"))
			return
		}
		time.Sleep(time.Second)
		answer(w, r)
	}))
	t.Cleanup(slowProxy.Close)
	storageBody := encryptStorageList(t, pubPEM, []string{slowProxy.URL})
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(storageBody)
	}))
	t.Cleanup(storage.Close)

	c := newTestClient(t, Config{
		GatewayEndpoint:     blocked.URL,
		PublicKeyPEM:        pubPEM,
		S3PrimaryEndpoints:  []string{storage.URL},
		RequestTimeout:      5 * time.Second,
		ProxyRequestTimeout: 200 * time.Millisecond,
	})
	started := time.Now()
	_, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if code := errCodeOf(t, err); code != TimeoutError {
		t.Fatalf("code %d, want %d", code, TimeoutError)
	}
	if took := time.Since(started); took > 2*time.Second {
		t.Fatalf("post took %s: the proxy attempt did not use the proxy timeout", took)
	}
	if !strings.Contains(err.(*Error).Trace.String(), "proxy 1/1: timeout after 200ms") {
		t.Fatalf("trace:\n%s", err.(*Error).Trace)
	}
}

func TestDirectAttemptUsesTheRequestTimeout(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)

	answer := gatewayHandler(priv, nil, func([]byte) []byte { return []byte(`{"ok":true}`) })
	slowGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		answer(w, r)
	}))
	t.Cleanup(slowGateway.Close)

	c := newTestClient(t, Config{
		GatewayEndpoint:     slowGateway.URL,
		PublicKeyPEM:        pubPEM,
		RequestTimeout:      3 * time.Second,
		ProxyRequestTimeout: 100 * time.Millisecond,
	})
	resp, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != `{"ok":true}` {
		t.Fatalf("body: %s", resp.Body)
	}
}

func TestSavedProxyAttemptUsesTheProxyTimeout(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)

	answer := gatewayHandler(priv, nil, func([]byte) []byte { return []byte(`{"via":"direct"}`) })
	gw := httptest.NewServer(answer)
	t.Cleanup(gw.Close)
	slowProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second)
		answer(w, r)
	}))
	t.Cleanup(slowProxy.Close)

	c := newTestClient(t, Config{
		GatewayEndpoint:     gw.URL,
		PublicKeyPEM:        pubPEM,
		RequestTimeout:      5 * time.Second,
		ProxyRequestTimeout: 200 * time.Millisecond,
	})
	if err := c.ImportState([]byte(`{"version":1,"working_proxy":"` + slowProxy.URL + `"}`)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	resp, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != `{"via":"direct"}` {
		t.Fatalf("body: %s", resp.Body)
	}
	if took := time.Since(started); took > time.Second {
		t.Fatalf("post took %s: the saved proxy attempt did not use the proxy timeout", took)
	}
}
