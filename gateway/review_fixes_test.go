package gateway

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// A block whose last byte is valid padding (0x03) but whose other padding
// bytes are not must be rejected, as EVP_DecryptFinal_ex rejects it.
func TestAESDecryptRejectsPartiallyValidPadding(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, aesKeyBytes)
	iv := bytes.Repeat([]byte{0x22}, aesIVBytes)
	pt := append(bytes.Repeat([]byte{'a'}, aesBlock-3), 0x01, 0x02, 0x03)

	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(blk, iv[:aesBlock]).CryptBlocks(ct, pt)

	if out, err := aesDecryptCBC(ct, key, iv); err == nil {
		t.Fatalf("partially valid padding accepted, plaintext %q", out)
	}
}

// Random ciphertext passes a full PKCS#7 check about 1 time in 256 (OpenSSL's
// rate); checking the last byte alone passed about 1 time in 16.
func TestAESDecryptRandomCiphertextAcceptRate(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, aesKeyBytes)
	iv := bytes.Repeat([]byte{0x44}, aesIVBytes)
	rng := rand.New(rand.NewPCG(1, 2))

	const trials = 20000
	accepted := 0
	ct := make([]byte, 2*aesBlock)
	for i := 0; i < trials; i++ {
		for j := range ct {
			ct[j] = byte(rng.Uint32())
		}
		if _, err := aesDecryptCBC(ct, key, iv); err == nil {
			accepted++
		}
	}
	// Expected about 78; the old check gave about 1250.
	if accepted > trials/100 {
		t.Fatalf("accepted %d of %d random ciphertexts, want under 1%%", accepted, trials)
	}
}

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

// A decryptable answer with HTTP 5xx goes to failover, as QNetworkReply
// reported it as an error.
func TestPostDecryptableHTTP503RunsFailover(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)

	var directHits atomic.Int32
	inner := gatewayHandler(priv, nil, func([]byte) []byte { return []byte(`{"services":["stale"]}`) })
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directHits.Add(1)
		inner(&statusWriter{ResponseWriter: w, status: http.StatusServiceUnavailable}, r)
	}))
	t.Cleanup(direct.Close)

	proxy, _ := proxyServer(t, priv, func([]byte) []byte { return []byte(`{"services":["via-proxy"]}`) })
	storageBody := encryptStorageList(t, pubPEM, []string{proxy.URL})
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(storageBody)
	}))
	t.Cleanup(storage.Close)

	c := newTestClient(t, Config{GatewayEndpoint: direct.URL, PublicKeyPEM: pubPEM, S3PrimaryEndpoints: []string{storage.URL}})
	resp, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != `{"services":["via-proxy"]}` {
		t.Fatalf("want the proxy answer, got %s", resp.Body)
	}
	if resp.HTTPStatus != http.StatusOK {
		t.Fatalf("HTTPStatus %d, want 200", resp.HTTPStatus)
	}
	if directHits.Load() != 1 {
		t.Fatalf("direct hit %d times, want 1", directHits.Load())
	}
}

// An undecryptable raw HTTP 501 surfaces its status, so the host can show
// "update the application" instead of a decryption error.
func TestPostRawHTTP501ReportsStatus(t *testing.T) {
	_, pubPEM := newTestKeyPair(t)
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Implemented", http.StatusNotImplemented)
	}))
	t.Cleanup(direct.Close)

	c := newTestClient(t, Config{GatewayEndpoint: direct.URL, PublicKeyPEM: pubPEM})
	_, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	gwErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("want *Error, got %v", err)
	}
	if gwErr.Code != DecryptError || gwErr.HTTPStatus != http.StatusNotImplemented {
		t.Fatalf("got code %d status %d, want %d and 501", gwErr.Code, gwErr.HTTPStatus, DecryptError)
	}
}

func TestPostDirectSuccessReportsStatus(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)
	srv := httptest.NewServer(gatewayHandler(priv, nil, func([]byte) []byte { return []byte(`{}`) }))
	t.Cleanup(srv.Close)

	c := newTestClient(t, Config{GatewayEndpoint: srv.URL, PublicKeyPEM: pubPEM})
	resp, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.HTTPStatus != http.StatusOK {
		t.Fatalf("HTTPStatus %d, want 200", resp.HTTPStatus)
	}
}

// statusWriter forces a status code on a handler that only writes a body.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.ResponseWriter.WriteHeader(w.status)
	}
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.WriteHeader(w.status)
	return w.ResponseWriter.Write(b)
}
