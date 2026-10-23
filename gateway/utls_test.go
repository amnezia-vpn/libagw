package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
)

func tlsServerWithHello(t *testing.T) (*httptest.Server, func() *tls.ClientHelloInfo) {
	t.Helper()
	var (
		mu    sync.Mutex
		hello *tls.ClientHelloInfo
	)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		hello = h
		mu.Unlock()
		return nil, nil
	}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, func() *tls.ClientHelloInfo {
		mu.Lock()
		defer mu.Unlock()
		return hello
	}
}

func serverRoots(srv *httptest.Server) *x509.CertPool {
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return roots
}

func TestChromeTransportSendsBrowserHello(t *testing.T) {
	srv, hello := tlsServerWithHello(t)
	client := &http.Client{Transport: newChromeTransport(serverRoots(srv))}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.ProtoMajor != 1 {
		t.Fatalf("protocol %s, want HTTP/1.x", resp.Proto)
	}
	h := hello()
	if h == nil {
		t.Fatal("no ClientHello seen")
	}
	grease := slices.ContainsFunc(h.CipherSuites, func(c uint16) bool { return c&0x0f0f == 0x0a0a })
	if !grease {
		t.Fatalf("no GREASE cipher in ClientHello %v: looks like the Go hello", h.CipherSuites)
	}
	if !slices.Equal(h.SupportedProtos, []string{"http/1.1"}) {
		t.Fatalf("ALPN %v, want [http/1.1]", h.SupportedProtos)
	}
}

func TestChromeTransportUntrustedCertIsTLSError(t *testing.T) {
	srv, _ := tlsServerWithHello(t)
	client := &http.Client{Transport: newChromeTransport(x509.NewCertPool())}
	_, err := client.Get(srv.URL)
	if err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if !isTLSError(err) {
		t.Fatalf("isTLSError(%v) = false", err)
	}
}

func TestChromeTransportHandshakeHonoursContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	client := &http.Client{Transport: newChromeTransport(nil)}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+ln.Addr().String()+"/", nil)
	started := time.Now()
	_, err = client.Do(req)
	if err == nil {
		t.Fatal("handshake with a silent server succeeded")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("handshake ignored the context: %v", elapsed)
	}
}

func TestNetstackTransportUsesChromeHello(t *testing.T) {
	srv, hello := tlsServerWithHello(t)
	s := stackFor(newFakeResolver())
	s.transport.TLSClientConfig = &tls.Config{RootCAs: serverRoots(srv)}
	client := &http.Client{Transport: s.transport}
	resp, err := client.Get(named(srv.URL, "example.com"))
	if err != nil {
		t.Fatalf("get through netstack: %v", err)
	}
	resp.Body.Close()
	h := hello()
	if h == nil || h.ServerName != "example.com" {
		t.Fatalf("ClientHello %+v, want SNI example.com", h)
	}
	if !slices.ContainsFunc(h.CipherSuites, func(c uint16) bool { return c&0x0f0f == 0x0a0a }) {
		t.Fatalf("netstack sent the Go hello: %v", h.CipherSuites)
	}
}
