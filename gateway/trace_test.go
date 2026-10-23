package gateway

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestStorageKind(t *testing.T) {
	for url, want := range map[string]string{
		"https://s3.eu-north-1.amazonaws.com/bucket/endpoints.json": " (s3)",
		"https://storage.googleapis.com/bucket/endpoints.json":      " (gcs)",
		"https://mirror.example/endpoints.json":                     "",
		"http://127.0.0.1:8080/endpoints.json":                      "",
		"https://notamazonaws.com/endpoints.json":                   "",
	} {
		if got := storageKind(url); got != want {
			t.Errorf("storageKind(%q) = %q, want %q", url, got, want)
		}
	}
}

func TestDNSReasonHidesResolverText(t *testing.T) {
	for _, tc := range []struct {
		err  *net.DNSError
		want string
	}{
		{&net.DNSError{Err: "no such host", IsNotFound: true}, "dns lookup failed: no such host"},
		{&net.DNSError{Err: "i/o timeout", IsTimeout: true}, "dns lookup failed: timeout"},
		{&net.DNSError{Err: "read udp 10.0.0.1:53: connection refused", IsTemporary: true}, "dns lookup failed: temporary failure"},
		{&net.DNSError{Err: "no suitable address"}, "dns lookup failed: no suitable address"},
		{&net.DNSError{Err: "server misbehaving 10.0.0.1"}, "dns lookup failed: other"},
	} {
		if got := connReason(fmt.Errorf("dial: %w", tc.err)); got != tc.want {
			t.Errorf("connReason(%q) = %q, want %q", tc.err.Err, got, tc.want)
		}
	}
}

func TestChromeTLSAlertIsNamed(t *testing.T) {
	if got := connReason(fmt.Errorf("handshake: %w", utls.AlertError(40))); got != "tls alert" {
		t.Fatalf("connReason = %q, want tls alert", got)
	}
}

func TestResetDuringChromeHandshakeIsTracedAsTLS(t *testing.T) {
	_, pubPEM := newTestKeyPair(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Read(make([]byte, 512))
			conn.(*net.TCPConn).SetLinger(0)
			conn.Close()
		}
	}()

	c := New(Config{
		GatewayEndpoint: "https://gw.test:" + strings.TrimPrefix(ln.Addr().String(), "127.0.0.1:"),
		PublicKeyPEM:    pubPEM,
		Resolver:        newFakeResolver(),
	})
	_, err = c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if tr := traceOf(err); !strings.Contains(tr, "direct: connect failed: connection reset, in tls handshake, suspicious") {
		t.Fatalf("trace:\n%s", tr)
	}
}

func TestOnlyTheDirectLineNamesAnAddress(t *testing.T) {
	_, pubPEM := newTestKeyPair(t)
	gw := httptest.NewServer(http.HandlerFunc(http.NotFound))
	gw.Close()
	storage := httptest.NewServer(http.HandlerFunc(http.NotFound))
	t.Cleanup(storage.Close)

	c := New(Config{
		GatewayEndpoint:    named(gw.URL, "gw.test"),
		PublicKeyPEM:       pubPEM,
		S3PrimaryEndpoints: []string{named(storage.URL, "st.test")},
		Resolver:           newFakeResolver(),
	})
	_, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{ServiceType: "svc", UserCountryCode: "de"})
	if code := errCodeOf(t, err); code != NetworkError {
		t.Fatalf("code %d, want %d\n%s", code, NetworkError, traceOf(err))
	}
	lines := err.(*Error).Trace
	var direct, storages int
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "direct: "):
			direct++
			if !strings.HasPrefix(line, "direct: connect failed: connection refused, in tcp connect, suspicious; after ") ||
				!strings.HasSuffix(line, "; ipv4; candidates 127.0.0.1") {
				t.Errorf("direct line: %q", line)
			}
		case strings.HasPrefix(line, "storage "):
			storages++
			if strings.Contains(line, "127.0.0.1") || !strings.HasSuffix(line, "; ipv4") {
				t.Errorf("storage line: %q", line)
			}
		}
	}
	if direct != 1 || storages == 0 {
		t.Fatalf("trace:\n%s", lines)
	}
}
