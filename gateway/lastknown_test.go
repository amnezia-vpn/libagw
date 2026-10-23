package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func stateWithHost(t *testing.T, host string, addrs ...string) []byte {
	t.Helper()
	blob, err := json.Marshal(persistedState{
		Version: stateVersion,
		Hosts:   map[string]persistedHost{host: {Addrs: addrs, Seen: today().Format(lkgDayLayout)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func exportedHosts(t *testing.T, c *Client) map[string]persistedHost {
	t.Helper()
	var st persistedState
	if err := json.Unmarshal(c.ExportState(), &st); err != nil {
		t.Fatal(err)
	}
	return st.Hosts
}

func TestLastKnownAddressWhenDNSHangs(t *testing.T) {
	srv, pubPEM := okGateway(t)
	res := newFakeResolver()
	res.set("gw.test", 3*time.Second)
	c := New(Config{GatewayEndpoint: named(srv.URL, "gw.test"), PublicKeyPEM: pubPEM, Resolver: res})
	if err := c.ImportState(stateWithHost(t, "gw.test", "127.0.0.1")); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	resp, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if err != nil {
		t.Fatalf("%v\n%s", err, traceOf(err))
	}
	if took := time.Since(started); took > time.Second {
		t.Fatalf("post took %s", took)
	}
	if len(resp.Trace) != 2 || !strings.HasSuffix(resp.Trace[1], ", accepted; dns 300ms; last known address; ipv4; address 127.0.0.1") {
		t.Fatalf("trace:\n%s", resp.Trace)
	}
}

func TestLastKnownAddressWhenDNSFails(t *testing.T) {
	srv, pubPEM := okGateway(t)
	res := newFakeResolver()
	res.fail["gw.test"] = &net.DNSError{Err: "no such host", Name: "gw.test", IsNotFound: true}
	c := New(Config{GatewayEndpoint: named(srv.URL, "gw.test"), PublicKeyPEM: pubPEM, Resolver: res})
	if err := c.ImportState(stateWithHost(t, "gw.test", "127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if err != nil {
		t.Fatalf("%v\n%s", err, traceOf(err))
	}
	if len(resp.Trace) != 2 || !strings.HasSuffix(resp.Trace[1], ", accepted; last known address; ipv4; address 127.0.0.1") {
		t.Fatalf("trace:\n%s", resp.Trace)
	}
}

func TestFreshDNSAnswerNeedsNoLastKnownNote(t *testing.T) {
	srv, pubPEM := okGateway(t)
	res := newFakeResolver()
	c := New(Config{GatewayEndpoint: named(srv.URL, "gw.test"), PublicKeyPEM: pubPEM, Resolver: res})
	if err := c.ImportState(stateWithHost(t, "gw.test", "127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if err != nil {
		t.Fatalf("%v\n%s", err, traceOf(err))
	}
	if len(resp.Trace) != 2 || !strings.HasSuffix(resp.Trace[1], ", accepted; ipv4; address 127.0.0.1") {
		t.Fatalf("trace:\n%s", resp.Trace)
	}
}

func TestOnlyConfirmedAnswersAreRemembered(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>blocked</html>"))
	}))
	t.Cleanup(blocked.Close)
	broken, _ := proxyServer(t, priv, func([]byte) []byte { return []byte(`{"ok":true}`) })
	broken.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, healthPath) {
			w.Write([]byte("ok"))
			return
		}
		w.Write([]byte("<html>blocked</html>"))
	})
	working, _ := proxyServer(t, priv, func([]byte) []byte { return []byte(`{"ok":true}`) })
	storageBody := encryptStorageList(t, pubPEM, []string{named(broken.URL, "broken.test"), named(working.URL, "working.test")})
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(storageBody) }))
	t.Cleanup(storage.Close)

	res := newFakeResolver()
	c := New(Config{
		GatewayEndpoint:    named(blocked.URL, "gw.test"),
		PublicKeyPEM:       pubPEM,
		S3PrimaryEndpoints: []string{named(storage.URL, "storage.test")},
		Resolver:           res,
	})
	resp, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if err != nil {
		t.Fatalf("%v\n%s", err, traceOf(err))
	}
	hosts := exportedHosts(t, c)
	if len(hosts) != 1 || len(hosts["working.test"].Addrs) != 1 || hosts["working.test"].Addrs[0] != "127.0.0.1" {
		t.Fatalf("hosts %v, want only the proxy that answered\ntrace:\n%s", hosts, resp.Trace)
	}
	if hosts["working.test"].Seen != today().Format(lkgDayLayout) {
		t.Fatalf("seen %q", hosts["working.test"].Seen)
	}
}

func trustingStack(t *testing.T, res Resolver, srv *httptest.Server) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	stackFor(res).transport.TLSClientConfig = &tls.Config{RootCAs: pool}
}

func TestStorageAddressIsRememberedOverVerifiedTLS(t *testing.T) {
	_, pubPEM := newTestKeyPair(t)
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>blocked</html>"))
	}))
	t.Cleanup(blocked.Close)
	storageBody := encryptStorageList(t, pubPEM, []string{"http://127.0.0.1:1"})
	storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(storageBody) }))
	t.Cleanup(storage.Close)

	res := newFakeResolver()
	trustingStack(t, res, storage)
	c := New(Config{
		GatewayEndpoint:    blocked.URL,
		PublicKeyPEM:       pubPEM,
		S3PrimaryEndpoints: []string{named(storage.URL, "example.com")},
		Resolver:           res,
	})
	_, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if !strings.Contains(traceOf(err), "storage 1/1: http 200") {
		t.Fatalf("trace:\n%s", traceOf(err))
	}
	if hosts := exportedHosts(t, c); len(hosts) != 1 || len(hosts["example.com"].Addrs) != 1 {
		t.Fatalf("hosts %v, want the storage", hosts)
	}
}

func TestLastKnownAddressFailingTLSIsForgotten(t *testing.T) {
	_, pubPEM := newTestKeyPair(t)
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>blocked</html>"))
	}))
	t.Cleanup(blocked.Close)
	storage := httptest.NewTLSServer(http.HandlerFunc(http.NotFound))
	t.Cleanup(storage.Close)

	res := newFakeResolver()
	res.set("wrong.test", 3*time.Second)
	trustingStack(t, res, storage)
	c := New(Config{
		GatewayEndpoint:    blocked.URL,
		PublicKeyPEM:       pubPEM,
		S3PrimaryEndpoints: []string{named(storage.URL, "wrong.test")},
		Resolver:           res,
	})
	if err := c.ImportState(stateWithHost(t, "wrong.test", "127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	_, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{})
	if tr := traceOf(err); !strings.Contains(tr, "storage 1/1: tls: certificate hostname mismatch; dns 300ms; last known address") {
		t.Fatalf("trace:\n%s", tr)
	}
	if hosts := exportedHosts(t, c); len(hosts) != 0 {
		t.Fatalf("hosts %v, want the address forgotten", hosts)
	}
}

func TestStateBlobChangesOnlyWithItsContent(t *testing.T) {
	srv, pubPEM := okGateway(t)
	res := newFakeResolver()
	c := New(Config{GatewayEndpoint: named(srv.URL, "gw.test"), PublicKeyPEM: pubPEM, Resolver: res})
	var blobs []string
	for i := 0; i < 3; i++ {
		if _, err := c.Post(context.Background(), testEndpoint, []byte(`{}`), PostOptions{}); err != nil {
			t.Fatal(err)
		}
		blobs = append(blobs, string(c.ExportState()))
	}
	if blobs[0] != blobs[1] || blobs[1] != blobs[2] || !strings.Contains(blobs[0], `"gw.test"`) {
		t.Fatalf("blobs differ or lack the host:\n%s", strings.Join(blobs, "\n"))
	}

	other := New(Config{GatewayEndpoint: "http://other.test", PublicKeyPEM: pubPEM, Resolver: res})
	if string(other.ExportState()) != blobs[0] {
		t.Fatalf("addresses are not shared by the stack")
	}
}

func TestLastKnownLimits(t *testing.T) {
	s := stackFor(newFakeResolver())
	for i := 0; i < lkgMaxHosts+10; i++ {
		s.remember(fmt.Sprintf("h%02d.test", i), netip.MustParseAddr("10.0.0.1"))
	}
	for i := 1; i <= lkgMaxAddrs+2; i++ {
		s.remember("many.test", netip.AddrFrom4([4]byte{10, 0, 1, byte(i)}))
	}
	hosts := s.exportHosts()
	if len(hosts) != lkgMaxHosts {
		t.Fatalf("%d hosts, want %d", len(hosts), lkgMaxHosts)
	}
	many := hosts["many.test"].Addrs
	if len(many) != lkgMaxAddrs || many[0] != "10.0.1.3" || many[len(many)-1] != "10.0.1.6" {
		t.Fatalf("many.test addrs %v, want the 4 most recent, sorted", many)
	}

	s.importHosts(map[string]persistedHost{
		"old.test":     {Addrs: []string{"10.0.0.2"}, Seen: "2000-01-01"},
		"bad.test":     {Addrs: []string{"not an ip"}, Seen: today().Format(lkgDayLayout)},
		"10.0.0.9":     {Addrs: []string{"10.0.0.9"}, Seen: today().Format(lkgDayLayout)},
		"undated.test": {Addrs: []string{"10.0.0.3"}, Seen: "yesterday"},
	})
	hosts = s.exportHosts()
	for _, host := range []string{"old.test", "bad.test", "10.0.0.9", "undated.test"} {
		if _, ok := hosts[host]; ok {
			t.Fatalf("%s must not be kept", host)
		}
	}
}

func TestStateBlobStaysCompatible(t *testing.T) {
	_, pubPEM := newTestKeyPair(t)
	c := New(Config{GatewayEndpoint: "http://gw.test", PublicKeyPEM: pubPEM, Resolver: newFakeResolver()})
	if err := c.ImportState([]byte(`{"version":1,"working_proxy":"http://p.test","proxy_lists":{"k":["http://p.test"]}}`)); err != nil {
		t.Fatalf("old blob: %v", err)
	}
	if err := c.ImportState(stateWithHost(t, "gw.test", "127.0.0.1")); err != nil {
		t.Fatal(err)
	}

	var old struct {
		Version      int                 `json:"version"`
		WorkingProxy string              `json:"working_proxy,omitempty"`
		ProxyLists   map[string][]string `json:"proxy_lists,omitempty"`
	}
	if err := json.Unmarshal(c.ExportState(), &old); err != nil || old.Version != stateVersion {
		t.Fatalf("old parser: %v %+v", err, old)
	}
}
