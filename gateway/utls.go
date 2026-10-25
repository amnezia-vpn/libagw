package gateway

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// chromeTLSDialer performs the TLS handshake with a Chrome ClientHello instead
// of the Go one. ALPN offers only http/1.1, so net/http keeps HTTP/1.1 on the
// returned connection. roots is asked on every dial; nil means the system
// trust store.
func chromeTLSDialer(dial dialFunc, roots func() *x509.CertPool) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		raw, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
		if err != nil {
			raw.Close()
			return nil, err
		}
		for _, ext := range spec.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{"http/1.1"}
			}
		}
		conn := utls.UClient(raw, &utls.Config{ServerName: host, RootCAs: roots()}, utls.HelloCustom)
		if err := conn.ApplyPreset(&spec); err != nil {
			raw.Close()
			return nil, err
		}
		if err := conn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		return conn, nil
	}
}

// transportRoots returns the RootCAs of tr.TLSClientConfig, which net/http
// itself ignores once DialTLSContext is set.
func transportRoots(tr *http.Transport) func() *x509.CertPool {
	return func() *x509.CertPool {
		if tr.TLSClientConfig == nil {
			return nil
		}
		return tr.TLSClientConfig.RootCAs
	}
}

func newChromeTransport(roots *x509.CertPool) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	tr.DialContext = dialer.DialContext
	tr.DialTLSContext = chromeTLSDialer(dialer.DialContext, func() *x509.CertPool { return roots })
	return tr
}
