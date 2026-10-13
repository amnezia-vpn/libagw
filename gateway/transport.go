package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
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
}

var phaseNames = []string{"tcp connect", "dns lookup", "tcp connect", "tls handshake", "waiting for response", "reading response"}

type phaseTracker struct{ current atomic.Int32 }

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

	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var phase phaseTracker
	started := time.Now()
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(tctx, phase.clientTrace()), method, target, bytes.NewReader(body))
	if err != nil {
		return sendResult{kind: transportConnError, err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	if requestID != "" {
		req.Header.Set("X-Client-Request-ID", requestID)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return sendResult{kind: classifyTransportError(ctx, err), ssl: isTLSError(err), err: err, phase: phase.name(), elapsed: time.Since(started)}
	}
	defer resp.Body.Close()

	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	out := sendResult{status: resp.StatusCode, body: data, phase: phase.name(), elapsed: time.Since(started)}
	if readErr != nil {
		out.kind = classifyTransportError(ctx, readErr)
		out.err = readErr
	}
	return out
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
