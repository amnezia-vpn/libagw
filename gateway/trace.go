package gateway

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
)

type Trace []string

func (t Trace) String() string { return strings.Join(t, "\n") }

type tracer struct{ lines Trace }

func (t *tracer) add(format string, args ...any) {
	t.lines = append(t.lines, fmt.Sprintf(format, args...))
}

func (sr sendResult) describe() string {
	switch {
	case sr.ssl:
		return "tls: " + tlsReason(sr.err)
	case sr.kind == transportTimeout:
		return fmt.Sprintf("timeout after %s in %s", sr.elapsed.Round(100*time.Millisecond), sr.phase)
	case sr.kind == transportCancelled:
		return "cancelled"
	case sr.kind == transportConnError:
		return fmt.Sprintf("connect failed: %s, in %s", connReason(sr.err), sr.phase)
	}
	return fmt.Sprintf("http %d, %d bytes, %s", sr.status, len(sr.body), sr.elapsed.Round(100*time.Millisecond))
}

func (a attemptResult) describe() string {
	d := a.send.describe()
	switch {
	case a.send.ssl || a.send.kind != transportOK:
		return d
	case a.decryptOK:
		return d + ", api status " + apiStatusText(a.body)
	case bytes.Contains(a.body, []byte("html")):
		return d + ", html instead of an answer"
	}
	return d + ", undecryptable"
}

func apiStatusText(body []byte) string {
	status, _ := apiStatus(body)
	if status < 0 {
		return "none"
	}
	return fmt.Sprint(status)
}

func tlsReason(err error) string {
	var (
		verifyErr   *tls.CertificateVerificationError
		recordErr   tls.RecordHeaderError
		unknownAuth x509.UnknownAuthorityError
		hostnameErr x509.HostnameError
		invalidCert x509.CertificateInvalidError
	)
	switch {
	case errors.As(err, &unknownAuth):
		return "unknown certificate authority"
	case errors.As(err, &hostnameErr):
		return "certificate hostname mismatch"
	case errors.As(err, &invalidCert):
		return "certificate invalid"
	case errors.As(err, &recordErr):
		return "server did not speak tls"
	case errors.As(err, &verifyErr):
		return "certificate verification failed"
	}
	return "handshake failed"
}

func connReason(err error) string {
	var (
		dnsErr *net.DNSError
		alert  tls.AlertError
		uAlert utls.AlertError
	)
	switch {
	case err == nil:
		return "unknown"
	case errors.As(err, &dnsErr):
		return "dns lookup failed: " + dnsReason(dnsErr)
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return "connection reset"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.ENETDOWN):
		return "network unreachable"
	case errors.As(err, &alert), errors.As(err, &uAlert):
		return "tls alert"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "connection closed"
	}
	return "other"
}

// dnsReason keeps the resolver's own text out of the trace: it may carry the
// DNS server address.
func dnsReason(err *net.DNSError) string {
	switch {
	case err.IsNotFound:
		return "no such host"
	case err.IsTimeout:
		return "timeout"
	case err.Err == "no suitable address":
		return "no suitable address"
	case err.IsTemporary:
		return "temporary failure"
	}
	return "other"
}
