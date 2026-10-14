package gateway

import (
	"context"
	"fmt"
	"time"
)

// ErrorCode classifies the outcomes in which there is no gateway answer to
// interpret. Whenever the gateway did answer, Post returns the body with a nil
// error regardless of the API status inside it — reading that status is the
// caller's business. Values are shared with cabi/agw_types.h.
type ErrorCode int

const (
	NoError      ErrorCode = 0
	ConfigError  ErrorCode = 3
	TimeoutError ErrorCode = 4
	SSLError     ErrorCode = 5
	NetworkError ErrorCode = 6
	DecryptError ErrorCode = 7
)

var errorTexts = map[ErrorCode]string{
	NoError:      "no error",
	ConfigError:  "gateway public key missing or invalid",
	TimeoutError: "request timed out",
	SSLError:     "tls error",
	NetworkError: "gateway unreachable",
	DecryptError: "response decryption failed",
}

// ErrorText returns a short human-readable description of a code.
func ErrorText(code ErrorCode) string {
	if s, ok := errorTexts[code]; ok {
		return s
	}
	return fmt.Sprintf("unknown error %d", int(code))
}

// Error is the error type returned by Client.Post.
type Error struct {
	Code  ErrorCode
	Trace Trace
}

func (e *Error) Error() string {
	return fmt.Sprintf("gateway: %s (%d)", ErrorText(e.Code), int(e.Code))
}

// CancelledError is returned by Client.Post when ctx ends before the gateway
// answered. It carries the attempts made until then and unwraps to ctx.Err().
type CancelledError struct {
	Err   error
	Trace Trace
}

func (e *CancelledError) Error() string { return "gateway: " + e.Err.Error() }

func (e *CancelledError) Unwrap() error { return e.Err }

func cancelledError(ctx context.Context, tr *tracer, began time.Time) *CancelledError {
	tr.add("cancelled after %s", time.Since(began).Round(100*time.Millisecond))
	return &CancelledError{Err: ctx.Err(), Trace: tr.lines}
}

func codeError(code ErrorCode, tr *tracer) *Error {
	tr.add("result: %s", ErrorText(code))
	return &Error{Code: code, Trace: tr.lines}
}
