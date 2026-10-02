package gateway

import "fmt"

// ErrorCode classifies the outcomes in which there is no gateway answer to
// interpret. Whenever the gateway did answer, Post returns the decrypted body
// with a nil error regardless of the API status inside it — reading that
// status is the caller's business. Values are shared with cabi/agw_types.h.
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
	Code ErrorCode
}

func (e *Error) Error() string {
	return fmt.Sprintf("gateway: %s (%d)", ErrorText(e.Code), int(e.Code))
}

func codeError(code ErrorCode) *Error { return &Error{Code: code} }
