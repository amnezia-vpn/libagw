package gateway

import "fmt"

// ErrorCode mirrors the amnezia-client ErrorCode enum (errorCodes.h) so that
// applications already built around the 1100-series API codes keep working.
// Values must never be renumbered.
type ErrorCode int

const (
	NoError ErrorCode = 0

	ApiConfigDownloadError           ErrorCode = 1100
	ApiConfigAlreadyAdded            ErrorCode = 1101
	ApiConfigEmptyError              ErrorCode = 1102
	ApiConfigTimeoutError            ErrorCode = 1103
	ApiConfigSslError                ErrorCode = 1104
	ApiMissingAgwPublicKey           ErrorCode = 1105
	ApiConfigDecryptionError         ErrorCode = 1106
	ApiServicesMissingError          ErrorCode = 1107
	ApiConfigLimitError              ErrorCode = 1108
	ApiNotFoundError                 ErrorCode = 1109
	ApiMigrationError                ErrorCode = 1110
	ApiUpdateRequestError            ErrorCode = 1111
	ApiSubscriptionExpiredError      ErrorCode = 1112
	ApiPurchaseError                 ErrorCode = 1113
	ApiSubscriptionNotActiveError    ErrorCode = 1114
	ApiNoPurchasedSubscriptionsError ErrorCode = 1115
	ApiTrialAlreadyUsedError         ErrorCode = 1116
	ApiCaptchaRequiredError          ErrorCode = 1117
	ApiCaptchaInvalidError           ErrorCode = 1118
	ApiCaptchaRefreshError           ErrorCode = 1119
	ApiRateLimitError                ErrorCode = 1120
	ApiForbiddenError                ErrorCode = 1121
	ApiBadGatewayError               ErrorCode = 1122
	ApiServiceUnavailableError       ErrorCode = 1123
)

var errorTexts = map[ErrorCode]string{
	NoError:                          "no error",
	ApiConfigDownloadError:           "config download error",
	ApiConfigAlreadyAdded:            "config already added",
	ApiConfigEmptyError:              "config empty",
	ApiConfigTimeoutError:            "request timeout",
	ApiConfigSslError:                "ssl error",
	ApiMissingAgwPublicKey:           "missing gateway public key",
	ApiConfigDecryptionError:         "response decryption error",
	ApiServicesMissingError:          "services missing",
	ApiConfigLimitError:              "config limit reached",
	ApiNotFoundError:                 "not found",
	ApiMigrationError:                "migration error",
	ApiUpdateRequestError:            "client version update required",
	ApiSubscriptionExpiredError:      "subscription expired",
	ApiPurchaseError:                 "purchase error",
	ApiSubscriptionNotActiveError:    "subscription not active",
	ApiNoPurchasedSubscriptionsError: "no purchased subscriptions",
	ApiTrialAlreadyUsedError:         "trial already used",
	ApiCaptchaRequiredError:          "captcha required",
	ApiCaptchaInvalidError:           "captcha invalid",
	ApiCaptchaRefreshError:           "captcha refresh required",
	ApiRateLimitError:                "rate limit exceeded",
	ApiForbiddenError:                "forbidden",
	ApiBadGatewayError:               "bad gateway",
	ApiServiceUnavailableError:       "service unavailable",
}

// ErrorText returns a short human-readable description of a code.
func ErrorText(code ErrorCode) string {
	if s, ok := errorTexts[code]; ok {
		return s
	}
	return fmt.Sprintf("unknown error %d", int(code))
}

// LookupErrorText reports whether the code is one this package defines. The C
// ABI needs the distinction: it interns the strings it hands out, and interning
// a per-code string for codes nobody defined lets a caller grow that table
// without bound.
func LookupErrorText(code ErrorCode) (string, bool) {
	s, ok := errorTexts[code]
	return s, ok
}

// Error is the error type returned by Client.Post. Even when Post returns an
// Error, the accompanying Response body may be non-empty and meaningful (for
// example captcha challenges arrive together with ApiCaptchaRequiredError).
type Error struct {
	Code ErrorCode
}

func (e *Error) Error() string {
	return fmt.Sprintf("gateway: %s (%d)", ErrorText(e.Code), int(e.Code))
}

func codeError(code ErrorCode) *Error { return &Error{Code: code} }
