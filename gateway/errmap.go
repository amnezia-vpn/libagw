package gateway

import (
	"encoding/json"
	"strings"
)

func containsCI(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

// The gateway reports API errors in the inner "http_status" of the decrypted
// body. The outer HTTP status is consulted only to stand in for the reply error
// the Qt client used to branch on, which is why 501 and >=400 appear twice.
func mapResponseError(sslError bool, kind transportErrorKind, outerStatus int, body []byte) ErrorCode {
	if sslError {
		return ApiConfigSslError
	}
	if kind == transportTimeout || kind == transportCancelled {
		return ApiConfigTimeoutError
	}
	if outerStatus == 501 {
		return ApiUpdateRequestError
	}

	status, message := apiStatus(body)
	switch status {
	case 429:
		return ApiRateLimitError
	case 409:
		if containsCI(message, "trial subscription already used") {
			return ApiTrialAlreadyUsedError
		}
		return ApiConfigLimitError
	case 404:
		return ApiNotFoundError
	case 408:
		return ApiConfigTimeoutError
	case 501:
		return ApiUpdateRequestError
	case 422:
		if message == unprocessableSubscriptionMessage {
			return ApiSubscriptionExpiredError
		}
		return ApiConfigDownloadError
	case 402:
		if containsCI(message, "refresh_captcha") {
			return ApiCaptchaRefreshError
		}
		if containsCI(message, "invalid_captcha") {
			return ApiCaptchaInvalidError
		}
		if hasCaptchaFields(body) || containsCI(message, "rate_limit_exceeded") {
			return ApiCaptchaRequiredError
		}
		return ApiSubscriptionNotActiveError
	}
	if status >= 300 {
		return ApiConfigDownloadError
	}

	if kind != transportOK {
		return ApiConfigDownloadError
	}
	if outerStatus >= 400 {
		return ApiConfigDownloadError
	}
	return NoError
}

func hasCaptchaFields(body []byte) bool {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return false
	}
	_, hasID := doc["captcha_id"]
	_, hasImage := doc["captcha_image"]
	return hasID || hasImage
}
