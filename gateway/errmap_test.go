package gateway

import "testing"

func TestMapResponseError(t *testing.T) {
	body := func(s string) []byte { return []byte(s) }
	cases := []struct {
		name        string
		ssl         bool
		kind        transportErrorKind
		outerStatus int
		body        []byte
		want        ErrorCode
	}{
		{"ssl error wins", true, transportTimeout, 200, body(`{}`), ApiConfigSslError},
		{"timeout", false, transportTimeout, 0, body(`{}`), ApiConfigTimeoutError},
		{"cancelled maps to timeout", false, transportCancelled, 0, body(`{}`), ApiConfigTimeoutError},
		{"outer 501", false, transportOK, 501, body(`not json`), ApiUpdateRequestError},
		{"inner 429", false, transportOK, 200, body(`{"http_status":429}`), ApiRateLimitError},
		{"inner 409 limit", false, transportOK, 200, body(`{"http_status":409,"message":"limit"}`), ApiConfigLimitError},
		{"inner 409 trial", false, transportOK, 200, body(`{"http_status":409,"message":"Trial Subscription Already Used"}`), ApiTrialAlreadyUsedError},
		{"inner 404", false, transportOK, 200, body(`{"http_status":404}`), ApiNotFoundError},
		{"inner 408", false, transportOK, 200, body(`{"http_status":408}`), ApiConfigTimeoutError},
		{"inner 501", false, transportOK, 200, body(`{"http_status":501}`), ApiUpdateRequestError},
		{"inner 422 subscription", false, transportOK, 200, body(`{"http_status":422,"message":"Failed to retrieve subscription information. Is it activated?"}`), ApiSubscriptionExpiredError},
		{"inner 422 other", false, transportOK, 200, body(`{"http_status":422,"message":"x"}`), ApiConfigDownloadError},
		{"402 refresh captcha", false, transportOK, 200, body(`{"http_status":402,"message":"refresh_captcha"}`), ApiCaptchaRefreshError},
		{"402 invalid captcha", false, transportOK, 200, body(`{"http_status":402,"message":"invalid_captcha"}`), ApiCaptchaInvalidError},
		{"402 captcha fields", false, transportOK, 200, body(`{"http_status":402,"captcha_id":"a","captcha_image":"b"}`), ApiCaptchaRequiredError},
		{"402 rate limit message", false, transportOK, 200, body(`{"http_status":402,"message":"rate_limit_exceeded"}`), ApiCaptchaRequiredError},
		{"402 plain", false, transportOK, 200, body(`{"http_status":402}`), ApiSubscriptionNotActiveError},
		{"inner 500", false, transportOK, 200, body(`{"http_status":500}`), ApiConfigDownloadError},
		{"transport error unmatched body", false, transportConnError, 0, body(`raw`), ApiConfigDownloadError},
		{"outer 403 unmatched body", false, transportOK, 403, body(`denied`), ApiConfigDownloadError},
		{"clean 200", false, transportOK, 200, body(`{"services":[]}`), NoError},
		{"clean 200 non-json", false, transportOK, 200, body(`ok`), NoError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapResponseError(tc.ssl, tc.kind, tc.outerStatus, tc.body)
			if got != tc.want {
				t.Fatalf("mapResponseError=%d, want %d", got, tc.want)
			}
		})
	}
}
