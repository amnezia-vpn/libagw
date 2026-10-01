package gateway

import "testing"

func TestShouldBypassProxy(t *testing.T) {
	body := func(s string) []byte { return []byte(s) }
	cases := []struct {
		name      string
		kind      transportErrorKind
		status    int
		body      []byte
		decryptOK bool
		want      bool
	}{
		{"decrypt failed", transportOK, 200, body("garbage"), false, true},
		{"timeout", transportTimeout, 0, body(`{}`), true, true},
		{"cancelled", transportCancelled, 0, body(`{}`), true, true},
		{"html in body", transportOK, 200, body(`{"page":"<html></html>"}`), true, true},
		{"request timeout 408", transportOK, 200, body(`{"http_status":408}`), true, false},
		{"404 no active configuration", transportOK, 200, body(`{"http_status":404,"message":"No active configuration found for key"}`), true, false},
		{"404 no non-revoked key", transportOK, 200, body(`{"http_status":404,"message":"No non-revoked public key found for device"}`), true, false},
		{"404 account not found", transportOK, 200, body(`{"http_status":404,"message":"Account not found."}`), true, false},
		{"404 qr session not found", transportOK, 200, body(`{"http_status":404,"message":"QR session not found"}`), true, false},
		{"404 session not found", transportOK, 200, body(`{"http_status":404,"message":"Session not found"}`), true, false},
		{"404 unknown", transportOK, 200, body(`{"http_status":404,"message":"nope"}`), true, true},
		{"501 update required", transportOK, 200, body(`{"http_status":501,"message":"client version update is required"}`), true, false},
		{"501 other", transportOK, 200, body(`{"http_status":501,"message":"not implemented"}`), true, true},
		{"409 conflict", transportOK, 200, body(`{"http_status":409}`), true, false},
		{"402 payment required", transportOK, 200, body(`{"http_status":402,"captcha_id":"x"}`), true, false},
		{"422 subscription message", transportOK, 200, body(`{"http_status":422,"message":"Failed to retrieve subscription information. Is it activated?"}`), true, false},
		{"422 subscription message padded", transportOK, 200, body(`{"http_status":422,"message":"  Failed to retrieve subscription information. Is it activated? "}`), true, false},
		{"422 other", transportOK, 200, body(`{"http_status":422,"message":"bad input"}`), true, true},
		{"connection error", transportConnError, 0, body(`{}`), true, true},
		{"decryptable answer with HTTP 502", transportOK, 502, body(`{"services":[]}`), true, true},
		{"decryptable answer with HTTP 403", transportOK, 403, body(`{"http_status":403,"message":"Invalid user API key."}`), true, true},
		{"HTTP 404 with a no-bypass pattern", transportOK, 404, body(`{"http_status":404,"message":"Account not found."}`), true, false},
		{"HTTP 501 update required", transportOK, 501, body(`{"http_status":501,"message":"client version update is required"}`), true, false},
		{"HTTP 402 captcha", transportOK, 402, body(`{"http_status":402,"captcha_id":"x"}`), true, false},
		{"clean 200", transportOK, 200, body(`{"services":[]}`), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldBypassProxy(tc.kind, tc.status, tc.body, tc.decryptOK); got != tc.want {
				t.Fatalf("shouldBypassProxy=%v, want %v", got, tc.want)
			}
		})
	}
}
