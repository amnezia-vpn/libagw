package gateway

import "testing"

func TestShouldBypassProxy(t *testing.T) {
	body := func(s string) []byte { return []byte(s) }
	cases := []struct {
		name      string
		kind      transportErrorKind
		body      []byte
		decryptOK bool
		want      bool
	}{
		{"decrypt failed", transportOK, body("garbage"), false, true},
		{"timeout", transportTimeout, body(`{}`), true, true},
		{"cancelled", transportCancelled, body(`{}`), true, true},
		{"html in body", transportOK, body(`{"page":"<html></html>"}`), true, true},
		{"request timeout 408", transportOK, body(`{"http_status":408}`), true, false},
		{"404 no active configuration", transportOK, body(`{"http_status":404,"message":"No active configuration found for key"}`), true, false},
		{"404 no non-revoked key", transportOK, body(`{"http_status":404,"message":"No non-revoked public key found for device"}`), true, false},
		{"404 account not found", transportOK, body(`{"http_status":404,"message":"Account not found."}`), true, false},
		{"404 qr session not found", transportOK, body(`{"http_status":404,"message":"QR session not found"}`), true, false},
		{"404 session not found", transportOK, body(`{"http_status":404,"message":"Session not found"}`), true, false},
		{"404 unknown", transportOK, body(`{"http_status":404,"message":"nope"}`), true, true},
		{"501 update required", transportOK, body(`{"http_status":501,"message":"client version update is required"}`), true, false},
		{"501 other", transportOK, body(`{"http_status":501,"message":"not implemented"}`), true, true},
		{"409 conflict", transportOK, body(`{"http_status":409}`), true, false},
		{"402 payment required", transportOK, body(`{"http_status":402,"captcha_id":"x"}`), true, false},
		{"422 subscription message", transportOK, body(`{"http_status":422,"message":"Failed to retrieve subscription information. Is it activated?"}`), true, false},
		{"422 subscription message padded", transportOK, body(`{"http_status":422,"message":"  Failed to retrieve subscription information. Is it activated? "}`), true, false},
		{"422 other", transportOK, body(`{"http_status":422,"message":"bad input"}`), true, true},
		{"connection error", transportConnError, body(`{}`), true, true},
		{"clean 200", transportOK, body(`{"services":[]}`), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldBypassProxy(tc.kind, tc.body, tc.decryptOK); got != tc.want {
				t.Fatalf("shouldBypassProxy=%v, want %v", got, tc.want)
			}
		})
	}
}
