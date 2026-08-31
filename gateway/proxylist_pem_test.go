package gateway

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"testing"
)

// canonicalPEM is the form the Qt client hashes: the PEM as a compiled-in string
// literal, with no trailing newline. Storage objects are encrypted against it.
const canonicalPEM = "-----BEGIN PUBLIC KEY-----\n" +
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtestkeytestkeytestkey\n" +
	"-----END PUBLIC KEY-----"

// sealProxyList encrypts a proxy list the way the server does: the key and iv
// come from sha512 over the canonical PEM, and the object is base64 of the raw
// CBC ciphertext.
func sealProxyList(t *testing.T, list string) []byte {
	t.Helper()
	sum := sha512.Sum512([]byte(canonicalPEM))
	h := hex.EncodeToString(sum[:])
	key, err := hex.DecodeString(h[0:64])
	if err != nil {
		t.Fatal(err)
	}
	iv, err := hex.DecodeString(h[64:96])
	if err != nil {
		t.Fatal(err)
	}
	ct, err := aesEncryptCBC([]byte(list), key, iv)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(base64.StdEncoding.EncodeToString(ct))
}

// A PEM that only differs in trailing whitespace must still derive the key the
// server used. Getting this wrong disables proxy failover with nothing but a
// debug-level log line, so it is worth pinning.
func TestDecodeProxyListIgnoresTrailingWhitespaceInPEM(t *testing.T) {
	want := []string{"https://one.example/", "https://two.example/"}
	body := sealProxyList(t, `["https://one.example/","https://two.example/"]`)

	for _, tc := range []struct {
		name string
		pem  string
	}{
		{"canonical", canonicalPEM},
		{"trailing newline", canonicalPEM + "\n"},
		{"trailing crlf", canonicalPEM + "\r\n"},
		{"trailing blank line", canonicalPEM + "\n\n"},
		{"trailing spaces", canonicalPEM + "  \n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeProxyList(body, false, []byte(tc.pem))
			if err != nil {
				t.Fatalf("decodeProxyList: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

// Leading bytes are part of the key by design: a PEM that differs anywhere but
// the tail is a different key, and must not silently decode.
func TestDecodeProxyListRejectsDifferentPEM(t *testing.T) {
	body := sealProxyList(t, `["https://one.example/"]`)
	other := "-----BEGIN PUBLIC KEY-----\nZGlmZmVyZW50\n-----END PUBLIC KEY-----"
	if _, err := decodeProxyList(body, false, []byte(other)); err == nil {
		t.Fatal("expected a decode error for an unrelated public key")
	}
}
