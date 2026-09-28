package gateway

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
)

func sealProxyList(t *testing.T, canonicalPEM []byte, list []string) []byte {
	t.Helper()
	sum := sha512.Sum512(canonicalPEM)
	h := hex.EncodeToString(sum[:])
	key, _ := hex.DecodeString(h[0:64])
	iv, _ := hex.DecodeString(h[64:96])
	plain, _ := json.Marshal(list)
	ct, err := aesEncryptCBC(plain, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(base64.StdEncoding.EncodeToString(ct))
}

func TestDecodeProxyListIgnoresTrailingWhitespaceInPEM(t *testing.T) {
	_, pubPEM := newTestKeyPair(t)
	canonical := bytes.TrimRight(pubPEM, "\n")
	list := []string{"https://proxy1.example.com/", "https://proxy2.example.com/"}
	body := sealProxyList(t, canonical, list)

	for name, suffix := range map[string]string{
		"canonical":           "",
		"trailing newline":    "\n",
		"trailing crlf":       "\r\n",
		"trailing blank line": "\n\n",
		"trailing spaces":     "  \n",
	} {
		t.Run(name, func(t *testing.T) {
			input := append(append([]byte{}, canonical...), suffix...)
			got, err := decodeProxyList(body, false, input)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, list) {
				t.Fatalf("got %v want %v", got, list)
			}
		})
	}
}

func TestDecodeProxyListRejectsDifferentPEM(t *testing.T) {
	_, pubPEM := newTestKeyPair(t)
	_, otherPEM := newTestKeyPair(t)
	body := sealProxyList(t, bytes.TrimRight(pubPEM, "\n"), []string{"https://proxy1.example.com/"})
	if _, err := decodeProxyList(body, false, otherPEM); err == nil {
		t.Fatal("a different key must not decode")
	}
}
