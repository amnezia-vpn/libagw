package gateway

import (
	"bytes"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	priv, pubPEM := newTestKeyPair(t)
	payload := []byte(`{"os_version":"14.0","app_version":"4.8.0"}`)

	env, err := buildEnvelope(payload, pubPEM)
	if err != nil {
		t.Fatal(err)
	}

	got, key, iv, err := openEnvelopeErr(priv, env.body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q", got)
	}
	if !bytes.Equal(key, env.key) || !bytes.Equal(iv, env.iv) {
		t.Fatal("transmitted AES material differs from envelope material")
	}

	respPlain := []byte(`{"services":[]}`)
	respCT, err := aesEncryptCBC(respPlain, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := aesDecryptCBC(respCT, env.key, env.iv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, respPlain) {
		t.Fatalf("response mismatch: got %q", dec)
	}
}

func TestEnvelopeUniquePerRequest(t *testing.T) {
	_, pubPEM := newTestKeyPair(t)
	a, err := buildEnvelope([]byte(`{}`), pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	b, err := buildEnvelope([]byte(`{}`), pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.key, b.key) || bytes.Equal(a.iv, b.iv) {
		t.Fatal("AES material must be fresh per request")
	}
}

func TestBuildEnvelopeRejectsBadKey(t *testing.T) {
	_, err := buildEnvelope([]byte("{}"), []byte("not a pem"))
	if err == nil || !isInvalidKeyErr(err) {
		t.Fatalf("want errInvalidPublicKey, got %v", err)
	}
}

func TestAESDecryptRejectsGarbage(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 32)
	if _, err := aesDecryptCBC([]byte("<html>blocked</html>"), key, iv); err == nil {
		t.Fatal("plaintext html must not decrypt")
	}
	if _, err := aesDecryptCBC(nil, key, iv); err == nil {
		t.Fatal("empty body must not decrypt")
	}
}

func TestDeriveProxyListKeyIV(t *testing.T) {
	pem := []byte("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n")
	key, iv := deriveProxyListKeyIV(pem)
	if len(key) != 32 || len(iv) != 16 {
		t.Fatalf("key=%d iv=%d, want 32/16", len(key), len(iv))
	}
	key2, iv2 := deriveProxyListKeyIV(pem)
	if !bytes.Equal(key, key2) || !bytes.Equal(iv, iv2) {
		t.Fatal("derivation must be deterministic")
	}
}
