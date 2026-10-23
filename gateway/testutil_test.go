package gateway

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestKeyPair(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return priv, pubPEM
}

func openEnvelopeErr(priv *rsa.PrivateKey, body []byte) (payload, key, iv []byte, err error) {
	var req requestBody
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, nil, nil, fmt.Errorf("request body is not JSON: %w", err)
	}
	encKeys, err := base64.StdEncoding.DecodeString(req.KeyPayload)
	if err != nil {
		return nil, nil, nil, err
	}
	keysJSON, err := rsa.DecryptPKCS1v15(nil, priv, encKeys)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("rsa decrypt: %w", err)
	}
	var keys keysPayload
	if err := json.Unmarshal(keysJSON, &keys); err != nil {
		return nil, nil, nil, fmt.Errorf("keys payload is not JSON: %w", err)
	}
	key, err = base64.StdEncoding.DecodeString(keys.AesKey)
	if err != nil {
		return nil, nil, nil, err
	}
	iv, err = base64.StdEncoding.DecodeString(keys.AesIv)
	if err != nil {
		return nil, nil, nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(keys.AesSalt)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(key) != 32 || len(iv) != 32 || len(salt) != 8 {
		return nil, nil, nil, fmt.Errorf("wire sizes: key=%d iv=%d salt=%d, want 32/32/8", len(key), len(iv), len(salt))
	}
	ct, err := base64.StdEncoding.DecodeString(req.ApiPayload)
	if err != nil {
		return nil, nil, nil, err
	}
	payload, err = aesDecryptCBC(ct, key, iv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("aes decrypt: %w", err)
	}
	return payload, key, iv, nil
}

func encryptStorageList(t *testing.T, pubPEM []byte, list []string) []byte {
	t.Helper()
	plain, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	key, iv := deriveProxyListKeyIV(pubPEM)
	ct, err := aesEncryptCBC(plain, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(base64.StdEncoding.EncodeToString(ct))
}

type fakeResolver struct {
	mu        sync.Mutex
	delay     map[string]time.Duration
	delay6    map[string]time.Duration
	addr6     map[string]netip.Addr
	fail      map[string]error
	calls     map[string]int
	active    int
	maxActive int
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		delay:  map[string]time.Duration{},
		delay6: map[string]time.Duration{},
		addr6:  map[string]netip.Addr{},
		fail:   map[string]error{},
		calls:  map[string]int{},
	}
}

func (f *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	v6 := network == "ip6"
	if !v6 {
		f.calls[host]++
	}
	f.active++
	f.maxActive = max(f.maxActive, f.active)
	delay, err := f.delay[host], f.fail[host]
	if d, ok := f.delay6[host]; ok && v6 {
		delay = d
	}
	addr6, has6 := f.addr6[host]
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.active--
		f.mu.Unlock()
	}()

	select {
	case <-time.After(delay):
	case <-ctx.Done():
		return nil, &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}
	}
	switch {
	case err != nil:
		return nil, err
	case v6 && !has6:
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	case v6:
		return []netip.Addr{addr6}, nil
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func (f *fakeResolver) set(host string, delay time.Duration) {
	f.mu.Lock()
	f.delay[host] = delay
	f.mu.Unlock()
}

func (f *fakeResolver) callsFor(host string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[host]
}

func (f *fakeResolver) maxConcurrent() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxActive
}

func named(srvURL, host string) string {
	return strings.Replace(srvURL, "127.0.0.1", host, 1)
}
