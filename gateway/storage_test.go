package gateway

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
)

func TestBuildStorageURLs(t *testing.T) {
	primary := []string{"https://p1.example.com/", "https://p2.example.com"}
	fallback := []string{"https://f1.example.com/"}

	got := buildStorageURLs(primary, fallback, "amnezia-premium", "ru")

	// base64url, no padding, of "endpoints-amnezia-premium-ru"
	token := base64.RawURLEncoding.EncodeToString([]byte("endpoints-amnezia-premium-ru"))
	want := []string{
		"https://p1.example.com/" + token + ".json",
		"https://p2.example.com/" + token + ".json",
		"https://p1.example.com/endpoints.json",
		"https://p2.example.com/endpoints.json",
		"https://f1.example.com/" + token + ".json",
		"https://f1.example.com/endpoints.json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestBuildStorageURLsNoServiceType(t *testing.T) {
	got := buildStorageURLs([]string{"https://p.example.com/"}, nil, "", "ru")
	want := []string{"https://p.example.com/endpoints.json"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestDecodeProxyListDev(t *testing.T) {
	got, err := decodeProxyList([]byte(`["https://a/","https://b/"]`), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"https://a/", "https://b/"}) {
		t.Fatalf("got %v", got)
	}
}

func TestDecodeProxyListProd(t *testing.T) {
	pubPEM := []byte("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n")
	list := []string{"https://proxy1.example.com/", "https://proxy2.example.com/"}
	plain, _ := json.Marshal(list)

	key, iv := deriveProxyListKeyIV(pubPEM)
	ct, err := aesEncryptCBC(plain, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(base64.StdEncoding.EncodeToString(ct))

	got, err := decodeProxyList(body, false, pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, list) {
		t.Fatalf("got %v want %v", got, list)
	}
}

func TestDecodeProxyListProdRejectsGarbage(t *testing.T) {
	pubPEM := []byte("pem")
	if _, err := decodeProxyList([]byte("<html>err</html>"), false, pubPEM); err == nil {
		t.Fatal("garbage must not decode")
	}
}

func TestProxyListKey(t *testing.T) {
	if got := proxyListKey("svc", "de"); got != "service_svc_country_de" {
		t.Fatalf("got %q", got)
	}
}
