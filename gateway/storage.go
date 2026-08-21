package gateway

import (
	"encoding/base64"
	"encoding/json"
)

// The token encoding — unpadded base64url of "endpoints-<service>-<country>" —
// is wire protocol.
func buildStorageURLs(primary, fallback []string, serviceType, userCountryCode string) []string {
	var out []string
	appendGroup := func(bases []string) {
		if serviceType != "" {
			token := "endpoints-" + serviceType + "-" + userCountryCode
			encoded := base64.RawURLEncoding.EncodeToString([]byte(token))
			for _, base := range bases {
				out = append(out, joinURL(base, encoded+".json"))
			}
		}
		for _, base := range bases {
			out = append(out, joinURL(base, "endpoints.json"))
		}
	}
	appendGroup(primary)
	appendGroup(fallback)
	return out
}

func decodeProxyList(body []byte, isDev bool, publicKeyPEM []byte) ([]string, error) {
	plain := body
	if !isDev {
		ct, err := base64.StdEncoding.DecodeString(string(body))
		if err != nil {
			return nil, err
		}
		key, iv := deriveProxyListKeyIV(publicKeyPEM)
		plain, err = aesDecryptCBC(ct, key, iv)
		if err != nil {
			return nil, err
		}
	}

	var raw []any
	if err := json.Unmarshal(plain, &raw); err != nil {
		return nil, err
	}
	urls := make([]string, 0, len(raw))
	for _, el := range raw {
		if s, ok := el.(string); ok {
			urls = append(urls, s)
		}
	}
	return urls, nil
}

func proxyListKey(serviceType, userCountryCode string) string {
	return "service_" + serviceType + "_country_" + userCountryCode
}
