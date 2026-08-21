package gateway

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	aesKeyBytes = 32
	aesIVBytes  = 32
	aesBlock    = 16
	saltBytes   = 8
)

var errInvalidPublicKey = errors.New("invalid gateway public key")

// Field names are wire protocol.
type keysPayload struct {
	AesKey  string `json:"aes_key"`
	AesIv   string `json:"aes_iv"`
	AesSalt string `json:"aes_salt"`
}

type requestBody struct {
	KeyPayload string `json:"key_payload"`
	ApiPayload string `json:"api_payload"`
}

type envelope struct {
	body []byte
	key  []byte
	iv   []byte
}

// Two oddities are deliberate, matching what the server expects: the "iv" is
// generated and transmitted as 32 bytes while CBC uses only the first 16, and
// the 8-byte salt is transmitted but never used.
func buildEnvelope(payload, publicKeyPEM []byte) (envelope, error) {
	rsaPub, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return envelope{}, fmt.Errorf("%w: %w", errInvalidPublicKey, err)
	}

	key := make([]byte, aesKeyBytes)
	iv := make([]byte, aesIVBytes)
	salt := make([]byte, saltBytes)
	for _, b := range [][]byte{key, iv, salt} {
		if _, err := rand.Read(b); err != nil {
			return envelope{}, err
		}
	}

	keysJSON, err := json.Marshal(keysPayload{
		AesKey:  base64.StdEncoding.EncodeToString(key),
		AesIv:   base64.StdEncoding.EncodeToString(iv),
		AesSalt: base64.StdEncoding.EncodeToString(salt),
	})
	if err != nil {
		return envelope{}, err
	}

	encKeys, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, keysJSON)
	if err != nil {
		return envelope{}, fmt.Errorf("rsa encrypt: %w", err)
	}

	ct, err := aesEncryptCBC(payload, key, iv)
	if err != nil {
		return envelope{}, err
	}

	body, err := json.Marshal(requestBody{
		KeyPayload: base64.StdEncoding.EncodeToString(encKeys),
		ApiPayload: base64.StdEncoding.EncodeToString(ct),
	})
	if err != nil {
		return envelope{}, err
	}
	return envelope{body: body, key: key, iv: iv}, nil
}

func parsePublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, errors.New("pem decode failed")
	}
	pk, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkix: %w", err)
	}
	rsaPub, ok := pk.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaPub, nil
}

func aesEncryptCBC(data, key, iv []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) < aesBlock {
		return nil, errors.New("iv too short")
	}
	pad := aesBlock - len(data)%aesBlock
	pt := append(append([]byte{}, data...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(blk, iv[:aesBlock]).CryptBlocks(ct, pt)
	return ct, nil
}

func aesDecryptCBC(data, key, iv []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) < aesBlock || len(data) == 0 || len(data)%aesBlock != 0 {
		return nil, errors.New("bad ciphertext/iv length")
	}
	pt := make([]byte, len(data))
	cipher.NewCBCDecrypter(blk, iv[:aesBlock]).CryptBlocks(pt, data)
	pad := int(pt[len(pt)-1])
	if pad <= 0 || pad > aesBlock || pad > len(pt) {
		return nil, errors.New("bad padding")
	}
	return pt[:len(pt)-pad], nil
}

// The hash input is the PEM string bytes, not the DER key.
func deriveProxyListKeyIV(publicKeyPEM []byte) (key, iv []byte) {
	sum := sha512.Sum512(publicKeyPEM)
	h := hex.EncodeToString(sum[:])
	key, _ = hex.DecodeString(h[0:64])
	iv, _ = hex.DecodeString(h[64:96])
	return key, iv
}
