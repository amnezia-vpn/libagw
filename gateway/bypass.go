package gateway

import (
	"bytes"
	"encoding/json"
	"strings"
)

// The patterns below and the crude `contains("html")` check are a contract with
// real backend and CDN behaviour, not sloppiness: do not "clean them up".
var noBypassBodyPatterns = [][]byte{
	[]byte("No active configuration found for"),
	[]byte("No non-revoked public key found for"),
	[]byte("Account not found."),
	[]byte("QR session not found"),
	[]byte("Session not found"),
}

var updateRequestPattern = []byte("client version update is required")

const unprocessableSubscriptionMessage = "Failed to retrieve subscription information. Is it activated?"

func apiStatus(body []byte) (status int, message string) {
	status = -1
	var doc map[string]any
	if json.Unmarshal(body, &doc) != nil {
		return status, ""
	}
	if v, ok := doc["http_status"].(float64); ok {
		status = int(v)
	}
	if v, ok := doc["message"].(string); ok {
		message = strings.TrimSpace(v)
	}
	return status, message
}

func shouldBypassProxy(kind transportErrorKind, body []byte, decryptOK bool) bool {
	if !decryptOK {
		return true
	}

	status, message := apiStatus(body)

	if kind == transportTimeout || kind == transportCancelled {
		return true
	}
	if bytes.Contains(body, []byte("html")) {
		return true
	}
	switch status {
	case 408:
		return false
	case 404:
		for _, p := range noBypassBodyPatterns {
			if bytes.Contains(body, p) {
				return false
			}
		}
		return true
	case 501:
		return !bytes.Contains(body, updateRequestPattern)
	case 409:
		return false
	case 402:
		return false
	case 422:
		return message != unprocessableSubscriptionMessage
	}
	return kind != transportOK
}
