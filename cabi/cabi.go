// Package cabi is the C ABI over gateway.Client; the contract it implements is
// documented in agw.h.
//
// It is a library rather than a main on purpose: a host that already ships a Go
// binary blank-imports it, and the agw_* symbols ride along in that artifact
// instead of adding a second Go runtime to the process. cgo emits //export
// directives for an imported package just as it does for main.
package cabi

/*
#include <stdlib.h>
#include "agw_types.h"
#include "bridge.h"
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"runtime/cgo"
	"sync"
	"time"
	"unsafe"

	"github.com/amnezia-vpn/libagw/gateway"
)

const abiVersion = 1

type clientBox struct {
	client *gateway.Client
}

type cancelBox struct {
	ctx    context.Context
	cancel context.CancelFunc
}

type abiConfig struct {
	GatewayEndpoint          string   `json:"gateway_endpoint"`
	PublicKeyPEM             string   `json:"public_key_pem"`
	S3PrimaryEndpoints       []string `json:"s3_primary_endpoints"`
	S3FallbackEndpoints      []string `json:"s3_fallback_endpoints"`
	IsDevEnvironment         bool     `json:"is_dev_environment"`
	RequestTimeoutMsecs      int      `json:"request_timeout_msecs"`
	ProxyStorageTimeoutMsecs int      `json:"proxy_storage_timeout_msecs"`
	ProxyHealthTimeoutMsecs  int      `json:"proxy_health_timeout_msecs"`
}

type abiOptions struct {
	ServiceType     string `json:"service_type"`
	UserCountryCode string `json:"user_country_code"`
}

func goString(s *C.char) string {
	if s == nil {
		return ""
	}
	return C.GoString(s)
}

func clientFrom(h C.agw_client_handle) *clientBox {
	if h == 0 {
		return nil
	}
	v := cgo.Handle(h).Value()
	box, _ := v.(*clientBox)
	return box
}

func cancelFrom(h C.agw_cancel_handle) *cancelBox {
	if h == 0 {
		return nil
	}
	v := cgo.Handle(h).Value()
	box, _ := v.(*cancelBox)
	return box
}

//export agw_abi_version
func agw_abi_version() C.uint32_t {
	return abiVersion
}

//export agw_client_create
func agw_client_create(configJSON *C.char, callbacks *C.agw_callbacks) C.agw_client_handle {
	var cfg abiConfig
	if err := json.Unmarshal([]byte(goString(configJSON)), &cfg); err != nil {
		return 0
	}
	if cfg.GatewayEndpoint == "" || cfg.PublicKeyPEM == "" {
		return 0
	}

	gcfg := gateway.Config{
		GatewayEndpoint:     cfg.GatewayEndpoint,
		PublicKeyPEM:        []byte(cfg.PublicKeyPEM),
		S3PrimaryEndpoints:  cfg.S3PrimaryEndpoints,
		S3FallbackEndpoints: cfg.S3FallbackEndpoints,
		IsDevEnvironment:    cfg.IsDevEnvironment,
		RequestTimeout:      time.Duration(cfg.RequestTimeoutMsecs) * time.Millisecond,
		ProxyStorageTimeout: time.Duration(cfg.ProxyStorageTimeoutMsecs) * time.Millisecond,
		ProxyHealthTimeout:  time.Duration(cfg.ProxyHealthTimeoutMsecs) * time.Millisecond,
	}

	// Snapshotted: the caller may free the struct after this returns.
	if callbacks != nil {
		if callbacks.log != nil {
			logFn := callbacks.log
			logUD := callbacks.log_user_data
			gcfg.Logger = func(level gateway.LogLevel, msg string) {
				cmsg := C.CString(msg)
				defer C.free(unsafe.Pointer(cmsg))
				C.agw_bridge_log(logFn, C.int(level), cmsg, logUD)
			}
		}
		if callbacks.on_before_request != nil {
			reqFn := callbacks.on_before_request
			reqUD := callbacks.on_before_request_user_data
			gcfg.OnBeforeRequest = func(host string) {
				chost := C.CString(host)
				defer C.free(unsafe.Pointer(chost))
				C.agw_bridge_before_request(reqFn, chost, reqUD)
			}
		}
	}

	h := cgo.NewHandle(&clientBox{client: gateway.New(gcfg)})
	return C.agw_client_handle(h)
}

//export agw_client_destroy
func agw_client_destroy(client C.agw_client_handle) {
	if client == 0 {
		return
	}
	cgo.Handle(client).Delete()
}

//export agw_post
func agw_post(client C.agw_client_handle, endpoint, payloadJSON, optionsJSON *C.char, cancel C.agw_cancel_handle) C.agw_result {
	box := clientFrom(client)
	if box == nil {
		return makeResult(int32(gateway.ApiConfigDownloadError), nil)
	}

	var opts abiOptions
	if o := goString(optionsJSON); o != "" {
		// A malformed options document degrades to an empty failover context
		// rather than failing the request.
		_ = json.Unmarshal([]byte(o), &opts)
	}

	ctx := context.Background()
	if cb := cancelFrom(cancel); cb != nil {
		ctx = cb.ctx
	}

	resp, err := box.client.Post(ctx, goString(endpoint), []byte(goString(payloadJSON)), gateway.PostOptions{
		ServiceType:     opts.ServiceType,
		UserCountryCode: opts.UserCountryCode,
	})
	return makeResult(errorCodeOf(err), resp.Body)
}

func errorCodeOf(err error) int32 {
	if err == nil {
		return int32(gateway.NoError)
	}
	var gwErr *gateway.Error
	if errors.As(err, &gwErr) {
		return int32(gwErr.Code)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return C.AGW_CANCELLED
	}
	return int32(gateway.ApiConfigDownloadError)
}

func makeResult(code int32, body []byte) C.agw_result {
	var r C.agw_result
	r.code = C.int32_t(code)
	if len(body) > 0 {
		r.body = (*C.char)(C.CBytes(append(body, 0)))
		r.body_len = C.size_t(len(body))
	}
	return r
}

//export agw_result_free
func agw_result_free(result *C.agw_result) {
	if result == nil {
		return
	}
	if result.body != nil {
		C.free(unsafe.Pointer(result.body))
		result.body = nil
	}
	result.body_len = 0
}

//export agw_cancel_create
func agw_cancel_create() C.agw_cancel_handle {
	ctx, cancel := context.WithCancel(context.Background())
	h := cgo.NewHandle(&cancelBox{ctx: ctx, cancel: cancel})
	return C.agw_cancel_handle(h)
}

//export agw_cancel_cancel
func agw_cancel_cancel(cancel C.agw_cancel_handle) {
	if cb := cancelFrom(cancel); cb != nil {
		cb.cancel()
	}
}

//export agw_cancel_destroy
func agw_cancel_destroy(cancel C.agw_cancel_handle) {
	if cancel == 0 {
		return
	}
	if cb := cancelFrom(cancel); cb != nil {
		cb.cancel()
	}
	cgo.Handle(cancel).Delete()
}

//export agw_export_state
func agw_export_state(client C.agw_client_handle) *C.char {
	box := clientFrom(client)
	if box == nil {
		return nil
	}
	return C.CString(string(box.client.ExportState()))
}

//export agw_import_state
func agw_import_state(client C.agw_client_handle, stateJSON *C.char) C.int32_t {
	box := clientFrom(client)
	if box == nil {
		return C.int32_t(gateway.ApiConfigDownloadError)
	}
	if err := box.client.ImportState([]byte(goString(stateJSON))); err != nil {
		return C.int32_t(gateway.ApiConfigDownloadError)
	}
	return C.AGW_OK
}

//export agw_string_free
func agw_string_free(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

// Never freed: agw_error_string promises static-lifetime strings.
var (
	cErrorStringsMu sync.Mutex
	cErrorStrings   = map[int32]*C.char{}
)

//export agw_error_string
func agw_error_string(code C.int32_t) *C.char {
	c := int32(code)
	cErrorStringsMu.Lock()
	defer cErrorStringsMu.Unlock()
	if s, ok := cErrorStrings[c]; ok {
		return s
	}
	var text string
	if c == C.AGW_CANCELLED {
		text = "cancelled"
	} else {
		text = gateway.ErrorText(gateway.ErrorCode(c))
	}
	s := C.CString(text)
	cErrorStrings[c] = s
	return s
}
