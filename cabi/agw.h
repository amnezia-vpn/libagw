/* libagw C ABI.
 *
 * JSON-first contract: configuration, per-request options and persisted
 * state are JSON documents; the only C structs are the small fixed-size
 * callbacks/result types in agw_types.h.
 *
 * Threading: agw_post blocks for up to the full failover sequence — call it
 * off the UI thread and use a cancel handle to interrupt it. A client handle
 * is safe to use from multiple threads concurrently.
 *
 * Memory: every char* returned by this library is owned by the caller and
 * released with agw_result_free / agw_string_free. Strings passed in are
 * copied before the call returns.
 */
#ifndef AMNEZIA_GATEWAY_SDK_AGW_H
#define AMNEZIA_GATEWAY_SDK_AGW_H

#include "agw_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ABI version of this header/library pair. */
uint32_t agw_abi_version(void);

/* Creates a client from a JSON config:
 * {
 *   "gateway_endpoint": "https://api.example.com",     (required)
 *   "public_key_pem": "-----BEGIN PUBLIC KEY-----...", (required)
 *   "s3_primary_endpoints": ["https://...", ...],
 *   "s3_fallback_endpoints": ["https://...", ...],
 *   "is_dev_environment": false,
 *   "request_timeout_msecs": 12000,
 *   "proxy_storage_timeout_msecs": 3000,
 *   "proxy_health_timeout_msecs": 1000
 * }
 * callbacks may be NULL. Returns 0 on invalid input. */
agw_client_handle agw_client_create(const char *config_json, const agw_callbacks *callbacks);
void agw_client_destroy(agw_client_handle client);

/* Posts one request. endpoint is a path relative to the gateway base
 * ("v1/services"), payload_json is the plain request document (encrypted by
 * the library), options_json is the failover context and may be NULL:
 *   {"service_type": "...", "user_country_code": "..."}
 * cancel may be 0. */
agw_result agw_post(agw_client_handle client, const char *endpoint,
                    const char *payload_json, const char *options_json,
                    agw_cancel_handle cancel);
void agw_result_free(agw_result *result);

/* Cancel handles interrupt a running agw_post from another thread. A handle
 * is single-shot: destroy it after the cancelled call returns. */
agw_cancel_handle agw_cancel_create(void);
void agw_cancel_cancel(agw_cancel_handle cancel);
void agw_cancel_destroy(agw_cancel_handle cancel);

/* Failover caches (working proxy + proxy lists) as an opaque JSON blob. The
 * blob contains censorship-bypass endpoints — persist it in protected
 * storage. Returns NULL on invalid handle; free with agw_string_free.
 * agw_import_state returns AGW_OK or a non-zero code on malformed input. */
char *agw_export_state(agw_client_handle client);
int32_t agw_import_state(agw_client_handle client, const char *state_json);
void agw_string_free(char *s);

/* Static description of a result code; never freed by the caller. */
const char *agw_error_string(int32_t code);

#ifdef __cplusplus
}
#endif

#endif /* AMNEZIA_GATEWAY_SDK_AGW_H */
