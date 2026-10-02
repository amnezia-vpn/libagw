/* libagw C ABI: type definitions.
 *
 * This header is included by the Go cgo layer and must contain types only
 * (no function prototypes) — consumer-facing prototypes live in agw.h.
 */
#ifndef AMNEZIA_GATEWAY_SDK_AGW_TYPES_H
#define AMNEZIA_GATEWAY_SDK_AGW_TYPES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Result codes. Non-zero codes describe the outcomes in which there is no
 * gateway answer to interpret; whenever the gateway did answer, agw_post
 * returns AGW_OK with the decrypted body regardless of the API status inside
 * it ("http_status"/"message" fields) — interpreting that is the host's job. */
#define AGW_OK 0
#define AGW_CANCELLED 1            /* cancelled through an agw_cancel_handle */
#define AGW_ERR_INVALID_ARGUMENT 2 /* bad handle or malformed input */
#define AGW_ERR_CONFIG 3           /* gateway public key missing or invalid */
#define AGW_ERR_TIMEOUT 4          /* request timed out */
#define AGW_ERR_SSL 5              /* tls error on the direct path */
#define AGW_ERR_NETWORK 6          /* gateway unreachable, failover exhausted */
#define AGW_ERR_DECRYPT 7          /* answer could not be decrypted */

/* Opaque handles. 0 is never a valid handle. */
typedef uintptr_t agw_client_handle;
typedef uintptr_t agw_cancel_handle;

/* Log levels passed to agw_log_fn. */
#define AGW_LOG_DEBUG 0
#define AGW_LOG_INFO 1
#define AGW_LOG_WARNING 2
#define AGW_LOG_ERROR 3

typedef void (*agw_log_fn)(int level, const char *message, void *user_data);
typedef void (*agw_before_request_fn)(const char *host, void *user_data);

/* Host callbacks. struct_size must be set to sizeof(agw_callbacks) by the
 * caller; it versions the struct for future additions. Callbacks may be
 * invoked from arbitrary threads. */
typedef struct {
    size_t struct_size;
    agw_log_fn log;
    void *log_user_data;
    agw_before_request_fn on_before_request;
    void *on_before_request_user_data;
} agw_callbacks;

/* One request result. body is set only when code is AGW_OK; it is
 * NUL-terminated (body_len excludes the NUL). Free with agw_result_free. */
typedef struct {
    int32_t code;
    char *body;
    size_t body_len;
} agw_result;

#ifdef __cplusplus
}
#endif

#endif /* AMNEZIA_GATEWAY_SDK_AGW_TYPES_H */
