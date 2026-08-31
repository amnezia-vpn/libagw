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

/* Result codes: 0 = success, 1 = cancelled by the caller, 1100..1120 mirror
 * the amnezia-client ErrorCode enum (see gateway/errors.go). */
#define AGW_OK 0
#define AGW_CANCELLED 1

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

/* One request result. body is NUL-terminated (body_len excludes the NUL) and
 * may be non-empty even for non-zero codes (e.g. captcha challenges). Free
 * with agw_result_free. */
typedef struct {
    int32_t code;
    char *body;
    size_t body_len;
} agw_result;

#ifdef __cplusplus
}
#endif

#endif /* AMNEZIA_GATEWAY_SDK_AGW_TYPES_H */
