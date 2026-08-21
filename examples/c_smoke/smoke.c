/* Offline smoke test for the C ABI: no network, exercises handle lifecycle,
 * error codes, state round-trip and cancellation plumbing.
 *
 *   go build -buildmode=c-archive -o libagw.a ./archive
 *   cc examples/c_smoke/smoke.c libagw.a -Icabi -o smoke && ./smoke
 *
 * On macOS add: -framework CoreFoundation -framework Security
 * (Go's crypto/x509 uses the platform certificate verifier there.)
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "agw.h"

int main(void)
{
    assert(agw_abi_version() == 1);

    /* Invalid configs are rejected. */
    assert(agw_client_create(NULL, NULL) == 0);
    assert(agw_client_create("not json", NULL) == 0);
    assert(agw_client_create("{}", NULL) == 0);

    /* A syntactically valid config with a garbage key still creates a
     * client; the key is validated per request. */
    agw_client_handle client = agw_client_create(
            "{\"gateway_endpoint\":\"http://127.0.0.1:1\","
            "\"public_key_pem\":\"garbage\","
            "\"request_timeout_msecs\":200}",
            NULL);
    assert(client != 0);

    /* Envelope build fails offline with the parity code 1105. */
    agw_result r = agw_post(client, "v1/services", "{}", NULL, 0);
    assert(r.code == 1105);
    agw_result_free(&r);
    assert(r.body == NULL && r.body_len == 0);

    const char *msg = agw_error_string(1105);
    assert(msg != NULL && strlen(msg) > 0);

    /* State round-trip. */
    char *state = agw_export_state(client);
    assert(state != NULL && strstr(state, "\"version\":1") != NULL);
    assert(agw_import_state(client, state) == AGW_OK);
    assert(agw_import_state(client, "junk") != AGW_OK);
    agw_string_free(state);

    /* Cancel handle lifecycle (single-shot, idempotent cancel). */
    agw_cancel_handle cancel = agw_cancel_create();
    assert(cancel != 0);
    agw_cancel_cancel(cancel);
    agw_cancel_cancel(cancel);
    agw_cancel_destroy(cancel);

    agw_client_destroy(client);

    printf("smoke ok\n");
    return 0;
}
