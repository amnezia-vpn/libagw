/* Null-checking shims for calling host callbacks from Go. Declarations only:
 * the file with //export directives must not define C functions in its
 * preamble. */
#ifndef AMNEZIA_GATEWAY_SDK_BRIDGE_H
#define AMNEZIA_GATEWAY_SDK_BRIDGE_H

#include "agw_types.h"

void agw_bridge_log(agw_log_fn fn, int level, const char *msg, void *user_data);
void agw_bridge_before_request(agw_before_request_fn fn, const char *host, void *user_data);

#endif /* AMNEZIA_GATEWAY_SDK_BRIDGE_H */
