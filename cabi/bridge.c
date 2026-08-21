#include "bridge.h"

void agw_bridge_log(agw_log_fn fn, int level, const char *msg, void *user_data)
{
    if (fn != NULL) {
        fn(level, msg, user_data);
    }
}

void agw_bridge_before_request(agw_before_request_fn fn, const char *host, void *user_data)
{
    if (fn != NULL) {
        fn(host, user_data);
    }
}
