// Offline C++ smoke test: RAII wrapper lifecycle, move semantics, before-request
// callback plumbing, trace and state round-trip. No network.
//
//   scripts/smoke.sh   (builds the archive and runs this)
#include <cassert>
#include <cstdio>
#include <string>
#include <utility>

#include "agw.hpp"

namespace {

int g_beforeRequests = 0;

void onBeforeRequest(const char *host, void *user_data)
{
    (void)host;
    ++*static_cast<int *>(user_data);
}

} // namespace

int main()
{
    assert(agw_abi_version() == 2);

    agw_callbacks callbacks{};
    callbacks.struct_size = sizeof(agw_callbacks);
    callbacks.on_before_request = &onBeforeRequest;
    callbacks.on_before_request_user_data = &g_beforeRequests;

    // Invalid config yields an unusable client.
    agw::Client bad("{}", &callbacks);
    assert(!bad.valid());

    agw::Client client(R"({"gateway_endpoint":"http://127.0.0.1:1",)"
                       R"("public_key_pem":"garbage","request_timeout_msecs":200})",
                       &callbacks);
    assert(client.valid());

    // Offline: envelope build fails because the key is garbage, before any
    // network attempt, and the trace explains it.
    agw::Client::Result r = client.post("v1/services", "{}");
    assert(!r.ok());
    assert(r.code == AGW_ERR_CONFIG);
    assert(std::string(r.message()).find("public key") != std::string::npos);
    assert(r.trace.find("envelope:") != std::string::npos);
    assert(g_beforeRequests == 0);

    // Options JSON is accepted and a malformed one degrades gracefully.
    assert(client.post("v1/services", "{}", R"({"service_type":"svc","user_country_code":"ru"})").code == AGW_ERR_CONFIG);
    assert(client.post("v1/services", "{}", "not json").code == AGW_ERR_CONFIG);

    // Cancellation plumbing.
    agw::CancelToken cancel;
    cancel.cancel();
    assert(client.post("v1/services", "{}", "", &cancel).code == AGW_CANCELLED);

    // State round-trip.
    const std::string state = client.exportState();
    assert(state.find("\"version\":1") != std::string::npos);
    assert(client.importState(state));
    assert(!client.importState("junk"));

    // Move semantics leave exactly one owner.
    agw::Client moved = std::move(client);
    assert(moved.valid());
    assert(!client.valid());

    std::printf("cpp smoke ok\n");
    return 0;
}
