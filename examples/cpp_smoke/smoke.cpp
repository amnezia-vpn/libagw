// Offline C++ smoke test: RAII wrapper lifecycle, move semantics, log
// callback plumbing and state round-trip. No network.
//
//   scripts/smoke.sh   (builds the archive and runs this)
#include <cassert>
#include <cstdio>
#include <string>
#include <utility>

#include "agw.hpp"

namespace {

int g_logLines = 0;

void onLog(int level, const char *message, void *user_data)
{
    (void)level;
    (void)message;
    ++*static_cast<int *>(user_data);
}

} // namespace

int main()
{
    assert(agw_abi_version() == 1);

    agw_callbacks callbacks{};
    callbacks.struct_size = sizeof(agw_callbacks);
    callbacks.log = &onLog;
    callbacks.log_user_data = &g_logLines;

    // Invalid config yields an unusable client.
    agw::Client bad("{}", &callbacks);
    assert(!bad.valid());

    agw::Client client(R"({"gateway_endpoint":"http://127.0.0.1:1",)"
                       R"("public_key_pem":"garbage","request_timeout_msecs":200})",
                       &callbacks);
    assert(client.valid());

    // Offline: envelope build fails with the client-parity code 1105.
    agw::Client::Result r = client.post("v1/services", "{}");
    assert(!r.ok());
    assert(r.code == 1105);
    assert(std::string(r.message()).find("public key") != std::string::npos);
    assert(g_logLines > 0 && "log callback must have fired");

    // Options JSON is accepted and a malformed one degrades gracefully.
    assert(client.post("v1/services", "{}", R"({"service_type":"svc","user_country_code":"ru"})").code == 1105);
    assert(client.post("v1/services", "{}", "not json").code == 1105);

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

    std::printf("cpp smoke ok (%d log lines)\n", g_logLines);
    return 0;
}
