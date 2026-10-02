// Minimal RAII wrapper over the C ABI — the shape a C++ host (e.g. the Qt
// client) would use. Header-only, no Qt, no exceptions across the boundary.
#ifndef AMNEZIA_GATEWAY_SDK_EXAMPLE_AGW_HPP
#define AMNEZIA_GATEWAY_SDK_EXAMPLE_AGW_HPP

#include <cstddef>
#include <string>
#include <utility>

#include "agw.h"

namespace agw {

// CancelToken interrupts a blocking Post from another thread. Single-shot.
class CancelToken
{
public:
    CancelToken() : m_handle(agw_cancel_create()) {}
    ~CancelToken() { agw_cancel_destroy(m_handle); }

    CancelToken(const CancelToken &) = delete;
    CancelToken &operator=(const CancelToken &) = delete;

    void cancel() { agw_cancel_cancel(m_handle); }
    agw_cancel_handle handle() const { return m_handle; }

private:
    agw_cancel_handle m_handle;
};

class Client
{
public:
    struct Result
    {
        int code = 0;
        std::string body;

        bool ok() const { return code == AGW_OK; }
        const char *message() const { return agw_error_string(code); }
    };

    // callbacks may be nullptr. Check valid() before use.
    explicit Client(const std::string &configJson, const agw_callbacks *callbacks = nullptr)
        : m_handle(agw_client_create(configJson.c_str(), callbacks))
    {
    }

    ~Client()
    {
        if (m_handle != 0) {
            agw_client_destroy(m_handle);
        }
    }

    Client(const Client &) = delete;
    Client &operator=(const Client &) = delete;

    Client(Client &&other) noexcept : m_handle(std::exchange(other.m_handle, 0)) {}
    Client &operator=(Client &&other) noexcept
    {
        if (this != &other) {
            if (m_handle != 0) {
                agw_client_destroy(m_handle);
            }
            m_handle = std::exchange(other.m_handle, 0);
        }
        return *this;
    }

    bool valid() const { return m_handle != 0; }

    // Blocks for up to the full failover sequence — call off the UI thread.
    Result post(const std::string &endpoint, const std::string &payloadJson,
                const std::string &optionsJson = std::string(), const CancelToken *cancel = nullptr)
    {
        agw_result r = agw_post(m_handle, endpoint.c_str(), payloadJson.c_str(),
                                optionsJson.empty() ? nullptr : optionsJson.c_str(),
                                cancel != nullptr ? cancel->handle() : 0);
        Result out;
        out.code = r.code;
        if (r.body != nullptr) {
            out.body.assign(r.body, r.body_len);
        }
        agw_result_free(&r);
        return out;
    }

    // Failover caches; persist in protected storage (bypass endpoints).
    std::string exportState()
    {
        char *s = agw_export_state(m_handle);
        if (s == nullptr) {
            return {};
        }
        std::string out(s);
        agw_string_free(s);
        return out;
    }

    bool importState(const std::string &stateJson)
    {
        return agw_import_state(m_handle, stateJson.c_str()) == AGW_OK;
    }

private:
    agw_client_handle m_handle;
};

} // namespace agw

#endif
