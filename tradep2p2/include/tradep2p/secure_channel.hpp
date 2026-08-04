#pragma once

#include "tradep2p/protocol.hpp"

#include <cstdint>
#include <span>
#include <string>

struct ssl_ctx_st;
struct ssl_st;

namespace tradep2p {

struct Endpoint {
    std::string host;
    std::uint16_t port{};
};

// The mediator has a TLS certificate. Clients remain anonymous and present no
// client certificate, account, username, or application identity.
struct ServerTlsIdentity {
    std::string certificate_file;
    std::string private_key_file;
};

struct ClientTlsPolicy {
    // Exact SHA-256 pin of the mediator certificate. Mandatory. This
    // authenticates the mediator without authenticating the anonymous client.
    std::string expected_server_sha256;
};

class SecureChannel {
public:
    SecureChannel() = default;
    ~SecureChannel();

    SecureChannel(const SecureChannel&) = delete;
    SecureChannel& operator=(const SecureChannel&) = delete;
    SecureChannel(SecureChannel&& other) noexcept;
    SecureChannel& operator=(SecureChannel&& other) noexcept;

    static SecureChannel connect_direct(const Endpoint& endpoint,
                                        const ClientTlsPolicy& policy);
    static SecureChannel connect_via_socks5(const Endpoint& proxy,
                                            const Endpoint& destination,
                                            const ClientTlsPolicy& policy);

    void send_frame(MessageType type, std::span<const std::uint8_t> payload);
    [[nodiscard]] Frame receive_frame();
    void set_timeout(std::uint32_t timeout_seconds);
    [[nodiscard]] int native_handle() const noexcept { return socket_fd_; }
    [[nodiscard]] bool has_pending_input() const noexcept;
    void close();

private:
    friend class SecureListener;
    SecureChannel(int socket_fd, ssl_ctx_st* ctx, ssl_st* ssl, bool owns_ctx);

    static SecureChannel make_client(int socket_fd,
                                     const ClientTlsPolicy& policy);
    static SecureChannel make_server(int socket_fd,
                                     ssl_ctx_st* shared_server_ctx);
    static void verify_server_pin(ssl_st* ssl, const std::string& expected_hex);

    int socket_fd_{-1};
    ssl_ctx_st* ctx_{nullptr};
    ssl_st* ssl_{nullptr};
    bool owns_ctx_{true};
    std::uint64_t send_sequence_{1};
    std::uint64_t receive_sequence_{1};
};

class SecureListener {
public:
    SecureListener(const Endpoint& bind_endpoint,
                   const ServerTlsIdentity& identity);
    ~SecureListener();

    SecureListener(const SecureListener&) = delete;
    SecureListener& operator=(const SecureListener&) = delete;

    [[nodiscard]] SecureChannel accept();

private:
    int listen_fd_{-1};
    ssl_ctx_st* ctx_{nullptr};
};

} // namespace tradep2p
