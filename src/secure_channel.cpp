#include "tradep2p/secure_channel.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace tradep2p {
namespace {

bool log_enabled() noexcept {
    static const bool enabled = [] {
        if (const char* value = std::getenv("TRADEP2P_LOG_ENABLED")) {
            const std::string env_value(value);
            return env_value != "0" && env_value != "false" && env_value != "FALSE";
        }
        return false;
    }();
    return enabled;
}

void append_log(const std::string& message) {
    if (!log_enabled()) {
        return;
    }

    if (const char* value = std::getenv("TRADEP2P_LOG_FILE")) {
        const std::string path(value);
        if (path.empty()) {
            return;
        }

        std::FILE* file = std::fopen(path.c_str(), "a");
        if (file == nullptr) {
            return;
        }

        const std::time_t now = std::time(nullptr);
        std::tm tm{};
        if (::localtime_r(&now, &tm) != nullptr) {
            std::fprintf(file,
                         "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                         tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                         tm.tm_hour, tm.tm_min, tm.tm_sec, message.c_str());
        } else {
            std::fprintf(file, "%s\n", message.c_str());
        }
        std::fflush(file);
        std::fclose(file);
    }
}

[[noreturn]] void throw_ssl(const std::string& message) {
    const unsigned long error = ERR_get_error();
    char buffer[256]{};
    if (error != 0U) {
        ERR_error_string_n(error, buffer, sizeof(buffer));
        throw std::runtime_error(message + ": " + buffer);
    }
    throw std::runtime_error(message);
}

void close_fd(int& fd) noexcept {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

void set_close_on_exec(int fd) {
    const int flags = ::fcntl(fd, F_GETFD, 0);
    if (flags < 0 || ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
        throw std::runtime_error(std::string("failed to set FD_CLOEXEC: ") +
                                 std::strerror(errno));
    }
}

int connect_tcp(const Endpoint& endpoint) {
    if (endpoint.host.empty() || endpoint.port == 0U) {
        throw std::invalid_argument("invalid endpoint");
    }

    append_log("connect_tcp " + endpoint.host + ":" + std::to_string(endpoint.port));

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* results = nullptr;
    const auto port = std::to_string(endpoint.port);
    const int rc = ::getaddrinfo(endpoint.host.c_str(), port.c_str(), &hints, &results);
    if (rc != 0) {
        throw std::runtime_error(std::string("getaddrinfo failed: ") + gai_strerror(rc));
    }

    int fd = -1;
    for (auto* current = results; current != nullptr; current = current->ai_next) {
        fd = ::socket(current->ai_family, current->ai_socktype, current->ai_protocol);
        if (fd < 0) {
            continue;
        }
        try {
            set_close_on_exec(fd);
        } catch (...) {
            close_fd(fd);
            continue;
        }
        if (::connect(fd, current->ai_addr, current->ai_addrlen) == 0) {
            break;
        }
        close_fd(fd);
    }
    ::freeaddrinfo(results);

    if (fd < 0) {
        throw std::runtime_error("TCP connection failed");
    }
    append_log("connect_tcp ready");
    return fd;
}

int create_listener(const Endpoint& endpoint) {
    if (endpoint.port == 0U) {
        throw std::invalid_argument("invalid listen endpoint");
    }

    append_log("create_listener " + endpoint.host + ":" + std::to_string(endpoint.port));

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    addrinfo* results = nullptr;
    const auto port = std::to_string(endpoint.port);
    const char* host = endpoint.host.empty() ? nullptr : endpoint.host.c_str();
    const int rc = ::getaddrinfo(host, port.c_str(), &hints, &results);
    if (rc != 0) {
        throw std::runtime_error(std::string("getaddrinfo failed: ") + gai_strerror(rc));
    }

    int listen_fd = -1;
    for (auto* current = results; current != nullptr; current = current->ai_next) {
        listen_fd = ::socket(current->ai_family, current->ai_socktype, current->ai_protocol);
        if (listen_fd < 0) {
            continue;
        }
        try {
            set_close_on_exec(listen_fd);
        } catch (...) {
            close_fd(listen_fd);
            continue;
        }
        int one = 1;
        (void)::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (::bind(listen_fd, current->ai_addr, current->ai_addrlen) == 0 &&
            ::listen(listen_fd, 8) == 0) {
            break;
        }
        close_fd(listen_fd);
    }
    ::freeaddrinfo(results);

    if (listen_fd < 0) {
        throw std::runtime_error("listen failed");
    }
    append_log("create_listener ready");
    return listen_fd;
}

void socket_send_all(int fd, std::span<const std::uint8_t> bytes) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto sent = ::send(fd, bytes.data() + offset, bytes.size() - offset, 0);
        if (sent <= 0) {
            throw std::runtime_error("SOCKS5 send failed");
        }
        offset += static_cast<std::size_t>(sent);
    }
}

void socket_recv_exact(int fd, std::span<std::uint8_t> bytes) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto received = ::recv(fd, bytes.data() + offset, bytes.size() - offset, 0);
        if (received <= 0) {
            throw std::runtime_error("SOCKS5 receive failed");
        }
        offset += static_cast<std::size_t>(received);
    }
}

void socks5_connect(int fd, const Endpoint& destination) {
    append_log("socks5_connect " + destination.host + ":" + std::to_string(destination.port));
    const std::array<std::uint8_t, 3> hello{0x05U, 0x01U, 0x00U};
    socket_send_all(fd, hello);

    std::array<std::uint8_t, 2> hello_reply{};
    socket_recv_exact(fd, hello_reply);
    if (hello_reply != std::array<std::uint8_t, 2>{0x05U, 0x00U}) {
        throw std::runtime_error("SOCKS5 proxy rejected anonymous mode");
    }

    if (destination.host.empty() || destination.host.size() > 255U ||
        destination.port == 0U) {
        throw std::invalid_argument("invalid SOCKS5 destination");
    }

    std::vector<std::uint8_t> request;
    request.reserve(7U + destination.host.size());
    request.push_back(0x05U);
    request.push_back(0x01U);
    request.push_back(0x00U);
    request.push_back(0x03U); // Domain name; .onion resolution remains in Tor.
    request.push_back(static_cast<std::uint8_t>(destination.host.size()));
    request.insert(request.end(), destination.host.begin(), destination.host.end());
    request.push_back(static_cast<std::uint8_t>((destination.port >> 8U) & 0xffU));
    request.push_back(static_cast<std::uint8_t>(destination.port & 0xffU));
    socket_send_all(fd, request);

    std::array<std::uint8_t, 4> reply{};
    socket_recv_exact(fd, reply);
    if (reply[0] != 0x05U || reply[1] != 0x00U) {
        throw std::runtime_error("SOCKS5 CONNECT failed");
    }

    std::size_t address_length = 0;
    if (reply[3] == 0x01U) {
        address_length = 4U;
    } else if (reply[3] == 0x04U) {
        address_length = 16U;
    } else if (reply[3] == 0x03U) {
        std::array<std::uint8_t, 1> length{};
        socket_recv_exact(fd, length);
        address_length = length[0];
    } else {
        throw std::runtime_error("invalid SOCKS5 address type");
    }

    std::vector<std::uint8_t> discard(address_length + 2U);
    socket_recv_exact(fd, discard);
}

void harden_context(SSL_CTX* ctx) {
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1) {
        throw_ssl("failed to require TLS 1.3");
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET);
    if (SSL_CTX_set_ciphersuites(
            ctx, "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384") != 1) {
        throw_ssl("failed to set TLS 1.3 cipher suites");
    }
    // Post-quantum hybrid key exchange (specs.txt SS11): harvest-now-
    // decrypt-later applies to key exchange specifically - a passive
    // adversary recording today's TLS sessions decrypts them retroactively
    // once a cryptographically relevant quantum computer exists, and that
    // is unfixable after the fact (unlike a forged signature, which is
    // worthless against a handshake that already completed). X25519MLKEM768
    // is listed FIRST so it is preferred whenever both peers support it;
    // X25519 and P-256 remain as classical fallback for interop with a peer
    // that doesn't. SSL_CTX_set1_groups_list() rejects the ENTIRE list if
    // any single group name is unrecognized by the linked OpenSSL, so this
    // already satisfies "fail loudly rather than silently negotiating
    // classical if the linked library lacks it" - there is no separate
    // opt-in check needed: an OpenSSL genuinely too old to know
    // "X25519MLKEM768" makes this whole function throw via throw_ssl()
    // below, rather than silently falling back to a classical-only list.
    if (SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:X25519:P-256") != 1) {
        throw_ssl("failed to set TLS groups (requires an OpenSSL build providing the "
                  "X25519MLKEM768 hybrid group - see specs.txt SS11)");
    }
}

SSL_CTX* make_client_context() {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) {
        throw_ssl("SSL_CTX_new failed");
    }
    try {
        harden_context(ctx);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        append_log("TLS client context initialized");
        return ctx;
    } catch (...) {
        SSL_CTX_free(ctx);
        throw;
    }
}

SSL_CTX* make_server_context(const ServerTlsIdentity& identity) {
    if (identity.certificate_file.empty() || identity.private_key_file.empty()) {
        throw std::invalid_argument("server certificate and key are required");
    }
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == nullptr) {
        throw_ssl("SSL_CTX_new failed");
    }
    try {
        harden_context(ctx);
        if (SSL_CTX_use_certificate_file(
                ctx, identity.certificate_file.c_str(), SSL_FILETYPE_PEM) != 1) {
            throw_ssl("failed to load server certificate");
        }
        if (SSL_CTX_use_PrivateKey_file(
                ctx, identity.private_key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
            throw_ssl("failed to load server private key");
        }
        if (SSL_CTX_check_private_key(ctx) != 1) {
            throw_ssl("server certificate/private key mismatch");
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        SSL_CTX_set_num_tickets(ctx, 0);
        append_log("TLS server context initialized");
        return ctx;
    } catch (...) {
        SSL_CTX_free(ctx);
        throw;
    }
}

void ssl_write_all(SSL* ssl, std::span<const std::uint8_t> bytes) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        std::size_t written = 0;
        if (SSL_write_ex(ssl, bytes.data() + offset, bytes.size() - offset, &written) != 1) {
            throw_ssl("TLS write failed");
        }
        if (written == 0U) {
            throw std::runtime_error("TLS write returned zero bytes");
        }
        offset += written;
    }
}

void ssl_read_exact(SSL* ssl, std::span<std::uint8_t> bytes) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        std::size_t received = 0;
        if (SSL_read_ex(ssl, bytes.data() + offset, bytes.size() - offset, &received) != 1) {
            throw_ssl("TLS read failed");
        }
        if (received == 0U) {
            throw std::runtime_error("peer closed TLS connection");
        }
        offset += received;
    }
}

std::string normalized_hex(std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for (const char c : value) {
        if (c == ':' || c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            continue;
        }
        if (c >= 'A' && c <= 'F') {
            result.push_back(static_cast<char>(c - 'A' + 'a'));
        } else {
            result.push_back(c);
        }
    }
    return result;
}

} // namespace

SecureChannel::SecureChannel(int socket_fd,
                             SSL_CTX* ctx,
                             SSL* ssl,
                             bool owns_ctx)
    : socket_fd_(socket_fd), ctx_(ctx), ssl_(ssl), owns_ctx_(owns_ctx) {}

SecureChannel::~SecureChannel() { close(); }

SecureChannel::SecureChannel(SecureChannel&& other) noexcept
    : socket_fd_(other.socket_fd_),
      ctx_(other.ctx_),
      ssl_(other.ssl_),
      owns_ctx_(other.owns_ctx_),
      send_sequence_(other.send_sequence_),
      receive_sequence_(other.receive_sequence_) {
    other.socket_fd_ = -1;
    other.ctx_ = nullptr;
    other.ssl_ = nullptr;
    other.owns_ctx_ = true;
}

SecureChannel& SecureChannel::operator=(SecureChannel&& other) noexcept {
    if (this != &other) {
        close();
        socket_fd_ = other.socket_fd_;
        ctx_ = other.ctx_;
        ssl_ = other.ssl_;
        owns_ctx_ = other.owns_ctx_;
        send_sequence_ = other.send_sequence_;
        receive_sequence_ = other.receive_sequence_;
        other.socket_fd_ = -1;
        other.ctx_ = nullptr;
        other.ssl_ = nullptr;
        other.owns_ctx_ = true;
    }
    return *this;
}

SecureChannel SecureChannel::make_client(int socket_fd,
                                          const ClientTlsPolicy& policy) {
     if (normalized_hex(policy.expected_server_sha256).size() != 64U) {
         throw std::invalid_argument("expected_server_sha256 must be 64 hex chars");
     }
 
    SSL_CTX* ctx = make_client_context();
    SSL* ssl = SSL_new(ctx);
    if (ssl == nullptr) {
        SSL_CTX_free(ctx);
        throw_ssl("SSL_new failed");
    }
    
     try {
        append_log("TLS client handshake start");
         if (SSL_set_fd(ssl, socket_fd) != 1) {
             throw_ssl("SSL_set_fd failed");
         }
         if (SSL_connect(ssl) != 1) {
             throw_ssl("TLS client handshake failed");
         }
         verify_server_pin(ssl, policy.expected_server_sha256);
        append_log("TLS client handshake complete");
         return SecureChannel(socket_fd, ctx, ssl, true);
     } catch (...) {
         SSL_free(ssl);
         SSL_CTX_free(ctx);
         throw;
     }
 }

SecureChannel SecureChannel::make_server(int socket_fd,
                                         SSL_CTX* shared_server_ctx) {
    // Bound the TLS handshake itself. Without this, a client can open TCP and
    // never finish SSL_accept(), blocking the listener's accept loop.
    timeval handshake_timeout{};
    handshake_timeout.tv_sec = 10;
    handshake_timeout.tv_usec = 0;
    if (::setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO,
                     &handshake_timeout, sizeof(handshake_timeout)) != 0 ||
        ::setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO,
                     &handshake_timeout, sizeof(handshake_timeout)) != 0) {
        throw std::runtime_error(std::string("failed to set TLS handshake timeout: ") +
                                 std::strerror(errno));
    }

    SSL* ssl = SSL_new(shared_server_ctx);
    if (ssl == nullptr) {
        throw_ssl("SSL_new failed");
    }

    try {
        append_log("TLS server handshake start");
        if (SSL_set_fd(ssl, socket_fd) != 1) {
            throw_ssl("SSL_set_fd failed");
        }
        if (SSL_accept(ssl) != 1) {
            throw_ssl("TLS server handshake failed");
        }
        append_log("TLS server handshake complete");
        return SecureChannel(socket_fd, shared_server_ctx, ssl, false);
    } catch (...) {
        SSL_free(ssl);
        throw;
    }
}

SecureChannel SecureChannel::connect_direct(const Endpoint& endpoint,
                                            const ClientTlsPolicy& policy) {
    int fd = connect_tcp(endpoint);
    try {
        return make_client(fd, policy);
    } catch (...) {
        close_fd(fd);
        throw;
    }
}

SecureChannel SecureChannel::connect_via_socks5(const Endpoint& proxy,
                                                const Endpoint& destination,
                                                const ClientTlsPolicy& policy) {
    int fd = connect_tcp(proxy);
    try {
        socks5_connect(fd, destination);
        return make_client(fd, policy);
    } catch (...) {
        close_fd(fd);
        throw;
    }
}

int connect_raw_tcp(const Endpoint& endpoint) { return connect_tcp(endpoint); }

int connect_raw_via_socks5(const Endpoint& proxy, const Endpoint& destination) {
    int fd = connect_tcp(proxy);
    try {
        socks5_connect(fd, destination);
    } catch (...) {
        close_fd(fd);
        throw;
    }
    return fd;
}

void SecureChannel::verify_server_pin(SSL* ssl, const std::string& expected_hex) {
    append_log("verify_server_pin");
    X509* certificate = SSL_get1_peer_certificate(ssl);
    if (certificate == nullptr) {
        throw std::runtime_error("mediator did not provide a certificate");
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0;
    const int ok = X509_digest(certificate, EVP_sha256(), digest.data(), &length);
    X509_free(certificate);
    if (ok != 1 || length != 32U) {
        throw_ssl("server certificate fingerprint failed");
    }

    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < length; ++i) {
        stream << std::setw(2) << static_cast<unsigned int>(digest[i]);
    }

    if (normalized_hex(stream.str()) != normalized_hex(expected_hex)) {
        throw std::runtime_error("server certificate pin mismatch");
    }
    append_log("verify_server_pin success");
}

void SecureChannel::send_frame(MessageType type,
                               std::span<const std::uint8_t> payload) {
    if (ssl_ == nullptr) {
        throw std::logic_error("channel is closed");
    }
    validate_message_type(type);
    if (payload.size() > kMaxFramePayload) {
        throw std::invalid_argument("frame payload exceeds hard limit");
    }

    std::array<std::uint8_t, 20> header{};
    header[0] = 'T';
    header[1] = 'P';
    header[2] = '2';
    header[3] = 'P';
    header[4] = static_cast<std::uint8_t>((kProtocolVersion >> 8U) & 0xffU);
    header[5] = static_cast<std::uint8_t>(kProtocolVersion & 0xffU);

    const auto type_value = static_cast<std::uint16_t>(type);
    header[6] = static_cast<std::uint8_t>((type_value >> 8U) & 0xffU);
    header[7] = static_cast<std::uint8_t>(type_value & 0xffU);

    for (int i = 0; i < 8; ++i) {
        header[8U + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>((send_sequence_ >> (56 - i * 8)) & 0xffU);
    }

    const auto length = static_cast<std::uint32_t>(payload.size());
    for (int i = 0; i < 4; ++i) {
        header[16U + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>((length >> (24 - i * 8)) & 0xffU);
    }

    ssl_write_all(ssl_, header);
    if (!payload.empty()) {
        ssl_write_all(ssl_, payload);
    }

    if (send_sequence_ == std::numeric_limits<std::uint64_t>::max()) {
        throw std::runtime_error("send sequence exhausted");
    }
    append_log("send_frame type=" + std::to_string(static_cast<int>(type)) +
               " seq=" + std::to_string(send_sequence_));
    ++send_sequence_;
}

Frame SecureChannel::receive_frame() {
    if (ssl_ == nullptr) {
        throw std::logic_error("channel is closed");
    }

    std::array<std::uint8_t, 20> header{};
    ssl_read_exact(ssl_, header);

    if (header[0] != 'T' || header[1] != 'P' ||
        header[2] != '2' || header[3] != 'P') {
        throw std::runtime_error("invalid frame magic");
    }

    const auto version = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(header[4]) << 8U) | header[5]);
    if (version != kProtocolVersion) {
        throw std::runtime_error("unsupported wire version");
    }

    const auto type = static_cast<MessageType>(static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(header[6]) << 8U) | header[7]));
    validate_message_type(type);

    std::uint64_t sequence = 0;
    for (int i = 0; i < 8; ++i) {
        sequence = (sequence << 8U) | header[8U + static_cast<std::size_t>(i)];
    }
    if (sequence != receive_sequence_) {
        throw std::runtime_error("unexpected frame sequence");
    }

    std::uint32_t length = 0;
    for (int i = 0; i < 4; ++i) {
        length = (length << 8U) | header[16U + static_cast<std::size_t>(i)];
    }
    if (length > kMaxFramePayload) {
        throw std::runtime_error("incoming frame exceeds hard limit");
    }

    Frame frame;
    frame.type = type;
    frame.sequence = sequence;
    frame.payload.resize(length);
    if (length != 0U) {
        ssl_read_exact(ssl_, frame.payload);
    }

    if (receive_sequence_ == std::numeric_limits<std::uint64_t>::max()) {
        throw std::runtime_error("receive sequence exhausted");
    }
    append_log("receive_frame type=" + std::to_string(static_cast<int>(type)) +
               " seq=" + std::to_string(receive_sequence_));
    ++receive_sequence_;
    return frame;
}

void SecureChannel::set_timeout(std::uint32_t timeout_seconds) {
    if (socket_fd_ < 0 || timeout_seconds == 0U) {
        throw std::invalid_argument("invalid socket timeout");
    }

    timeval timeout{};
    timeout.tv_sec = static_cast<time_t>(timeout_seconds);
    timeout.tv_usec = 0;
    if (::setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        ::setsockopt(socket_fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        throw std::runtime_error(std::string("failed to set socket timeout: ") +
                                 std::strerror(errno));
    }
    append_log("set_timeout " + std::to_string(timeout_seconds));
}


bool SecureChannel::has_pending_input() const noexcept {
    return ssl_ != nullptr && SSL_pending(ssl_) > 0;
}

TlsSessionInfo SecureChannel::session_info() const {
    TlsSessionInfo info;
    if (ssl_ == nullptr) {
        return info;
    }

    if (const char* version = SSL_get_version(ssl_); version != nullptr) {
        info.protocol_version = version;
    }
    if (const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_); cipher != nullptr) {
        if (const char* name = SSL_CIPHER_get_name(cipher); name != nullptr) {
            info.cipher_suite = name;
        }
    }
    // Requires OpenSSL 3.2+ (this project already requires 3.5+ for the
    // X25519MLKEM768 group itself - see harden_context()); reports the
    // classical fallback name just as accurately as the hybrid PQ one, so
    // this is exactly how an operator would notice a peer that didn't
    // support the hybrid group and silently fell back.
    if (const char* group = SSL_get0_group_name(ssl_); group != nullptr) {
        info.negotiated_group = group;
    }

    X509* certificate = SSL_get1_peer_certificate(ssl_);
    if (certificate != nullptr) {
        std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
        unsigned int length = 0;
        if (X509_digest(certificate, EVP_sha256(), digest.data(), &length) == 1) {
            std::ostringstream stream;
            stream << std::hex << std::setfill('0');
            for (unsigned int i = 0; i < length; ++i) {
                stream << std::setw(2) << static_cast<unsigned int>(digest[i]);
            }
            info.peer_certificate_sha256_hex = stream.str();
        }

        int digest_nid = 0;
        int signature_nid = 0;
        int security_bits = 0;
        std::uint32_t signature_flags = 0;
        if (X509_get_signature_info(certificate, &digest_nid, &signature_nid,
                                    &security_bits, &signature_flags) == 1) {
            info.peer_certificate_signature_algorithm = OBJ_nid2ln(signature_nid);
            // A pure post-quantum signature (ML-DSA, SLH-DSA) has no
            // separate digest step, unlike RSA/ECDSA's hash-then-sign - this
            // is itself informative, not just a formatting detail.
            if (digest_nid != NID_undef) {
                info.peer_certificate_signature_algorithm +=
                    std::string(" + ") + OBJ_nid2sn(digest_nid);
            }
        }
        X509_free(certificate);
    }

    return info;
}

void SecureChannel::close() {
    if (ssl_ != nullptr) {
        (void)SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (ctx_ != nullptr && owns_ctx_) {
        SSL_CTX_free(ctx_);
    }
    ctx_ = nullptr;
    close_fd(socket_fd_);
    append_log("secure channel closed");
}

SecureListener::SecureListener(const Endpoint& bind_endpoint,
                               const ServerTlsIdentity& identity)
    : listen_fd_(create_listener(bind_endpoint)),
      ctx_(make_server_context(identity)) {}

SecureListener::~SecureListener() {
    close_fd(listen_fd_);
    if (ctx_ != nullptr) {
        SSL_CTX_free(ctx_);
        ctx_ = nullptr;
    }
}

int SecureListener::accept_raw() {
    if (listen_fd_ < 0) {
        throw std::logic_error("listener is closed");
    }

    int fd = -1;
    do {
        fd = ::accept(listen_fd_, nullptr, nullptr);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0) {
        throw std::runtime_error(std::string("accept failed: ") + std::strerror(errno));
    }

    set_close_on_exec(fd);
    append_log("accept incoming client");
    return fd;
}

SecureChannel SecureListener::complete_handshake(int socket_fd) const {
    if (ctx_ == nullptr) {
        close_fd(socket_fd);
        throw std::logic_error("listener is closed");
    }
    try {
        return SecureChannel::make_server(socket_fd, ctx_);
    } catch (...) {
        close_fd(socket_fd);
        throw;
    }
}

} // namespace tradep2p
