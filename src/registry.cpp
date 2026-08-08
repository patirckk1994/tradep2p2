#include "tradep2p/registry.hpp"

#include "tradep2p/protocol.hpp"

#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace tradep2p {
namespace {

// Bounds how many TLS handshakes may be in flight at once. Handshakes run
// concurrently, one per accepted connection, rather than serialized on the
// accept loop; without this bound a burst of bare TCP connections that never
// send a ClientHello could still spawn unbounded threads.
constexpr std::size_t kMaxPendingHandshakes = 64U;

struct RegistryEntry {
    RegistryNode node;
    std::chrono::steady_clock::time_point expires_at;
};

std::string registry_key(const RegistryNode& node) {
    return node.host + ":" + std::to_string(node.port);
}

std::string safe_reason(std::string text) {
    if (text.empty()) {
        text = "registry request rejected";
    }
    if (text.size() > kMaxReasonLength) {
        text.resize(kMaxReasonLength);
    }
    for (char& c : text) {
        const auto value = static_cast<unsigned char>(c);
        if (value < 0x20U || value > 0x7eU) {
            c = '?';
        }
    }
    return text;
}

std::string json_escape(const std::string& text) {
    std::ostringstream out;
    for (const unsigned char ch : text) {
        switch (ch) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (ch < 0x20U) {
                out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<unsigned int>(ch) << std::dec;
            } else {
                out << static_cast<char>(ch);
            }
        }
    }
    return out.str();
}

std::string configured_registry_state_file() {
    const char* value = std::getenv("TRADEP2P_REGISTRY_STATE_FILE");
    return value == nullptr ? std::string{} : std::string(value);
}

} // namespace

class RegistryServer::Impl {
public:
    Impl(Endpoint bind_endpoint, ServerTlsIdentity identity)
        : bind_endpoint_(std::move(bind_endpoint)),
          identity_(std::move(identity)),
          state_file_(configured_registry_state_file()) {}

    ~Impl() {
        snapshot_running_.store(false);
        if (snapshot_thread_.joinable()) {
            snapshot_thread_.join();
        }
    }

    void run() {
        SecureListener listener(bind_endpoint_, identity_);
        std::cout << "TradeP2P registry listening on " << bind_endpoint_.host << ':'
                  << bind_endpoint_.port << '\n';
        std::cout << "Directory only: registrations are unauthenticated and expire after "
                  << kRegistryTtlSeconds << " seconds.\n";

        if (!state_file_.empty()) {
            snapshot_running_.store(true);
            snapshot_thread_ = std::thread([this] { snapshot_loop(); });
            std::cout << "Local registry state snapshot: " << state_file_ << '\n';
        }

        for (;;) {
            int fd = -1;
            try {
                fd = listener.accept_raw();
            } catch (const std::exception& error) {
                // A bare accept() failure; it does not block on a slow or
                // hostile peer, so it cannot itself starve other connections
                // the way the old combined accept-plus-handshake call could.
                std::cerr << "accept failed: " << error.what() << '\n';
                continue;
            }

            if (pending_handshakes_.fetch_add(1U) >= kMaxPendingHandshakes) {
                pending_handshakes_.fetch_sub(1U);
                ::close(fd);
                continue;
            }

            std::thread([this, &listener, fd]() {
                struct HandshakeGuard {
                    std::atomic<std::size_t>& counter;
                    ~HandshakeGuard() { counter.fetch_sub(1U); }
                } guard{pending_handshakes_};

                // The handshake (and its up-to-10-second timeout) now runs
                // here, on a per-connection thread, so one stalled peer can
                // no longer block the accept loop from servicing anyone else.
                SecureChannel channel;
                try {
                    channel = listener.complete_handshake(fd);
                } catch (const std::exception& error) {
                    std::cerr << "rejected registry connection: "
                              << error.what() << '\n';
                    return;
                }
                handle_connection(std::move(channel));
            }).detach();
        }
    }

private:
    void remove_expired_locked(std::chrono::steady_clock::time_point now) {
        for (auto it = entries_.begin(); it != entries_.end();) {
            if (it->second.expires_at <= now) {
                it = entries_.erase(it);
            } else {
                ++it;
            }
        }
    }

    void handle_connection(SecureChannel channel) {
        try {
            channel.set_timeout(15U);
            const Frame frame = channel.receive_frame();
            if (frame.type == MessageType::RegistryRegister) {
                const auto message = decode_registry_register(frame.payload);
                register_node(message.node);
                channel.send_frame(
                    MessageType::RegistryRegistered,
                    encode_registry_registered(
                        RegistryRegisteredMessage{kRegistryTtlSeconds}));
            } else if (frame.type == MessageType::RegistryList) {
                if (!frame.payload.empty()) {
                    throw std::invalid_argument("registry list request must be empty");
                }
                channel.send_frame(
                    MessageType::RegistryNodes,
                    encode_registry_nodes(snapshot()));
            } else {
                throw std::invalid_argument("unsupported registry request");
            }
        } catch (const std::exception& error) {
            try {
                channel.send_frame(
                    MessageType::Error,
                    encode_error(ErrorMessage{safe_reason(error.what())}));
            } catch (...) {
            }
        }
        channel.close();
    }

    void register_node(RegistryNode node) {
        validate_registry_node(node, false);
        node.remaining_ttl_seconds = 0U;
        const auto now = std::chrono::steady_clock::now();
        std::scoped_lock lock(mutex_);
        remove_expired_locked(now);
        const auto key = registry_key(node);
        const auto existing = entries_.find(key);
        if (existing != entries_.end() &&
            existing->second.node.certificate_pin != node.certificate_pin) {
            // This is not full registry authentication, but it prevents an
            // unauthenticated refresh from silently replacing the pin of a
            // live endpoint. Key rotation must wait for expiry or use a future
            // signed-registration protocol.
            throw std::runtime_error(
                "endpoint is already registered with a different certificate pin");
        }
        if (existing == entries_.end() && entries_.size() >= kMaxRegistryNodes) {
            throw std::runtime_error("registry is full");
        }
        entries_[key] = RegistryEntry{
            std::move(node), now + std::chrono::seconds(kRegistryTtlSeconds)};
    }

    RegistryNodesMessage snapshot() {
        const auto now = std::chrono::steady_clock::now();
        RegistryNodesMessage result;
        {
            std::scoped_lock lock(mutex_);
            remove_expired_locked(now);
            result.nodes.reserve(entries_.size());
            for (const auto& [key, entry] : entries_) {
                (void)key;
                RegistryNode node = entry.node;
                const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
                    entry.expires_at - now);
                node.remaining_ttl_seconds = static_cast<std::uint32_t>(
                    std::max<std::int64_t>(1, remaining.count()));
                result.nodes.push_back(std::move(node));
            }
        }
        std::sort(result.nodes.begin(), result.nodes.end(),
                  [](const RegistryNode& left, const RegistryNode& right) {
                      if (left.host != right.host) {
                          return left.host < right.host;
                      }
                      return left.port < right.port;
                  });
        return result;
    }

private:
    void snapshot_loop() {
        while (snapshot_running_.load()) {
            try {
                write_state_snapshot();
            } catch (const std::exception& error) {
                std::cerr << "registry snapshot failed: " << error.what() << '\n';
            }
            for (int tick = 0; tick < 10 && snapshot_running_.load(); ++tick) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }

    void write_state_snapshot() {
        const RegistryNodesMessage nodes = snapshot();

        const auto now = std::chrono::system_clock::now();
        const std::time_t timestamp = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
        std::ostringstream generated;
        if (::localtime_r(&timestamp, &tm) != nullptr) {
            generated << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        } else {
            generated << "time-unavailable";
        }

        std::ostringstream json;
        json << "{\"enabled\":true,\"available\":true"
             << ",\"generated_at\":\"" << json_escape(generated.str()) << "\""
             << ",\"bind\":\""
             << json_escape(bind_endpoint_.host + ":" +
                            std::to_string(bind_endpoint_.port))
             << "\",\"node_count\":" << nodes.nodes.size()
             << ",\"nodes\":[";
        for (std::size_t index = 0; index < nodes.nodes.size(); ++index) {
            if (index != 0U) {
                json << ',';
            }
            const auto& node = nodes.nodes[index];
            json << "{\"host\":\"" << json_escape(node.host)
                 << "\",\"port\":" << node.port
                 << ",\"certificate_pin\":\""
                 << json_escape(certificate_pin_to_hex(node.certificate_pin))
                 << "\",\"remaining_ttl_seconds\":" << node.remaining_ttl_seconds
                 << '}';
        }
        json << "]}";

        const std::filesystem::path path(state_file_);
        if (path.has_parent_path()) {
            std::filesystem::create_directories(path.parent_path());
        }
        const std::filesystem::path temporary =
            path.string() + ".tmp." + std::to_string(::getpid());
        {
            std::ofstream output(temporary, std::ios::trunc);
            if (!output.is_open()) {
                throw std::runtime_error("cannot open registry snapshot temporary file");
            }
            output << json.str() << '\n';
            if (!output.good()) {
                throw std::runtime_error("cannot write registry snapshot");
            }
        }
        std::error_code error;
        std::filesystem::rename(temporary, path, error);
        if (error) {
            std::filesystem::remove(path, error);
            error.clear();
            std::filesystem::rename(temporary, path, error);
            if (error) {
                throw std::runtime_error("cannot replace registry snapshot: " +
                                         error.message());
            }
        }
    }

    Endpoint bind_endpoint_;
    ServerTlsIdentity identity_;
    std::string state_file_;
    std::atomic<bool> snapshot_running_{false};
    std::thread snapshot_thread_;
    std::atomic<std::size_t> pending_handshakes_{0U};
    std::mutex mutex_;
    std::unordered_map<std::string, RegistryEntry> entries_;
};

RegistryServer::RegistryServer(Endpoint bind_endpoint, ServerTlsIdentity identity)
    : impl_(std::make_unique<Impl>(std::move(bind_endpoint), std::move(identity))) {}

RegistryServer::~RegistryServer() = default;

void RegistryServer::run() { impl_->run(); }

void register_node_once(const Endpoint& registry,
                        const ClientTlsPolicy& registry_tls,
                        const RegistryNode& node) {
    validate_registry_node(node, false);
    auto channel = SecureChannel::connect_direct(registry, registry_tls);
    channel.set_timeout(15U);
    channel.send_frame(
        MessageType::RegistryRegister,
        encode_registry_register(RegistryRegisterMessage{node}));
    const Frame reply = channel.receive_frame();
    if (reply.type == MessageType::Error) {
        throw std::runtime_error(decode_error(reply.payload).reason);
    }
    if (reply.type != MessageType::RegistryRegistered) {
        throw std::runtime_error("registry returned unexpected response");
    }
    (void)decode_registry_registered(reply.payload);
}

namespace {

RegistryNodesMessage list_registered_nodes_over(SecureChannel channel) {
    channel.set_timeout(15U);
    channel.send_frame(MessageType::RegistryList, {});
    const Frame reply = channel.receive_frame();
    if (reply.type == MessageType::Error) {
        throw std::runtime_error(decode_error(reply.payload).reason);
    }
    if (reply.type != MessageType::RegistryNodes) {
        throw std::runtime_error("registry returned unexpected response");
    }
    return decode_registry_nodes(reply.payload);
}

} // namespace

RegistryNodesMessage list_registered_nodes(
    const Endpoint& registry,
    const ClientTlsPolicy& registry_tls) {
    return list_registered_nodes_over(SecureChannel::connect_direct(registry, registry_tls));
}

RegistryNodesMessage list_registered_nodes_via_socks5(
    const Endpoint& proxy,
    const Endpoint& registry,
    const ClientTlsPolicy& registry_tls) {
    return list_registered_nodes_over(
        SecureChannel::connect_via_socks5(proxy, registry, registry_tls));
}

} // namespace tradep2p
