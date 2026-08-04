#include "tradep2p/registry.hpp"

#include "tradep2p/protocol.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace tradep2p {
namespace {

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

} // namespace

class RegistryServer::Impl {
public:
    Impl(Endpoint bind_endpoint, ServerTlsIdentity identity)
        : bind_endpoint_(std::move(bind_endpoint)), identity_(std::move(identity)) {}

    void run() {
        SecureListener listener(bind_endpoint_, identity_);
        std::cout << "TradeP2P registry listening on " << bind_endpoint_.host << ':'
                  << bind_endpoint_.port << '\n';
        std::cout << "Directory only: registrations are unauthenticated and expire after "
                  << kRegistryTtlSeconds << " seconds.\n";

        for (;;) {
            SecureChannel channel;
            try {
                channel = listener.accept();
            } catch (const std::exception& error) {
                // Garbage or a timed-out TLS handshake must not terminate the
                // registry process.
                std::cerr << "rejected registry connection: "
                          << error.what() << '\n';
                continue;
            }
            std::thread([this, channel = std::move(channel)]() mutable {
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

    Endpoint bind_endpoint_;
    ServerTlsIdentity identity_;
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

RegistryNodesMessage list_registered_nodes(
    const Endpoint& registry,
    const ClientTlsPolicy& registry_tls) {
    auto channel = SecureChannel::connect_direct(registry, registry_tls);
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

} // namespace tradep2p
