#include "tradep2p/registry.hpp"

#include "tradep2p/protocol.hpp"

#include <openssl/crypto.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <optional>
#include <chrono>
#include <cstdlib>
#include <cstring>
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

// A registration is invisible to ordinary RegistryList callers (and to the
// public state-snapshot JSON) until an admin explicitly approves it over the
// loopback admin channel below - see Impl::admin_control_loop(). This is
// enforced by filtering in snapshot(), not by a separate wire message, so
// the public RegistryList/RegistryRegister framing is unchanged for every
// existing mediator operator and client.
enum class RegistryStatus { Pending, Approved };

struct RegistryEntry {
    RegistryNode node;
    std::chrono::steady_clock::time_point expires_at;
    RegistryStatus status;
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

// Gates the live admin control channel (see Impl::admin_control_loop()
// below), mirroring lobby.cpp's configured_admin_token()/admin_control_loop
// exactly. Unset (the default) disables the channel entirely - no listening
// socket is even opened - rather than opening on a fixed port with a
// guessable or empty token.
std::string configured_registry_admin_token() {
    const char* value = std::getenv("TRADEP2P_REGISTRY_ADMIN_TOKEN");
    return value == nullptr ? std::string{} : std::string(value);
}

std::uint16_t configured_registry_admin_port() {
    const char* value = std::getenv("TRADEP2P_REGISTRY_ADMIN_PORT");
    if (value == nullptr || *value == '\0') {
        return 7445U; // one past the mediator admin channel's default 7444
    }
    const std::string text(value);
    std::uint16_t port = 0U;
    const auto [ptr, error] = std::from_chars(text.data(), text.data() + text.size(), port, 10);
    if (error != std::errc{} || ptr != text.data() + text.size() || port == 0U) {
        throw std::invalid_argument("invalid TRADEP2P_REGISTRY_ADMIN_PORT");
    }
    return port;
}

// A peer registry this registry pulls from - see Impl::gossip_loop().
// Single-hop only: this registry re-shares only its own directly-registered,
// approved entries with ITS OWN callers, never anything it learned from a
// peer via this mechanism - see gossip_entries_'s comment for why.
// Choosing to configure a peer at all IS the trust decision; auto_trust
// only controls how much of that trust extends to what the peer vouches
// for.
struct RegistryPeer {
    Endpoint registry;
    ClientTlsPolicy registry_tls;
    // Set for a peer reachable only over Tor (host ends in ".onion") -
    // reuses list_registered_nodes_via_socks5() instead of the direct
    // variant, via the single shared TRADEP2P_REGISTRY_GOSSIP_PROXY.
    std::optional<Endpoint> proxy;
    bool auto_trust{false};
};

std::uint16_t parse_gossip_port(const std::string& value) {
    std::size_t used = 0U;
    const auto parsed = std::stoul(value, &used, 10);
    if (used != value.size() || parsed == 0U || parsed > 65535U) {
        throw std::invalid_argument("invalid TRADEP2P_REGISTRY_GOSSIP_PEERS port");
    }
    return static_cast<std::uint16_t>(parsed);
}

Endpoint parse_gossip_endpoint(const std::string& text) {
    const auto separator = text.rfind(':');
    if (separator == std::string::npos || separator == 0U || separator + 1U >= text.size()) {
        throw std::invalid_argument("TRADEP2P_REGISTRY_GOSSIP_PEERS entry must be host:port|pin[|trust]");
    }
    return Endpoint{text.substr(0U, separator), parse_gossip_port(text.substr(separator + 1U))};
}

// Format: "host:port|pinhex|trust,host:port|pinhex|trust,..." - "trust"
// literally "1" means auto_trust (matches this project's existing "1" for
// true convention, e.g. TRADEP2P_FEE_REQUIRE_CONFIRMATION), anything else
// (including an omitted third field) means require-local-approval, the
// safer default. Any peer whose host ends in ".onion" is reached through
// TRADEP2P_REGISTRY_GOSSIP_PROXY (one shared proxy for every onion peer,
// same "single shared proxy" convention setup_mediator.sh's own
// --registry-proxy already established) - unset while an onion peer is
// configured fails loudly at startup rather than silently trying (and
// failing) a direct connection to an address that can never resolve.
std::vector<RegistryPeer> configured_registry_gossip_peers() {
    const char* peers_value = std::getenv("TRADEP2P_REGISTRY_GOSSIP_PEERS");
    if (peers_value == nullptr || *peers_value == '\0') {
        return {};
    }
    std::optional<Endpoint> shared_proxy;
    if (const char* proxy_value = std::getenv("TRADEP2P_REGISTRY_GOSSIP_PROXY");
        proxy_value != nullptr && *proxy_value != '\0') {
        shared_proxy = parse_gossip_endpoint(proxy_value);
    }

    std::vector<RegistryPeer> peers;
    std::string remaining(peers_value);
    std::size_t start = 0U;
    while (start <= remaining.size()) {
        const auto comma = remaining.find(',', start);
        const std::string entry = remaining.substr(
            start, comma == std::string::npos ? std::string::npos : comma - start);
        const auto first_bar = entry.find('|');
        if (first_bar == std::string::npos) {
            throw std::invalid_argument(
                "TRADEP2P_REGISTRY_GOSSIP_PEERS entry must be host:port|pin[|trust]");
        }
        const auto second_bar = entry.find('|', first_bar + 1U);
        const std::string endpoint_text = entry.substr(0U, first_bar);
        const std::string pin_text = second_bar == std::string::npos
                                         ? entry.substr(first_bar + 1U)
                                         : entry.substr(first_bar + 1U, second_bar - first_bar - 1U);
        const std::string trust_text =
            second_bar == std::string::npos ? std::string{} : entry.substr(second_bar + 1U);

        RegistryPeer peer;
        peer.registry = parse_gossip_endpoint(endpoint_text);
        peer.registry_tls = ClientTlsPolicy{pin_text};
        peer.auto_trust = trust_text == "1";
        if (peer.registry.host.size() >= 6U &&
            peer.registry.host.compare(peer.registry.host.size() - 6U, 6U, ".onion") == 0) {
            if (!shared_proxy.has_value()) {
                throw std::invalid_argument(
                    "TRADEP2P_REGISTRY_GOSSIP_PEERS names an .onion peer but "
                    "TRADEP2P_REGISTRY_GOSSIP_PROXY is unset");
            }
            peer.proxy = shared_proxy;
        }
        peers.push_back(std::move(peer));

        if (comma == std::string::npos) {
            break;
        }
        start = comma + 1U;
    }
    return peers;
}

} // namespace

class RegistryServer::Impl {
public:
    Impl(Endpoint bind_endpoint, ServerTlsIdentity identity)
        : bind_endpoint_(std::move(bind_endpoint)),
          identity_(std::move(identity)),
          state_file_(configured_registry_state_file()),
          admin_token_(configured_registry_admin_token()),
          admin_port_(configured_registry_admin_port()),
          gossip_peers_(configured_registry_gossip_peers()) {}

    ~Impl() {
        snapshot_running_.store(false);
        if (snapshot_thread_.joinable()) {
            snapshot_thread_.join();
        }
        gossip_running_.store(false);
        if (gossip_thread_.joinable()) {
            gossip_thread_.join();
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

        if (!admin_token_.empty()) {
            std::thread([this] { admin_control_loop(); }).detach();
            std::cout << "Registry admin control channel on 127.0.0.1:" << admin_port_ << '\n';
        } else {
            std::cout << "New registrations are Pending until approved: set "
                         "TRADEP2P_REGISTRY_ADMIN_TOKEN to enable the admin control "
                         "channel, otherwise nothing can ever be approved.\n";
        }

        if (!gossip_peers_.empty()) {
            gossip_running_.store(true);
            gossip_thread_ = std::thread([this] { gossip_loop(); });
            std::cout << "Gossiping with " << gossip_peers_.size()
                      << " peer registr" << (gossip_peers_.size() == 1U ? "y" : "ies")
                      << " (single-hop, own direct+approved entries only)\n";
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
    static void remove_expired_from_locked(std::unordered_map<std::string, RegistryEntry>& map,
                                           std::chrono::steady_clock::time_point now) {
        for (auto it = map.begin(); it != map.end();) {
            if (it->second.expires_at <= now) {
                it = map.erase(it);
            } else {
                ++it;
            }
        }
    }

    void remove_expired_locked(std::chrono::steady_clock::time_point now) {
        remove_expired_from_locked(entries_, now);
        remove_expired_from_locked(gossip_entries_, now);
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
        // A heartbeat refresh from an already-known key preserves whatever
        // approval status it already has - only a brand-new key starts
        // Pending. Otherwise every ~60-second re-registration (main.cpp's
        // run_registry_heartbeat) would silently revert an approved mediator
        // back to invisible.
        const RegistryStatus status =
            existing != entries_.end() ? existing->second.status : RegistryStatus::Pending;
        entries_[key] = RegistryEntry{
            std::move(node), now + std::chrono::seconds(kRegistryTtlSeconds), status};
    }

    RegistryNodesMessage snapshot() {
        const auto now = std::chrono::steady_clock::now();
        RegistryNodesMessage result;
        {
            std::scoped_lock lock(mutex_);
            remove_expired_locked(now);
            result.nodes.reserve(entries_.size() + gossip_entries_.size());
            const auto append_approved = [&](const std::unordered_map<std::string, RegistryEntry>& map) {
                for (const auto& [key, entry] : map) {
                    (void)key;
                    // Pending entries are invisible to every ordinary caller
                    // (RegistryList responses and the public state-snapshot
                    // JSON both go through this function) until approved -
                    // either over the loopback admin channel
                    // (admin_control_loop()) for a direct registration, or
                    // an auto_trust peer's own approval for a gossip-learned
                    // one (gossip_loop()).
                    if (entry.status != RegistryStatus::Approved) {
                        continue;
                    }
                    RegistryNode node = entry.node;
                    const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
                        entry.expires_at - now);
                    node.remaining_ttl_seconds = static_cast<std::uint32_t>(
                        std::max<std::int64_t>(1, remaining.count()));
                    result.nodes.push_back(std::move(node));
                }
            };
            append_approved(entries_);
            append_approved(gossip_entries_);
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

    // Loopback-only moderation channel, structurally copied from
    // lobby.cpp's Impl::admin_control_loop()/handle_admin_connection() - a
    // shared token gates a simple "COMMAND token args...\n" line protocol,
    // one line in, one line out, connection closed. Deliberately not part of
    // the public TLS-facing registry protocol: RegistryList/RegistryRegister
    // framing is unchanged for every existing mediator operator and client,
    // and admin capability never touches the port reachable over Tor.
    void admin_control_loop() {
        const int listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) {
            std::cerr << "registry admin control: socket() failed\n";
            return;
        }
        const int reuse = 1;
        ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(admin_port_);
        if (::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) {
            std::cerr << "registry admin control: inet_pton failed\n";
            ::close(listen_fd);
            return;
        }
        if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            std::cerr << "registry admin control: bind failed on 127.0.0.1:" << admin_port_
                      << " (" << std::strerror(errno) << ")\n";
            ::close(listen_fd);
            return;
        }
        if (::listen(listen_fd, 8) != 0) {
            std::cerr << "registry admin control: listen failed\n";
            ::close(listen_fd);
            return;
        }

        for (;;) {
            const int client_fd = ::accept(listen_fd, nullptr, nullptr);
            if (client_fd < 0) {
                continue;
            }
            timeval io_timeout{5, 0};
            ::setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &io_timeout, sizeof(io_timeout));
            ::setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &io_timeout, sizeof(io_timeout));
            try {
                handle_admin_connection(client_fd);
            } catch (const std::exception& error) {
                std::cerr << "registry admin control: " << error.what() << '\n';
            }
            ::close(client_fd);
        }
    }

    static void send_admin_line(int fd, const std::string& line) {
        const std::string framed = line + "\n";
        ::send(fd, framed.data(), framed.size(), 0);
    }

    void handle_admin_connection(int fd) {
        std::string line;
        char buffer[512];
        for (;;) {
            const ssize_t received = ::recv(fd, buffer, sizeof(buffer), 0);
            if (received <= 0) {
                return;
            }
            line.append(buffer, static_cast<std::size_t>(received));
            if (line.find('\n') != std::string::npos || line.size() > 4096U) {
                break;
            }
        }
        if (const auto newline = line.find('\n'); newline != std::string::npos) {
            line.resize(newline);
        }
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        std::istringstream stream(line);
        std::string command;
        std::string token;
        stream >> command >> token;

        if (admin_token_.empty() || token.size() != admin_token_.size() ||
            CRYPTO_memcmp(token.data(), admin_token_.data(), token.size()) != 0) {
            send_admin_line(fd, "ERR unauthorized");
            return;
        }

        if (command == "LISTPENDING") {
            std::string listing;
            {
                std::scoped_lock lock(mutex_);
                remove_expired_locked(std::chrono::steady_clock::now());
                const auto append_pending =
                    [&](const std::unordered_map<std::string, RegistryEntry>& map) {
                        for (const auto& [key, entry] : map) {
                            if (entry.status != RegistryStatus::Pending) {
                                continue;
                            }
                            if (!listing.empty()) {
                                listing += ',';
                            }
                            // Three fields always, even when source is empty
                            // (a direct registration) - a consistent shape
                            // is easier for a caller (e.g. the registry
                            // dashboard) to parse than one that sometimes
                            // has two fields and sometimes three.
                            listing += key + '|' + certificate_pin_to_hex(entry.node.certificate_pin) +
                                      '|' + entry.node.source_registry;
                        }
                    };
                append_pending(entries_);
                append_pending(gossip_entries_);
            }
            send_admin_line(fd, listing.empty() ? "OK NONE" : "OK " + listing);
            return;
        }

        if (command == "APPROVE" || command == "REJECT") {
            std::string host;
            std::string port_text;
            stream >> host >> port_text;
            std::uint16_t port = 0U;
            const auto [ptr, error] =
                std::from_chars(port_text.data(), port_text.data() + port_text.size(), port, 10);
            if (host.empty() || error != std::errc{} ||
                ptr != port_text.data() + port_text.size()) {
                send_admin_line(fd, "ERR invalid host/port");
                return;
            }
            const std::string key = host + ":" + std::to_string(port);
            std::scoped_lock lock(mutex_);
            auto existing = entries_.find(key);
            std::unordered_map<std::string, RegistryEntry>* owning_map = &entries_;
            if (existing == entries_.end()) {
                existing = gossip_entries_.find(key);
                owning_map = &gossip_entries_;
            }
            if (existing == owning_map->end()) {
                send_admin_line(fd, "ERR no such registration");
                return;
            }
            if (command == "APPROVE") {
                existing->second.status = RegistryStatus::Approved;
            } else {
                owning_map->erase(existing);
            }
            send_admin_line(fd, "OK");
            return;
        }

        send_admin_line(fd, "ERR unknown command");
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

    // Single-hop registry federation: pulls each configured peer's own
    // PUBLIC listing (RegistryList/RegistryNodes - the exact same request
    // the `nodes`/`nodes-tor` CLI commands already make, nothing new on
    // the wire) and caches what comes back in gossip_entries_, separate
    // from and bounded independently of this registry's own entries_ (see
    // kMaxGossipCachedNodes's comment in protocol.hpp - gossip can never
    // crowd out an operator's own direct-registration capacity). Never
    // re-shares a gossip-learned entry with ITS OWN peers - only entries_
    // (this registry's own direct, approved registrations) ever go out
    // over the wire to a peer's RegistryList caller, so information can
    // travel at most one hop from wherever it was first registered.
    void gossip_loop() {
        while (gossip_running_.load()) {
            for (const auto& peer : gossip_peers_) {
                if (!gossip_running_.load()) {
                    break;
                }
                try {
                    const RegistryNodesMessage pulled =
                        peer.proxy.has_value()
                            ? list_registered_nodes_via_socks5(*peer.proxy, peer.registry,
                                                               peer.registry_tls)
                            : list_registered_nodes(peer.registry, peer.registry_tls);
                    const std::string peer_key =
                        peer.registry.host + ":" + std::to_string(peer.registry.port);
                    const auto now = std::chrono::steady_clock::now();
                    std::scoped_lock lock(mutex_);
                    for (RegistryNode node : pulled.nodes) {
                        node.source_registry = peer_key;
                        const std::string key = registry_key(node);
                        const auto existing = gossip_entries_.find(key);
                        // Same "a refresh preserves whatever approval status
                        // it already has" reasoning as register_node() below -
                        // otherwise every ~60s pull would silently revert a
                        // manually-approved (non-auto-trust) entry back to
                        // Pending, or flip an auto-trusted one that a peer
                        // later stopped trusting mid-cycle in a confusing way.
                        const RegistryStatus status =
                            existing != gossip_entries_.end()
                                ? existing->second.status
                                : (peer.auto_trust ? RegistryStatus::Approved
                                                   : RegistryStatus::Pending);
                        if (existing == gossip_entries_.end() &&
                            gossip_entries_.size() >= kMaxGossipCachedNodes) {
                            evict_soonest_expiring_gossip_entry_locked();
                        }
                        const auto ttl = std::chrono::seconds(std::max<std::uint32_t>(
                            1U, std::min(node.remaining_ttl_seconds, kRegistryTtlSeconds)));
                        gossip_entries_[key] = RegistryEntry{std::move(node), now + ttl, status};
                    }
                } catch (const std::exception& error) {
                    std::cerr << "gossip pull from " << peer.registry.host << ':'
                              << peer.registry.port << " failed: " << error.what() << '\n';
                    // Deliberately no special handling beyond logging - a
                    // peer that stays unreachable just has its previously
                    // cached entries expire on their own TTL, same as any
                    // other stale registration.
                }
            }
            for (int tick = 0; tick < 600 && gossip_running_.load(); ++tick) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }

    // Only called with mutex_ already held and gossip_entries_ confirmed at
    // capacity. A linear scan is fine at kMaxGossipCachedNodes's size - no
    // need for a real priority structure at this bound.
    void evict_soonest_expiring_gossip_entry_locked() {
        auto soonest = gossip_entries_.begin();
        for (auto it = gossip_entries_.begin(); it != gossip_entries_.end(); ++it) {
            if (it->second.expires_at < soonest->second.expires_at) {
                soonest = it;
            }
        }
        gossip_entries_.erase(soonest);
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
                 << ",\"source_registry\":\"" << json_escape(node.source_registry) << "\""
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
    // Gates admin_control_loop() - see configured_registry_admin_token()'s
    // comment. Read once at construction, never mutated afterward, so no
    // lock is needed to read it from the admin thread.
    std::string admin_token_;
    std::uint16_t admin_port_;
    std::mutex mutex_;
    std::unordered_map<std::string, RegistryEntry> entries_;
    // Configured once at construction, never mutated afterward - read from
    // gossip_loop() with no lock needed, same reasoning as admin_token_
    // above. Empty means gossip is off entirely - no client connections to
    // any peer are ever attempted.
    std::vector<RegistryPeer> gossip_peers_;
    std::atomic<bool> gossip_running_{false};
    std::thread gossip_thread_;
    // Single-hop gossip-learned cache - see gossip_loop()'s file comment.
    // Bounded independently of entries_ (kMaxGossipCachedNodes, distinct
    // from kMaxRegistryNodes) so peering can never crowd out an operator's
    // own direct registrations. Guarded by the same mutex_ as entries_
    // (both need to be read together in snapshot(), and both need
    // APPROVE/REJECT to check them together) rather than a separate lock.
    std::unordered_map<std::string, RegistryEntry> gossip_entries_;
};

RegistryServer::RegistryServer(Endpoint bind_endpoint, ServerTlsIdentity identity)
    : impl_(std::make_unique<Impl>(std::move(bind_endpoint), std::move(identity))) {}

RegistryServer::~RegistryServer() = default;

void RegistryServer::run() { impl_->run(); }

namespace {

void register_node_once_over(SecureChannel channel, const RegistryNode& node) {
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

} // namespace

void register_node_once(const Endpoint& registry,
                        const ClientTlsPolicy& registry_tls,
                        const RegistryNode& node) {
    validate_registry_node(node, false);
    register_node_once_over(SecureChannel::connect_direct(registry, registry_tls), node);
}

void register_node_once_via_socks5(const Endpoint& proxy,
                                   const Endpoint& registry,
                                   const ClientTlsPolicy& registry_tls,
                                   const RegistryNode& node) {
    validate_registry_node(node, false);
    register_node_once_over(
        SecureChannel::connect_via_socks5(proxy, registry, registry_tls), node);
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
