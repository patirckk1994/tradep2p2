#include "tradep2p/lobby.hpp"

#include "tradep2p/ephemeral.hpp"
#include "tradep2p/mediator.hpp"
#include "tradep2p/protocol.hpp"
#include "tradep2p/receipt.hpp"
#include "tradep2p/room_persistence.hpp"

#include <openssl/rand.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <poll.h>
#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <deque>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace tradep2p {
namespace {

constexpr std::size_t kMaxClients = 128U;
// Bounds how many TLS handshakes may be in flight at once. Handshakes now
// run concurrently, one per accepted connection, rather than serialized on
// the accept loop; without this bound a burst of bare TCP connections that
// never send a ClientHello could still spawn unbounded threads.
constexpr std::size_t kMaxPendingHandshakes = 64U;
constexpr std::size_t kMaxRooms = 256U;
constexpr std::size_t kMaxOpenOffers = 256U;
constexpr std::size_t kMaxOffersPerClient = 16U;
constexpr std::size_t kMaxPendingInvites = 256U;
constexpr std::size_t kMaxInvitesPerClient = 16U;
constexpr std::size_t kMaxQueuedFrames = 128U;
constexpr int kConnectionIoTimeoutSeconds = 30;

struct QueuedFrame {
    MessageType type{};
    std::vector<std::uint8_t> payload;
};

void set_nonblocking_close_on_exec(int fd) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        throw std::runtime_error("failed to configure wake pipe");
    }
    const int fd_flags = ::fcntl(fd, F_GETFD, 0);
    if (fd_flags < 0 || ::fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC) < 0) {
        throw std::runtime_error("failed to configure wake pipe");
    }
}

std::string safe_reason(std::string text) {
    if (text.empty()) {
        text = "request rejected";
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

template <typename Id>
Id random_id() {
    Id id{};
    if (RAND_bytes(id.data(), static_cast<int>(id.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return id;
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
                out << "\\u" << std::hex << std::setw(4)
                    << std::setfill('0') << static_cast<unsigned int>(ch)
                    << std::dec;
            } else {
                out << static_cast<char>(ch);
            }
        }
    }
    return out.str();
}

const char* session_state_name(SessionState state) {
    switch (state) {
    case SessionState::WaitingForPeer: return "waiting_for_peer";
    case SessionState::WaitingForSent: return "waiting_for_sent";
    case SessionState::WaitingForReceived: return "waiting_for_received";
    case SessionState::WaitingForFeeSent: return "waiting_for_fee_sent";
    case SessionState::WaitingForFinalReceiptAck: return "waiting_for_final_receipt_ack";
    case SessionState::Complete: return "complete";
    case SessionState::Aborted: return "aborted";
    }
    return "unknown";
}

std::string configured_state_file() {
    const char* value = std::getenv("TRADEP2P_LOBBY_STATE_FILE");
    return value == nullptr ? std::string{} : std::string(value);
}

// Phase 3 (mediator-side room persistence, see
// docs/identity-03-journal-recovery.md and room_persistence.hpp): a
// SEPARATE file from TRADEP2P_LOBBY_STATE_FILE. That file is (and remains)
// a lossy, JSON, for-display-only snapshot with no restore path and no
// client ids or addresses - it must not be repurposed for recovery, since
// it is deliberately missing the fields recovery needs. This is a distinct,
// binary, security-relevant file (room/party/terms/progress, though never
// receive addresses - see room_persistence.hpp's file comment for the full
// privacy trade-off this implements) that IS read back on startup. Unset or
// empty means persistence is disabled entirely: rooms_ starts empty on
// every restart exactly as it does today, and no file is ever written.
std::string configured_room_persistence_file() {
    const char* value = std::getenv("TRADEP2P_ROOM_STATE_FILE");
    return value == nullptr ? std::string{} : std::string(value);
}

std::string env_or_empty(const char* name) {
    const char* value = std::getenv(name);
    return value == nullptr ? std::string{} : std::string(value);
}

// Phase 6 (mediator-signed staged receipts, see docs/identity-06-
// receipts.md): the mediator's own receipt-signing identity. Receipts are
// meant to "stay verifiable for years" (specs.txt SS11), so a key that
// changes on every restart would make every previously-issued receipt
// unverifiable against whatever public key the mediator currently
// advertises - the same "silently destroys accumulated standing" problem
// specs.txt SS5 already names for pseudonym keys, one layer up. If
// TRADEP2P_MEDIATOR_RECEIPT_KEY_FILE is set, the key is loaded from (or,
// on first run, generated and written to) that path as a raw 32-byte
// private seed, 0600-permissioned - a materially WEAKER protection than
// keystore.hpp's AEAD-encrypted, passphrase-derived storage (this is a
// plaintext-on-disk operational key, not a user identity), which is an
// honest, stated trade-off: encrypting it would require the mediator
// operator to supply a passphrase on every restart, which most mediator
// deployments (a long-running service process) are not set up for. If
// unset, a fresh key is generated every process start - every receipt
// issued that run becomes unverifiable against a later restart's key,
// which is a real, named limitation of running without this option set,
// not a silent one.
Ed25519KeyPair load_or_create_mediator_receipt_key(const std::string& path) {
    if (path.empty()) {
        return generate_mediator_receipt_keypair();
    }
    const int existing_fd = ::open(path.c_str(), O_RDONLY);
    if (existing_fd >= 0) {
        std::array<std::uint8_t, kEd25519PrivateSeedLength> raw{};
        const ssize_t n = ::read(existing_fd, raw.data(), raw.size());
        ::close(existing_fd);
        if (n != static_cast<ssize_t>(raw.size())) {
            throw std::runtime_error("mediator receipt key file '" + path +
                                     "' is not exactly " +
                                     std::to_string(kEd25519PrivateSeedLength) + " bytes");
        }
        // Re-derives the public key from the loaded seed rather than
        // storing it separately, so the file's only content is the one
        // thing that actually needs protecting.
        return load_ed25519_keypair(Ed25519PrivateSeed(raw));
    }

    Ed25519KeyPair fresh = generate_mediator_receipt_keypair();
    const int fd = ::open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) {
        throw std::runtime_error("failed to create mediator receipt key file '" + path + "'");
    }
    const auto& seed_bytes = fresh.private_seed.bytes();
    const ssize_t written = ::write(fd, seed_bytes.data(), seed_bytes.size());
    ::close(fd);
    if (written != static_cast<ssize_t>(seed_bytes.size())) {
        ::unlink(path.c_str());
        throw std::runtime_error("failed to write mediator receipt key file '" + path + "'");
    }
    return fresh;
}

std::string configured_mediator_receipt_key_file() {
    return env_or_empty("TRADEP2P_MEDIATOR_RECEIPT_KEY_FILE");
}

std::uint64_t now_unix_seconds() {
    return static_cast<std::uint64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
}

// A mediator-wide fee configured by the operator through environment
// variables, kept out of the CLI argument list so existing invocations stay
// unchanged. Unset or empty TRADEP2P_FEE_ASSET means no fee is charged.
FeeTerms configured_fee() {
    FeeTerms fee;
    fee.asset = env_or_empty("TRADEP2P_FEE_ASSET");
    if (fee.asset.empty()) {
        return fee;
    }
    const std::string amount_text = env_or_empty("TRADEP2P_FEE_AMOUNT");
    const std::string address = env_or_empty("TRADEP2P_FEE_ADDRESS");
    if (amount_text.empty() || address.empty()) {
        throw std::invalid_argument(
            "TRADEP2P_FEE_ASSET requires TRADEP2P_FEE_AMOUNT and "
            "TRADEP2P_FEE_ADDRESS to also be set");
    }
    std::uint64_t amount = 0U;
    const char* begin = amount_text.data();
    const char* end = begin + amount_text.size();
    const auto [ptr, error] = std::from_chars(begin, end, amount, 10);
    if (error != std::errc{} || ptr != end || amount == 0U) {
        throw std::invalid_argument("invalid TRADEP2P_FEE_AMOUNT");
    }
    fee.amount = amount;
    fee.address = address;
    validate_fee_terms(fee);
    return fee;
}

} // namespace

class LobbyServer::Impl {
public:
    Impl(Endpoint bind_endpoint, ServerTlsIdentity identity)
        : bind_endpoint_(std::move(bind_endpoint)),
          identity_(std::move(identity)),
          state_file_(configured_state_file()),
          room_persistence_path_(configured_room_persistence_file()),
          fee_(configured_fee()),
          mediator_id_(bind_endpoint_.host + ":" + std::to_string(bind_endpoint_.port)),
          mediator_receipt_keypair_(
              load_or_create_mediator_receipt_key(configured_mediator_receipt_key_file())) {}

    ~Impl() {
        snapshot_running_.store(false);
        if (snapshot_thread_.joinable()) {
            snapshot_thread_.join();
        }
    }

    void run() {
        SecureListener listener(bind_endpoint_, identity_);
        std::cout << "TradeP2P lobby listening on " << bind_endpoint_.host << ':'
                  << bind_endpoint_.port << '\n';
        std::cout << "Anonymous offer rooms, address exchange and multi-room settlement.\n";
        std::cout << "No accounts, client certificates, transaction data or wallet custody.\n";
        if (fee_.amount > 0U) {
            std::cout << "Mediator fee: " << fee_.amount << ' ' << fee_.asset
                      << " to " << fee_.address << " per settled trade.\n";
        }

        if (!state_file_.empty()) {
            snapshot_running_.store(true);
            snapshot_thread_ = std::thread([this] { snapshot_loop(); });
            std::cout << "Local lobby state snapshot: " << state_file_ << '\n';
        }

        load_persisted_rooms_at_startup();

        for (;;) {
            int fd = -1;
            try {
                fd = listener.accept_raw();
            } catch (const std::exception& error) {
                // Only a bare accept() failure lands here now; it does not
                // block on a slow or hostile peer, so this cannot itself
                // starve other connections the way the old combined
                // accept-plus-handshake call could.
                std::cerr << "accept failed: " << error.what() << '\n';
                continue;
            }

            if (pending_handshakes_.fetch_add(1U) >= kMaxPendingHandshakes) {
                pending_handshakes_.fetch_sub(1U);
                ::close(fd);
                continue;
            }

            std::thread([this, &listener, fd] {
                struct HandshakeGuard {
                    std::atomic<std::size_t>& counter;
                    ~HandshakeGuard() { counter.fetch_sub(1U); }
                } guard{pending_handshakes_};

                // The handshake itself (and its up-to-10-second timeout) now
                // runs here, on a per-connection thread, so one stalled peer
                // can no longer block the accept loop from servicing anyone
                // else.
                SecureChannel channel;
                try {
                    channel = listener.complete_handshake(fd);
                } catch (const std::exception& error) {
                    std::cerr << "rejected connection: " << error.what() << '\n';
                    return;
                }

                std::shared_ptr<Client> client;
                {
                    std::scoped_lock lock(hub_mutex_);
                    if (clients_.size() >= kMaxClients) {
                        try {
                            channel.send_frame(
                                MessageType::Error,
                                encode_error({"mediator is full"}));
                        } catch (...) {
                        }
                        return;
                    }

                    ClientId id{};
                    std::string key;
                    do {
                        id = random_id<ClientId>();
                        validate_client_id(id);
                        key = client_id_to_hex(id);
                    } while (clients_.contains(key));

                    client = std::make_shared<Client>(id, std::move(channel));
                    clients_.emplace(key, client);
                }

                client_loop(client);
            }).detach();
        }
    }

private:
    struct Client {
        Client(ClientId client_id, SecureChannel secure_channel)
            : id(client_id), channel(std::move(secure_channel)) {
            int pipe_fds[2]{-1, -1};
            if (::pipe(pipe_fds) != 0) {
                throw std::runtime_error("failed to create wake pipe");
            }
            wake_read = pipe_fds[0];
            wake_write = pipe_fds[1];
            try {
                set_nonblocking_close_on_exec(wake_read);
                set_nonblocking_close_on_exec(wake_write);
            } catch (...) {
                ::close(wake_read);
                ::close(wake_write);
                wake_read = -1;
                wake_write = -1;
                throw;
            }
        }

        ~Client() {
            if (wake_read >= 0) {
                ::close(wake_read);
            }
            if (wake_write >= 0) {
                ::close(wake_write);
            }
        }

        bool enqueue(MessageType type, std::vector<std::uint8_t> payload) {
            {
                std::scoped_lock lock(queue_mutex);
                if (!alive.load()) {
                    return false;
                }
                if (outgoing.size() >= kMaxQueuedFrames) {
                    alive.store(false);
                    wake();
                    return false;
                }
                outgoing.push_back(QueuedFrame{type, std::move(payload)});
            }
            wake();
            return true;
        }

        std::deque<QueuedFrame> take_outgoing() {
            std::deque<QueuedFrame> result;
            std::scoped_lock lock(queue_mutex);
            result.swap(outgoing);
            return result;
        }

        void wake() const noexcept {
            if (wake_write < 0) {
                return;
            }
            const std::uint8_t byte = 1U;
            const auto rc = ::write(wake_write, &byte, sizeof(byte));
            (void)rc;
        }

        void drain_wake_pipe() const noexcept {
            std::uint8_t buffer[64]{};
            while (::read(wake_read, buffer, sizeof(buffer)) > 0) {
            }
        }

        ClientId id{};
        SecureChannel channel;
        int wake_read{-1};
        int wake_write{-1};
        std::mutex queue_mutex;
        std::deque<QueuedFrame> outgoing;
        std::atomic<bool> alive{true};
        unsigned int bad_messages{0U};
    };

    struct OpenOffer {
        RoomId id{};
        ClientId creator{};
        TradeTerms terms;
        std::string receive_address_a;
    };

    struct PendingInvite {
        InviteId id{};
        ClientId from{};
        ClientId to{};
        TradeTerms terms;
        std::string receive_address_a;
    };

    struct RoomEntry {
        RoomEntry(const PendingInvite& invite,
                  RoomId room_id,
                  std::string receive_address_b,
                  FeeTerms fee)
            : id(room_id),
              party_a(invite.from),
              party_b(invite.to),
              session(CreateRoomMessage{invite.terms, invite.receive_address_a},
                      room_id, std::move(fee)) {
            session.join(JoinRoomMessage{room_id, std::move(receive_address_b)});
        }

        RoomEntry(const OpenOffer& offer,
                  ClientId joining_client,
                  std::string receive_address_b,
                  FeeTerms fee)
            : id(offer.id),
              party_a(offer.creator),
              party_b(joining_client),
              session(CreateRoomMessage{offer.terms, offer.receive_address_a},
                      offer.id, std::move(fee)) {
            session.join(JoinRoomMessage{offer.id, std::move(receive_address_b)});
        }

        // Phase 3: reconstructs a room from mediator-side persisted state
        // after a restart (see room_persistence.hpp). Deliberately built via
        // MediatorSession::restore() rather than the normal
        // constructor+join() flow above, since the persisted record never
        // carries receive addresses (the chosen privacy option - see
        // room_persistence.hpp's file comment) - both addresses come back
        // as empty strings, which restore() explicitly allows and every
        // later address-consuming path (encode_turn/encode_trade_ready)
        // fails closed on if anything tries to use them for real
        // settlement traffic before they are genuinely known again. `active`
        // is false only for the states persistence never actually writes
        // (Complete/Aborted are pruned immediately, not persisted - see
        // LobbyServer::Impl::persist_room_upsert()), so this is here purely
        // as a defensive default, not a path this constructor expects to
        // exercise for those two states in practice.
        explicit RoomEntry(const PersistedRoom& persisted)
            : id(persisted.room_id),
              party_a(persisted.party_a),
              party_b(persisted.party_b),
              session(MediatorSession::restore(
                  persisted.room_id, persisted.terms, /*receive_address_a=*/std::string{},
                  /*receive_address_b=*/std::string{}, persisted.fee, persisted.state,
                  persisted.round_index, persisted.leg_index, persisted.abort_reason)),
              active(persisted.state != SessionState::Complete &&
                     persisted.state != SessionState::Aborted) {}

        RoomId id{};
        ClientId party_a{};
        ClientId party_b{};
        MediatorSession session;
        std::mutex mutex;
        bool active{true};

        // Phase 5/6: each party's announced ephemeral trade key (phase 5),
        // passively cached the moment the mediator relays their
        // TradeEphemeralKey announcement - see handle_room_relay(). Needed
        // here (not just relayed and forgotten) so phase 6's receipts can
        // bind both parties' ephemeral keys, and so a ReceiptAck's
        // signature can be checked against the SAME key its party actually
        // announced, never a key embedded in the ack itself.
        std::optional<Ed25519PublicKey> ephemeral_key_a;
        std::optional<Ed25519PublicKey> ephemeral_key_b;
        // Phase 6: the stage-3 ("penultimate obligations complete")
        // receipt, once issued - kept so the stage-4 ("settlement
        // completed") receipt can chain onto it via
        // receipt_chain_link_hash(). Guarded by `mutex` like every other
        // mutable field here.
        std::optional<IssuedReceipt> final_ack_receipt;
    };

    static Party party_for(const RoomEntry& room, const ClientId& client_id) {
        if (room.party_a == client_id) {
            return Party::A;
        }
        if (room.party_b == client_id) {
            return Party::B;
        }
        throw std::invalid_argument("client is not a member of this room");
    }

    void client_loop(const std::shared_ptr<Client>& client) {
        const std::string client_key = client_id_to_hex(client->id);
        try {
            client->channel.set_timeout(kConnectionIoTimeoutSeconds);
            client->channel.send_frame(
                MessageType::Welcome,
                encode_welcome(WelcomeMessage{client->id, fee_}));

            std::cout << "client connected: " << client_key << '\n';

            while (client->alive.load()) {
                pollfd fds[2]{};
                fds[0].fd = client->channel.native_handle();
                fds[0].events = POLLIN;
                fds[1].fd = client->wake_read;
                fds[1].events = POLLIN;

                const bool pending = client->channel.has_pending_input();
                const int rc = ::poll(fds, 2, pending ? 0 : 1000);
                if (rc < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    throw std::runtime_error("poll failed");
                }

                if ((fds[1].revents & POLLIN) != 0) {
                    client->drain_wake_pipe();
                    flush_outgoing(client);
                }

                if ((fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                    break;
                }

                if (pending || (fds[0].revents & POLLIN) != 0) {
                    unsigned int processed = 0U;
                    do {
                        const Frame frame = client->channel.receive_frame();
                        if (frame.type == MessageType::Disconnect) {
                            client->alive.store(false);
                            break;
                        }

                        try {
                            dispatch(client, frame);
                        } catch (const std::exception& error) {
                            ++client->bad_messages;
                            send_error(client, error.what());
                            if (client->bad_messages >= 3U) {
                                client->alive.store(false);
                                break;
                            }
                        }
                        ++processed;
                    } while (client->alive.load() &&
                             client->channel.has_pending_input() &&
                             processed < 16U);
                }

                if (client->alive.load()) {
                    flush_outgoing(client);
                }
            }
        } catch (const std::exception& error) {
            std::cerr << "client " << client_key << " disconnected: "
                      << error.what() << '\n';
        }

        client->alive.store(false);
        remove_client(client->id);
        client->channel.close();
        std::cout << "client removed: " << client_key << '\n';
    }

    void flush_outgoing(const std::shared_ptr<Client>& client) {
        auto frames = client->take_outgoing();
        for (auto& frame : frames) {
            client->channel.send_frame(frame.type, frame.payload);
        }
    }

    void dispatch(const std::shared_ptr<Client>& client, const Frame& frame) {
        switch (frame.type) {
        case MessageType::CreateOffer:
            handle_create_offer(client, decode_create_offer(frame.payload));
            return;
        case MessageType::ListOffers:
            handle_list_offers(client, decode_list_offers(frame.payload));
            return;
        case MessageType::JoinOffer:
            handle_join_offer(client, decode_join_offer(frame.payload));
            return;
        case MessageType::CancelOffer:
            handle_cancel_offer(client, decode_cancel_offer(frame.payload));
            return;
        case MessageType::Sent:
            handle_sent(client, decode_round_signal(frame.payload));
            return;
        case MessageType::Received:
            handle_received(client, decode_round_signal(frame.payload));
            return;
        case MessageType::Abort:
            handle_abort(client, decode_abort(frame.payload));
            return;
        case MessageType::RecoveryStateRequest:
            handle_recovery_state_request(client, decode_recovery_state_request(frame.payload));
            return;
        case MessageType::RecognitionChallenge:
            handle_room_relay(client, MessageType::RecognitionChallenge,
                              decode_recognition_challenge(frame.payload).room_id,
                              frame.payload);
            return;
        case MessageType::RecognitionResponse:
            handle_room_relay(client, MessageType::RecognitionResponse,
                              decode_recognition_response(frame.payload).room_id,
                              frame.payload);
            return;
        case MessageType::TradeEphemeralKey:
            handle_trade_ephemeral_key(client, decode_trade_ephemeral_key(frame.payload), frame.payload);
            return;
        case MessageType::ReceiptAck:
            handle_receipt_ack(client, decode_receipt_ack(frame.payload));
            return;
        case MessageType::ReceiptDisclosure:
            handle_room_relay(client, MessageType::ReceiptDisclosure,
                              decode_receipt_disclosure(frame.payload).room_id, frame.payload);
            return;
        default:
            throw std::invalid_argument("message type is not accepted from clients");
        }
    }


    void handle_create_offer(const std::shared_ptr<Client>& client,
                             const CreateOfferMessage& message) {
        OpenOffer offer;
        {
            std::scoped_lock lock(hub_mutex_);
            if (offers_.size() >= kMaxOpenOffers) {
                throw std::runtime_error("too many open offers");
            }
            std::size_t own_count = 0U;
            for (const auto& entry : offers_) {
                if (entry.second.creator == client->id) {
                    ++own_count;
                }
            }
            if (own_count >= kMaxOffersPerClient) {
                throw std::runtime_error("too many open offers from this client");
            }

            std::string key;
            do {
                offer.id = random_id<RoomId>();
                validate_room_id(offer.id);
                key = room_id_to_hex(offer.id);
            } while (offers_.contains(key) || rooms_.contains(key));

            offer.creator = client->id;
            offer.terms = message.terms;
            offer.receive_address_a = message.receive_address_a;
            offers_.emplace(key, offer);
        }
        client->enqueue(MessageType::OfferCreated,
                        encode_offer_created(OfferCreatedMessage{offer.id}));
    }

    void handle_list_offers(const std::shared_ptr<Client>& client,
                            const ListOffersMessage& request) {
        std::vector<OfferSummary> candidates;
        {
            std::scoped_lock lock(hub_mutex_);
            candidates.reserve(offers_.size());
            for (const auto& entry : offers_) {
                candidates.push_back(OfferSummary{entry.second.id,
                                                  entry.second.terms});
            }
        }

        std::sort(candidates.begin(), candidates.end(),
                  [](const OfferSummary& left, const OfferSummary& right) {
                      return left.room_id < right.room_id;
                  });

        auto begin = candidates.begin();
        if (request.has_cursor) {
            begin = std::upper_bound(
                candidates.begin(), candidates.end(), request.after_room_id,
                [](const RoomId& cursor, const OfferSummary& offer) {
                    return cursor < offer.room_id;
                });
        }

        OfferListMessage page;
        const auto remaining = static_cast<std::size_t>(
            std::distance(begin, candidates.end()));
        page.offers.reserve(std::min<std::size_t>(request.limit, remaining));
        for (auto it = begin;
             it != candidates.end() && page.offers.size() < request.limit; ++it) {
            page.offers.push_back(*it);
        }

        const auto consumed = static_cast<std::ptrdiff_t>(page.offers.size());
        page.has_more = std::distance(begin, candidates.end()) > consumed;
        if (page.has_more) {
            page.next_cursor = page.offers.back().room_id;
        }

        auto encoded = encode_offer_list(page);
        if (encoded.size() > kMaxFramePayload) {
            throw std::logic_error("encoded offer page exceeds frame limit");
        }
        client->enqueue(MessageType::OfferList, std::move(encoded));
    }

    void handle_join_offer(const std::shared_ptr<Client>& client,
                           const JoinOfferMessage& message) {
        OpenOffer offer;
        std::shared_ptr<Client> party_a;
        std::shared_ptr<RoomEntry> room;
        {
            std::scoped_lock lock(hub_mutex_);
            const std::string key = room_id_to_hex(message.room_id);
            const auto offer_it = offers_.find(key);
            if (offer_it == offers_.end()) {
                throw std::invalid_argument("offer does not exist or was already taken");
            }
            if (offer_it->second.creator == client->id) {
                throw std::invalid_argument("cannot join your own offer");
            }
            if (rooms_.size() >= kMaxRooms) {
                throw std::runtime_error("too many active rooms");
            }
            const auto creator_it = clients_.find(
                client_id_to_hex(offer_it->second.creator));
            if (creator_it == clients_.end()) {
                offers_.erase(offer_it);
                throw std::runtime_error("offer creator disconnected");
            }
            offer = offer_it->second;
            party_a = creator_it->second;

            // Promote the accepted offer directly into an active settlement room.
            // The room id published in /offers remains stable for both parties and
            // for all later /sent, /received and /abort messages.
            room = std::make_shared<RoomEntry>(offer, client->id,
                                               message.receive_address_b, fee_);
            rooms_.emplace(key, room);
            offers_.erase(offer_it);
        }

        // Persist the newly-created room's state machine BEFORE either
        // party is told the room is ready, so a crash right after this
        // point can never leave a client believing a room exists that the
        // mediator has no memory of on restart.
        {
            std::scoped_lock room_lock(room->mutex);
            persist_room_upsert(*room);
        }

        const auto ready_a = room->session.ready_message(Party::A, room->party_b);
        const auto ready_b = room->session.ready_message(Party::B, room->party_a);
        party_a->enqueue(MessageType::TradeReady, encode_trade_ready(ready_a));
        client->enqueue(MessageType::TradeReady, encode_trade_ready(ready_b));
        send_turn_to_room(room, room->session.current_turn());
    }

    void handle_cancel_offer(const std::shared_ptr<Client>& client,
                             const CancelOfferMessage& message) {
        {
            std::scoped_lock lock(hub_mutex_);
            const std::string key = room_id_to_hex(message.room_id);
            const auto it = offers_.find(key);
            if (it == offers_.end()) {
                throw std::invalid_argument("open offer does not exist");
            }
            if (it->second.creator != client->id) {
                throw std::invalid_argument("offer belongs to another client");
            }
            offers_.erase(it);
        }
        client->enqueue(MessageType::OfferCancelled,
                        encode_offer_cancelled(OfferCancelledMessage{message.room_id}));
    }

    void handle_list_peers(const std::shared_ptr<Client>& client) {
        PeerListMessage message;
        {
            std::scoped_lock lock(hub_mutex_);
            message.peers.reserve(clients_.size());
            for (const auto& entry : clients_) {
                if (entry.second->id != client->id) {
                    message.peers.push_back(entry.second->id);
                }
            }
        }
        std::sort(message.peers.begin(), message.peers.end(),
                  [](const ClientId& left, const ClientId& right) {
                      return client_id_to_hex(left) < client_id_to_hex(right);
                  });
        client->enqueue(MessageType::PeerList, encode_peer_list(message));
    }

    void handle_invite(const std::shared_ptr<Client>& client,
                       const InviteTradeMessage& message) {
        if (message.target == client->id) {
            throw std::invalid_argument("cannot invite yourself");
        }

        PendingInvite invite;
        std::shared_ptr<Client> target;
        {
            std::scoped_lock lock(hub_mutex_);
            if (invites_.size() >= kMaxPendingInvites) {
                throw std::runtime_error("too many pending invitations");
            }

            std::size_t outgoing_count = 0U;
            for (const auto& entry : invites_) {
                if (entry.second.from == client->id) {
                    ++outgoing_count;
                }
            }
            if (outgoing_count >= kMaxInvitesPerClient) {
                throw std::runtime_error("too many pending invitations from this client");
            }

            const auto target_it = clients_.find(client_id_to_hex(message.target));
            if (target_it == clients_.end()) {
                throw std::invalid_argument("target client is not connected");
            }
            target = target_it->second;

            std::string invite_key;
            do {
                invite.id = random_id<InviteId>();
                validate_invite_id(invite.id);
                invite_key = invite_id_to_hex(invite.id);
            } while (invites_.contains(invite_key));

            invite.from = client->id;
            invite.to = message.target;
            invite.terms = message.terms;
            invite.receive_address_a = message.receive_address_a;
            invites_.emplace(invite_key, invite);
        }

        client->enqueue(
            MessageType::InviteCreated,
            encode_invite_created(InviteCreatedMessage{invite.id, invite.to}));
        target->enqueue(
            MessageType::InviteReceived,
            encode_invite_received(InviteReceivedMessage{
                invite.id, invite.from, invite.terms, invite.receive_address_a}));
    }

    void handle_accept(const std::shared_ptr<Client>& client,
                       const AcceptInviteMessage& message) {
        PendingInvite invite;
        std::shared_ptr<Client> party_a;
        std::shared_ptr<Client> party_b;
        std::shared_ptr<RoomEntry> room;

        {
            std::scoped_lock lock(hub_mutex_);
            const std::string invite_key = invite_id_to_hex(message.invite_id);
            const auto invite_it = invites_.find(invite_key);
            if (invite_it == invites_.end()) {
                throw std::invalid_argument("invitation does not exist");
            }
            if (invite_it->second.to != client->id) {
                throw std::invalid_argument("invitation belongs to another client");
            }
            if (rooms_.size() >= kMaxRooms) {
                throw std::runtime_error("too many active rooms");
            }

            invite = invite_it->second;
            const auto a_it = clients_.find(client_id_to_hex(invite.from));
            const auto b_it = clients_.find(client_id_to_hex(invite.to));
            if (a_it == clients_.end() || b_it == clients_.end()) {
                invites_.erase(invite_it);
                throw std::runtime_error("inviting peer disconnected");
            }
            party_a = a_it->second;
            party_b = b_it->second;

            RoomId room_id{};
            std::string room_key;
            do {
                room_id = random_id<RoomId>();
                validate_room_id(room_id);
                room_key = room_id_to_hex(room_id);
            } while (rooms_.contains(room_key));

            room = std::make_shared<RoomEntry>(
                invite, room_id, message.receive_address_b, fee_);
            rooms_.emplace(room_key, room);
            invites_.erase(invite_it);
        }

        // Same durability-before-acknowledgement ordering as
        // handle_join_offer() above.
        {
            std::scoped_lock room_lock(room->mutex);
            persist_room_upsert(*room);
        }

        const auto ready_a = room->session.ready_message(Party::A, room->party_b);
        const auto ready_b = room->session.ready_message(Party::B, room->party_a);
        party_a->enqueue(MessageType::TradeReady, encode_trade_ready(ready_a));
        party_b->enqueue(MessageType::TradeReady, encode_trade_ready(ready_b));
        send_turn_to_room(room, room->session.current_turn());
    }

    void handle_decline(const std::shared_ptr<Client>& client,
                        const DeclineInviteMessage& message) {
        std::shared_ptr<Client> inviter;
        {
            std::scoped_lock lock(hub_mutex_);
            const std::string key = invite_id_to_hex(message.invite_id);
            const auto it = invites_.find(key);
            if (it == invites_.end()) {
                throw std::invalid_argument("invitation does not exist");
            }
            if (it->second.to != client->id) {
                throw std::invalid_argument("invitation belongs to another client");
            }
            const auto inviter_it = clients_.find(client_id_to_hex(it->second.from));
            if (inviter_it != clients_.end()) {
                inviter = inviter_it->second;
            }
            invites_.erase(it);
        }
        if (inviter) {
            inviter->enqueue(
                MessageType::InviteDeclined,
                encode_invite_declined(InviteDeclinedMessage{message.invite_id}));
        }
    }

    void handle_sent(const std::shared_ptr<Client>& client,
                     const RoundSignalMessage& message) {
        const auto room = find_room_for(client->id, message.room_id);
        std::shared_ptr<Client> receiver;
        bool complete = false;
        std::optional<IssuedReceipt> completion_receipt;
        {
            std::scoped_lock lock(room->mutex);
            if (!room->active) {
                throw std::runtime_error("room is no longer active");
            }
            const Party reporting_party = party_for(*room, client->id);
            room->session.sender_reported_sent(reporting_party, message);
            receiver = client_for_party(*room, other_party(reporting_party));
            // Reporting a mediator fee as sent can complete the room directly,
            // since the mediator (not the counterparty) is the recipient of
            // that leg and needs no separate receipt acknowledgement. By the
            // time this room could ever be in WaitingForFeeSent at all, it
            // already passed through the final-receipt-ack gate (phase 6 -
            // see mediator.hpp's SessionState::WaitingForFinalReceiptAck),
            // so issuing the stage-4 "settlement completed" receipt here is
            // never premature - see receipt.hpp's file comment.
            complete = room->session.state() == SessionState::Complete;
            if (complete) {
                room->active = false;
                completion_receipt = issue_receipt(*room, ReceiptStage::SettlementCompleted, true);
            }
            // Durably record the new state (or drop it - see
            // persist_room_remove()'s comment - once it is Complete)
            // BEFORE either enqueueing a forwarded Sent signal to the
            // counterparty or announcing completion below: the mediator
            // must never tell a client about a transition it could still
            // forget on the very next crash.
            if (!complete) {
                persist_room_upsert(*room);
            }
        }

        if (complete) {
            persist_room_remove(room->id);
            erase_room(room->id, room);
            if (completion_receipt.has_value()) {
                send_to_room(room, MessageType::ReceiptIssued,
                            encode_receipt_issued(to_wire(*completion_receipt)));
            }
            const auto payload = encode_complete(CompleteMessage{room->id});
            send_to_room(room, MessageType::Complete, payload);
            return;
        }

        if (!receiver) {
            abort_room(room, "peer disconnected");
            return;
        }
        receiver->enqueue(MessageType::Sent, encode_round_signal(message));
    }

    void handle_received(const std::shared_ptr<Client>& client,
                         const RoundSignalMessage& message) {
        const auto room = find_room_for(client->id, message.room_id);
        std::shared_ptr<Client> sender;
        bool complete = false;
        bool gating = false; // phase 6: entered SessionState::WaitingForFinalReceiptAck
        TurnMessage next_turn;
        std::optional<IssuedReceipt> completion_receipt;

        {
            std::scoped_lock lock(room->mutex);
            if (!room->active) {
                throw std::runtime_error("room is no longer active");
            }
            const Party reporting_party = party_for(*room, client->id);
            room->session.receiver_reported_received(reporting_party, message);
            sender = client_for_party(*room, other_party(reporting_party));
            const SessionState new_state = room->session.state();
            complete = new_state == SessionState::Complete;
            gating = new_state == SessionState::WaitingForFinalReceiptAck;
            if (complete) {
                room->active = false;
                completion_receipt = issue_receipt(*room, ReceiptStage::SettlementCompleted, true);
            } else if (!gating) {
                next_turn = room->session.current_turn();
            }
            // `gating` intentionally fetches no Turn - see mediator.hpp's
            // SessionState::WaitingForFinalReceiptAck: no Turn is issuable
            // until both parties submit a ReceiptAck (MessageType::
            // ReceiptAckRequired, sent below, is the explicit signal that
            // tells clients this - not silence they must interpret).
            //
            // Same durability-before-acknowledgement ordering as
            // handle_sent() above - this is the call that advances
            // round/leg, so it is the one that matters most for the
            // "mediator restart mid-room" recovery windows.
            if (!complete) {
                persist_room_upsert(*room);
            }
        }

        if (sender) {
            sender->enqueue(MessageType::Received, encode_round_signal(message));
        }

        if (complete) {
            persist_room_remove(room->id);
            erase_room(room->id, room);
            if (completion_receipt.has_value()) {
                send_to_room(room, MessageType::ReceiptIssued,
                            encode_receipt_issued(to_wire(*completion_receipt)));
            }
            const auto payload = encode_complete(CompleteMessage{room->id});
            send_to_room(room, MessageType::Complete, payload);
        } else if (gating) {
            send_to_room(room, MessageType::ReceiptAckRequired,
                        encode_receipt_ack_required(ReceiptAckRequiredMessage{room->id}));
        } else {
            send_turn_to_room(room, next_turn);
        }
    }

    // A generic client-to-counterparty relay for identity-layer room
    // messages that carry their own client-verified meaning and need no
    // mediator interpretation: phase 4b's RecognitionChallenge/
    // RecognitionResponse (docs/identity-04b-counterparty-recognition.md)
    // and phase 5's TradeEphemeralKey (docs/identity-05-ephemeral-trade-
    // identity.md) all share this exact shape, and later phases (6/8's
    // receipt exchange) are expected to reuse it too rather than each
    // growing their own copy. Relays `payload` from `client` to the OTHER
    // party in `room_id`, verbatim - exactly the same decode-validate-then-
    // relay-raw-payload shape handle_sent()/handle_received() already use
    // for Sent/Received. This mediator never signs, verifies, or interprets
    // the payload's meaning; it only confirms `client` is actually a member
    // of `room_id` (via find_room_for(), the same membership check every
    // other in-room message already requires) before forwarding the
    // already-decoded-and-therefore-well-formed bytes on to the
    // counterparty. All cryptographic verification happens only on each
    // client (recognition.hpp / ephemeral.hpp).
    void handle_room_relay(const std::shared_ptr<Client>& client, MessageType type,
                           const RoomId& room_id, const std::vector<std::uint8_t>& payload) {
        const auto room = find_room_for(client->id, room_id);
        const Party sender_party = party_for(*room, client->id);
        const auto receiver = client_for_party(*room, other_party(sender_party));
        if (!receiver) {
            throw std::runtime_error("counterparty is not currently connected");
        }
        receiver->enqueue(type, payload);
    }

    // Phase 5/6: like handle_room_relay(), but additionally caches the
    // announced key on the room (see RoomEntry::ephemeral_key_a/b) before
    // relaying - phase 6's receipts need to know both parties' ephemeral
    // keys, and the only honest source for "what key does party X actually
    // control" is the announcement that party itself sent, passively
    // observed here, never a key supplied later by someone claiming to
    // speak for that party.
    void handle_trade_ephemeral_key(const std::shared_ptr<Client>& client,
                                    const TradeEphemeralKeyMessage& message,
                                    const std::vector<std::uint8_t>& payload) {
        const auto parsed = parse_ed25519_public_key(message.ephemeral_public_key);
        if (!parsed.has_value()) {
            throw std::invalid_argument("malformed ephemeral trade public key");
        }
        const auto room = find_room_for(client->id, message.room_id);
        const Party party = party_for(*room, client->id);
        {
            std::scoped_lock lock(room->mutex);
            (party == Party::A ? room->ephemeral_key_a : room->ephemeral_key_b) = *parsed;
        }
        handle_room_relay(client, MessageType::TradeEphemeralKey, message.room_id, payload);
    }

    // Phase 6: a party's signed acknowledgement of the "penultimate
    // obligations complete" stage - see mediator.hpp's SessionState::
    // WaitingForFinalReceiptAck and receipt.hpp's file comment for the
    // withholding fix this implements. Verifies the signature against the
    // ephemeral key THAT PARTY announced (never a key supplied in the ack
    // itself), records the ack, and - once both parties have acked - issues
    // the stage-3 receipt to both and unblocks the now-issuable final Turn.
    void handle_receipt_ack(const std::shared_ptr<Client>& client, const ReceiptAckMessage& message) {
        const auto room = find_room_for(client->id, message.room_id);
        const Party party = party_for(*room, client->id);

        std::optional<IssuedReceipt> stage3_receipt;
        std::optional<TurnMessage> unblocked_turn;
        {
            std::scoped_lock lock(room->mutex);
            if (!room->active) {
                throw std::runtime_error("room is no longer active");
            }
            if (room->session.state() != SessionState::WaitingForFinalReceiptAck) {
                throw std::invalid_argument(
                    "room is not currently awaiting a final receipt acknowledgement");
            }
            if (static_cast<ReceiptStage>(message.stage) !=
                ReceiptStage::PenultimateObligationsComplete) {
                throw std::invalid_argument("unexpected receipt acknowledgement stage");
            }
            const auto& announced_key = party == Party::A ? room->ephemeral_key_a : room->ephemeral_key_b;
            if (!announced_key.has_value()) {
                throw std::invalid_argument(
                    "no ephemeral trade key announced for this room yet - cannot verify acknowledgement");
            }

            ReceiptAckFields fields;
            fields.mediator_id = mediator_id_;
            fields.room_id = room->id;
            fields.stage = ReceiptStage::PenultimateObligationsComplete;
            fields.terms_commitment = trade_payload_hash(encode_terms(room->session.terms()));
            fields.timestamp = message.timestamp;
            if (!verify_receipt_ack(*announced_key, fields, message.signature)) {
                throw std::invalid_argument("receipt acknowledgement signature does not verify");
            }

            room->session.acknowledge_final_receipt(party); // throws on a duplicate ack
            if (room->session.state() != SessionState::WaitingForFinalReceiptAck) {
                // Both parties have now acked - the gate just opened.
                stage3_receipt = issue_receipt(*room, ReceiptStage::PenultimateObligationsComplete, false);
                unblocked_turn = room->session.current_turn();
            }
            persist_room_upsert(*room);
        }

        if (stage3_receipt.has_value()) {
            send_to_room(room, MessageType::ReceiptIssued, encode_receipt_issued(to_wire(*stage3_receipt)));
        }
        if (unblocked_turn.has_value()) {
            send_turn_to_room(room, *unblocked_turn);
        }
    }

    void handle_abort(const std::shared_ptr<Client>& client,
                      const AbortMessage& message) {
        const auto room = find_room_for(client->id, message.room_id);
        abort_room(room, message.reason);
    }

    // Phase 3 recovery protocol. Deliberately does NOT go through
    // find_room_for()/party_for(): those enforce that the CURRENT
    // connection's ClientId matches a party already on file, which is
    // exactly the check a mediator restart or client reconnect breaks (a
    // fresh TLS connection always gets a fresh, unrelated ClientId - see
    // the MessageType::RecoveryStateRequest enum comment in protocol.hpp).
    // Authorization here is knowledge of the 32-byte random room id alone,
    // the same bearer-credential trust level every other room operation in
    // this protocol already relies on. This is a read-only status query: it
    // never mutates `room`, never rebinds a connection to a party slot, and
    // never re-solicits an address - see room_persistence.hpp's file
    // comment for why actually resuming a recovered room is out of scope
    // for this phase.
    void handle_recovery_state_request(const std::shared_ptr<Client>& client,
                                       const RecoveryStateRequestMessage& message) {
        std::shared_ptr<RoomEntry> room;
        {
            std::scoped_lock lock(hub_mutex_);
            const auto it = rooms_.find(room_id_to_hex(message.room_id));
            if (it != rooms_.end()) {
                room = it->second;
            }
        }

        RecoveryStateResponseMessage response;
        response.room_id = message.room_id;
        if (!room) {
            response.found = false;
            response.reason = "no room on file for this id (never existed, already "
                              "finished and pruned, or persistence was disabled)";
            client->enqueue(MessageType::RecoveryStateResponse,
                            encode_recovery_state_response(response));
            return;
        }

        {
            std::scoped_lock lock(room->mutex);
            response.found = true;
            response.terms = room->session.terms();
            response.state = static_cast<std::uint8_t>(room->session.state());
            response.round_index = room->session.round_index();
            response.leg_index = room->session.leg_index();
            if (room->session.state() == SessionState::Aborted) {
                response.reason = room->session.abort_reason();
            }
        }
        response.fee = fee_;
        response.party_a_connected = client_for_party(*room, Party::A) != nullptr;
        response.party_b_connected = client_for_party(*room, Party::B) != nullptr;

        client->enqueue(MessageType::RecoveryStateResponse,
                        encode_recovery_state_response(response));
    }

    std::shared_ptr<RoomEntry> find_room_for(const ClientId& client_id,
                                             const RoomId& room_id) {
        std::shared_ptr<RoomEntry> room;
        {
            std::scoped_lock lock(hub_mutex_);
            const auto it = rooms_.find(room_id_to_hex(room_id));
            if (it == rooms_.end()) {
                throw std::invalid_argument("room does not exist");
            }
            room = it->second;
        }
        (void)party_for(*room, client_id);
        return room;
    }

    std::shared_ptr<Client> client_for_party(const RoomEntry& room, Party party) {
        const ClientId& id = party == Party::A ? room.party_a : room.party_b;
        std::scoped_lock lock(hub_mutex_);
        const auto it = clients_.find(client_id_to_hex(id));
        return it == clients_.end() ? nullptr : it->second;
    }

    void send_turn_to_room(const std::shared_ptr<RoomEntry>& room,
                           const TurnMessage& turn) {
        send_to_room(room, MessageType::Turn, encode_turn(turn));
    }

    // Phase 6: builds, mediator-signs, and returns an IssuedReceipt for
    // `stage`. PRECONDITION: caller already holds `room.mutex` (this reads
    // room.session/ephemeral keys and, for the stage-3 case, writes
    // room.final_ack_receipt so stage 4 can later chain onto it). Throws if
    // either party's ephemeral key hasn't been announced yet - by
    // construction this cannot happen on the call paths that actually
    // reach this (see mediator.hpp's SessionState::WaitingForFinalReceiptAck
    // comment: reaching either stage 3 or stage 4 already required passing
    // through the ack gate, which itself requires both keys to exist).
    IssuedReceipt issue_receipt(RoomEntry& room, ReceiptStage stage, bool completed) {
        if (!room.ephemeral_key_a.has_value() || !room.ephemeral_key_b.has_value()) {
            throw std::runtime_error(
                "cannot issue a receipt before both parties have announced an ephemeral trade key");
        }
        ReceiptFields fields;
        fields.mediator_id = mediator_id_;
        fields.room_id = room.id;
        fields.terms_commitment = trade_payload_hash(encode_terms(room.session.terms()));
        fields.party_a_ephemeral_key = *room.ephemeral_key_a;
        fields.party_b_ephemeral_key = *room.ephemeral_key_b;
        fields.mediator_public_key = mediator_receipt_keypair_.public_key;
        fields.stage = stage;
        fields.completed = completed;
        fields.timestamp = now_unix_seconds();
        fields.nonce = random_id<std::array<std::uint8_t, kReceiptNonceLength>>();
        fields.previous_stage_hash =
            (stage == ReceiptStage::SettlementCompleted && room.final_ack_receipt.has_value())
                ? receipt_chain_link_hash(room.final_ack_receipt->fields,
                                          room.final_ack_receipt->mediator_signature)
                : std::array<std::uint8_t, 32>{};

        IssuedReceipt issued;
        issued.fields = fields;
        issued.mediator_signature = sign_receipt(mediator_receipt_keypair_.private_seed, fields);
        if (stage == ReceiptStage::PenultimateObligationsComplete) {
            room.final_ack_receipt = issued;
        }
        return issued;
    }

    static ReceiptIssuedMessage to_wire(const IssuedReceipt& issued) {
        ReceiptIssuedMessage message;
        message.room_id = issued.fields.room_id;
        message.mediator_id = issued.fields.mediator_id;
        message.stage = static_cast<std::uint8_t>(issued.fields.stage);
        message.completed = issued.fields.completed;
        message.terms_commitment = issued.fields.terms_commitment;
        message.party_a_ephemeral_key = issued.fields.party_a_ephemeral_key;
        message.party_b_ephemeral_key = issued.fields.party_b_ephemeral_key;
        message.mediator_public_key = issued.fields.mediator_public_key;
        message.timestamp = issued.fields.timestamp;
        message.nonce = issued.fields.nonce;
        message.previous_stage_hash = issued.fields.previous_stage_hash;
        message.mediator_signature = issued.mediator_signature;
        return message;
    }

    void send_to_room(const std::shared_ptr<RoomEntry>& room,
                      MessageType type,
                      const std::vector<std::uint8_t>& payload) {
        std::shared_ptr<Client> a;
        std::shared_ptr<Client> b;
        {
            std::scoped_lock lock(hub_mutex_);
            const auto a_it = clients_.find(client_id_to_hex(room->party_a));
            const auto b_it = clients_.find(client_id_to_hex(room->party_b));
            if (a_it != clients_.end()) {
                a = a_it->second;
            }
            if (b_it != clients_.end()) {
                b = b_it->second;
            }
        }
        if (a) {
            a->enqueue(type, payload);
        }
        if (b) {
            b->enqueue(type, payload);
        }
    }

    void abort_room(const std::shared_ptr<RoomEntry>& room,
                    std::string reason) {
        reason = safe_reason(std::move(reason));
        {
            std::scoped_lock lock(room->mutex);
            if (!room->active) {
                return;
            }
            room->active = false;
            if (room->session.state() != SessionState::Complete &&
                room->session.state() != SessionState::Aborted) {
                room->session.abort(reason);
            }
        }
        // An aborted room has no recovery value left (nothing further can
        // be resumed), so it is pruned from the persisted snapshot exactly
        // like a completed one - see persist_room_remove()'s comment.
        persist_room_remove(room->id);
        erase_room(room->id, room);
        send_to_room(
            room, MessageType::Abort,
            encode_abort(AbortMessage{room->id, reason}));
    }

    void erase_room(const RoomId& room_id,
                    const std::shared_ptr<RoomEntry>& expected) {
        std::scoped_lock lock(hub_mutex_);
        const auto it = rooms_.find(room_id_to_hex(room_id));
        if (it != rooms_.end() && it->second == expected) {
            rooms_.erase(it);
        }
    }

    // --- Phase 3: mediator-side room persistence -------------------------
    //
    // Builds the durable, address-free snapshot of one room's current
    // state. PRECONDITION: caller already holds `room.mutex` (mirrors the
    // existing informal convention write_state_snapshot() already uses for
    // reading room->session under that same lock).
    static PersistedRoom persisted_room_snapshot(const RoomEntry& room) {
        PersistedRoom snapshot;
        snapshot.room_id = room.id;
        snapshot.party_a = room.party_a;
        snapshot.party_b = room.party_b;
        snapshot.terms = room.session.terms();
        snapshot.state = room.session.state();
        snapshot.round_index = room.session.round_index();
        snapshot.leg_index = room.session.leg_index();
        snapshot.abort_reason = room.session.abort_reason();
        const auto now = std::chrono::system_clock::now();
        snapshot.updated_at =
            static_cast<std::uint64_t>(std::chrono::system_clock::to_time_t(now));
        // Fee terms are not exposed by MediatorSession directly (its
        // accessor surface only exposes `terms()`), so they are threaded
        // through separately by every call site below, which all already
        // have `fee_` (the mediator-wide configured fee) in scope.
        return snapshot;
    }

    // Durably records/updates one room's persisted snapshot - called with
    // `room.mutex` already held, immediately after mutating that room's
    // session state and BEFORE any resulting frame is enqueued to a client,
    // so a crash between "we decided the new state" and "we told a client
    // about it" can never leave disk behind what a client was already told.
    // No-op if persistence is disabled (room_persistence_path_ empty).
    void persist_room_upsert(const RoomEntry& room) {
        if (room_persistence_path_.empty()) {
            return;
        }
        PersistedRoom snapshot = persisted_room_snapshot(room);
        snapshot.fee = fee_;
        std::scoped_lock lock(persistence_mutex_);
        persisted_rooms_[room_id_to_hex(room.id)] = std::move(snapshot);
        write_persisted_rooms_locked();
    }

    // Removes a room from the persisted snapshot - called once a room
    // reaches Complete or Aborted (see the file comment in
    // room_persistence.hpp for why finished rooms are pruned rather than
    // left to accumulate: there is no recovery value left once a room
    // cannot be resumed, so keeping it on disk would be pure unnecessary
    // exposure). No-op if persistence is disabled.
    void persist_room_remove(const RoomId& room_id) {
        if (room_persistence_path_.empty()) {
            return;
        }
        std::scoped_lock lock(persistence_mutex_);
        persisted_rooms_.erase(room_id_to_hex(room_id));
        write_persisted_rooms_locked();
    }

    // PRECONDITION: persistence_mutex_ already held.
    void write_persisted_rooms_locked() {
        PersistedRoomFile file;
        file.rooms.reserve(persisted_rooms_.size());
        for (const auto& [key, room] : persisted_rooms_) {
            (void)key;
            file.rooms.push_back(room);
        }
        write_persisted_rooms(room_persistence_path_, file);
    }

    // Reads back whatever was persisted before this process started (if
    // anything) and reconstructs `rooms_` from it, so a restart no longer
    // silently starts from total amnesia for rooms that were still open.
    // Called once, from run(), before the accept loop starts. Deliberately
    // NOT reusing snapshot_loop()/write_state_snapshot() - see this file's
    // configured_room_persistence_file() comment for why that JSON display
    // feed is the wrong file for this.
    void load_persisted_rooms_at_startup() {
        if (room_persistence_path_.empty()) {
            return;
        }
        PersistedRoomFile file; // throws PersistenceFormatError on a malformed file -
                                 // deliberately NOT caught here, so a corrupted
                                 // persistence file fails the mediator's startup
                                 // loudly rather than silently discarding rooms an
                                 // operator might still be able to recover by hand.
        file = load_persisted_rooms(room_persistence_path_);
        rooms_restored_at_startup_ = 0U;
        if (file.rooms.empty()) {
            return;
        }

        std::scoped_lock hub_lock(hub_mutex_);
        std::scoped_lock persistence_lock(persistence_mutex_);
        std::size_t restored = 0U;
        for (const auto& persisted : file.rooms) {
            const std::string key = room_id_to_hex(persisted.room_id);
            if (rooms_.contains(key)) {
                continue; // should never happen this early, but never clobber
            }
            rooms_.emplace(key, std::make_shared<RoomEntry>(persisted));
            persisted_rooms_[key] = persisted;
            ++restored;
        }
        rooms_restored_at_startup_ = restored;
        if (restored > 0U) {
            std::cout << "Restored " << restored
                      << " room(s) from " << room_persistence_path_
                      << " (state/terms/progress only - receive addresses were never "
                         "persisted and must be re-established before settlement can "
                         "resume; see RecoveryStateRequest).\n";
        }
    }

    void send_error(const std::shared_ptr<Client>& client,
                    const std::string& reason) {
        try {
            client->enqueue(
                MessageType::Error,
                encode_error(ErrorMessage{safe_reason(reason)}));
        } catch (...) {
            client->alive.store(false);
            client->wake();
        }
    }

    void remove_client(const ClientId& client_id) {
        std::vector<std::pair<ClientId, InviteId>> invite_notifications;
        std::vector<std::shared_ptr<RoomEntry>> affected_rooms;

        {
            std::scoped_lock lock(hub_mutex_);
            clients_.erase(client_id_to_hex(client_id));

            for (auto it = offers_.begin(); it != offers_.end();) {
                if (it->second.creator == client_id) {
                    it = offers_.erase(it);
                } else {
                    ++it;
                }
            }

            for (auto it = invites_.begin(); it != invites_.end();) {
                if (it->second.from == client_id) {
                    invite_notifications.emplace_back(it->second.to, it->second.id);
                    it = invites_.erase(it);
                } else if (it->second.to == client_id) {
                    invite_notifications.emplace_back(it->second.from, it->second.id);
                    it = invites_.erase(it);
                } else {
                    ++it;
                }
            }

            for (auto it = rooms_.begin(); it != rooms_.end();) {
                if (it->second->party_a == client_id ||
                    it->second->party_b == client_id) {
                    affected_rooms.push_back(it->second);
                    it = rooms_.erase(it);
                } else {
                    ++it;
                }
            }
        }

        for (const auto& notification : invite_notifications) {
            std::shared_ptr<Client> peer;
            {
                std::scoped_lock lock(hub_mutex_);
                const auto it = clients_.find(client_id_to_hex(notification.first));
                if (it != clients_.end()) {
                    peer = it->second;
                }
            }
            if (peer) {
                peer->enqueue(
                    MessageType::InviteDeclined,
                    encode_invite_declined(InviteDeclinedMessage{
                        notification.second}));
            }
        }

        for (const auto& room : affected_rooms) {
            bool already_inactive = false;
            {
                std::scoped_lock lock(room->mutex);
                if (!room->active) {
                    already_inactive = true;
                } else {
                    room->active = false;
                    if (room->session.state() != SessionState::Complete &&
                        room->session.state() != SessionState::Aborted) {
                        room->session.abort("peer disconnected");
                    }
                }
            }
            if (already_inactive) {
                continue;
            }
            // Same pruning as abort_room(): this room was already removed
            // from rooms_ above (under hub_mutex_), but the persisted
            // snapshot is a separate cache that must be told explicitly.
            persist_room_remove(room->id);
            send_to_room(
                room, MessageType::Abort,
                encode_abort(AbortMessage{room->id, "peer disconnected"}));
        }
    }

    struct OfferSnapshot {
        std::string room_id;
        TradeTerms terms;
    };

    struct RoomSnapshot {
        std::string room_id;
        TradeTerms terms;
        std::string state;
        std::uint32_t round{};
        std::string current_sender;
    };

    void snapshot_loop() {
        while (snapshot_running_.load()) {
            try {
                write_state_snapshot();
            } catch (const std::exception& error) {
                std::cerr << "lobby snapshot failed: " << error.what() << '\n';
            }
            for (int tick = 0; tick < 10 && snapshot_running_.load(); ++tick) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }

    void write_state_snapshot() {
        std::size_t client_count = 0U;
        std::size_t pending_invites = 0U;
        std::vector<OfferSnapshot> offer_snapshots;
        std::vector<std::shared_ptr<RoomEntry>> rooms;
        {
            std::scoped_lock lock(hub_mutex_);
            client_count = clients_.size();
            pending_invites = invites_.size();
            offer_snapshots.reserve(offers_.size());
            for (const auto& [key, offer] : offers_) {
                offer_snapshots.push_back(OfferSnapshot{key, offer.terms});
            }
            rooms.reserve(rooms_.size());
            for (const auto& [key, room] : rooms_) {
                (void)key;
                rooms.push_back(room);
            }
        }

        std::sort(offer_snapshots.begin(), offer_snapshots.end(),
                  [](const OfferSnapshot& left, const OfferSnapshot& right) {
                      return left.room_id < right.room_id;
                  });

        std::vector<RoomSnapshot> room_snapshots;
        room_snapshots.reserve(rooms.size());
        for (const auto& room : rooms) {
            std::scoped_lock lock(room->mutex);
            RoomSnapshot snapshot;
            snapshot.room_id = room_id_to_hex(room->id);
            snapshot.terms = room->session.terms();
            snapshot.state = session_state_name(room->session.state());
            snapshot.round = room->session.round_index() + 1U;
            if (room->session.state() == SessionState::WaitingForSent ||
                room->session.state() == SessionState::WaitingForReceived ||
                room->session.state() == SessionState::WaitingForFeeSent) {
                snapshot.current_sender =
                    room->session.current_sender() == Party::A ? "A" : "B";
            }
            room_snapshots.push_back(std::move(snapshot));
        }
        std::sort(room_snapshots.begin(), room_snapshots.end(),
                  [](const RoomSnapshot& left, const RoomSnapshot& right) {
                      return left.room_id < right.room_id;
                  });

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
             << "\",\"clients\":" << client_count
             << ",\"pending_invites\":" << pending_invites
             << ",\"fee_asset\":\"" << json_escape(fee_.asset)
             << "\",\"fee_amount\":" << fee_.amount
             << ",\"fee_address\":\"" << json_escape(fee_.address)
             << "\",\"room_persistence_enabled\":"
             << (room_persistence_path_.empty() ? "false" : "true")
             << ",\"room_persistence_path\":\""
             << json_escape(room_persistence_path_)
             << "\",\"rooms_restored_at_startup\":" << rooms_restored_at_startup_
             << ",\"offers\":[";

        for (std::size_t index = 0; index < offer_snapshots.size(); ++index) {
            if (index != 0U) {
                json << ',';
            }
            const auto& offer = offer_snapshots[index];
            json << "{\"room_id\":\"" << json_escape(offer.room_id)
                 << "\",\"asset_a\":\"" << json_escape(offer.terms.asset_a)
                 << "\",\"total_a\":" << offer.terms.total_a
                 << ",\"asset_b\":\"" << json_escape(offer.terms.asset_b)
                 << "\",\"total_b\":" << offer.terms.total_b
                 << ",\"rounds\":" << offer.terms.rounds << '}';
        }
        json << "],\"rooms\":[";
        for (std::size_t index = 0; index < room_snapshots.size(); ++index) {
            if (index != 0U) {
                json << ',';
            }
            const auto& room = room_snapshots[index];
            json << "{\"room_id\":\"" << json_escape(room.room_id)
                 << "\",\"state\":\"" << json_escape(room.state)
                 << "\",\"round\":" << room.round
                 << ",\"rounds\":" << room.terms.rounds
                 << ",\"current_sender\":\""
                 << json_escape(room.current_sender)
                 << "\",\"asset_a\":\"" << json_escape(room.terms.asset_a)
                 << "\",\"total_a\":" << room.terms.total_a
                 << ",\"asset_b\":\"" << json_escape(room.terms.asset_b)
                 << "\",\"total_b\":" << room.terms.total_b << '}';
        }
        json << "]}";

        const std::filesystem::path path(state_file_);
        if (path.has_parent_path()) {
            std::filesystem::create_directories(path.parent_path());
        }
        const std::filesystem::path temporary = path.string() + ".tmp";
        {
            std::ofstream output(temporary, std::ios::trunc);
            if (!output.is_open()) {
                throw std::runtime_error("cannot open lobby snapshot temporary file");
            }
            output << json.str() << '\n';
            if (!output.good()) {
                throw std::runtime_error("cannot write lobby snapshot");
            }
        }
        std::error_code error;
        std::filesystem::rename(temporary, path, error);
        if (error) {
            std::filesystem::remove(path, error);
            error.clear();
            std::filesystem::rename(temporary, path, error);
            if (error) {
                throw std::runtime_error("cannot replace lobby snapshot: " +
                                         error.message());
            }
        }
    }

    Endpoint bind_endpoint_;
    ServerTlsIdentity identity_;
    std::string state_file_;
    std::string room_persistence_path_;
    FeeTerms fee_;
    // Phase 6: this mediator's own identifier (matching the "host:port" text
    // convention every client-side mediator_id already uses - see
    // ReceiptAckFields' comment for why the two must agree for a receipt
    // ack's signature to verify) and its receipt-signing keypair.
    std::string mediator_id_;
    Ed25519KeyPair mediator_receipt_keypair_;
    std::atomic<bool> snapshot_running_{false};
    std::thread snapshot_thread_;
    std::atomic<std::size_t> pending_handshakes_{0U};
    std::mutex hub_mutex_;
    std::unordered_map<std::string, std::shared_ptr<Client>> clients_;
    std::unordered_map<std::string, OpenOffer> offers_;
    std::unordered_map<std::string, PendingInvite> invites_;
    std::unordered_map<std::string, std::shared_ptr<RoomEntry>> rooms_;
    // Phase 3 mediator-side room persistence: a cache of the last-known
    // PersistedRoom per room, kept in sync incrementally by
    // persist_room_upsert()/persist_room_remove() so that writing the full
    // snapshot file never requires re-locking every room's own mutex (only
    // the room that was JUST mutated needs its mutex held - the rest of the
    // snapshot comes from this cache, already up to date from whenever it
    // was last touched). Guarded by its own mutex, separate from
    // hub_mutex_/each room's mutex - see persist_room_upsert()'s comment
    // for the lock-ordering discipline this depends on.
    std::mutex persistence_mutex_;
    std::unordered_map<std::string, PersistedRoom> persisted_rooms_;
    // Phase 4 dashboard wiring: how many rooms load_persisted_rooms_at_startup()
    // actually restored the one time it ran (0 if persistence is disabled, or
    // if it is enabled but nothing was on file yet). Surfaced in
    // write_state_snapshot()'s JSON so tradep2p-mediator-dashboard can show
    // this fact instead of only the one-line stdout log above.
    std::size_t rooms_restored_at_startup_{0U};
};

LobbyServer::LobbyServer(Endpoint bind_endpoint, ServerTlsIdentity identity)
    : impl_(std::make_unique<Impl>(std::move(bind_endpoint), std::move(identity))) {}

LobbyServer::~LobbyServer() = default;

void LobbyServer::run() { impl_->run(); }

} // namespace tradep2p
