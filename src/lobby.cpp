#include "tradep2p/lobby.hpp"

#include "tradep2p/mediator.hpp"
#include "tradep2p/protocol.hpp"

#include <openssl/rand.h>

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
    case SessionState::Complete: return "complete";
    case SessionState::Aborted: return "aborted";
    }
    return "unknown";
}

std::string configured_state_file() {
    const char* value = std::getenv("TRADEP2P_LOBBY_STATE_FILE");
    return value == nullptr ? std::string{} : std::string(value);
}

std::string env_or_empty(const char* name) {
    const char* value = std::getenv(name);
    return value == nullptr ? std::string{} : std::string(value);
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
          fee_(configured_fee()) {}

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

        for (;;) {
            SecureChannel channel;
            try {
                channel = listener.accept();
            } catch (const std::exception& error) {
                // A malformed or timed-out TLS handshake is a rejected client,
                // not a fatal mediator error.
                std::cerr << "rejected connection: " << error.what() << '\n';
                continue;
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
                    continue;
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

            std::thread([this, client] { client_loop(client); }).detach();
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

        RoomId id{};
        ClientId party_a{};
        ClientId party_b{};
        MediatorSession session;
        std::mutex mutex;
        bool active{true};
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
            // that leg and needs no separate receipt acknowledgement.
            complete = room->session.state() == SessionState::Complete;
            if (complete) {
                room->active = false;
            }
        }

        if (complete) {
            erase_room(room->id, room);
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
        TurnMessage next_turn;

        {
            std::scoped_lock lock(room->mutex);
            if (!room->active) {
                throw std::runtime_error("room is no longer active");
            }
            const Party reporting_party = party_for(*room, client->id);
            room->session.receiver_reported_received(reporting_party, message);
            sender = client_for_party(*room, other_party(reporting_party));
            complete = room->session.state() == SessionState::Complete;
            if (complete) {
                room->active = false;
            } else {
                next_turn = room->session.current_turn();
            }
        }

        if (sender) {
            sender->enqueue(MessageType::Received, encode_round_signal(message));
        }

        if (complete) {
            erase_room(room->id, room);
            const auto payload = encode_complete(CompleteMessage{room->id});
            send_to_room(room, MessageType::Complete, payload);
        } else {
            send_turn_to_room(room, next_turn);
        }
    }

    void handle_abort(const std::shared_ptr<Client>& client,
                      const AbortMessage& message) {
        const auto room = find_room_for(client->id, message.room_id);
        abort_room(room, message.reason);
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
            {
                std::scoped_lock lock(room->mutex);
                if (!room->active) {
                    continue;
                }
                room->active = false;
                if (room->session.state() != SessionState::Complete &&
                    room->session.state() != SessionState::Aborted) {
                    room->session.abort("peer disconnected");
                }
            }
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
             << "\",\"offers\":[";

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
    FeeTerms fee_;
    std::atomic<bool> snapshot_running_{false};
    std::thread snapshot_thread_;
    std::mutex hub_mutex_;
    std::unordered_map<std::string, std::shared_ptr<Client>> clients_;
    std::unordered_map<std::string, OpenOffer> offers_;
    std::unordered_map<std::string, PendingInvite> invites_;
    std::unordered_map<std::string, std::shared_ptr<RoomEntry>> rooms_;
};

LobbyServer::LobbyServer(Endpoint bind_endpoint, ServerTlsIdentity identity)
    : impl_(std::make_unique<Impl>(std::move(bind_endpoint), std::move(identity))) {}

LobbyServer::~LobbyServer() = default;

void LobbyServer::run() { impl_->run(); }

} // namespace tradep2p
