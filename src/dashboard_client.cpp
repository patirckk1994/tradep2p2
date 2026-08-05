#include "tradep2p/dashboard_client.hpp"

#include <openssl/rand.h>

#include <poll.h>

#include <array>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace tradep2p::dashboard {

namespace {
constexpr std::size_t kMaxEvents = 160U;
constexpr int kDashboardPollMilliseconds = 250;
} // namespace

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

std::string now_text() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t timestamp = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    if (::localtime_r(&timestamp, &tm) == nullptr) {
        return "time-unavailable";
    }
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return out.str();
}

std::string random_token() {
    std::array<unsigned char, 24> bytes{};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed while creating a session token");
    }
    static constexpr char digits[] = "0123456789abcdef";
    std::string token;
    token.reserve(bytes.size() * 2U);
    for (const unsigned char byte : bytes) {
        token.push_back(digits[(byte >> 4U) & 0x0fU]);
        token.push_back(digits[byte & 0x0fU]);
    }
    return token;
}

const char* party_name(Party party) {
    return party == Party::A ? "A" : "B";
}

DashboardClient::DashboardClient(Endpoint mediator,
                                 ClientTlsPolicy tls_policy,
                                 std::optional<Endpoint> socks_proxy)
    : mediator_(std::move(mediator)),
      tls_policy_(std::move(tls_policy)),
      socks_proxy_(std::move(socks_proxy)) {}

DashboardClient::~DashboardClient() {
    stop_.store(true);
    if (worker_.joinable()) {
        worker_.join();
    }
}

void DashboardClient::start() {
    worker_ = std::thread([this] { worker_loop(); });
}

void DashboardClient::refresh_offers() {
    enqueue(MessageType::ListOffers,
            tradep2p::encode_list_offers(ListOffersMessage{}),
            "requested open-offer list");
}

void DashboardClient::create_offer(const TradeTerms& terms, const std::string& address) {
    tradep2p::validate_terms(terms);
    tradep2p::validate_address(address);
    enqueue(MessageType::CreateOffer,
            tradep2p::encode_create_offer(CreateOfferMessage{terms, address}),
            "submitted a new offer");
}

void DashboardClient::join_offer(const std::string& room_text, const std::string& address) {
    const RoomId room_id = tradep2p::room_id_from_hex(room_text);
    tradep2p::validate_address(address);
    enqueue(MessageType::JoinOffer,
            tradep2p::encode_join_offer(JoinOfferMessage{room_id, address}),
            "requested to join room " + tradep2p::room_id_to_hex(room_id));
}

void DashboardClient::cancel_offer(const std::string& room_text) {
    const RoomId room_id = tradep2p::room_id_from_hex(room_text);
    enqueue(MessageType::CancelOffer,
            tradep2p::encode_cancel_offer(CancelOfferMessage{room_id}),
            "requested cancellation of room " + tradep2p::room_id_to_hex(room_id));
}

void DashboardClient::mark_sent(const std::string& room_text) {
    enqueue_turn_signal(room_text, true);
}

void DashboardClient::mark_received(const std::string& room_text) {
    enqueue_turn_signal(room_text, false);
}

void DashboardClient::abort_room(const std::string& room_text) {
    const RoomId room_id = tradep2p::room_id_from_hex(room_text);
    enqueue(MessageType::Abort,
            tradep2p::encode_abort(AbortMessage{room_id, "dashboard user aborted"}),
            "requested abort of room " + tradep2p::room_id_to_hex(room_id));
}

std::string DashboardClient::state_json() const {
    std::scoped_lock lock(state_mutex_);
    std::ostringstream json;
    json << "{\"connected\":" << (connected_ ? "true" : "false")
         << ",\"connection_status\":\"" << json_escape(connection_status_)
         << "\",\"client_id\":\"" << json_escape(client_id_) << "\""
         << ",\"revision\":" << revision_
         << ",\"mediator_fee_asset\":\"" << json_escape(mediator_fee_.asset)
         << "\",\"mediator_fee_amount\":" << mediator_fee_.amount
         << ",\"mediator_fee_address\":\"" << json_escape(mediator_fee_.address)
         << "\",\"offers\":[";

    for (std::size_t index = 0; index < offers_.size(); ++index) {
        if (index != 0U) {
            json << ',';
        }
        const auto& offer = offers_[index];
        json << "{\"room_id\":\"" << json_escape(offer.room_id)
             << "\",\"sell_asset\":\"" << json_escape(offer.terms.asset_a)
             << "\",\"sell_amount\":" << offer.terms.total_a
             << ",\"buy_asset\":\"" << json_escape(offer.terms.asset_b)
             << "\",\"buy_amount\":" << offer.terms.total_b
             << ",\"rounds\":" << offer.terms.rounds << '}';
    }
    json << "],\"rooms\":[";

    bool first_room = true;
    for (const auto& [room_id, room] : rooms_) {
        (void)room_id;
        if (!first_room) {
            json << ',';
        }
        first_room = false;
        const bool is_fee_turn =
            room.has_turn && room.turn.round_index >= room.terms.rounds;
        std::string action = "none";
        if (room.status == "active" && room.has_turn) {
            if (is_fee_turn) {
                action = room.party == room.turn.sender ? "sent" : "none";
            } else {
                action = room.party == room.turn.sender ? "sent" : "received";
            }
        }
        json << "{\"room_id\":\"" << json_escape(room.room_id)
             << "\",\"peer_id\":\"" << json_escape(room.peer_id)
             << "\",\"party\":\"" << party_name(room.party)
             << "\",\"status\":\"" << json_escape(room.status)
             << "\",\"detail\":\"" << json_escape(room.detail)
             << "\",\"sell_asset\":\"" << json_escape(room.terms.asset_a)
             << "\",\"sell_amount\":" << room.terms.total_a
             << ",\"buy_asset\":\"" << json_escape(room.terms.asset_b)
             << "\",\"buy_amount\":" << room.terms.total_b
             << ",\"rounds\":" << room.terms.rounds
             << ",\"receive_address_a\":\"" << json_escape(room.receive_address_a)
             << "\",\"receive_address_b\":\"" << json_escape(room.receive_address_b)
             << "\",\"fee_asset\":\"" << json_escape(room.fee.asset)
             << "\",\"fee_amount\":" << room.fee.amount
             << ",\"fee_address\":\"" << json_escape(room.fee.address)
             << "\",\"has_turn\":" << (room.has_turn ? "true" : "false")
             << ",\"action\":\"" << action << "\"";
        if (room.has_turn) {
            json << ",\"turn\":{\"round\":" << (room.turn.round_index + 1U)
                 << ",\"is_fee\":" << (is_fee_turn ? "true" : "false")
                 << ",\"sender\":\"" << party_name(room.turn.sender)
                 << "\",\"asset\":\"" << json_escape(room.turn.asset)
                 << "\",\"amount\":" << room.turn.amount
                 << ",\"destination\":\"" << json_escape(room.turn.destination) << "\"}";
        } else {
            json << ",\"turn\":null";
        }
        json << '}';
    }
    json << "],\"events\":[";
    for (std::size_t index = 0; index < events_.size(); ++index) {
        if (index != 0U) {
            json << ',';
        }
        json << '"' << json_escape(events_[index]) << '"';
    }
    json << "]}";
    return json.str();
}

void DashboardClient::enqueue(MessageType type,
                              std::vector<std::uint8_t> payload,
                              std::string description) {
    {
        std::scoped_lock lock(state_mutex_);
        if (!connected_) {
            throw std::runtime_error("dashboard client is not connected");
        }
    }
    std::scoped_lock lock(queue_mutex_);
    outgoing_.push_back(OutgoingFrame{type, std::move(payload), std::move(description)});
}

void DashboardClient::enqueue_turn_signal(const std::string& room_text, bool sent) {
    const RoomId room_id = tradep2p::room_id_from_hex(room_text);
    const std::string canonical = tradep2p::room_id_to_hex(room_id);
    RoundSignalMessage signal;
    {
        std::scoped_lock lock(state_mutex_);
        const auto room_it = rooms_.find(canonical);
        if (room_it == rooms_.end() || room_it->second.status != "active" ||
            !room_it->second.has_turn) {
            throw std::invalid_argument("room has no active turn");
        }
        const bool am_sender = room_it->second.party == room_it->second.turn.sender;
        if (sent && !am_sender) {
            throw std::invalid_argument("this dashboard client is not the current sender");
        }
        if (!sent && am_sender) {
            throw std::invalid_argument("this dashboard client is not the current receiver");
        }
        signal = RoundSignalMessage{room_id, room_it->second.turn.round_index,
                                    room_it->second.turn.sender};
    }
    enqueue(sent ? MessageType::Sent : MessageType::Received,
            tradep2p::encode_round_signal(signal),
            std::string(sent ? "reported sent in room " : "reported received in room ") +
                canonical);
}

void DashboardClient::add_event_locked(const std::string& message) {
    events_.push_front(now_text() + " | " + message);
    while (events_.size() > kMaxEvents) {
        events_.pop_back();
    }
    ++revision_;
}

void DashboardClient::set_disconnected(const std::string& reason) {
    {
        std::scoped_lock lock(state_mutex_);
        connected_ = false;
        connection_status_ = reason;
        add_event_locked(reason);
    }
    {
        std::scoped_lock lock(queue_mutex_);
        outgoing_.clear();
    }
}

void DashboardClient::worker_loop() {
    while (!stop_.load()) {
        try {
            SecureChannel channel = socks_proxy_.has_value()
                ? SecureChannel::connect_via_socks5(*socks_proxy_, mediator_, tls_policy_)
                : SecureChannel::connect_direct(mediator_, tls_policy_);
            channel.set_timeout(30U);
            const Frame welcome_frame = channel.receive_frame();
            if (welcome_frame.type != MessageType::Welcome) {
                throw std::runtime_error("mediator did not send a welcome message");
            }
            const auto welcome = tradep2p::decode_welcome(welcome_frame.payload);
            {
                std::scoped_lock lock(state_mutex_);
                connected_ = true;
                connection_status_ = "connected";
                client_id_ = tradep2p::client_id_to_hex(welcome.client_id);
                mediator_fee_ = welcome.fee;
                offers_.clear();
                rooms_.clear();
                add_event_locked("connected as anonymous client " + client_id_);
            }
            channel.send_frame(MessageType::ListOffers,
                               tradep2p::encode_list_offers(ListOffersMessage{}));
            session_loop(channel);
        } catch (const std::exception& error) {
            if (!stop_.load()) {
                set_disconnected(std::string("connection lost: ") + error.what());
                for (int tick = 0; tick < 12 && !stop_.load(); ++tick) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(250));
                }
            }
        }
    }
}

void DashboardClient::session_loop(SecureChannel& channel) {
    while (!stop_.load()) {
        flush_outgoing(channel);

        pollfd descriptor{};
        descriptor.fd = channel.native_handle();
        descriptor.events = POLLIN;
        const bool pending = channel.has_pending_input();
        const int result = ::poll(&descriptor, 1, pending ? 0 : kDashboardPollMilliseconds);
        if (result < 0) {
            throw std::runtime_error("dashboard socket poll failed");
        }
        if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            throw std::runtime_error("mediator connection closed");
        }
        if (pending || (descriptor.revents & POLLIN) != 0) {
            do {
                handle_frame(channel.receive_frame());
            } while (channel.has_pending_input());
        }
    }
    try {
        channel.send_frame(MessageType::Disconnect, {});
    } catch (...) {
    }
}

void DashboardClient::flush_outgoing(SecureChannel& channel) {
    std::deque<OutgoingFrame> frames;
    {
        std::scoped_lock lock(queue_mutex_);
        frames.swap(outgoing_);
    }
    for (const auto& frame : frames) {
        channel.send_frame(frame.type, frame.payload);
        std::scoped_lock lock(state_mutex_);
        add_event_locked(frame.description);
    }
}

void DashboardClient::handle_frame(const Frame& frame) {
    bool refresh_offers_after = false;
    {
        std::scoped_lock lock(state_mutex_);
        switch (frame.type) {
        case MessageType::OfferCreated: {
            const auto message = tradep2p::decode_offer_created(frame.payload);
            add_event_locked("offer room created: " + tradep2p::room_id_to_hex(message.room_id));
            refresh_offers_after = true;
            break;
        }
        case MessageType::OfferList: {
            const auto message = tradep2p::decode_offer_list(frame.payload);
            offers_.clear();
            offers_.reserve(message.offers.size());
            for (const auto& offer : message.offers) {
                offers_.push_back(OfferView{tradep2p::room_id_to_hex(offer.room_id), offer.terms});
            }
            add_event_locked("open-offer list updated: " + std::to_string(offers_.size()) +
                             " offer(s)");
            break;
        }
        case MessageType::OfferCancelled: {
            const auto message = tradep2p::decode_offer_cancelled(frame.payload);
            const std::string room_id = tradep2p::room_id_to_hex(message.room_id);
            std::erase_if(offers_, [&](const OfferView& offer) { return offer.room_id == room_id; });
            add_event_locked("offer cancelled: " + room_id);
            refresh_offers_after = true;
            break;
        }
        case MessageType::TradeReady: {
            const auto message = tradep2p::decode_trade_ready(frame.payload);
            const std::string room_id = tradep2p::room_id_to_hex(message.room_id);
            RoomView room;
            room.room_id = room_id;
            room.peer_id = tradep2p::client_id_to_hex(message.peer_id);
            room.party = message.assigned_party;
            room.terms = message.terms;
            room.receive_address_a = message.receive_address_a;
            room.receive_address_b = message.receive_address_b;
            room.fee = message.fee;
            room.status = "active";
            rooms_[room_id] = std::move(room);
            std::erase_if(offers_, [&](const OfferView& offer) { return offer.room_id == room_id; });
            add_event_locked("room ready: " + room_id + " as party " +
                             party_name(message.assigned_party));
            refresh_offers_after = true;
            break;
        }
        case MessageType::Turn: {
            const auto message = tradep2p::decode_turn(frame.payload);
            const std::string room_id = tradep2p::room_id_to_hex(message.room_id);
            auto& room = rooms_[room_id];
            room.room_id = room_id;
            room.turn = message;
            room.has_turn = true;
            room.status = "active";
            add_event_locked("room " + room_id + " round " +
                             std::to_string(message.round_index + 1U) + " turn: party " +
                             party_name(message.sender) + " sends " +
                             std::to_string(message.amount) + " " + message.asset);
            break;
        }
        case MessageType::Sent: {
            const auto message = tradep2p::decode_round_signal(frame.payload);
            add_event_locked("peer reported sent in room " +
                             tradep2p::room_id_to_hex(message.room_id));
            break;
        }
        case MessageType::Received: {
            const auto message = tradep2p::decode_round_signal(frame.payload);
            add_event_locked("peer reported receipt in room " +
                             tradep2p::room_id_to_hex(message.room_id));
            break;
        }
        case MessageType::Complete: {
            const auto message = tradep2p::decode_complete(frame.payload);
            const std::string room_id = tradep2p::room_id_to_hex(message.room_id);
            auto& room = rooms_[room_id];
            room.room_id = room_id;
            room.status = "complete";
            room.detail = "all rounds completed";
            room.has_turn = false;
            add_event_locked("room complete: " + room_id);
            break;
        }
        case MessageType::Abort: {
            const auto message = tradep2p::decode_abort(frame.payload);
            const std::string room_id = tradep2p::room_id_to_hex(message.room_id);
            auto& room = rooms_[room_id];
            room.room_id = room_id;
            room.status = "aborted";
            room.detail = message.reason;
            room.has_turn = false;
            add_event_locked("room aborted: " + room_id + " - " + message.reason);
            break;
        }
        case MessageType::Error: {
            const auto message = tradep2p::decode_error(frame.payload);
            add_event_locked("server rejected request: " + message.reason);
            break;
        }
        default:
            add_event_locked("ignored unexpected mediator message type " +
                             std::to_string(static_cast<unsigned int>(frame.type)));
            break;
        }
    }

    if (refresh_offers_after) {
        std::scoped_lock lock(queue_mutex_);
        outgoing_.push_back(OutgoingFrame{MessageType::ListOffers,
                                          tradep2p::encode_list_offers(ListOffersMessage{}),
                                          "refreshed open offers"});
    }
}

} // namespace tradep2p::dashboard
