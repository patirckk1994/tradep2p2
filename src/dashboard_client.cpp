#include "tradep2p/dashboard_client.hpp"

#include <openssl/rand.h>

#include <poll.h>

#include <array>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <span>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace tradep2p::dashboard {

namespace {
constexpr std::size_t kMaxEvents = 160U;
constexpr int kDashboardPollMilliseconds = 250;

std::string hex_encode_bytes(std::span<const std::uint8_t> bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2U);
    for (const std::uint8_t byte : bytes) {
        out.push_back(digits[(byte >> 4U) & 0x0fU]);
        out.push_back(digits[byte & 0x0fU]);
    }
    return out;
}
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
                                 std::optional<Endpoint> socks_proxy,
                                 std::string mediator_id)
    : mediator_(std::move(mediator)),
      tls_policy_(std::move(tls_policy)),
      socks_proxy_(std::move(socks_proxy)),
      mediator_id_(std::move(mediator_id)) {}

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

void DashboardClient::recognize(const std::string& room_text) {
    const RoomId room_id = tradep2p::room_id_from_hex(room_text);
    const std::string canonical = tradep2p::room_id_to_hex(room_id);
    RecognitionChallengeFields fields;
    {
        std::scoped_lock lock(state_mutex_);
        const auto room_it = rooms_.find(canonical);
        if (room_it == rooms_.end() || room_it->second.status != "active") {
            throw std::invalid_argument("room is not currently active");
        }
        fields = recognition_tracker_.issue(mediator_id_, room_id);
        room_it->second.recognition_status = "challenge_sent";
        room_it->second.recognized_fingerprint_hex.clear();
        room_it->second.has_recognition_challenge = true;
        room_it->second.recognition_challenge_nonce_hex = hex_encode_bytes(fields.nonce);
        room_it->second.recognition_challenge_created_at = fields.created_at;
        room_it->second.recognition_challenge_expires_at = fields.expires_at;
        room_it->second.recognition_challenge_suite_id = fields.suite_id;
    }
    RecognitionChallengeMessage wire;
    wire.room_id = fields.room_id;
    wire.suite_id = fields.suite_id;
    wire.nonce = fields.nonce;
    wire.created_at = fields.created_at;
    wire.expires_at = fields.expires_at;
    enqueue(MessageType::RecognitionChallenge, tradep2p::encode_recognition_challenge(wire),
            "sent recognition challenge for room " + canonical);
}

void DashboardClient::set_recognition_key_provider(RecognitionKeyProvider provider) {
    recognition_key_provider_ = std::move(provider);
}

void DashboardClient::set_recognition_outcome_handler(RecognitionOutcomeHandler handler) {
    recognition_outcome_handler_ = std::move(handler);
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
         << "\",\"tls\":{\"protocol_version\":\"" << json_escape(tls_session_.protocol_version)
         << "\",\"cipher_suite\":\"" << json_escape(tls_session_.cipher_suite)
         << "\",\"negotiated_group\":\"" << json_escape(tls_session_.negotiated_group)
         << "\",\"peer_certificate_sha256\":\""
         << json_escape(tls_session_.peer_certificate_sha256_hex)
         << "\",\"peer_certificate_signature_algorithm\":\""
         << json_escape(tls_session_.peer_certificate_signature_algorithm) << "\"}"
         << ",\"mediator_receipt_key\":\""
         << (mediator_receipt_key_.has_value() ? hex_encode_bytes(*mediator_receipt_key_) : "")
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
            } else if (room.party == room.turn.sender) {
                action = "sent";
            } else if (room.peer_sent_this_turn) {
                action = "received";
            } else {
                // The round has started but the sender hasn't reported Sent
                // yet - nothing to confirm, so this must not read as
                // "received" (that would make the confirm button live
                // before there's anything to confirm).
                action = "awaiting_peer_send";
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
             << ",\"action\":\"" << action << "\""
             << ",\"recognition_status\":\"" << json_escape(room.recognition_status) << "\""
             << ",\"recognized_fingerprint\":\"" << json_escape(room.recognized_fingerprint_hex) << "\""
             << ",\"own_ephemeral_key\":\"" << json_escape(room.own_ephemeral_public_key_hex) << "\""
             << ",\"counterparty_ephemeral_key\":\""
             << json_escape(room.counterparty_ephemeral_public_key_hex) << "\""
             << ",\"receipt_status\":\"" << json_escape(room.receipt_status) << "\""
             << ",\"receipt_chain_verifies\":" << (room.receipt_chain_verifies ? "true" : "false");

        // Crypto telemetry - display only, mirrors the trust decisions
        // already reflected in recognition_status/receipt_chain_verifies
        // above rather than making any of its own.
        json << ",\"recognition_challenge\":";
        if (room.has_recognition_challenge) {
            json << "{\"nonce\":\"" << json_escape(room.recognition_challenge_nonce_hex)
                 << "\",\"suite_id\":" << room.recognition_challenge_suite_id
                 << ",\"created_at\":" << room.recognition_challenge_created_at
                 << ",\"expires_at\":" << room.recognition_challenge_expires_at << "}";
        } else {
            json << "null";
        }
        json << ",\"recognition_response\":";
        if (room.has_recognition_response) {
            json << "{\"public_key\":\"" << json_escape(room.recognition_response_public_key_hex)
                 << "\",\"signature\":\"" << json_escape(room.recognition_response_signature_hex)
                 << "\"}";
        } else {
            json << "null";
        }
        json << ",\"own_recognition_response_signature\":\""
             << json_escape(room.own_recognition_response_signature_hex) << "\"";

        json << ",\"receipts\":[";
        if (const auto receipts_it = room_receipts_.find(room.room_id);
            receipts_it != room_receipts_.end()) {
            bool first_receipt = true;
            for (const auto& issued : receipts_it->second) {
                if (!first_receipt) {
                    json << ',';
                }
                first_receipt = false;
                const auto link_hash =
                    receipt_chain_link_hash(issued.fields, issued.mediator_signature);
                json << "{\"stage\":\"" << receipt_stage_name(issued.fields.stage) << "\""
                     << ",\"completed\":" << (issued.fields.completed ? "true" : "false")
                     << ",\"suite_id\":" << issued.fields.suite_id
                     << ",\"timestamp\":" << issued.fields.timestamp
                     << ",\"nonce\":\"" << hex_encode_bytes(issued.fields.nonce) << "\""
                     << ",\"terms_commitment\":\""
                     << hex_encode_bytes(issued.fields.terms_commitment) << "\""
                     << ",\"party_a_ephemeral_key\":\""
                     << hex_encode_bytes(issued.fields.party_a_ephemeral_key) << "\""
                     << ",\"party_b_ephemeral_key\":\""
                     << hex_encode_bytes(issued.fields.party_b_ephemeral_key) << "\""
                     << ",\"mediator_public_key\":\""
                     << hex_encode_bytes(issued.fields.mediator_public_key) << "\""
                     << ",\"previous_stage_hash\":\""
                     << hex_encode_bytes(issued.fields.previous_stage_hash) << "\""
                     << ",\"mediator_signature\":\""
                     << hex_encode_bytes(issued.mediator_signature) << "\""
                     << ",\"chain_link_hash\":\"" << hex_encode_bytes(link_hash) << "\"}";
            }
        }
        json << "]";

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
                tls_session_ = channel.session_info();
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
    // Phase 4b: computed under state_mutex_ below but only ACTED ON after
    // it is released, since answering a challenge (recognition_key_provider_)
    // and reporting an outcome (recognition_outcome_handler_) both call back
    // into caller-supplied code that may take a DIFFERENT lock
    // (IdentityDashboardState::mutex in http_dashboard.cpp) - see this
    // class's header comment on set_recognition_key_provider() for the
    // lock-ordering discipline this preserves.
    std::optional<RecognitionChallengeMessage> challenge_to_answer;
    std::optional<std::pair<std::array<std::uint8_t, 32>, RecognitionOutcome>> outcome_to_report;
    // Phase 5: generating the keypair happens under the lock below (cheap,
    // no external callback involved), but SENDING the announcement must
    // happen after it releases, same reasoning as every other post-lock
    // action in this function.
    std::optional<TradeEphemeralKeyMessage> ephemeral_key_to_announce;
    // Phase 6: same "compute under lock, send after unlock" reasoning -
    // signing itself needs no external callback (the ephemeral private key
    // is already this object's own state), but enqueue() cannot be called
    // while state_mutex_ is held.
    std::optional<ReceiptAckMessage> receipt_ack_to_send;
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

            // Phase 5: every room automatically announces a fresh
            // ephemeral trade key - see ephemeral.hpp for why this is safe
            // to do by default (unlike phase 4b's opt-in recognition): a
            // freshly random, never-derived key reveals nothing linkable.
            auto ephemeral_keypair = generate_ephemeral_trade_keypair();
            room.own_ephemeral_public_key_hex = hex_encode_bytes(ephemeral_keypair.public_key);
            TradeEphemeralKeyMessage announce;
            announce.room_id = message.room_id;
            announce.ephemeral_public_key = ephemeral_keypair.public_key;
            ephemeral_keypairs_.erase(room_id);
            ephemeral_keypairs_.emplace(room_id, std::move(ephemeral_keypair));
            ephemeral_key_to_announce = announce;

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
            room.peer_sent_this_turn = false;
            room.status = "active";
            add_event_locked("room " + room_id + " round " +
                             std::to_string(message.round_index + 1U) + " turn: party " +
                             party_name(message.sender) + " sends " +
                             std::to_string(message.amount) + " " + message.asset);
            break;
        }
        case MessageType::Sent: {
            const auto message = tradep2p::decode_round_signal(frame.payload);
            const std::string room_id = tradep2p::room_id_to_hex(message.room_id);
            rooms_[room_id].peer_sent_this_turn = true;
            add_event_locked("peer reported sent in room " + room_id);
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
            if (room.has_recognized_fingerprint) {
                outcome_to_report = {room.recognized_fingerprint, RecognitionOutcome::Successful};
            }
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
            if (room.has_recognized_fingerprint) {
                outcome_to_report = {room.recognized_fingerprint, RecognitionOutcome::Incomplete};
            }
            add_event_locked("room aborted: " + room_id + " - " + message.reason);
            break;
        }
        case MessageType::Error: {
            const auto message = tradep2p::decode_error(frame.payload);
            add_event_locked("server rejected request: " + message.reason);
            break;
        }
        case MessageType::RecognitionChallenge: {
            // Signing and sending the response both need to happen OUTSIDE
            // this lock (see the header comment above) - just decode and
            // defer here.
            challenge_to_answer = tradep2p::decode_recognition_challenge(frame.payload);
            add_event_locked("room " + tradep2p::room_id_to_hex(challenge_to_answer->room_id) +
                             ": counterparty requested recognition proof");
            break;
        }
        case MessageType::TradeEphemeralKey: {
            const auto message = tradep2p::decode_trade_ephemeral_key(frame.payload);
            const std::string room_id = tradep2p::room_id_to_hex(message.room_id);
            const auto parsed = tradep2p::parse_ed25519_public_key(message.ephemeral_public_key);
            auto& room = rooms_[room_id];
            room.room_id = room_id;
            if (!parsed.has_value()) {
                add_event_locked("room " + room_id + ": counterparty announced a malformed ephemeral key");
                break;
            }
            room.counterparty_ephemeral_public_key_hex = hex_encode_bytes(*parsed);
            add_event_locked("room " + room_id + ": counterparty announced ephemeral trade key " +
                             room.counterparty_ephemeral_public_key_hex);
            break;
        }
        case MessageType::ReceiptAckRequired: {
            const auto message = tradep2p::decode_receipt_ack_required(frame.payload);
            const std::string room_id = tradep2p::room_id_to_hex(message.room_id);
            auto& room = rooms_[room_id];
            room.room_id = room_id;
            room.receipt_status = "gate_open";
            const auto keypair_it = ephemeral_keypairs_.find(room_id);
            if (keypair_it == ephemeral_keypairs_.end()) {
                add_event_locked("room " + room_id +
                                 ": cannot acknowledge final-receipt gate - no ephemeral key for "
                                 "this room");
                break;
            }
            ReceiptAckFields fields;
            fields.mediator_id = mediator_id_;
            fields.room_id = message.room_id;
            fields.stage = ReceiptStage::PenultimateObligationsComplete;
            fields.terms_commitment = trade_payload_hash(encode_terms(room.terms));
            fields.timestamp = static_cast<std::uint64_t>(std::time(nullptr));

            ReceiptAckMessage ack;
            ack.room_id = message.room_id;
            ack.stage = static_cast<std::uint8_t>(ReceiptStage::PenultimateObligationsComplete);
            ack.timestamp = fields.timestamp;
            ack.signature = sign_receipt_ack(keypair_it->second.private_seed, fields);
            receipt_ack_to_send = ack;
            add_event_locked("room " + room_id + ": final-receipt gate opened, acknowledged");
            break;
        }
        case MessageType::ReceiptIssued: {
            const auto message = tradep2p::decode_receipt_issued(frame.payload);
            const std::string room_id = tradep2p::room_id_to_hex(message.room_id);
            auto& room = rooms_[room_id];
            room.room_id = room_id;
            const auto stage = static_cast<ReceiptStage>(message.stage);

            IssuedReceipt issued;
            issued.fields.mediator_id = message.mediator_id;
            issued.fields.room_id = message.room_id;
            issued.fields.terms_commitment = message.terms_commitment;
            issued.fields.party_a_ephemeral_key = message.party_a_ephemeral_key;
            issued.fields.party_b_ephemeral_key = message.party_b_ephemeral_key;
            issued.fields.mediator_public_key = message.mediator_public_key;
            issued.fields.stage = stage;
            issued.fields.completed = message.completed;
            issued.fields.timestamp = message.timestamp;
            issued.fields.nonce = message.nonce;
            issued.fields.previous_stage_hash = message.previous_stage_hash;
            issued.mediator_signature = message.mediator_signature;

            room.receipt_status = stage == ReceiptStage::SettlementCompleted ? "stage4" : "stage3";

            if (!mediator_receipt_key_.has_value()) {
                mediator_receipt_key_ = message.mediator_public_key;
            }
            if (*mediator_receipt_key_ != message.mediator_public_key ||
                !verify_receipt(*mediator_receipt_key_, issued.fields, issued.mediator_signature)) {
                room.receipt_chain_verifies = false;
                add_event_locked("room " + room_id +
                                 ": WARNING - receipt did not verify against the pinned mediator "
                                 "key, discarding");
                break;
            }

            auto& chain = room_receipts_[room_id];
            chain.push_back(issued);
            try {
                verify_receipt_chain(chain, *mediator_receipt_key_);
                room.receipt_chain_verifies = true;
            } catch (const ReceiptChainError&) {
                room.receipt_chain_verifies = false;
            }
            add_event_locked("room " + room_id + ": receipt issued - stage " +
                             receipt_stage_name(stage) +
                             (room.receipt_chain_verifies ? " (chain verifies)" : " (chain INVALID)"));
            break;
        }
        case MessageType::RecognitionResponse: {
            const auto message = tradep2p::decode_recognition_response(frame.payload);
            const std::string room_id = tradep2p::room_id_to_hex(message.room_id);
            const auto fingerprint = recognition_tracker_.consume(mediator_id_, message);
            auto& room = rooms_[room_id];
            room.room_id = room_id;
            // Telemetry only, captured regardless of whether it verified -
            // recognition_status (set below) remains the sole trust-relevant
            // signal, exactly as consume() already decided it.
            room.has_recognition_response = true;
            room.recognition_response_public_key_hex = hex_encode_bytes(message.prover_public_key);
            room.recognition_response_signature_hex = hex_encode_bytes(message.signature);
            if (!fingerprint.has_value()) {
                room.recognition_status = "failed";
                add_event_locked(
                    "room " + room_id +
                    ": recognition response did not verify - treated as no proof, not evidence "
                    "of anything");
                break;
            }
            room.recognition_status = "recognized";
            room.recognized_fingerprint = *fingerprint;
            room.has_recognized_fingerprint = true;
            room.recognized_fingerprint_hex = hex_encode_bytes(*fingerprint);
            add_event_locked("room " + room_id + ": counterparty proved control of " +
                             room.recognized_fingerprint_hex);
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

    // Phase 4b post-lock actions - see the comment above the locked block
    // for why these cannot run while state_mutex_ is held.
    if (challenge_to_answer.has_value()) {
        const auto key = recognition_key_provider_ ? recognition_key_provider_() : std::nullopt;
        const std::string room_id = tradep2p::room_id_to_hex(challenge_to_answer->room_id);
        if (!key.has_value()) {
            // Declining is not evidence of anything (specs.txt SS8.2) - no
            // keystore unlocked means nothing to prove control with.
            std::scoped_lock lock(state_mutex_);
            auto& room = rooms_[room_id];
            room.room_id = room_id;
            room.recognition_status = "declined";
            add_event_locked("room " + room_id +
                             ": no keystore unlocked, declined to answer recognition challenge");
        } else {
            RecognitionChallengeFields fields;
            fields.suite_id = challenge_to_answer->suite_id;
            fields.protocol_version = tradep2p::kProtocolVersion;
            fields.mediator_id = mediator_id_;
            fields.room_id = challenge_to_answer->room_id;
            fields.nonce = challenge_to_answer->nonce;
            fields.created_at = challenge_to_answer->created_at;
            fields.expires_at = challenge_to_answer->expires_at;

            RecognitionResponseMessage response;
            response.room_id = challenge_to_answer->room_id;
            response.nonce = challenge_to_answer->nonce;
            response.prover_public_key = key->public_key;
            response.signature = tradep2p::sign_recognition_response(key->private_seed, fields);
            {
                std::scoped_lock lock(state_mutex_);
                auto& room = rooms_[room_id];
                room.room_id = room_id;
                room.own_recognition_response_signature_hex = hex_encode_bytes(response.signature);
            }
            enqueue(MessageType::RecognitionResponse, tradep2p::encode_recognition_response(response),
                    "answered recognition challenge for room " + room_id);
        }
    }

    if (outcome_to_report.has_value() && recognition_outcome_handler_) {
        recognition_outcome_handler_(outcome_to_report->first, outcome_to_report->second);
    }

    if (ephemeral_key_to_announce.has_value()) {
        enqueue(MessageType::TradeEphemeralKey,
                tradep2p::encode_trade_ephemeral_key(*ephemeral_key_to_announce),
                "announced ephemeral trade key for room " +
                    tradep2p::room_id_to_hex(ephemeral_key_to_announce->room_id));
    }

    if (receipt_ack_to_send.has_value()) {
        enqueue(MessageType::ReceiptAck, tradep2p::encode_receipt_ack(*receipt_ack_to_send),
                "acknowledged final-receipt gate for room " +
                    tradep2p::room_id_to_hex(receipt_ack_to_send->room_id));
    }
}

} // namespace tradep2p::dashboard
