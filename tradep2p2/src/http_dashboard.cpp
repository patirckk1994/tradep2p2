#include <httplib.h>

#include "tradep2p/protocol.hpp"
#include "tradep2p/secure_channel.hpp"

#include <openssl/rand.h>

#include <poll.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

using tradep2p::AbortMessage;
using tradep2p::CancelOfferMessage;
using tradep2p::ClientTlsPolicy;
using tradep2p::CreateOfferMessage;
using tradep2p::Endpoint;
using tradep2p::Frame;
using tradep2p::JoinOfferMessage;
using tradep2p::ListOffersMessage;
using tradep2p::MessageType;
using tradep2p::Party;
using tradep2p::RoomId;
using tradep2p::RoundSignalMessage;
using tradep2p::SecureChannel;
using tradep2p::TradeTerms;
using tradep2p::TurnMessage;

constexpr std::size_t kMaxEvents = 160U;
constexpr int kDashboardPollMilliseconds = 250;

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

std::uint16_t parse_port(const std::string& value) {
    std::size_t used = 0U;
    const auto parsed = std::stoul(value, &used, 10);
    if (used != value.size() || parsed == 0U || parsed > 65535U) {
        throw std::invalid_argument("invalid port");
    }
    return static_cast<std::uint16_t>(parsed);
}

Endpoint parse_endpoint(const std::string& text) {
    if (!text.empty() && text.front() == '[') {
        const auto close = text.find(']');
        if (close == std::string::npos || close + 2U >= text.size() ||
            text[close + 1U] != ':') {
            throw std::invalid_argument("endpoint must be [ipv6]:port");
        }
        return Endpoint{text.substr(1U, close - 1U),
                        parse_port(text.substr(close + 2U))};
    }

    const auto separator = text.rfind(':');
    if (separator == std::string::npos || separator == 0U ||
        separator + 1U >= text.size()) {
        throw std::invalid_argument("endpoint must be host:port");
    }
    return Endpoint{text.substr(0U, separator),
                    parse_port(text.substr(separator + 1U))};
}

std::uint64_t parse_u64(const std::string& value, const char* name) {
    if (value.empty()) {
        throw std::invalid_argument(std::string("missing ") + name);
    }
    std::uint64_t parsed = 0U;
    const char* begin = value.data();
    const char* end = begin + value.size();
    const auto [ptr, error] = std::from_chars(begin, end, parsed, 10);
    if (error != std::errc{} || ptr != end || parsed == 0U) {
        throw std::invalid_argument(std::string("invalid ") + name);
    }
    return parsed;
}

std::uint32_t parse_u32(const std::string& value, const char* name) {
    const auto parsed = parse_u64(value, name);
    if (parsed > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument(std::string(name) + " is too large");
    }
    return static_cast<std::uint32_t>(parsed);
}

std::string random_token() {
    std::array<unsigned char, 24> bytes{};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed while creating dashboard token");
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

std::string required_param(const httplib::Request& request,
                           const char* name) {
    if (!request.has_param(name)) {
        throw std::invalid_argument(std::string("missing form field: ") + name);
    }
    const std::string value = request.get_param_value(name);
    if (value.empty()) {
        throw std::invalid_argument(std::string("empty form field: ") + name);
    }
    return value;
}

const char* party_name(Party party) {
    return party == Party::A ? "A" : "B";
}

struct OfferView {
    std::string room_id;
    TradeTerms terms;
};

struct RoomView {
    std::string room_id;
    std::string peer_id;
    Party party{Party::A};
    TradeTerms terms;
    std::string receive_address_a;
    std::string receive_address_b;
    std::string status{"active"};
    std::string detail;
    bool has_turn{false};
    TurnMessage turn;
};

struct OutgoingFrame {
    MessageType type{};
    std::vector<std::uint8_t> payload;
    std::string description;
};

class DashboardClient {
public:
    DashboardClient(Endpoint mediator,
                    ClientTlsPolicy tls_policy,
                    std::optional<Endpoint> socks_proxy)
        : mediator_(std::move(mediator)),
          tls_policy_(std::move(tls_policy)),
          socks_proxy_(std::move(socks_proxy)) {}

    ~DashboardClient() {
        stop_.store(true);
        if (worker_.joinable()) {
            worker_.join();
        }
    }

    DashboardClient(const DashboardClient&) = delete;
    DashboardClient& operator=(const DashboardClient&) = delete;

    void start() {
        worker_ = std::thread([this] { worker_loop(); });
    }

    void refresh_offers() {
        enqueue(MessageType::ListOffers,
                tradep2p::encode_list_offers(ListOffersMessage{}),
                "requested open-offer list");
    }

    void create_offer(const TradeTerms& terms, const std::string& address) {
        tradep2p::validate_terms(terms);
        tradep2p::validate_address(address);
        enqueue(MessageType::CreateOffer,
                tradep2p::encode_create_offer(CreateOfferMessage{terms, address}),
                "submitted a new offer");
    }

    void join_offer(const std::string& room_text, const std::string& address) {
        const RoomId room_id = tradep2p::room_id_from_hex(room_text);
        tradep2p::validate_address(address);
        enqueue(MessageType::JoinOffer,
                tradep2p::encode_join_offer(JoinOfferMessage{room_id, address}),
                "requested to join room " + tradep2p::room_id_to_hex(room_id));
    }

    void cancel_offer(const std::string& room_text) {
        const RoomId room_id = tradep2p::room_id_from_hex(room_text);
        enqueue(MessageType::CancelOffer,
                tradep2p::encode_cancel_offer(CancelOfferMessage{room_id}),
                "requested cancellation of room " +
                    tradep2p::room_id_to_hex(room_id));
    }

    void mark_sent(const std::string& room_text) {
        enqueue_turn_signal(room_text, true);
    }

    void mark_received(const std::string& room_text) {
        enqueue_turn_signal(room_text, false);
    }

    void abort_room(const std::string& room_text) {
        const RoomId room_id = tradep2p::room_id_from_hex(room_text);
        enqueue(MessageType::Abort,
                tradep2p::encode_abort(
                    AbortMessage{room_id, "dashboard user aborted"}),
                "requested abort of room " + tradep2p::room_id_to_hex(room_id));
    }

    std::string state_json() const {
        std::scoped_lock lock(state_mutex_);
        std::ostringstream json;
        json << "{\"connected\":" << (connected_ ? "true" : "false")
             << ",\"connection_status\":\"" << json_escape(connection_status_)
             << "\",\"client_id\":\"" << json_escape(client_id_) << "\""
             << ",\"revision\":" << revision_
             << ",\"offers\":[";

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
            std::string action = "none";
            if (room.status == "active" && room.has_turn) {
                action = room.party == room.turn.sender ? "sent" : "received";
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
                 << ",\"receive_address_a\":\""
                 << json_escape(room.receive_address_a)
                 << "\",\"receive_address_b\":\""
                 << json_escape(room.receive_address_b)
                 << "\",\"has_turn\":" << (room.has_turn ? "true" : "false")
                 << ",\"action\":\"" << action << "\"";
            if (room.has_turn) {
                json << ",\"turn\":{\"round\":" << (room.turn.round_index + 1U)
                     << ",\"sender\":\"" << party_name(room.turn.sender)
                     << "\",\"asset\":\"" << json_escape(room.turn.asset)
                     << "\",\"amount\":" << room.turn.amount
                     << ",\"destination\":\""
                     << json_escape(room.turn.destination) << "\"}";
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

private:
    void enqueue(MessageType type,
                 std::vector<std::uint8_t> payload,
                 std::string description) {
        {
            std::scoped_lock lock(state_mutex_);
            if (!connected_) {
                throw std::runtime_error("dashboard client is not connected");
            }
        }
        std::scoped_lock lock(queue_mutex_);
        outgoing_.push_back(
            OutgoingFrame{type, std::move(payload), std::move(description)});
    }

    void enqueue_turn_signal(const std::string& room_text, bool sent) {
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
            const bool am_sender =
                room_it->second.party == room_it->second.turn.sender;
            if (sent && !am_sender) {
                throw std::invalid_argument(
                    "this dashboard client is not the current sender");
            }
            if (!sent && am_sender) {
                throw std::invalid_argument(
                    "this dashboard client is not the current receiver");
            }
            signal = RoundSignalMessage{room_id,
                                        room_it->second.turn.round_index,
                                        room_it->second.turn.sender};
        }
        enqueue(sent ? MessageType::Sent : MessageType::Received,
                tradep2p::encode_round_signal(signal),
                std::string(sent ? "reported sent in room "
                                 : "reported received in room ") + canonical);
    }

    void add_event_locked(const std::string& message) {
        events_.push_front(now_text() + " | " + message);
        while (events_.size() > kMaxEvents) {
            events_.pop_back();
        }
        ++revision_;
    }

    void set_disconnected(const std::string& reason) {
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

    void worker_loop() {
        while (!stop_.load()) {
            try {
                SecureChannel channel = socks_proxy_.has_value()
                    ? SecureChannel::connect_via_socks5(
                          *socks_proxy_, mediator_, tls_policy_)
                    : SecureChannel::connect_direct(mediator_, tls_policy_);
                channel.set_timeout(30U);
                const Frame welcome_frame = channel.receive_frame();
                if (welcome_frame.type != MessageType::Welcome) {
                    throw std::runtime_error(
                        "mediator did not send a welcome message");
                }
                const auto welcome = tradep2p::decode_welcome(welcome_frame.payload);
                {
                    std::scoped_lock lock(state_mutex_);
                    connected_ = true;
                    connection_status_ = "connected";
                    client_id_ = tradep2p::client_id_to_hex(welcome.client_id);
                    offers_.clear();
                    rooms_.clear();
                    add_event_locked("connected as anonymous client " + client_id_);
                }
                channel.send_frame(
                    MessageType::ListOffers,
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

    void session_loop(SecureChannel& channel) {
        while (!stop_.load()) {
            flush_outgoing(channel);

            pollfd descriptor{};
            descriptor.fd = channel.native_handle();
            descriptor.events = POLLIN;
            const bool pending = channel.has_pending_input();
            const int result = ::poll(
                &descriptor, 1, pending ? 0 : kDashboardPollMilliseconds);
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

    void flush_outgoing(SecureChannel& channel) {
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

    void handle_frame(const Frame& frame) {
        bool refresh_offers_after = false;
        {
            std::scoped_lock lock(state_mutex_);
            switch (frame.type) {
            case MessageType::OfferCreated: {
                const auto message = tradep2p::decode_offer_created(frame.payload);
                add_event_locked("offer room created: " +
                                 tradep2p::room_id_to_hex(message.room_id));
                refresh_offers_after = true;
                break;
            }
            case MessageType::OfferList: {
                const auto message = tradep2p::decode_offer_list(frame.payload);
                offers_.clear();
                offers_.reserve(message.offers.size());
                for (const auto& offer : message.offers) {
                    offers_.push_back(
                        OfferView{tradep2p::room_id_to_hex(offer.room_id),
                                  offer.terms});
                }
                add_event_locked("open-offer list updated: " +
                                 std::to_string(offers_.size()) + " offer(s)");
                break;
            }
            case MessageType::OfferCancelled: {
                const auto message = tradep2p::decode_offer_cancelled(frame.payload);
                const std::string room_id =
                    tradep2p::room_id_to_hex(message.room_id);
                std::erase_if(offers_, [&](const OfferView& offer) {
                    return offer.room_id == room_id;
                });
                add_event_locked("offer cancelled: " + room_id);
                refresh_offers_after = true;
                break;
            }
            case MessageType::TradeReady: {
                const auto message = tradep2p::decode_trade_ready(frame.payload);
                const std::string room_id =
                    tradep2p::room_id_to_hex(message.room_id);
                RoomView room;
                room.room_id = room_id;
                room.peer_id = tradep2p::client_id_to_hex(message.peer_id);
                room.party = message.assigned_party;
                room.terms = message.terms;
                room.receive_address_a = message.receive_address_a;
                room.receive_address_b = message.receive_address_b;
                room.status = "active";
                rooms_[room_id] = std::move(room);
                std::erase_if(offers_, [&](const OfferView& offer) {
                    return offer.room_id == room_id;
                });
                add_event_locked("room ready: " + room_id + " as party " +
                                 party_name(message.assigned_party));
                refresh_offers_after = true;
                break;
            }
            case MessageType::Turn: {
                const auto message = tradep2p::decode_turn(frame.payload);
                const std::string room_id =
                    tradep2p::room_id_to_hex(message.room_id);
                auto& room = rooms_[room_id];
                room.room_id = room_id;
                room.turn = message;
                room.has_turn = true;
                room.status = "active";
                add_event_locked("room " + room_id + " round " +
                                 std::to_string(message.round_index + 1U) +
                                 " turn: party " + party_name(message.sender) +
                                 " sends " + std::to_string(message.amount) + " " +
                                 message.asset);
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
                const std::string room_id =
                    tradep2p::room_id_to_hex(message.room_id);
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
                const std::string room_id =
                    tradep2p::room_id_to_hex(message.room_id);
                auto& room = rooms_[room_id];
                room.room_id = room_id;
                room.status = "aborted";
                room.detail = message.reason;
                room.has_turn = false;
                add_event_locked("room aborted: " + room_id + " - " +
                                 message.reason);
                break;
            }
            case MessageType::Error: {
                const auto message = tradep2p::decode_error(frame.payload);
                add_event_locked("server rejected request: " + message.reason);
                break;
            }
            default:
                add_event_locked("ignored unexpected mediator message type " +
                                 std::to_string(
                                     static_cast<unsigned int>(frame.type)));
                break;
            }
        }

        if (refresh_offers_after) {
            std::scoped_lock lock(queue_mutex_);
            outgoing_.push_back(OutgoingFrame{
                MessageType::ListOffers,
                tradep2p::encode_list_offers(ListOffersMessage{}),
                "refreshed open offers"});
        }
    }

    Endpoint mediator_;
    ClientTlsPolicy tls_policy_;
    std::optional<Endpoint> socks_proxy_;
    std::atomic<bool> stop_{false};
    std::thread worker_;

    mutable std::mutex state_mutex_;
    bool connected_{false};
    std::string connection_status_{"connecting"};
    std::string client_id_;
    std::vector<OfferView> offers_;
    std::map<std::string, RoomView> rooms_;
    std::deque<std::string> events_;
    std::uint64_t revision_{0U};

    std::mutex queue_mutex_;
    std::deque<OutgoingFrame> outgoing_;
};

std::string read_server_state(const std::string& state_file) {
    if (state_file.empty()) {
        return "{\"enabled\":false}";
    }
    std::ifstream input(state_file);
    if (!input.is_open()) {
        return "{\"enabled\":true,\"available\":false,\"error\":\"state file not available yet\"}";
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    const std::string content = buffer.str();
    if (content.empty()) {
        return "{\"enabled\":true,\"available\":false,\"error\":\"state file is empty\"}";
    }
    return content;
}

std::string dashboard_html(const std::string& token,
                           bool server_state_enabled) {
    std::string html = R"HTML(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TradeP2P Lobby Dashboard</title>
<style>
:root{--bg:#071019;--panel:#0d1824;--panel2:#101f2e;--line:#20384d;--text:#dcecff;--muted:#8da7bd;--cyan:#58d8ff;--green:#77ff9b;--amber:#ffd166;--red:#ff7575}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0,#12364b 0,transparent 32%),var(--bg);color:var(--text);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.wrap{width:min(1500px,calc(100% - 24px));margin:18px auto 60px}.top,.panel{border:1px solid var(--line);background:rgba(13,24,36,.96);border-radius:14px;box-shadow:0 18px 48px #0007}.top{padding:20px 24px;margin-bottom:14px}.topline{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}h1{font-size:clamp(1.4rem,3vw,2.4rem);margin:.2rem 0}h2{margin:0 0 14px;color:var(--cyan);font-size:1.05rem}h3{margin:0 0 10px;color:var(--green);font-size:.95rem}.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:minmax(340px,.8fr) minmax(500px,1.7fr);gap:14px}.stack{display:grid;gap:14px}.panel{padding:18px}.status{display:inline-block;padding:.25rem .6rem;border-radius:99px;background:#38495c}.status.connected,.status.active,.status.complete{background:#155c35}.status.connecting{background:#604d16}.status.disconnected,.status.aborted{background:#6b2525}label{display:grid;gap:5px;color:var(--muted)}input,button{font:inherit;border-radius:8px;border:1px solid var(--line)}input{width:100%;padding:9px 10px;background:#07111b;color:var(--text)}button{padding:8px 11px;background:#15334a;color:var(--text);cursor:pointer}button:hover{border-color:var(--cyan)}button.primary{background:#135534;color:#effff4}button.danger{background:#622727}button:disabled{opacity:.45;cursor:not-allowed}.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.span2{grid-column:span 2}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse}th,td{padding:9px 8px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}th{color:var(--muted);font-size:.8rem}.room{border:1px solid var(--line);background:var(--panel2);border-radius:10px;padding:13px;margin-bottom:10px}.room-head{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.mono-break{word-break:break-all}.turn{margin-top:10px;padding:10px;border-left:3px solid var(--amber);background:#09131d}.events{max-height:330px;overflow:auto;margin:0;padding-left:20px}.events li{margin:5px 0;color:#bfd1df}.server-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.metric{background:#08131d;border:1px solid var(--line);border-radius:9px;padding:10px}.metric b{display:block;color:var(--cyan);font-size:.75rem}.error{color:var(--red)}.notice{margin:8px 0 0;color:var(--amber)}@media(max-width:1000px){.grid{grid-template-columns:1fr}}@media(max-width:620px){.form-grid,.server-grid{grid-template-columns:1fr}.span2{grid-column:auto}}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div class="topline"><div><div class="muted">TRADEP2P / PROGRESSIVE FRACTIONAL SETTLEMENT</div><h1>Lobby client + mediator dashboard</h1></div><div><span id="connection" class="status connecting">connecting</span></div></div>
    <div id="identity" class="muted">anonymous client not connected yet</div>
    <div id="notice" class="notice"></div>
  </header>
  <div class="grid">
    <div class="stack">
      <section class="panel">
        <h2>// publish offer</h2>
        <form id="offer-form" class="form-grid">
          <label>Sell symbol<input name="sell_asset" value="QRL" maxlength="16" required></label>
          <label>Sell amount (integer units)<input name="sell_amount" value="500000" inputmode="numeric" required></label>
          <label>Buy symbol<input name="buy_asset" value="BTC" maxlength="16" required></label>
          <label>Buy amount (integer units)<input name="buy_amount" value="100000" inputmode="numeric" required></label>
          <label>Settlement rounds<input name="rounds" value="2" inputmode="numeric" required></label>
          <label class="span2">Your receiving address for the asset you buy<input name="address" placeholder="receiving-address" maxlength="256" required></label>
          <div class="actions span2"><button class="primary" type="submit">Publish offer</button></div>
        </form>
      </section>
      <section class="panel">
        <h2>// take offer</h2>
        <label>Your receiving address for the asset offered by the seller<input id="join-address" placeholder="receiving-address" maxlength="256"></label>
        <p class="muted">Set this once, then press Join next to an open offer.</p>
      </section>
      <section class="panel">
        <h2>// mediator state</h2>
        <div id="server-state" class="muted">__SERVER_STATE_TEXT__</div>
      </section>
      <section class="panel">
        <h2>// event stream</h2>
        <ol id="events" class="events"><li>waiting for dashboard client</li></ol>
      </section>
    </div>
    <div class="stack">
      <section class="panel">
        <div class="topline"><h2>// open lobbies / offers</h2><button id="refresh-offers">Refresh offers</button></div>
        <div class="table-wrap"><table><thead><tr><th>Room</th><th>Sell</th><th>Buy</th><th>Rounds</th><th>Actions</th></tr></thead><tbody id="offers"><tr><td colspan="5" class="muted">waiting for offer list</td></tr></tbody></table></div>
      </section>
      <section class="panel">
        <h2>// my settlement rooms</h2>
        <div id="rooms"><p class="muted">No active rooms.</p></div>
      </section>
    </div>
  </div>
</div>
<script>
const TOKEN="__TOKEN__";
const serverStateEnabled=__SERVER_STATE_ENABLED__;
const esc=(v)=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const short=(v)=>{v=String(v??'');return v.length>22?v.slice(0,10)+'…'+v.slice(-10):v};
function notice(text,bad=false){const n=document.getElementById('notice');n.textContent=text;n.className=bad?'notice error':'notice';setTimeout(()=>{if(n.textContent===text)n.textContent=''},5000)}
async function post(path,data={}){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-TradeP2P-Token':TOKEN},body:new URLSearchParams(data)});const body=await r.json().catch(()=>({ok:false,error:'invalid dashboard response'}));if(!r.ok||!body.ok)throw new Error(body.error||('HTTP '+r.status));return body}
function renderOffers(offers){const target=document.getElementById('offers');if(!offers.length){target.innerHTML='<tr><td colspan="5" class="muted">No open offers.</td></tr>';return}target.innerHTML=offers.map(o=>`<tr><td title="${esc(o.room_id)}">${esc(short(o.room_id))}</td><td>${esc(o.sell_amount)} ${esc(o.sell_asset)}</td><td>${esc(o.buy_amount)} ${esc(o.buy_asset)}</td><td>${esc(o.rounds)}</td><td><div class="actions"><button data-join="${esc(o.room_id)}" class="primary">Join</button><button data-cancel="${esc(o.room_id)}" class="danger">Cancel mine</button></div></td></tr>`).join('');target.querySelectorAll('[data-join]').forEach(b=>b.onclick=async()=>{try{const address=document.getElementById('join-address').value.trim();if(!address)throw new Error('enter your receiving address first');await post('/api/offers/join',{room_id:b.dataset.join,address});notice('join request queued')}catch(e){notice(e.message,true)}});target.querySelectorAll('[data-cancel]').forEach(b=>b.onclick=async()=>{try{await post('/api/offers/cancel',{room_id:b.dataset.cancel});notice('cancel request queued')}catch(e){notice(e.message,true)}})}
function renderRooms(rooms){const target=document.getElementById('rooms');if(!rooms.length){target.innerHTML='<p class="muted">No settlement rooms in this browser session.</p>';return}target.innerHTML=rooms.map(r=>{const turn=r.turn?`<div class="turn"><b>Round ${esc(r.turn.round)}:</b> party ${esc(r.turn.sender)} sends <b>${esc(r.turn.amount)} ${esc(r.turn.asset)}</b><br><span class="muted mono-break">destination: ${esc(r.turn.destination)}</span></div>`:'';let primary='';if(r.status==='active'&&r.action==='sent')primary=`<button class="primary" data-sent="${esc(r.room_id)}">I sent it</button>`;if(r.status==='active'&&r.action==='received')primary=`<button class="primary" data-received="${esc(r.room_id)}">I verified receipt</button>`;const abort=r.status==='active'?`<button class="danger" data-abort="${esc(r.room_id)}">Abort room</button>`:'';return `<article class="room"><div class="room-head"><div><h3 title="${esc(r.room_id)}">Room ${esc(short(r.room_id))}</h3><div class="muted">party ${esc(r.party)} · peer ${esc(short(r.peer_id))}</div></div><span class="status ${esc(r.status)}">${esc(r.status)}</span></div><p>${esc(r.sell_amount)} ${esc(r.sell_asset)} ↔ ${esc(r.buy_amount)} ${esc(r.buy_asset)} · ${esc(r.rounds)} rounds</p><div class="muted mono-break">party A receives: ${esc(r.receive_address_a)}<br>party B receives: ${esc(r.receive_address_b)}</div>${turn}${r.detail?`<p class="notice">${esc(r.detail)}</p>`:''}<div class="actions">${primary}${abort}</div></article>`}).join('');target.querySelectorAll('[data-sent]').forEach(b=>b.onclick=()=>roomAction('/api/rooms/sent',b.dataset.sent));target.querySelectorAll('[data-received]').forEach(b=>b.onclick=()=>roomAction('/api/rooms/received',b.dataset.received));target.querySelectorAll('[data-abort]').forEach(b=>b.onclick=()=>roomAction('/api/rooms/abort',b.dataset.abort))}
async function roomAction(path,room){try{await post(path,{room_id:room});notice('room action queued')}catch(e){notice(e.message,true)}}
function renderEvents(events){document.getElementById('events').innerHTML=(events.length?events:['No events yet.']).map(e=>`<li>${esc(e)}</li>`).join('')}
async function refreshClient(){try{const r=await fetch('/api/state',{cache:'no-store'});const s=await r.json();const c=document.getElementById('connection');c.textContent=s.connection_status;c.className='status '+(s.connected?'connected':'disconnected');document.getElementById('identity').textContent=s.client_id?'anonymous client '+s.client_id:'anonymous client not connected';renderOffers(s.offers||[]);renderRooms(s.rooms||[]);renderEvents(s.events||[])}catch(e){notice('dashboard refresh failed: '+e.message,true)}}
function renderServer(s){const t=document.getElementById('server-state');if(!serverStateEnabled){t.innerHTML='<span class="muted">Server snapshot disabled. Start the mediator with TRADEP2P_LOBBY_STATE_FILE and pass the same path to --server-state.</span>';return}if(s.available===false){t.innerHTML='<span class="error">'+esc(s.error||'snapshot unavailable')+'</span>';return}t.innerHTML=`<div class="server-grid"><div class="metric"><b>Clients</b>${esc(s.clients??0)}</div><div class="metric"><b>Open offers</b>${esc((s.offers||[]).length)}</div><div class="metric"><b>Active rooms</b>${esc((s.rooms||[]).length)}</div><div class="metric"><b>Pending invites</b>${esc(s.pending_invites??0)}</div></div><p class="muted">${esc(s.bind||'')} · snapshot ${esc(s.generated_at||'')}</p>`+(s.rooms||[]).map(r=>`<div class="room"><b title="${esc(r.room_id)}">${esc(short(r.room_id))}</b> · ${esc(r.state)} · round ${esc(r.round)}/${esc(r.rounds)} · ${esc(r.total_a)} ${esc(r.asset_a)} ↔ ${esc(r.total_b)} ${esc(r.asset_b)}</div>`).join('')}
async function refreshServer(){if(!serverStateEnabled)return;try{const r=await fetch('/api/server-state',{cache:'no-store'});renderServer(await r.json())}catch(e){document.getElementById('server-state').textContent='server snapshot error: '+e.message}}
document.getElementById('offer-form').onsubmit=async(e)=>{e.preventDefault();try{const d=Object.fromEntries(new FormData(e.target));await post('/api/offers/create',d);notice('offer request queued')}catch(err){notice(err.message,true)}};
document.getElementById('refresh-offers').onclick=async()=>{try{await post('/api/offers/refresh');notice('offer refresh queued')}catch(e){notice(e.message,true)}};
refreshClient();refreshServer();setInterval(refreshClient,1000);setInterval(refreshServer,1500);
</script>
</body>
</html>)HTML";

    const auto replace_all = [&](const std::string& needle,
                                 const std::string& replacement) {
        std::size_t position = 0U;
        while ((position = html.find(needle, position)) != std::string::npos) {
            html.replace(position, needle.size(), replacement);
            position += replacement.size();
        }
    };
    replace_all("__TOKEN__", token);
    replace_all("__SERVER_STATE_ENABLED__",
                server_state_enabled ? "true" : "false");
    replace_all("__SERVER_STATE_TEXT__",
                server_state_enabled ? "waiting for mediator snapshot"
                                     : "server snapshot disabled");
    return html;
}

void set_json_result(httplib::Response& response,
                     bool ok,
                     const std::string& message,
                     int status = 200) {
    response.status = status;
    response.set_content(
        std::string("{\"ok\":") + (ok ? "true" : "false") +
            (ok ? ",\"message\":\"" : ",\"error\":\"") +
            json_escape(message) + "\"}",
        "application/json; charset=utf-8");
}

void print_usage(const char* program) {
    std::cerr
        << "Usage:\n"
        << "  " << program
        << " client <mediator:port> <certificate-sha256> [options]\n"
        << "  " << program
        << " client-tor <proxy:port> <onion:port> <certificate-sha256> [options]\n\n"
        << "Options:\n"
        << "  --listen HOST        HTTP bind address (default 127.0.0.1)\n"
        << "  --port PORT          HTTP port (default 8080)\n"
        << "  --server-state FILE  read local mediator snapshot JSON\n";
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 4) {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }

        const std::string mode = argv[1];
        std::optional<Endpoint> proxy;
        Endpoint mediator;
        ClientTlsPolicy tls;
        int option_index = 0;

        if (mode == "client") {
            mediator = parse_endpoint(argv[2]);
            tls = ClientTlsPolicy{argv[3]};
            option_index = 4;
        } else if (mode == "client-tor") {
            if (argc < 5) {
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            proxy = parse_endpoint(argv[2]);
            mediator = parse_endpoint(argv[3]);
            tls = ClientTlsPolicy{argv[4]};
            option_index = 5;
        } else {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }

        std::string listen_host = "127.0.0.1";
        int http_port = 8080;
        std::string server_state_file;
        for (int index = option_index; index < argc; ++index) {
            const std::string argument = argv[index];
            if (argument == "--listen" && index + 1 < argc) {
                listen_host = argv[++index];
            } else if (argument == "--port" && index + 1 < argc) {
                http_port = static_cast<int>(parse_port(argv[++index]));
            } else if (argument == "--server-state" && index + 1 < argc) {
                server_state_file = argv[++index];
            } else if (argument == "--help") {
                print_usage(argv[0]);
                return EXIT_SUCCESS;
            } else {
                throw std::invalid_argument("unknown or incomplete dashboard option: " +
                                            argument);
            }
        }

        DashboardClient client(mediator, tls, proxy);
        client.start();
        const std::string token = random_token();

        httplib::Server server;
        const auto host_allowed = [&](const httplib::Request& request) {
            if (listen_host != "127.0.0.1" && listen_host != "localhost" &&
                listen_host != "::1") {
                return true;
            }
            const std::string host = request.get_header_value("Host");
            const std::string port_text = std::to_string(http_port);
            return host == "127.0.0.1:" + port_text ||
                   host == "localhost:" + port_text ||
                   host == "[::1]:" + port_text;
        };

        server.Get("/", [&](const httplib::Request& request, httplib::Response& response) {
            if (!host_allowed(request)) {
                response.status = 403;
                response.set_content("forbidden host", "text/plain; charset=utf-8");
                return;
            }
            response.set_header("Cache-Control", "no-store");
            response.set_header("X-Frame-Options", "DENY");
            response.set_header("Content-Security-Policy",
                                "default-src 'self'; style-src 'unsafe-inline'; "
                                "script-src 'unsafe-inline'; frame-ancestors 'none'");
            response.set_content(
                dashboard_html(token, !server_state_file.empty()),
                "text/html; charset=utf-8");
        });

        server.Get("/api/state",
                   [&](const httplib::Request& request, httplib::Response& response) {
                       if (!host_allowed(request)) {
                           response.status = 403;
                           return;
                       }
                       response.set_header("Cache-Control", "no-store");
                       response.set_content(client.state_json(),
                                            "application/json; charset=utf-8");
                   });

        server.Get("/api/server-state",
                   [&](const httplib::Request& request, httplib::Response& response) {
                       if (!host_allowed(request)) {
                           response.status = 403;
                           return;
                       }
                       response.set_header("Cache-Control", "no-store");
                       response.set_content(read_server_state(server_state_file),
                                            "application/json; charset=utf-8");
                   });

        const auto authorized = [&](const httplib::Request& request) {
            return request.get_header_value("X-TradeP2P-Token") == token;
        };

        const auto action = [&](auto handler) {
            return [&, handler](const httplib::Request& request,
                                httplib::Response& response) {
                if (!host_allowed(request)) {
                    set_json_result(response, false, "forbidden host", 403);
                    return;
                }
                if (!authorized(request)) {
                    set_json_result(response, false, "invalid dashboard token", 403);
                    return;
                }
                try {
                    handler(request);
                    set_json_result(response, true, "queued");
                } catch (const std::exception& error) {
                    set_json_result(response, false, error.what(), 400);
                }
            };
        };

        server.Post("/api/offers/refresh", action([&](const httplib::Request&) {
                        client.refresh_offers();
                    }));

        server.Post("/api/offers/create", action([&](const httplib::Request& request) {
                        TradeTerms terms;
                        terms.asset_a = required_param(request, "sell_asset");
                        terms.total_a = parse_u64(
                            required_param(request, "sell_amount"), "sell amount");
                        terms.asset_b = required_param(request, "buy_asset");
                        terms.total_b = parse_u64(
                            required_param(request, "buy_amount"), "buy amount");
                        terms.rounds = parse_u32(
                            required_param(request, "rounds"), "round count");
                        terms.first_sender = Party::A;
                        client.create_offer(
                            terms, required_param(request, "address"));
                    }));

        server.Post("/api/offers/join", action([&](const httplib::Request& request) {
                        client.join_offer(required_param(request, "room_id"),
                                          required_param(request, "address"));
                    }));

        server.Post("/api/offers/cancel", action([&](const httplib::Request& request) {
                        client.cancel_offer(required_param(request, "room_id"));
                    }));

        server.Post("/api/rooms/sent", action([&](const httplib::Request& request) {
                        client.mark_sent(required_param(request, "room_id"));
                    }));

        server.Post("/api/rooms/received", action([&](const httplib::Request& request) {
                        client.mark_received(required_param(request, "room_id"));
                    }));

        server.Post("/api/rooms/abort", action([&](const httplib::Request& request) {
                        client.abort_room(required_param(request, "room_id"));
                    }));

        std::cout << "TradeP2P interactive dashboard listening on http://"
                  << listen_host << ':' << http_port << "\n";
        std::cout << "The HTTP dashboard is intentionally local by default.\n";
        if (!server_state_file.empty()) {
            std::cout << "Reading mediator state from " << server_state_file << "\n";
        }

        if (!server.listen(listen_host, http_port)) {
            throw std::runtime_error("failed to bind dashboard HTTP listener");
        }
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "fatal: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
