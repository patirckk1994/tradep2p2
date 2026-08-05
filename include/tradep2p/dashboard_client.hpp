#pragma once

#include "tradep2p/protocol.hpp"
#include "tradep2p/secure_channel.hpp"

#include <atomic>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace tradep2p::dashboard {

std::string json_escape(const std::string& text);
std::string now_text();
std::string random_token();
const char* party_name(Party party);

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
    FeeTerms fee;
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

// A persistent anonymous protocol client connected to one mediator, driven by
// queued HTTP-originated actions. Owns one worker thread and one
// SecureChannel so concurrent HTTP handler threads never touch TLS directly.
class DashboardClient {
public:
    DashboardClient(Endpoint mediator,
                    ClientTlsPolicy tls_policy,
                    std::optional<Endpoint> socks_proxy);
    ~DashboardClient();

    DashboardClient(const DashboardClient&) = delete;
    DashboardClient& operator=(const DashboardClient&) = delete;

    void start();

    void refresh_offers();
    void create_offer(const TradeTerms& terms, const std::string& address);
    void join_offer(const std::string& room_text, const std::string& address);
    void cancel_offer(const std::string& room_text);
    void mark_sent(const std::string& room_text);
    void mark_received(const std::string& room_text);
    void abort_room(const std::string& room_text);

    [[nodiscard]] std::string state_json() const;

private:
    void enqueue(MessageType type,
                 std::vector<std::uint8_t> payload,
                 std::string description);
    void enqueue_turn_signal(const std::string& room_text, bool sent);
    void add_event_locked(const std::string& message);
    void set_disconnected(const std::string& reason);
    void worker_loop();
    void session_loop(SecureChannel& channel);
    void flush_outgoing(SecureChannel& channel);
    void handle_frame(const Frame& frame);

    Endpoint mediator_;
    ClientTlsPolicy tls_policy_;
    std::optional<Endpoint> socks_proxy_;
    std::atomic<bool> stop_{false};
    std::thread worker_;

    mutable std::mutex state_mutex_;
    bool connected_{false};
    std::string connection_status_{"connecting"};
    std::string client_id_;
    FeeTerms mediator_fee_;
    std::vector<OfferView> offers_;
    std::map<std::string, RoomView> rooms_;
    std::deque<std::string> events_;
    std::uint64_t revision_{0U};

    std::mutex queue_mutex_;
    std::deque<OutgoingFrame> outgoing_;
};

} // namespace tradep2p::dashboard
