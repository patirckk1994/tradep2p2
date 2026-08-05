#pragma once

#include "tradep2p/protocol.hpp"

#include <cstdint>
#include <string>

namespace tradep2p {

enum class SessionState : std::uint8_t {
    WaitingForPeer,
    WaitingForSent,
    WaitingForReceived,
    WaitingForFeeSent,
    Complete,
    Aborted,
};

// Coordinates turns only. It never creates, inspects, searches, confirms,
// stores, or identifies cryptocurrency transactions. When a mediator-wide fee
// is configured, it is settled as one extra final leg paid by the offer
// creator (party A) after the last real round, acknowledged the same
// honor-system way as every other transfer.
class MediatorSession {
public:
    MediatorSession(CreateRoomMessage creator, RoomId room_id, FeeTerms fee);

    [[nodiscard]] const RoomId& id() const noexcept { return room_id_; }
    [[nodiscard]] SessionState state() const noexcept { return state_; }
    [[nodiscard]] std::uint32_t round_index() const noexcept { return round_index_; }
    [[nodiscard]] Party current_sender() const;
    [[nodiscard]] Party current_receiver() const;
    [[nodiscard]] const TradeTerms& terms() const noexcept { return creator_.terms; }

    void join(const JoinRoomMessage& message);
    [[nodiscard]] TradeReadyMessage ready_message(Party party, ClientId peer_id) const;
    [[nodiscard]] TurnMessage current_turn() const;

    void sender_reported_sent(Party reporting_party,
                              const RoundSignalMessage& message);
    void receiver_reported_received(Party reporting_party,
                                    const RoundSignalMessage& message);
    void abort(std::string reason);

    [[nodiscard]] const std::string& abort_reason() const noexcept {
        return abort_reason_;
    }

private:
    [[nodiscard]] Party first_sender_for_round() const;
    void validate_signal(const RoundSignalMessage& message) const;
    void advance_after_receipt();

    CreateRoomMessage creator_;
    RoomId room_id_{};
    std::string receive_address_b_;
    FeeTerms fee_;
    SessionState state_{SessionState::WaitingForPeer};
    std::uint32_t round_index_{0};
    std::uint8_t leg_index_{0};
    std::string abort_reason_;
};

} // namespace tradep2p
