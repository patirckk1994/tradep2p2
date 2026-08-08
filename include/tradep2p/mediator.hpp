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
    // Phase 6 (mediator-signed staged receipts, see
    // docs/identity-06-receipts.md "Staged receipts, and the withholding
    // fix"): entered instead of going straight to WaitingForSent/
    // WaitingForFeeSent the moment the NEXT leg to be sent would be the
    // trade's actual final tranche (the last leg of the last round if no
    // fee is configured, or the fee leg if one is). Both parties must
    // submit a signed ReceiptAck for the "penultimate obligations complete"
    // stage before the mediator will advance out of this state and issue
    // the Turn for that final leg - see acknowledge_final_receipt(). This
    // is the actual fix, not just staging: a party who refuses to
    // cooperate with the receipt exchange also never gets (or gives) the
    // final tranche, so withholding costs exactly what an ordinary
    // defection already costs (an aborted/incomplete room, visible in the
    // counterparty's local history - specs.txt SS8.3), instead of costing
    // nothing.
    WaitingForFinalReceiptAck,
    // Optional (see MediatorSession's require_fee_confirmation constructor
    // parameter, default false - existing honor-system behavior is
    // unchanged unless an operator opts in). Entered instead of Complete
    // the moment the offer creator reports the fee leg sent. The mediator
    // still cannot verify any transfer occurred - this does not change that
    // - it just requires an explicit operator action (confirm_fee_received(),
    // driven by lobby.cpp's admin control channel) before the room closes,
    // instead of trusting the sender's own claim alone the way every other
    // leg in this protocol still does. Appended at the end of the enum,
    // like WaitingForFinalReceiptAck before it, so existing numeric values
    // used in persisted rooms and the wire protocol never shift.
    WaitingForFeeConfirmation,
};

// Coordinates turns only. It never creates, inspects, searches, confirms,
// stores, or identifies cryptocurrency transactions. When a mediator-wide fee
// is configured, it is settled as one extra final leg paid by the offer
// creator (party A) after the last real round, acknowledged the same
// honor-system way as every other transfer.
class MediatorSession {
public:
    // require_fee_confirmation: see SessionState::WaitingForFeeConfirmation.
    // Defaults false so every existing call site (and every already-shipped
    // deployment) keeps today's honor-system-only behavior unless an
    // operator explicitly opts in.
    MediatorSession(CreateRoomMessage creator, RoomId room_id, FeeTerms fee,
                    bool require_fee_confirmation = false);

    // Phase 3 (mediator-side room persistence, see
    // docs/identity-03-journal-recovery.md and room_persistence.hpp):
    // reconstructs a session from state read back off disk after a
    // mediator restart, bypassing the normal constructor+join() flow. Per
    // the persistence design's chosen option (persist the state machine,
    // not the receive addresses - see room_persistence.hpp's file comment),
    // `receive_address_a`/`receive_address_b` may legitimately be empty
    // strings here, meaning "not yet re-solicited from a reconnecting
    // client" - validate_address() is deliberately NOT applied to an empty
    // address in this one factory (every other entry point in this class
    // still requires non-empty, validated addresses). A restored session
    // with a blank address must never be used to compute current_turn()/
    // ready_message() for real settlement traffic; both already fail closed
    // if that is attempted, because encode_turn()/encode_trade_ready()
    // (protocol.cpp) call validate_address() on the destination/address
    // fields and reject an empty string.
    // require_fee_confirmation is NOT itself persisted (only the resulting
    // `state` is) - a restored room already sitting in
    // WaitingForFeeConfirmation stays there regardless of what is passed
    // here, since that transition already happened before persistence.
    // This only matters for the rare case of restoring a room still in
    // WaitingForFeeSent, where the caller (lobby.cpp) supplies its current
    // startup configuration, same as it would for a brand-new room.
    [[nodiscard]] static MediatorSession restore(RoomId room_id,
                                                  TradeTerms terms,
                                                  std::string receive_address_a,
                                                  std::string receive_address_b,
                                                  FeeTerms fee,
                                                  SessionState state,
                                                  std::uint32_t round_index,
                                                  std::uint8_t leg_index,
                                                  std::string abort_reason,
                                                  bool require_fee_confirmation = false);

    [[nodiscard]] const RoomId& id() const noexcept { return room_id_; }
    [[nodiscard]] SessionState state() const noexcept { return state_; }
    [[nodiscard]] std::uint32_t round_index() const noexcept { return round_index_; }
    [[nodiscard]] std::uint8_t leg_index() const noexcept { return leg_index_; }
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

    // Phase 6: records `party`'s acknowledgement of the final-receipt gate.
    // Throws std::logic_error if state() is not WaitingForFinalReceiptAck,
    // or if `party` already acked (a duplicate ack is a caller bug, not a
    // retry - the wire handler is expected to de-duplicate before calling
    // this, same as every other state-mutating call in this class). Once
    // BOTH parties have acked, advances to WaitingForSent (gating the last
    // round's final leg) or WaitingForFeeSent (gating the fee leg) per
    // final_receipt_gate_is_fee_leg() below - the caller (lobby.cpp) checks
    // both_parties_acked_final_receipt() beforehand to know which case
    // applies and to build the stage-3 receipt before this call flips the
    // state out from under it.
    void acknowledge_final_receipt(Party party);
    [[nodiscard]] bool final_receipt_acked(Party party) const noexcept {
        return party == Party::A ? final_receipt_acked_a_ : final_receipt_acked_b_;
    }
    // True while gating the mediator-collected fee leg (fee configured,
    // this is the trade's true final tranche); false while gating the last
    // round's second leg (no fee configured, that leg is the final
    // tranche). Deterministically derivable from already-persisted state
    // (round_index_, terms().rounds, fee amount) - not itself persisted,
    // so a mediator restart mid-gate recomputes it identically rather than
    // needing a new persisted field.
    [[nodiscard]] bool final_receipt_gate_is_fee_leg() const noexcept {
        return fee_.amount > 0U && round_index_ == creator_.terms.rounds;
    }
    [[nodiscard]] const FeeTerms& fee() const noexcept { return fee_; }

    // The only caller of this is lobby.cpp's admin control channel (an
    // operator action, not a client message - no client-facing wire message
    // type exists for this). Throws std::logic_error if state() is not
    // WaitingForFeeConfirmation.
    void confirm_fee_received();

private:
    // Only reachable via restore() - leaves every member at its in-class
    // default and skips the normal constructor's validation, since restore()
    // performs its own (looser, address-optional) validation itself.
    MediatorSession() = default;

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
    // Phase 6: reset to false whenever WaitingForFinalReceiptAck is
    // (re-)entered, including after MediatorSession::restore() - a
    // mediator restart mid-gate simply asks both parties to ack again
    // rather than trying to persist and trust a pre-restart ack.
    bool final_receipt_acked_a_{false};
    bool final_receipt_acked_b_{false};
    // See SessionState::WaitingForFeeConfirmation. Only read inside
    // sender_reported_sent()'s WaitingForFeeSent branch - irrelevant once a
    // room has already left that state, restored or not.
    bool require_fee_confirmation_{false};
};

} // namespace tradep2p
