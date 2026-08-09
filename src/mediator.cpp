#include "tradep2p/mediator.hpp"

#include <stdexcept>
#include <utility>

namespace tradep2p {

MediatorSession::MediatorSession(CreateRoomMessage creator, RoomId room_id, FeeTerms fee,
                                 bool require_fee_confirmation, FeePosition fee_position)
    : creator_(std::move(creator)), room_id_(room_id), fee_(std::move(fee)),
      require_fee_confirmation_(require_fee_confirmation), fee_position_(fee_position) {
    validate_terms(creator_.terms);
    validate_address(creator_.receive_address_a);
    validate_room_id(room_id_);
    validate_fee_terms(fee_);
}

MediatorSession MediatorSession::restore(RoomId room_id,
                                          TradeTerms terms,
                                          std::string receive_address_a,
                                          std::string receive_address_b,
                                          FeeTerms fee,
                                          SessionState state,
                                          std::uint32_t round_index,
                                          std::uint8_t leg_index,
                                          std::string abort_reason,
                                          bool require_fee_confirmation,
                                          FeePosition fee_position) {
    // Everything that is always persisted (never blank, per the phase-3
    // room-persistence design) is validated exactly like the normal
    // constructor would. Only the receive addresses get the relaxed,
    // empty-is-allowed treatment - see the header comment on restore().
    validate_terms(terms);
    validate_room_id(room_id);
    validate_fee_terms(fee);
    if (!receive_address_a.empty()) {
        validate_address(receive_address_a);
    }
    if (!receive_address_b.empty()) {
        validate_address(receive_address_b);
    }
    if (round_index > terms.rounds) {
        throw std::invalid_argument("restored round index exceeds configured rounds");
    }
    if (leg_index > 1U) {
        throw std::invalid_argument("restored leg index must be 0 or 1");
    }

    MediatorSession session;
    session.creator_.terms = std::move(terms);
    session.creator_.receive_address_a = std::move(receive_address_a);
    session.room_id_ = room_id;
    session.receive_address_b_ = std::move(receive_address_b);
    session.fee_ = std::move(fee);
    session.state_ = state;
    session.round_index_ = round_index;
    session.leg_index_ = leg_index;
    session.abort_reason_ = std::move(abort_reason);
    session.require_fee_confirmation_ = require_fee_confirmation;
    session.fee_position_ = fee_position;
    return session;
}

void MediatorSession::join(const JoinRoomMessage& message) {
    if (state_ != SessionState::WaitingForPeer) {
        throw std::logic_error("room is not accepting a peer");
    }
    if (message.room_id != room_id_) {
        throw std::invalid_argument("wrong room id");
    }
    validate_address(message.receive_address_b);
    receive_address_b_ = message.receive_address_b;
    // BeforeFirstRound always hooks here, before any real tranche. So does
    // BeforeLastRound when there's only one round - "before the last round"
    // and "before the first round" are the same round in that case, and
    // there is no earlier round-completion event in advance_after_receipt()
    // to hook onto instead. No receipt-ack gate for an early fee leg - it is
    // never the room's true final tranche, so it doesn't need the phase-6
    // withholding protection that exists specifically to guard the last
    // transfer (see final_receipt_gate_is_fee_leg()).
    const bool fee_due_before_any_round =
        fee_.amount > 0U &&
        (fee_position_ == FeePosition::BeforeFirstRound ||
         (fee_position_ == FeePosition::BeforeLastRound && creator_.terms.rounds <= 1U));
    state_ = fee_due_before_any_round ? SessionState::WaitingForFeeSent
                                      : SessionState::WaitingForSent;
}

TradeReadyMessage MediatorSession::ready_message(Party party, ClientId peer_id) const {
    if (state_ == SessionState::WaitingForPeer) {
        throw std::logic_error("peer has not joined");
    }
    if (state_ == SessionState::Aborted) {
        throw std::logic_error("session is aborted");
    }
    validate_client_id(peer_id);
    return TradeReadyMessage{
        room_id_, party, peer_id, creator_.terms,
        creator_.receive_address_a, receive_address_b_, fee_};
}

Party MediatorSession::first_sender_for_round() const {
    const bool alternate = (round_index_ % 2U) != 0U;
    return alternate ? other_party(creator_.terms.first_sender)
                     : creator_.terms.first_sender;
}

Party MediatorSession::current_sender() const {
    if (state_ == SessionState::WaitingForPeer ||
        state_ == SessionState::Complete ||
        state_ == SessionState::Aborted ||
        state_ == SessionState::WaitingForFinalReceiptAck ||
        state_ == SessionState::WaitingForFeeConfirmation) {
        throw std::logic_error("session has no active sender");
    }
    if (state_ == SessionState::WaitingForFeeSent) {
        // The offer creator always settles the mediator fee.
        return Party::A;
    }
    const Party first = first_sender_for_round();
    return leg_index_ == 0U ? first : other_party(first);
}

Party MediatorSession::current_receiver() const {
    return other_party(current_sender());
}

TurnMessage MediatorSession::current_turn() const {
    if (state_ == SessionState::WaitingForFeeSent) {
        TurnMessage message;
        message.room_id = room_id_;
        message.round_index = round_index_;
        message.sender = Party::A;
        message.asset = fee_.asset;
        message.amount = fee_.amount;
        message.destination = fee_.address;
        message.is_fee = true;
        return message;
    }
    const Party sender = current_sender();
    TurnMessage message;
    message.room_id = room_id_;
    message.round_index = round_index_;
    message.sender = sender;
    if (sender == Party::A) {
        message.asset = creator_.terms.asset_a;
        message.amount = tranche_amount(
            creator_.terms.total_a, creator_.terms.rounds, round_index_);
        message.destination = receive_address_b_;
    } else {
        message.asset = creator_.terms.asset_b;
        message.amount = tranche_amount(
            creator_.terms.total_b, creator_.terms.rounds, round_index_);
        message.destination = creator_.receive_address_a;
    }
    return message;
}

void MediatorSession::validate_signal(const RoundSignalMessage& message) const {
    if (message.room_id != room_id_) {
        throw std::invalid_argument("signal has wrong room id");
    }
    if (message.round_index != round_index_) {
        throw std::invalid_argument("signal has wrong round index");
    }
    if (message.sender != current_sender()) {
        throw std::invalid_argument("signal has wrong sender");
    }
}

void MediatorSession::sender_reported_sent(
    Party reporting_party,
    const RoundSignalMessage& message) {
    if (state_ == SessionState::WaitingForFeeSent) {
        // The mediator is the recipient of the fee leg, so there is no
        // counterparty to confirm receipt; the fee follows the same
        // honor-system acknowledgement as every other transfer in this
        // protocol and completes the room immediately.
        if (message.room_id != room_id_) {
            throw std::invalid_argument("signal has wrong room id");
        }
        if (message.round_index != round_index_) {
            throw std::invalid_argument("signal has wrong round index");
        }
        if (reporting_party != Party::A || message.sender != Party::A) {
            throw std::invalid_argument(
                "only the offer creator settles the mediator fee");
        }
        // AfterLastRound: this fee leg IS the room's final action, exactly
        // as before. BeforeFirstRound/BeforeLastRound: real trade rounds
        // still remain, so the room resumes at whatever round_index_/
        // leg_index_ already sit at (join() never advanced them for
        // BeforeFirstRound; advance_after_receipt() already incremented
        // round_index_ before deferring to the fee for BeforeLastRound).
        const bool fee_is_final_action = fee_position_ == FeePosition::AfterLastRound;
        if (require_fee_confirmation_) {
            state_ = SessionState::WaitingForFeeConfirmation;
        } else {
            state_ = fee_is_final_action ? SessionState::Complete : SessionState::WaitingForSent;
        }
        return;
    }
    if (state_ != SessionState::WaitingForSent) {
        throw std::logic_error("not waiting for sent acknowledgement");
    }
    validate_signal(message);
    if (reporting_party != current_sender()) {
        throw std::invalid_argument("wrong party reported sent");
    }
    state_ = SessionState::WaitingForReceived;
}

void MediatorSession::receiver_reported_received(
    Party reporting_party,
    const RoundSignalMessage& message) {
    if (state_ != SessionState::WaitingForReceived) {
        throw std::logic_error("not waiting for received acknowledgement");
    }
    validate_signal(message);
    if (reporting_party != current_receiver()) {
        throw std::invalid_argument("wrong party reported received");
    }
    advance_after_receipt();
}

void MediatorSession::confirm_fee_received() {
    if (state_ != SessionState::WaitingForFeeConfirmation) {
        throw std::logic_error("session is not waiting for fee confirmation");
    }
    // See sender_reported_sent()'s identical fee_is_final_action reasoning -
    // fee_position_ (not itself changed by entering WaitingForFeeConfirmation)
    // still tells us whether real trade rounds remain after this.
    state_ = fee_position_ == FeePosition::AfterLastRound ? SessionState::Complete
                                                          : SessionState::WaitingForSent;
}

void MediatorSession::advance_after_receipt() {
    if (leg_index_ == 0U) {
        leg_index_ = 1U;
        // The upcoming leg (this round's second) is the trade's actual
        // final tranche if this is the last round AND either no fee is
        // configured, or the fee is positioned before this round anyway (so
        // it isn't what comes after this leg) - if the fee is positioned
        // AfterLastRound, the fee leg (handled in the other branch below) is
        // the true final tranche instead.
        const bool is_last_round = (round_index_ + 1U == creator_.terms.rounds);
        const bool this_leg_is_final_tranche =
            is_last_round && (fee_.amount == 0U || fee_position_ != FeePosition::AfterLastRound);
        if (this_leg_is_final_tranche) {
            final_receipt_acked_a_ = false;
            final_receipt_acked_b_ = false;
            state_ = SessionState::WaitingForFinalReceiptAck;
        } else {
            state_ = SessionState::WaitingForSent;
        }
        return;
    }

    leg_index_ = 0U;
    ++round_index_;

    // BeforeLastRound hooks here, the moment the round we just finished
    // hands off to what is now the last real round - one round short of
    // AfterLastRound's "all rounds done" trigger below. Rounds<=1 is handled
    // entirely by join() instead (there is no earlier round-completion event
    // to hook), so this can only fire when there IS an earlier round.
    if (fee_.amount > 0U && fee_position_ == FeePosition::BeforeLastRound &&
        round_index_ == creator_.terms.rounds - 1U) {
        state_ = SessionState::WaitingForFeeSent;
        return;
    }

    if (round_index_ == creator_.terms.rounds) {
        if (fee_.amount > 0U && fee_position_ == FeePosition::AfterLastRound) {
            final_receipt_acked_a_ = false;
            final_receipt_acked_b_ = false;
            state_ = SessionState::WaitingForFinalReceiptAck;
        } else {
            // Either no fee at all, or an early-positioned fee that was
            // already settled earlier in this room's lifetime - either way,
            // every round and the fee (if any) are both done.
            state_ = SessionState::Complete;
        }
    } else {
        state_ = SessionState::WaitingForSent;
    }
}

void MediatorSession::acknowledge_final_receipt(Party party) {
    if (state_ != SessionState::WaitingForFinalReceiptAck) {
        throw std::logic_error("not waiting for a final receipt acknowledgement");
    }
    if (final_receipt_acked(party)) {
        throw std::logic_error("this party already acknowledged the final receipt");
    }
    if (party == Party::A) {
        final_receipt_acked_a_ = true;
    } else {
        final_receipt_acked_b_ = true;
    }
    if (final_receipt_acked_a_ && final_receipt_acked_b_) {
        state_ = final_receipt_gate_is_fee_leg() ? SessionState::WaitingForFeeSent
                                                 : SessionState::WaitingForSent;
    }
}

void MediatorSession::abort(std::string reason) {
    if (state_ == SessionState::Complete) {
        throw std::logic_error("completed session cannot be aborted");
    }
    if (reason.empty()) {
        reason = "session aborted";
    }
    if (reason.size() > kMaxReasonLength) {
        reason.resize(kMaxReasonLength);
    }
    abort_reason_ = std::move(reason);
    state_ = SessionState::Aborted;
}

} // namespace tradep2p
