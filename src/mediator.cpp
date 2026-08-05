#include "tradep2p/mediator.hpp"

#include <stdexcept>
#include <utility>

namespace tradep2p {

MediatorSession::MediatorSession(CreateRoomMessage creator, RoomId room_id, FeeTerms fee)
    : creator_(std::move(creator)), room_id_(room_id), fee_(std::move(fee)) {
    validate_terms(creator_.terms);
    validate_address(creator_.receive_address_a);
    validate_room_id(room_id_);
    validate_fee_terms(fee_);
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
    state_ = SessionState::WaitingForSent;
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
        state_ == SessionState::Aborted) {
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
        state_ = SessionState::Complete;
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

void MediatorSession::advance_after_receipt() {
    if (leg_index_ == 0U) {
        leg_index_ = 1U;
        state_ = SessionState::WaitingForSent;
        return;
    }

    leg_index_ = 0U;
    ++round_index_;
    if (round_index_ == creator_.terms.rounds) {
        state_ = fee_.amount > 0U ? SessionState::WaitingForFeeSent
                                  : SessionState::Complete;
    } else {
        state_ = SessionState::WaitingForSent;
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
