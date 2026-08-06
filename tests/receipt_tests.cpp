#include "tradep2p/receipt.hpp"

#include "tradep2p/ephemeral.hpp"
#include "tradep2p/mediator.hpp"
#include "tradep2p/protocol.hpp"

#include <iostream>
#include <stdexcept>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

tradep2p::RoomId room_id(std::uint8_t seed) {
    tradep2p::RoomId id{};
    id.fill(seed);
    return id;
}

tradep2p::TradeTerms basic_terms(std::uint32_t rounds) {
    tradep2p::TradeTerms terms;
    terms.asset_a = "QRL";
    terms.asset_b = "BTC";
    terms.total_a = 100000;
    terms.total_b = 50000;
    terms.rounds = rounds;
    terms.first_sender = tradep2p::Party::A;
    return terms;
}

struct RoomFixture {
    tradep2p::MediatorSession session;
    tradep2p::Ed25519KeyPair ephemeral_a;
    tradep2p::Ed25519KeyPair ephemeral_b;
    tradep2p::Ed25519KeyPair mediator_key;
    tradep2p::RoomId room;
};

RoomFixture make_room(std::uint32_t rounds, tradep2p::FeeTerms fee = {}) {
    tradep2p::CreateRoomMessage creator;
    creator.terms = basic_terms(rounds);
    creator.receive_address_a = "addr-a";
    const auto room = room_id(1);
    tradep2p::MediatorSession session(creator, room, fee);
    session.join(tradep2p::JoinRoomMessage{room, "addr-b"});
    return RoomFixture{std::move(session), tradep2p::generate_ephemeral_trade_keypair(),
                       tradep2p::generate_ephemeral_trade_keypair(),
                       tradep2p::generate_mediator_receipt_keypair(), room};
}

// Drives one full leg (Sent then Received) for the current sender.
void drive_leg(tradep2p::MediatorSession& session) {
    const auto turn = session.current_turn();
    const tradep2p::RoundSignalMessage signal{session.id(), turn.round_index, turn.sender};
    session.sender_reported_sent(turn.sender, signal);
    session.receiver_reported_received(tradep2p::other_party(turn.sender), signal);
}

tradep2p::ReceiptFields terms_commitment_fields(const RoomFixture& fixture, tradep2p::ReceiptStage stage,
                                                std::array<std::uint8_t, 32> previous_hash = {}) {
    tradep2p::ReceiptFields fields;
    fields.mediator_id = "mediator-a";
    fields.room_id = fixture.room;
    fields.terms_commitment = tradep2p::trade_payload_hash(tradep2p::encode_terms(fixture.session.terms()));
    fields.party_a_ephemeral_key = fixture.ephemeral_a.public_key;
    fields.party_b_ephemeral_key = fixture.ephemeral_b.public_key;
    fields.mediator_public_key = fixture.mediator_key.public_key;
    fields.stage = stage;
    fields.completed = stage == tradep2p::ReceiptStage::SettlementCompleted;
    fields.timestamp = 1000;
    fields.nonce.fill(0x07U);
    fields.previous_stage_hash = previous_hash;
    return fields;
}

// ---------------------------------------------------------------------------
// Receipt ack sign/verify round trip and domain separation (replay across
// rooms/mediators/stages rejected).
// ---------------------------------------------------------------------------

void test_receipt_ack_sign_verify_and_domain_separation() {
    const auto prover = tradep2p::generate_ephemeral_trade_keypair();
    tradep2p::ReceiptAckFields fields;
    fields.mediator_id = "mediator-a";
    fields.room_id = room_id(2);
    fields.stage = tradep2p::ReceiptStage::PenultimateObligationsComplete;
    fields.terms_commitment.fill(0x11U);
    fields.timestamp = 5000;

    const auto signature = tradep2p::sign_receipt_ack(prover.private_seed, fields);
    require(tradep2p::verify_receipt_ack(prover.public_key, fields, signature),
            "a genuine receipt ack signature must verify");

    auto replayed_room = fields;
    replayed_room.room_id = room_id(3);
    require(!tradep2p::verify_receipt_ack(prover.public_key, replayed_room, signature),
            "a receipt ack signature must not verify when replayed into a different room");

    auto replayed_mediator = fields;
    replayed_mediator.mediator_id = "mediator-b";
    require(!tradep2p::verify_receipt_ack(prover.public_key, replayed_mediator, signature),
            "a receipt ack signature must not verify under a different mediator id");

    auto replayed_stage = fields;
    replayed_stage.stage = tradep2p::ReceiptStage::SettlementCompleted;
    require(!tradep2p::verify_receipt_ack(prover.public_key, replayed_stage, signature),
            "a receipt ack signature must not verify against a different stage");
}

// ---------------------------------------------------------------------------
// Staged-receipt chain: valid chain verifies; a later-stage receipt without
// a valid previous-stage hash is rejected; non-monotonic stages rejected;
// signature tampering rejected.
// ---------------------------------------------------------------------------

void test_receipt_chain_valid() {
    const auto fixture = make_room(1);
    const auto stage3 = terms_commitment_fields(fixture, tradep2p::ReceiptStage::PenultimateObligationsComplete);
    const auto stage3_sig = tradep2p::sign_receipt(fixture.mediator_key.private_seed, stage3);
    const auto link = tradep2p::receipt_chain_link_hash(stage3, stage3_sig);

    auto stage4 = terms_commitment_fields(fixture, tradep2p::ReceiptStage::SettlementCompleted, link);
    const auto stage4_sig = tradep2p::sign_receipt(fixture.mediator_key.private_seed, stage4);

    const std::vector<tradep2p::IssuedReceipt> chain = {
        {stage3, stage3_sig},
        {stage4, stage4_sig},
    };
    tradep2p::verify_receipt_chain(chain, fixture.mediator_key.public_key); // must not throw
}

void test_receipt_chain_bad_previous_hash_rejected() {
    const auto fixture = make_room(1);
    const auto stage3 = terms_commitment_fields(fixture, tradep2p::ReceiptStage::PenultimateObligationsComplete);
    const auto stage3_sig = tradep2p::sign_receipt(fixture.mediator_key.private_seed, stage3);

    std::array<std::uint8_t, 32> wrong_link{};
    wrong_link.fill(0xEEU);
    auto stage4 = terms_commitment_fields(fixture, tradep2p::ReceiptStage::SettlementCompleted, wrong_link);
    const auto stage4_sig = tradep2p::sign_receipt(fixture.mediator_key.private_seed, stage4);

    const std::vector<tradep2p::IssuedReceipt> chain = {{stage3, stage3_sig}, {stage4, stage4_sig}};
    bool threw = false;
    try {
        tradep2p::verify_receipt_chain(chain, fixture.mediator_key.public_key);
    } catch (const tradep2p::ReceiptChainError&) {
        threw = true;
    }
    require(threw, "a stage-4 receipt with the wrong previous-stage hash must be rejected");
}

void test_receipt_chain_non_monotonic_stage_rejected() {
    const auto fixture = make_room(1);
    const auto stage3 = terms_commitment_fields(fixture, tradep2p::ReceiptStage::PenultimateObligationsComplete);
    const auto stage3_sig = tradep2p::sign_receipt(fixture.mediator_key.private_seed, stage3);
    const auto link = tradep2p::receipt_chain_link_hash(stage3, stage3_sig);

    // Same stage repeated (not strictly increasing).
    auto repeated = terms_commitment_fields(fixture, tradep2p::ReceiptStage::PenultimateObligationsComplete, link);
    const auto repeated_sig = tradep2p::sign_receipt(fixture.mediator_key.private_seed, repeated);

    const std::vector<tradep2p::IssuedReceipt> chain = {{stage3, stage3_sig}, {repeated, repeated_sig}};
    bool threw = false;
    try {
        tradep2p::verify_receipt_chain(chain, fixture.mediator_key.public_key);
    } catch (const tradep2p::ReceiptChainError&) {
        threw = true;
    }
    require(threw, "a non-increasing stage sequence must be rejected");
}

void test_receipt_chain_tampered_signature_rejected() {
    const auto fixture = make_room(1);
    const auto stage3 = terms_commitment_fields(fixture, tradep2p::ReceiptStage::PenultimateObligationsComplete);
    auto stage3_sig = tradep2p::sign_receipt(fixture.mediator_key.private_seed, stage3);
    stage3_sig[0] ^= 0xFFU;

    const std::vector<tradep2p::IssuedReceipt> chain = {{stage3, stage3_sig}};
    bool threw = false;
    try {
        tradep2p::verify_receipt_chain(chain, fixture.mediator_key.public_key);
    } catch (const tradep2p::ReceiptChainError&) {
        threw = true;
    }
    require(threw, "a tampered mediator signature must be rejected");
}

void test_receipt_chain_mixed_room_rejected() {
    const auto fixture = make_room(1);
    const auto other_fixture = make_room(1);
    const auto stage3 = terms_commitment_fields(fixture, tradep2p::ReceiptStage::PenultimateObligationsComplete);
    const auto stage3_sig = tradep2p::sign_receipt(fixture.mediator_key.private_seed, stage3);
    const auto link = tradep2p::receipt_chain_link_hash(stage3, stage3_sig);

    // Second entry claims to continue the chain but is actually for a
    // DIFFERENT room's fixture (different ephemeral keys/terms commitment).
    auto stage4 = terms_commitment_fields(other_fixture, tradep2p::ReceiptStage::SettlementCompleted, link);
    stage4.room_id = fixture.room; // room id matches, but party keys don't
    const auto stage4_sig = tradep2p::sign_receipt(fixture.mediator_key.private_seed, stage4);

    const std::vector<tradep2p::IssuedReceipt> chain = {{stage3, stage3_sig}, {stage4, stage4_sig}};
    bool threw = false;
    try {
        tradep2p::verify_receipt_chain(chain, fixture.mediator_key.public_key);
    } catch (const tradep2p::ReceiptChainError&) {
        threw = true;
    }
    require(threw, "a chain mixing two different rooms' party keys must be rejected");
}

// ---------------------------------------------------------------------------
// The withholding fix, at the actual protocol level: a party who refuses to
// acknowledge the final-receipt gate never gets (or gives) the final
// tranche - the room stalls in WaitingForFinalReceiptAck, current_sender()
// throws (nobody is instructed to send), exactly like an ordinary
// unresolved defection.
// ---------------------------------------------------------------------------

void test_withholding_final_ack_blocks_final_tranche() {
    auto fixture = make_room(1); // single round, no fee: the round's 2nd leg is the final tranche
    drive_leg(fixture.session); // leg 1 of round 1 (A sends, B receives)

    require(fixture.session.state() == tradep2p::SessionState::WaitingForFinalReceiptAck,
            "entering the trade's final leg must be gated behind the receipt ack");

    bool threw = false;
    try {
        (void)fixture.session.current_turn();
    } catch (const std::logic_error&) {
        threw = true;
    }
    require(threw, "no Turn must be issuable while the final-receipt gate is unresolved");

    // Only ONE party acks (say, party A) - party B (the griefer in this
    // scenario) withholds. The gate must remain unresolved: B never
    // receives a Turn instructing them to send the final tranche, so
    // withholding the receipt ack costs B exactly what withholding the
    // tranche itself would have cost - the room never completes.
    fixture.session.acknowledge_final_receipt(tradep2p::Party::A);
    require(fixture.session.state() == tradep2p::SessionState::WaitingForFinalReceiptAck,
            "a single party's ack must not be enough to unblock the final tranche");
    threw = false;
    try {
        (void)fixture.session.current_turn();
    } catch (const std::logic_error&) {
        threw = true;
    }
    require(threw, "the gate must still block Turn issuance after only one party acks");

    // A double-ack from the SAME party must also be rejected (not silently
    // ignored) - each party gets exactly one vote.
    threw = false;
    try {
        fixture.session.acknowledge_final_receipt(tradep2p::Party::A);
    } catch (const std::logic_error&) {
        threw = true;
    }
    require(threw, "a duplicate ack from the same party must be rejected");

    // Once BOTH ack, the gate opens and the final tranche becomes sendable.
    fixture.session.acknowledge_final_receipt(tradep2p::Party::B);
    require(fixture.session.state() == tradep2p::SessionState::WaitingForSent,
            "once both parties ack, the final leg's Turn must become issuable");
    drive_leg(fixture.session);
    require(fixture.session.state() == tradep2p::SessionState::Complete,
            "the room must complete once the (now-unblocked) final leg is driven");
}

void test_withholding_gate_before_fee_leg() {
    tradep2p::FeeTerms fee;
    fee.asset = "QRL";
    fee.amount = 100;
    fee.address = "fee-addr";
    auto fixture = make_room(1, fee);
    drive_leg(fixture.session); // leg 1
    drive_leg(fixture.session); // leg 2 - the round's own last leg, NOT the true final tranche here

    require(fixture.session.state() == tradep2p::SessionState::WaitingForFinalReceiptAck,
            "with a fee configured, the fee leg (not the round's own last leg) must be gated");
    fixture.session.acknowledge_final_receipt(tradep2p::Party::A);
    fixture.session.acknowledge_final_receipt(tradep2p::Party::B);
    require(fixture.session.state() == tradep2p::SessionState::WaitingForFeeSent,
            "once both ack, the gate must open into WaitingForFeeSent, not WaitingForSent");
}

// ---------------------------------------------------------------------------
// False-completion rejection: SessionState::Complete (the only condition
// under which lobby.cpp's real call site would ever build a stage-4
// receipt - see receipt.hpp's file comment) is unreachable without driving
// every leg of every round AND passing the final-receipt gate. This is the
// structural guarantee backing "don't issue a completion receipt
// optimistically".
// ---------------------------------------------------------------------------

void test_completion_unreachable_without_full_sequence() {
    auto fixture = make_room(2); // two rounds - more legs to skip ahead of
    require(fixture.session.state() != tradep2p::SessionState::Complete,
            "a freshly joined room must not already read as complete");
    drive_leg(fixture.session); // round 1, leg 1
    require(fixture.session.state() != tradep2p::SessionState::Complete,
            "completion must not be reachable after only one leg");
    drive_leg(fixture.session); // round 1, leg 2 -> round 2, leg 1
    require(fixture.session.state() != tradep2p::SessionState::Complete,
            "completion must not be reachable before the final round starts");
    drive_leg(fixture.session); // round 2, leg 1 -> gates before round 2's leg 2 (the final tranche)
    require(fixture.session.state() == tradep2p::SessionState::WaitingForFinalReceiptAck,
            "the final leg of the final round must still be gated behind the receipt ack");
    require(fixture.session.state() != tradep2p::SessionState::Complete,
            "completion must never be reachable while the final-receipt gate is open");
}

// ---------------------------------------------------------------------------
// Malformed wire input: rejected cleanly, no crash.
// ---------------------------------------------------------------------------

void test_malformed_wire_messages_rejected() {
    bool threw = false;
    try {
        std::vector<std::uint8_t> truncated(10, 0x01);
        (void)tradep2p::decode_receipt_ack(truncated);
    } catch (const std::exception&) {
        threw = true;
    }
    require(threw, "a truncated ReceiptAck payload must be rejected, not crash");

    threw = false;
    try {
        std::vector<std::uint8_t> truncated(40, 0x01);
        (void)tradep2p::decode_receipt_issued(truncated);
    } catch (const std::exception&) {
        threw = true;
    }
    require(threw, "a truncated ReceiptIssued payload must be rejected, not crash");

    // Round-trip sanity check on well-formed messages.
    tradep2p::ReceiptAckMessage ack;
    ack.room_id = room_id(4);
    ack.stage = static_cast<std::uint8_t>(tradep2p::ReceiptStage::PenultimateObligationsComplete);
    ack.timestamp = 42;
    ack.signature.fill(0x05U);
    const auto encoded_ack = tradep2p::encode_receipt_ack(ack);
    const auto decoded_ack = tradep2p::decode_receipt_ack(encoded_ack);
    require(decoded_ack.room_id == ack.room_id && decoded_ack.stage == ack.stage &&
                decoded_ack.timestamp == ack.timestamp && decoded_ack.signature == ack.signature,
            "a well-formed ReceiptAck message must round-trip exactly");
}

} // namespace

int main() {
    try {
        test_receipt_ack_sign_verify_and_domain_separation();
        test_receipt_chain_valid();
        test_receipt_chain_bad_previous_hash_rejected();
        test_receipt_chain_non_monotonic_stage_rejected();
        test_receipt_chain_tampered_signature_rejected();
        test_receipt_chain_mixed_room_rejected();
        test_withholding_final_ack_blocks_final_tranche();
        test_withholding_gate_before_fee_leg();
        test_completion_unreachable_without_full_sequence();
        test_malformed_wire_messages_rejected();
        std::cout << "receipt unit tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "receipt test failure: " << error.what() << '\n';
        return 1;
    }
}
