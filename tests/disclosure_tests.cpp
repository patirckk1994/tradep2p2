#include "tradep2p/disclosure.hpp"

#include "tradep2p/ephemeral.hpp"

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

struct Fixture {
    tradep2p::Ed25519KeyPair party_a_original; // the key that earned the receipt
    tradep2p::Ed25519KeyPair party_b_original;
    tradep2p::Ed25519KeyPair mediator_key;
    std::vector<tradep2p::IssuedReceipt> chain;
};

Fixture make_fixture() {
    Fixture fixture;
    fixture.party_a_original = tradep2p::generate_ephemeral_trade_keypair();
    fixture.party_b_original = tradep2p::generate_ephemeral_trade_keypair();
    fixture.mediator_key = tradep2p::generate_mediator_receipt_keypair();

    tradep2p::ReceiptFields stage3;
    stage3.mediator_id = "mediator-a";
    stage3.room_id = room_id(1);
    stage3.terms_commitment.fill(0x11U);
    stage3.party_a_ephemeral_key = fixture.party_a_original.public_key;
    stage3.party_b_ephemeral_key = fixture.party_b_original.public_key;
    stage3.mediator_public_key = fixture.mediator_key.public_key;
    stage3.stage = tradep2p::ReceiptStage::PenultimateObligationsComplete;
    stage3.completed = false;
    stage3.timestamp = 1000;
    stage3.nonce.fill(0x02U);
    const auto stage3_sig = tradep2p::sign_receipt(fixture.mediator_key.private_seed, stage3);
    const auto link = tradep2p::receipt_chain_link_hash(stage3, stage3_sig);

    tradep2p::ReceiptFields stage4 = stage3;
    stage4.stage = tradep2p::ReceiptStage::SettlementCompleted;
    stage4.completed = true;
    stage4.timestamp = 1050;
    stage4.previous_stage_hash = link;
    const auto stage4_sig = tradep2p::sign_receipt(fixture.mediator_key.private_seed, stage4);

    fixture.chain = {{stage3, stage3_sig}, {stage4, stage4_sig}};
    return fixture;
}

tradep2p::DisclosureFields envelope_for(const Fixture& fixture, const tradep2p::RoomId& negotiation_room,
                                        const tradep2p::Ed25519PublicKey& recipient_key) {
    tradep2p::DisclosureFields fields;
    fields.mediator_id = "mediator-b"; // the CURRENT negotiation's mediator - may differ from the original
    fields.room_id = negotiation_room;
    fields.recipient_ephemeral_key = recipient_key;
    fields.disclosed_chain_hash = tradep2p::disclosed_chain_hash(fixture.chain);
    fields.timestamp = 2000;
    fields.nonce.fill(0x09U);
    return fields;
}

// ---------------------------------------------------------------------------
// The core deliverable: a genuine disclosure, signed by a real party to the
// original chain, verifies for its intended recipient in its intended room.
// ---------------------------------------------------------------------------

void test_genuine_disclosure_verifies() {
    const auto fixture = make_fixture();
    const auto negotiation_room = room_id(5);
    const auto recipient = tradep2p::generate_ephemeral_trade_keypair();

    const auto fields = envelope_for(fixture, negotiation_room, recipient.public_key);
    const auto signature = tradep2p::sign_disclosure(fixture.party_a_original.private_seed, fields);

    const auto failure = tradep2p::verify_disclosure_bundle(fixture.chain, fields, signature,
                                                             negotiation_room, recipient.public_key);
    require(!failure.has_value(), "a genuine disclosure from party A must verify");

    // Party B's original key must also work (either original party may
    // disclose).
    const auto signature_b = tradep2p::sign_disclosure(fixture.party_b_original.private_seed, fields);
    const auto failure_b = tradep2p::verify_disclosure_bundle(fixture.chain, fields, signature_b,
                                                               negotiation_room, recipient.public_key);
    require(!failure_b.has_value(), "a genuine disclosure from party B must also verify");
}

// ---------------------------------------------------------------------------
// A receipt disclosed to X cannot be replayed by X to Y, or into a
// different negotiation - the "not broadcastable" property.
// ---------------------------------------------------------------------------

void test_disclosure_not_replayable_to_different_recipient() {
    const auto fixture = make_fixture();
    const auto negotiation_room = room_id(5);
    const auto recipient_x = tradep2p::generate_ephemeral_trade_keypair();
    const auto recipient_y = tradep2p::generate_ephemeral_trade_keypair();

    const auto fields = envelope_for(fixture, negotiation_room, recipient_x.public_key);
    const auto signature = tradep2p::sign_disclosure(fixture.party_a_original.private_seed, fields);

    // Y tries to present the same envelope+signature as if it were
    // disclosed to them.
    const auto failure = tradep2p::verify_disclosure_bundle(fixture.chain, fields, signature,
                                                             negotiation_room, recipient_y.public_key);
    require(failure.has_value(), "a disclosure bound to X must not verify for Y");
}

void test_disclosure_not_replayable_into_different_room() {
    const auto fixture = make_fixture();
    const auto negotiation_room = room_id(5);
    const auto other_room = room_id(6);
    const auto recipient = tradep2p::generate_ephemeral_trade_keypair();

    const auto fields = envelope_for(fixture, negotiation_room, recipient.public_key);
    const auto signature = tradep2p::sign_disclosure(fixture.party_a_original.private_seed, fields);

    const auto failure = tradep2p::verify_disclosure_bundle(fixture.chain, fields, signature, other_room,
                                                             recipient.public_key);
    require(failure.has_value(), "a disclosure bound to one room must not verify in another");
}

// ---------------------------------------------------------------------------
// A discloser who is NOT a genuine party to the chain (signed with an
// unrelated key) cannot fabricate a valid disclosure.
// ---------------------------------------------------------------------------

void test_disclosure_from_unrelated_key_rejected() {
    const auto fixture = make_fixture();
    const auto negotiation_room = room_id(5);
    const auto recipient = tradep2p::generate_ephemeral_trade_keypair();
    const auto impostor = tradep2p::generate_ephemeral_trade_keypair();

    const auto fields = envelope_for(fixture, negotiation_room, recipient.public_key);
    const auto signature = tradep2p::sign_disclosure(impostor.private_seed, fields);

    const auto failure = tradep2p::verify_disclosure_bundle(fixture.chain, fields, signature,
                                                             negotiation_room, recipient.public_key);
    require(failure.has_value(), "a signature from a key not in the chain must be rejected");
}

// ---------------------------------------------------------------------------
// The envelope and the chain must match each other - swapping in a
// different (even individually valid) chain must fail.
// ---------------------------------------------------------------------------

void test_mismatched_chain_rejected() {
    const auto fixture = make_fixture();
    const auto other_fixture = make_fixture();
    const auto negotiation_room = room_id(5);
    const auto recipient = tradep2p::generate_ephemeral_trade_keypair();

    const auto fields = envelope_for(fixture, negotiation_room, recipient.public_key);
    const auto signature = tradep2p::sign_disclosure(fixture.party_a_original.private_seed, fields);

    // Present a DIFFERENT (also internally valid) chain alongside the
    // envelope that actually committed to `fixture`'s chain.
    const auto failure = tradep2p::verify_disclosure_bundle(
        other_fixture.chain, fields, signature, negotiation_room, recipient.public_key);
    require(failure.has_value(), "an envelope must not verify against a substituted chain");
}

// ---------------------------------------------------------------------------
// A broken underlying receipt chain (tampered/inconsistent) is rejected
// even if the envelope itself is otherwise well-formed.
// ---------------------------------------------------------------------------

void test_broken_underlying_chain_rejected() {
    auto fixture = make_fixture();
    fixture.chain[1].mediator_signature[0] ^= 0xFFU; // tamper with the stage-4 signature

    const auto negotiation_room = room_id(5);
    const auto recipient = tradep2p::generate_ephemeral_trade_keypair();
    const auto fields = envelope_for(fixture, negotiation_room, recipient.public_key);
    const auto signature = tradep2p::sign_disclosure(fixture.party_a_original.private_seed, fields);

    const auto failure = tradep2p::verify_disclosure_bundle(fixture.chain, fields, signature,
                                                             negotiation_room, recipient.public_key);
    require(failure.has_value(), "a tampered underlying receipt chain must be rejected");
}

// ---------------------------------------------------------------------------
// Empty / oversized chains rejected.
// ---------------------------------------------------------------------------

void test_empty_and_oversized_chain_rejected() {
    const auto negotiation_room = room_id(5);
    const auto recipient = tradep2p::generate_ephemeral_trade_keypair();
    tradep2p::DisclosureFields fields;
    fields.mediator_id = "mediator-b";
    fields.room_id = negotiation_room;
    fields.recipient_ephemeral_key = recipient.public_key;
    fields.disclosed_chain_hash = tradep2p::disclosed_chain_hash({});
    fields.timestamp = 2000;

    const auto some_key = tradep2p::generate_ephemeral_trade_keypair();
    const auto signature = tradep2p::sign_disclosure(some_key.private_seed, fields);
    const auto failure =
        tradep2p::verify_disclosure_bundle({}, fields, signature, negotiation_room, recipient.public_key);
    require(failure.has_value(), "an empty receipt chain must be rejected");

    const auto fixture = make_fixture();
    std::vector<tradep2p::IssuedReceipt> oversized(tradep2p::kDisclosureMaxChainLength + 1U,
                                                    fixture.chain.front());
    const auto failure2 = tradep2p::verify_disclosure_bundle(
        oversized, fields, signature, negotiation_room, recipient.public_key);
    require(failure2.has_value(), "an oversized receipt chain must be rejected");
}

// ---------------------------------------------------------------------------
// Wire round trip / malformed input.
// ---------------------------------------------------------------------------

void test_wire_round_trip_and_malformed_input() {
    const auto fixture = make_fixture();
    const auto negotiation_room = room_id(5);
    const auto recipient = tradep2p::generate_ephemeral_trade_keypair();
    const auto fields = envelope_for(fixture, negotiation_room, recipient.public_key);
    const auto signature = tradep2p::sign_disclosure(fixture.party_a_original.private_seed, fields);

    tradep2p::ReceiptDisclosureMessage message;
    message.room_id = negotiation_room;
    message.recipient_ephemeral_key = recipient.public_key;
    message.disclosed_chain_hash = fields.disclosed_chain_hash;
    message.timestamp = fields.timestamp;
    message.nonce = fields.nonce;
    message.signature = signature;
    for (const auto& issued : fixture.chain) {
        tradep2p::ReceiptIssuedMessage wire;
        wire.room_id = issued.fields.room_id;
        wire.mediator_id = issued.fields.mediator_id;
        wire.stage = static_cast<std::uint8_t>(issued.fields.stage);
        wire.completed = issued.fields.completed;
        wire.terms_commitment = issued.fields.terms_commitment;
        wire.party_a_ephemeral_key = issued.fields.party_a_ephemeral_key;
        wire.party_b_ephemeral_key = issued.fields.party_b_ephemeral_key;
        wire.mediator_public_key = issued.fields.mediator_public_key;
        wire.timestamp = issued.fields.timestamp;
        wire.nonce = issued.fields.nonce;
        wire.previous_stage_hash = issued.fields.previous_stage_hash;
        wire.mediator_signature = issued.mediator_signature;
        message.chain.push_back(wire);
    }

    const auto encoded = tradep2p::encode_receipt_disclosure(message);
    require(encoded.size() <= tradep2p::kMaxFramePayload, "encoded disclosure must fit one frame");
    const auto decoded = tradep2p::decode_receipt_disclosure(encoded);
    require(decoded.chain.size() == message.chain.size(), "chain length must round-trip");
    require(decoded.room_id == message.room_id && decoded.signature == message.signature,
            "disclosure message must round-trip exactly");

    bool threw = false;
    try {
        std::vector<std::uint8_t> truncated(20, 0x01);
        (void)tradep2p::decode_receipt_disclosure(truncated);
    } catch (const std::exception&) {
        threw = true;
    }
    require(threw, "a truncated ReceiptDisclosure payload must be rejected, not crash");
}

} // namespace

int main() {
    try {
        test_genuine_disclosure_verifies();
        test_disclosure_not_replayable_to_different_recipient();
        test_disclosure_not_replayable_into_different_room();
        test_disclosure_from_unrelated_key_rejected();
        test_mismatched_chain_rejected();
        test_broken_underlying_chain_rejected();
        test_empty_and_oversized_chain_rejected();
        test_wire_round_trip_and_malformed_input();
        std::cout << "disclosure unit tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "disclosure test failure: " << error.what() << '\n';
        return 1;
    }
}
