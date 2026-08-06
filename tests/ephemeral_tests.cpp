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

tradep2p::ClientId client_id(std::uint8_t seed) {
    tradep2p::ClientId id{};
    id.fill(seed);
    return id;
}

tradep2p::TradeMessageContext base_context() {
    tradep2p::TradeMessageContext context;
    context.mediator_id = "mediator-a";
    context.room_id = room_id(1);
    context.round = 0;
    context.message_type = tradep2p::MessageType::Sent;
    context.payload_hash = tradep2p::trade_payload_hash(std::vector<std::uint8_t>{1, 2, 3});
    context.recipient = client_id(9);
    context.timestamp = 1000;
    return context;
}

// ---------------------------------------------------------------------------
// Fresh ephemeral key per room: a structural, not just probabilistic,
// property - confirm nothing derives it from anything stable.
// ---------------------------------------------------------------------------

void test_ephemeral_keys_are_fresh_and_unlinkable() {
    const auto room_a_key = tradep2p::generate_ephemeral_trade_keypair();
    const auto room_b_key = tradep2p::generate_ephemeral_trade_keypair();
    require(room_a_key.public_key != room_b_key.public_key,
            "two ephemeral keys for two rooms must differ");

    // Structural check: generate_ephemeral_trade_keypair() takes no
    // identity/master-secret input at all, so there is no derivation path
    // to compare against by construction (unlike derive_ed25519_keypair(),
    // which is the derived-key path this phase deliberately does not use -
    // see identity.hpp's key_scope comment on why "trade" has no label).
    // The regression this guards against is a future edit accidentally
    // routing ephemeral key generation through a derived path; confirming
    // two independently generated keys never collide and never match a
    // derived key under any label is the practical proxy for that.
    const tradep2p::MasterSecret master = tradep2p::generate_master_secret();
    const auto derived_login = tradep2p::derive_ed25519_keypair(master, tradep2p::key_scope::kLogin, "svc");
    const auto derived_pseudonym =
        tradep2p::derive_ed25519_keypair(master, tradep2p::key_scope::kMediatorPseudonym, "mediator-a");
    require(room_a_key.public_key != derived_login.public_key &&
                room_a_key.public_key != derived_pseudonym.public_key,
            "an ephemeral trade key must never coincide with a derived scoped key");
}

// ---------------------------------------------------------------------------
// Sign/verify round trip.
// ---------------------------------------------------------------------------

void test_sign_verify_round_trip() {
    const auto sender = tradep2p::generate_ephemeral_trade_keypair();
    auto context = base_context();
    context.sender_ephemeral_public_key = sender.public_key;

    const auto signature = tradep2p::sign_trade_message(sender.private_seed, context);
    require(tradep2p::verify_trade_message(sender.public_key, context, signature),
            "a genuine signature over its own context must verify");

    const auto other = tradep2p::generate_ephemeral_trade_keypair();
    require(!tradep2p::verify_trade_message(other.public_key, context, signature),
            "a signature must not verify under an unrelated ephemeral key");
}

// ---------------------------------------------------------------------------
// Cross-room / cross-round / cross-message-type / cross-version /
// cross-mediator replay: a valid signature over one context must be
// rejected when the receiver checks it against any other context.
// ---------------------------------------------------------------------------

void test_cross_room_replay_rejected() {
    const auto sender = tradep2p::generate_ephemeral_trade_keypair();
    auto context = base_context();
    context.sender_ephemeral_public_key = sender.public_key;
    const auto signature = tradep2p::sign_trade_message(sender.private_seed, context);

    auto replayed = context;
    replayed.room_id = room_id(2);
    require(!tradep2p::verify_trade_message(sender.public_key, replayed, signature),
            "a signature must not verify when replayed into a different room");
}

void test_cross_round_replay_rejected() {
    const auto sender = tradep2p::generate_ephemeral_trade_keypair();
    auto context = base_context();
    context.sender_ephemeral_public_key = sender.public_key;
    const auto signature = tradep2p::sign_trade_message(sender.private_seed, context);

    auto replayed = context;
    replayed.round = context.round + 1U;
    require(!tradep2p::verify_trade_message(sender.public_key, replayed, signature),
            "a signature must not verify when replayed into a different round");
}

void test_cross_message_type_substitution_rejected() {
    const auto sender = tradep2p::generate_ephemeral_trade_keypair();
    auto context = base_context();
    context.sender_ephemeral_public_key = sender.public_key;
    context.message_type = tradep2p::MessageType::Sent;
    const auto signature = tradep2p::sign_trade_message(sender.private_seed, context);

    auto replayed = context;
    replayed.message_type = tradep2p::MessageType::Received;
    require(!tradep2p::verify_trade_message(sender.public_key, replayed, signature),
            "a Sent-context signature must not verify as if it signed a Received context");
}

void test_cross_protocol_version_replay_rejected() {
    const auto sender = tradep2p::generate_ephemeral_trade_keypair();
    auto context = base_context();
    context.sender_ephemeral_public_key = sender.public_key;
    const auto signature = tradep2p::sign_trade_message(sender.private_seed, context);

    auto replayed = context;
    replayed.protocol_version = static_cast<std::uint16_t>(context.protocol_version + 1U);
    require(!tradep2p::verify_trade_message(sender.public_key, replayed, signature),
            "a signature must not verify against a different protocol version");
}

void test_cross_mediator_replay_rejected() {
    const auto sender = tradep2p::generate_ephemeral_trade_keypair();
    auto context = base_context();
    context.sender_ephemeral_public_key = sender.public_key;
    const auto signature = tradep2p::sign_trade_message(sender.private_seed, context);

    auto replayed = context;
    replayed.mediator_id = "mediator-b";
    require(!tradep2p::verify_trade_message(sender.public_key, replayed, signature),
            "a signature must not verify when replayed under a different mediator id");
}

void test_cross_payload_hash_substitution_rejected() {
    const auto sender = tradep2p::generate_ephemeral_trade_keypair();
    auto context = base_context();
    context.sender_ephemeral_public_key = sender.public_key;
    const auto signature = tradep2p::sign_trade_message(sender.private_seed, context);

    auto replayed = context;
    replayed.payload_hash = tradep2p::trade_payload_hash(std::vector<std::uint8_t>{9, 9, 9});
    require(!tradep2p::verify_trade_message(sender.public_key, replayed, signature),
            "a signature must not verify against a substituted payload hash");
}

// ---------------------------------------------------------------------------
// Canonical encoding: length-prefix injectivity for the one variable-length
// field (mediator_id), matching identity.hpp's own encoding discipline.
// ---------------------------------------------------------------------------

void test_encoding_domain_separation() {
    auto a = base_context();
    auto b = a;
    b.mediator_id = "mediator-ax";
    require(tradep2p::encode_trade_message_context(a) != tradep2p::encode_trade_message_context(b),
            "different mediator id length must change the encoded context");

    auto c = a;
    c.suite_id = 0x0002;
    require(tradep2p::encode_trade_message_context(a) != tradep2p::encode_trade_message_context(c),
            "different suite id must change the encoded context");
}

// ---------------------------------------------------------------------------
// Malformed TradeEphemeralKey wire message: rejected cleanly, no crash.
// ---------------------------------------------------------------------------

void test_malformed_ephemeral_key_message_rejected() {
    bool threw = false;
    try {
        // Truncated: a well-formed room id but no public key bytes at all.
        std::vector<std::uint8_t> truncated(32, 0x11);
        (void)tradep2p::decode_trade_ephemeral_key(truncated);
    } catch (const std::exception&) {
        threw = true;
    }
    require(threw, "a truncated TradeEphemeralKey payload must be rejected, not crash");

    threw = false;
    try {
        tradep2p::TradeEphemeralKeyMessage message;
        message.room_id.fill(0U); // all-zero room id is never valid
        message.ephemeral_public_key.fill(0x22U);
        (void)tradep2p::encode_trade_ephemeral_key(message);
    } catch (const std::exception&) {
        threw = true;
    }
    require(threw, "an all-zero room id must be rejected");

    // Round trip sanity check on a well-formed message.
    tradep2p::TradeEphemeralKeyMessage message;
    message.room_id = room_id(5);
    message.ephemeral_public_key.fill(0x33U);
    const auto encoded = tradep2p::encode_trade_ephemeral_key(message);
    const auto decoded = tradep2p::decode_trade_ephemeral_key(encoded);
    require(decoded.room_id == message.room_id && decoded.ephemeral_public_key == message.ephemeral_public_key,
            "a well-formed TradeEphemeralKey message must round-trip exactly");
}

} // namespace

int main() {
    try {
        test_ephemeral_keys_are_fresh_and_unlinkable();
        test_sign_verify_round_trip();
        test_cross_room_replay_rejected();
        test_cross_round_replay_rejected();
        test_cross_message_type_substitution_rejected();
        test_cross_protocol_version_replay_rejected();
        test_cross_mediator_replay_rejected();
        test_cross_payload_hash_substitution_rejected();
        test_encoding_domain_separation();
        test_malformed_ephemeral_key_message_rejected();
        std::cout << "ephemeral unit tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "ephemeral test failure: " << error.what() << '\n';
        return 1;
    }
}
