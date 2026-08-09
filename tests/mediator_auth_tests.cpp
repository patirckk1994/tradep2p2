#include "tradep2p/mediator_auth.hpp"
#include "tradep2p/recognition.hpp"

#include <iostream>
#include <stdexcept>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

tradep2p::MediatorAuthFields base_fields() {
    tradep2p::MediatorAuthFields fields;
    fields.mediator_id = "mediator-a";
    fields.nonce = tradep2p::generate_mediator_auth_nonce();
    fields.created_at = 1000;
    fields.expires_at = 1120;
    return fields;
}

// ---------------------------------------------------------------------------
// Sign/verify round trip.
// ---------------------------------------------------------------------------

void test_sign_verify_round_trip() {
    const auto prover = tradep2p::generate_mldsa65_keypair();
    const auto fields = base_fields();

    const auto signature = tradep2p::sign_mediator_auth(prover.private_seed, fields);
    require(tradep2p::verify_mediator_auth(prover.public_key, fields, signature),
            "a genuine signature over its own fields must verify");

    const auto other = tradep2p::generate_mldsa65_keypair();
    require(!tradep2p::verify_mediator_auth(other.public_key, fields, signature),
            "a signature must not verify under an unrelated public key");
}

void test_wrong_signature_rejected() {
    const auto prover = tradep2p::generate_mldsa65_keypair();
    const auto fields = base_fields();
    auto signature = tradep2p::sign_mediator_auth(prover.private_seed, fields);
    signature[0] ^= 0xFFU;

    require(!tradep2p::verify_mediator_auth(prover.public_key, fields, signature),
            "a corrupted signature must be rejected");
}

// ---------------------------------------------------------------------------
// Signed payload: length-prefix injectivity and field coverage, matching
// recognition_tests.cpp's domain-separation test in spirit.
// ---------------------------------------------------------------------------

void test_signed_payload_domain_separation() {
    const auto base = base_fields();

    auto different_mediator = base;
    different_mediator.mediator_id = "mediator-b";
    require(tradep2p::encode_mediator_auth_signed_payload(base) !=
                tradep2p::encode_mediator_auth_signed_payload(different_mediator),
            "different mediator id must change the signed payload");

    auto different_nonce = base;
    different_nonce.nonce = tradep2p::generate_mediator_auth_nonce();
    require(tradep2p::encode_mediator_auth_signed_payload(base) !=
                tradep2p::encode_mediator_auth_signed_payload(different_nonce),
            "different nonce must change the signed payload");

    auto different_created = base;
    different_created.created_at = base.created_at + 1U;
    require(tradep2p::encode_mediator_auth_signed_payload(base) !=
                tradep2p::encode_mediator_auth_signed_payload(different_created),
            "different created_at must change the signed payload");

    auto different_expires = base;
    different_expires.expires_at = base.expires_at + 1U;
    require(tradep2p::encode_mediator_auth_signed_payload(base) !=
                tradep2p::encode_mediator_auth_signed_payload(different_expires),
            "different expires_at must change the signed payload");

    // Length-prefix injectivity: a mediator id boundary shift must not
    // collide, the same property recognition_tests.cpp checks for its own
    // encoding.
    auto shifted = base;
    shifted.mediator_id = "mediator-ax";
    require(tradep2p::encode_mediator_auth_signed_payload(base) !=
                tradep2p::encode_mediator_auth_signed_payload(shifted),
            "mediator id length must be unambiguous in the encoding");
}

// ---------------------------------------------------------------------------
// Cross-protocol replay: a payload encoded (and signed) under recognition.cpp's
// domain label must never verify against this module - the entire reason a
// dedicated domain label exists at all rather than reusing the shape.
// ---------------------------------------------------------------------------

void test_cross_domain_signature_rejected() {
    const auto prover = tradep2p::generate_mldsa65_keypair();

    tradep2p::RoomId room{};
    room.fill(0x11U);
    tradep2p::RecognitionChallengeFields recognition_fields;
    recognition_fields.mediator_id = "mediator-a";
    recognition_fields.room_id = room;
    recognition_fields.nonce = tradep2p::generate_recognition_nonce();
    recognition_fields.created_at = 1000;
    recognition_fields.expires_at = 1120;

    // Sign the RECOGNITION payload with the same private key.
    const auto recognition_signature =
        tradep2p::sign_recognition_response_mldsa65(prover.private_seed, recognition_fields);

    // Construct mediator-auth fields that happen to share the same mediator
    // id, created_at, and expires_at, with a nonce built from the
    // recognition nonce's own bytes (truncated/padded to fit) - an attacker
    // trying to replay the recognition signature into the auth context.
    tradep2p::MediatorAuthFields auth_fields;
    auth_fields.mediator_id = recognition_fields.mediator_id;
    auth_fields.nonce = tradep2p::generate_mediator_auth_nonce();
    auth_fields.created_at = recognition_fields.created_at;
    auth_fields.expires_at = recognition_fields.expires_at;

    require(!tradep2p::verify_mediator_auth(prover.public_key, auth_fields,
                                            recognition_signature),
            "a signature produced over recognition.cpp's domain-separated payload "
            "must not verify as a mediator-auth signature, even under the same key");
}

void test_mldsa65_generate_and_reload_round_trip() {
    const auto generated = tradep2p::generate_mldsa65_keypair();
    const auto reloaded = tradep2p::load_mldsa65_keypair(generated.private_seed);
    require(reloaded.public_key == generated.public_key,
            "re-loading a generated seed must reproduce the identical public key");

    const auto fields = base_fields();
    const auto signature = tradep2p::sign_mediator_auth(generated.private_seed, fields);
    require(tradep2p::verify_mediator_auth(reloaded.public_key, fields, signature),
            "a signature made with the generated key must verify under the reloaded key");
}

} // namespace

int main() {
    try {
        test_sign_verify_round_trip();
        test_wrong_signature_rejected();
        test_signed_payload_domain_separation();
        test_cross_domain_signature_rejected();
        test_mldsa65_generate_and_reload_round_trip();
        std::cout << "mediator auth unit tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "mediator auth test failure: " << error.what() << '\n';
        return 1;
    }
}
