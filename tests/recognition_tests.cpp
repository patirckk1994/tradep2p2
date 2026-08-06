#include "tradep2p/recognition.hpp"

#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

tradep2p::Ed25519KeyPair fresh_keypair() { return tradep2p::generate_ed25519_keypair(); }

tradep2p::RoomId room_id(std::uint8_t seed) {
    tradep2p::RoomId id{};
    id.fill(seed);
    return id;
}

tradep2p::RecognitionResponseMessage sign_response(const tradep2p::RecognitionChallengeFields& fields,
                                                    const tradep2p::Ed25519KeyPair& prover) {
    tradep2p::RecognitionResponseMessage response;
    response.room_id = fields.room_id;
    response.nonce = fields.nonce;
    response.prover_public_key = prover.public_key;
    response.signature = tradep2p::sign_recognition_response(prover.private_seed, fields);
    return response;
}

// ---------------------------------------------------------------------------
// Canonical payload: length-prefix injectivity, matching identity.hpp's
// encode_derivation_info() test vectors in spirit.
// ---------------------------------------------------------------------------

void test_signed_payload_domain_separation() {
    tradep2p::RecognitionChallengeFields base;
    base.mediator_id = "mediator-a";
    base.room_id = room_id(1);
    base.nonce = tradep2p::generate_recognition_nonce();
    base.created_at = 1000;
    base.expires_at = 1120;

    tradep2p::RecognitionChallengeFields different_mediator = base;
    different_mediator.mediator_id = "mediator-b";
    require(tradep2p::encode_recognition_signed_payload(base) !=
                tradep2p::encode_recognition_signed_payload(different_mediator),
            "different mediator id must change the signed payload");

    tradep2p::RecognitionChallengeFields different_room = base;
    different_room.room_id = room_id(2);
    require(tradep2p::encode_recognition_signed_payload(base) !=
                tradep2p::encode_recognition_signed_payload(different_room),
            "different room id must change the signed payload");

    tradep2p::RecognitionChallengeFields different_suite = base;
    different_suite.suite_id = 0x0002;
    require(tradep2p::encode_recognition_signed_payload(base) !=
                tradep2p::encode_recognition_signed_payload(different_suite),
            "different suite id must change the signed payload");

    // Length-prefix injectivity: a mediator id / nonce boundary shift must
    // not collide, the same property identity.hpp's own encoding tests
    // check for label/identifier.
    tradep2p::RecognitionChallengeFields shifted = base;
    shifted.mediator_id = "mediator-ax";
    require(tradep2p::encode_recognition_signed_payload(base) !=
                tradep2p::encode_recognition_signed_payload(shifted),
            "mediator id length must be unambiguous in the encoding");
}

// ---------------------------------------------------------------------------
// Sign/verify round trip.
// ---------------------------------------------------------------------------

void test_sign_verify_round_trip() {
    const auto prover = fresh_keypair();
    tradep2p::RecognitionChallengeFields fields;
    fields.mediator_id = "mediator-a";
    fields.room_id = room_id(3);
    fields.nonce = tradep2p::generate_recognition_nonce();
    fields.created_at = 5000;
    fields.expires_at = 5120;

    const auto signature = tradep2p::sign_recognition_response(prover.private_seed, fields);
    require(tradep2p::verify_recognition_response(prover.public_key, fields, signature),
            "a genuine signature over its own fields must verify");

    const auto other = fresh_keypair();
    require(!tradep2p::verify_recognition_response(other.public_key, fields, signature),
            "a signature must not verify under an unrelated public key");
}

// ---------------------------------------------------------------------------
// Nonce origin: the verifier generates it; a prover-invented nonce is never
// found in the tracker's outstanding set.
// ---------------------------------------------------------------------------

void test_prover_supplied_nonce_rejected() {
    tradep2p::RecognitionChallengeTracker tracker;
    const auto prover = fresh_keypair();
    const auto issued = tracker.issue("mediator-a", room_id(4), 1000);

    tradep2p::RecognitionChallengeFields forged_fields = issued;
    forged_fields.nonce = tradep2p::generate_recognition_nonce(); // prover invents its own nonce
    tradep2p::RecognitionResponseMessage response;
    response.room_id = forged_fields.room_id;
    response.nonce = forged_fields.nonce; // never matches anything tracker.issue() produced
    response.prover_public_key = prover.public_key;
    response.signature = tradep2p::sign_recognition_response(prover.private_seed, forged_fields);

    const auto result = tracker.consume("mediator-a", response, 1010);
    require(!result.has_value(), "a prover-invented nonce must never be accepted");
}

// ---------------------------------------------------------------------------
// Replay: a signature captured from a prior (already-consumed) challenge is
// rejected when replayed against that same, now-consumed challenge.
// ---------------------------------------------------------------------------

void test_replay_of_consumed_challenge_rejected() {
    tradep2p::RecognitionChallengeTracker tracker;
    const auto prover = fresh_keypair();
    const auto issued = tracker.issue("mediator-a", room_id(5), 1000);
    const auto response = sign_response(issued, prover);

    const auto first = tracker.consume("mediator-a", response, 1010);
    require(first.has_value(), "first, genuine response must verify");

    const auto replay = tracker.consume("mediator-a", response, 1015);
    require(!replay.has_value(), "replaying the exact same response must be rejected");
}

// ---------------------------------------------------------------------------
// Single-use: two DIFFERENT (but individually validly-signed) responses to
// the same issued challenge - only the first may succeed.
// ---------------------------------------------------------------------------

void test_single_use_second_response_rejected() {
    tradep2p::RecognitionChallengeTracker tracker;
    const auto prover_a = fresh_keypair();
    const auto prover_b = fresh_keypair();
    const auto issued = tracker.issue("mediator-a", room_id(6), 1000);

    const auto response_a = sign_response(issued, prover_a);
    const auto first = tracker.consume("mediator-a", response_a, 1010);
    require(first.has_value(), "first response to a fresh challenge must verify");

    // A second, independently-signed response to the SAME (now-consumed)
    // nonce must also fail, even though its own signature is genuine over
    // the same fields.
    const auto response_b = sign_response(issued, prover_b);
    const auto second = tracker.consume("mediator-a", response_b, 1011);
    require(!second.has_value(), "a second response to an already-consumed challenge must be rejected");
}

// ---------------------------------------------------------------------------
// Expiry: a response arriving after expires_at is rejected even though the
// signature itself is genuine.
// ---------------------------------------------------------------------------

void test_expired_challenge_rejected() {
    tradep2p::RecognitionChallengeTracker tracker;
    const auto prover = fresh_keypair();
    const auto issued = tracker.issue("mediator-a", room_id(7), 1000);
    require(issued.expires_at > issued.created_at, "issued challenge must have a real expiry window");

    const auto response = sign_response(issued, prover);
    const auto result = tracker.consume("mediator-a", response, issued.expires_at + 1U);
    require(!result.has_value(), "a response arriving after expiry must be rejected");
}

// ---------------------------------------------------------------------------
// Cross-context replay: a genuinely-signed response is only valid against
// the exact (mediator, room, nonce) triple it was issued for.
// ---------------------------------------------------------------------------

void test_cross_room_replay_rejected() {
    tradep2p::RecognitionChallengeTracker tracker;
    const auto prover = fresh_keypair();
    const auto issued_room_a = tracker.issue("mediator-a", room_id(8), 1000);
    // A second, unrelated outstanding challenge in a different room -
    // consume() must not accidentally match against it.
    (void)tracker.issue("mediator-a", room_id(9), 1000);

    tradep2p::RecognitionResponseMessage response = sign_response(issued_room_a, prover);
    response.room_id = room_id(9); // claim this signature answers the OTHER room

    const auto result = tracker.consume("mediator-a", response, 1010);
    require(!result.has_value(), "a response claiming the wrong room id must be rejected");
}

void test_cross_mediator_replay_rejected() {
    tradep2p::RecognitionChallengeTracker tracker;
    const auto prover = fresh_keypair();
    const auto issued = tracker.issue("mediator-a", room_id(10), 1000);
    const auto response = sign_response(issued, prover);

    // The same tracker instance, but the verifier now looks the response up
    // under a DIFFERENT mediator id than it was issued for (e.g. a client
    // mistakenly cross-wiring two sessions) - must not match.
    const auto result = tracker.consume("mediator-b", response, 1010);
    require(!result.has_value(), "a response looked up under the wrong mediator id must be rejected");
}

// ---------------------------------------------------------------------------
// Scope isolation: the same underlying master identity, derived under two
// different mediator identifiers, produces two unrelated fingerprints.
// ---------------------------------------------------------------------------

void test_scope_isolation_produces_unrelated_fingerprints() {
    const tradep2p::MasterSecret master = tradep2p::generate_master_secret();
    const auto keypair_mediator_a =
        tradep2p::derive_ed25519_keypair(master, tradep2p::key_scope::kMediatorPseudonym, "mediator-a");
    const auto keypair_mediator_b =
        tradep2p::derive_ed25519_keypair(master, tradep2p::key_scope::kMediatorPseudonym, "mediator-b");

    require(keypair_mediator_a.public_key != keypair_mediator_b.public_key,
            "the same identity must present unrelated pseudonym keys on different mediators");

    const auto fingerprint_a = tradep2p::recognition_fingerprint(keypair_mediator_a.public_key);
    const auto fingerprint_b = tradep2p::recognition_fingerprint(keypair_mediator_b.public_key);
    require(fingerprint_a != fingerprint_b,
            "fingerprints derived under two different mediator scopes must not match");

    // Determinism: re-deriving under the same (label, mediator id) pair
    // yields the identical fingerprint, which is what lets a mediator-scoped
    // recognition actually accumulate a count across separate encounters.
    const auto keypair_mediator_a_again =
        tradep2p::derive_ed25519_keypair(master, tradep2p::key_scope::kMediatorPseudonym, "mediator-a");
    require(tradep2p::recognition_fingerprint(keypair_mediator_a_again.public_key) == fingerprint_a,
            "re-deriving the same (identity, mediator) pair must reproduce the same fingerprint");
}

// ---------------------------------------------------------------------------
// Malformed input: rejected without crashing, uniformly (no distinguishable
// error path leaking which check failed first).
// ---------------------------------------------------------------------------

void test_malformed_public_key_rejected() {
    tradep2p::RecognitionChallengeTracker tracker;
    const auto issued = tracker.issue("mediator-a", room_id(11), 1000);

    tradep2p::RecognitionResponseMessage response;
    response.room_id = issued.room_id;
    response.nonce = issued.nonce;
    response.prover_public_key.fill(0U); // all-zero: never a valid Ed25519 point
    response.signature.fill(0x42U);

    const auto result = tracker.consume("mediator-a", response, 1010);
    require(!result.has_value(), "an all-zero public key must be rejected, not crash");
}

void test_wrong_signature_rejected() {
    tradep2p::RecognitionChallengeTracker tracker;
    const auto prover = fresh_keypair();
    const auto issued = tracker.issue("mediator-a", room_id(12), 1000);
    auto response = sign_response(issued, prover);
    response.signature[0] ^= 0xFFU; // corrupt one byte of an otherwise-genuine signature

    const auto result = tracker.consume("mediator-a", response, 1010);
    require(!result.has_value(), "a corrupted signature must be rejected");
}

void test_unknown_nonce_rejected() {
    tradep2p::RecognitionChallengeTracker tracker;
    const auto prover = fresh_keypair();
    // Nothing was ever issued for this room - any response is unsolicited.
    tradep2p::RecognitionChallengeFields fields;
    fields.mediator_id = "mediator-a";
    fields.room_id = room_id(13);
    fields.nonce = tradep2p::generate_recognition_nonce();
    fields.created_at = 1000;
    fields.expires_at = 1120;
    const auto response = sign_response(fields, prover);

    const auto result = tracker.consume("mediator-a", response, 1010);
    require(!result.has_value(), "a response to a never-issued challenge must be rejected");
}

// ---------------------------------------------------------------------------
// expire_stale(): outstanding challenges past their expiry are dropped, and
// a since-forgotten challenge cannot later be consumed.
// ---------------------------------------------------------------------------

void test_expire_stale_prunes_and_prevents_late_consumption() {
    tradep2p::RecognitionChallengeTracker tracker;
    const auto prover = fresh_keypair();
    const auto issued = tracker.issue("mediator-a", room_id(14), 1000);
    require(tracker.outstanding_count() == 1U, "issuing must record exactly one outstanding challenge");

    tracker.expire_stale(issued.expires_at + 1U);
    require(tracker.outstanding_count() == 0U, "expire_stale must prune a past-expiry challenge");

    const auto response = sign_response(issued, prover);
    const auto result = tracker.consume("mediator-a", response, issued.expires_at + 2U);
    require(!result.has_value(), "a pruned challenge must not be consumable afterward");
}

} // namespace

int main() {
    try {
        test_signed_payload_domain_separation();
        test_sign_verify_round_trip();
        test_prover_supplied_nonce_rejected();
        test_replay_of_consumed_challenge_rejected();
        test_single_use_second_response_rejected();
        test_expired_challenge_rejected();
        test_cross_room_replay_rejected();
        test_cross_mediator_replay_rejected();
        test_scope_isolation_produces_unrelated_fingerprints();
        test_malformed_public_key_rejected();
        test_wrong_signature_rejected();
        test_unknown_nonce_rejected();
        test_expire_stale_prunes_and_prevents_late_consumption();
        std::cout << "recognition unit tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "recognition test failure: " << error.what() << '\n';
        return 1;
    }
}
