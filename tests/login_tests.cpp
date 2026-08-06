#include "tradep2p/login.hpp"

#include <iostream>
#include <stdexcept>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

tradep2p::Ed25519KeyPair fresh_keypair() { return tradep2p::generate_ed25519_keypair(); }

tradep2p::Ed25519Signature sign_for(const tradep2p::LoginChallengeFields& fields,
                                    const tradep2p::Ed25519KeyPair& prover) {
    return tradep2p::sign_login_response(prover.private_seed, fields);
}

// ---------------------------------------------------------------------------
// Full round trip, valid signature accepted.
// ---------------------------------------------------------------------------

void test_full_round_trip_accepted() {
    tradep2p::LoginChallengeTracker tracker;
    const auto account_key = fresh_keypair();
    const auto issued = tracker.issue("tradep2p-webclient", "example.com:8090", "alice", 1000);

    const auto signature = sign_for(issued, account_key);
    const auto found = tracker.peek(issued.session_id, 1010);
    require(found.has_value(), "an unexpired, outstanding challenge must be found by peek()");
    require(tradep2p::verify_login_response(account_key.public_key, *found, signature),
            "a genuine signature over its own challenge fields must verify");
    tracker.consume(issued.session_id);
    require(!tracker.peek(issued.session_id, 1010).has_value(),
            "a consumed challenge must no longer be outstanding");
}

// ---------------------------------------------------------------------------
// Expired challenge rejected.
// ---------------------------------------------------------------------------

void test_expired_challenge_rejected() {
    tradep2p::LoginChallengeTracker tracker;
    const auto issued = tracker.issue("tradep2p-webclient", "example.com:8090", "alice", 1000);
    require(issued.expires_at > issued.created_at, "issued challenge must have a real expiry window");
    const auto found = tracker.peek(issued.session_id, issued.expires_at + 1U);
    require(!found.has_value(), "an expired challenge must not be returned by peek()");
}

// ---------------------------------------------------------------------------
// Replayed (already-used) challenge/signature rejected.
// ---------------------------------------------------------------------------

void test_replayed_challenge_rejected() {
    tradep2p::LoginChallengeTracker tracker;
    const auto account_key = fresh_keypair();
    const auto issued = tracker.issue("tradep2p-webclient", "example.com:8090", "alice", 1000);
    const auto signature = sign_for(issued, account_key);

    // First use succeeds, then the challenge is consumed.
    require(tracker.peek(issued.session_id, 1010).has_value(), "first lookup must succeed");
    tracker.consume(issued.session_id);

    // A second attempt with the exact same (genuine) signature must find
    // nothing outstanding to check it against.
    require(!tracker.peek(issued.session_id, 1010).has_value(),
            "a replayed session id must not be found after consumption");
    (void)signature;
}

// ---------------------------------------------------------------------------
// Challenge bound to wrong service/session rejected (signature valid, wrong
// context).
// ---------------------------------------------------------------------------

void test_wrong_context_rejected() {
    const auto account_key = fresh_keypair();
    tradep2p::LoginChallengeTracker tracker;
    const auto issued = tracker.issue("tradep2p-webclient", "example.com:8090", "alice", 1000);
    const auto signature = sign_for(issued, account_key);

    auto wrong_service = issued;
    wrong_service.service_id = "some-other-service";
    require(!tradep2p::verify_login_response(account_key.public_key, wrong_service, signature),
            "a signature must not verify under a different service id");

    auto wrong_username = issued;
    wrong_username.username = "mallory";
    require(!tradep2p::verify_login_response(account_key.public_key, wrong_username, signature),
            "a signature must not verify under a different username");

    auto wrong_server_identity = issued;
    wrong_server_identity.server_identity = "attacker.example:8090";
    require(!tradep2p::verify_login_response(account_key.public_key, wrong_server_identity, signature),
            "a signature must not verify under a different server identity");

    auto wrong_session = issued;
    wrong_session.session_id = tradep2p::generate_login_session_id();
    require(!tradep2p::verify_login_response(account_key.public_key, wrong_session, signature),
            "a signature must not verify under a different session id");
}

// ---------------------------------------------------------------------------
// Malformed/invalid public key rejected - parse_ed25519_public_key() is the
// shared primitive every phase's server-side verification uses for this;
// confirmed here for the login path specifically.
// ---------------------------------------------------------------------------

void test_malformed_public_key_rejected() {
    std::vector<std::uint8_t> all_zero(tradep2p::kEd25519PublicKeyLength, 0U);
    require(!tradep2p::parse_ed25519_public_key(all_zero).has_value(),
            "an all-zero public key must never parse as valid");

    std::vector<std::uint8_t> wrong_length(10, 0x42U);
    require(!tradep2p::parse_ed25519_public_key(wrong_length).has_value(),
            "a wrong-length public key must never parse as valid");
}

// ---------------------------------------------------------------------------
// Encoding domain separation (login field boundaries are unambiguous).
// ---------------------------------------------------------------------------

void test_encoding_domain_separation() {
    tradep2p::LoginChallengeFields a;
    a.service_id = "svc";
    a.server_identity = "host:1";
    a.username = "alice";
    a.session_id = tradep2p::generate_login_session_id();
    a.nonce = tradep2p::generate_login_nonce();
    a.created_at = 1000;
    a.expires_at = 1120;

    auto b = a;
    b.username = "alicex"; // shifts a length boundary rather than changing content type
    require(tradep2p::encode_login_challenge_signed_payload(a) !=
                tradep2p::encode_login_challenge_signed_payload(b),
            "username length must be unambiguous in the encoding");

    auto c = a;
    c.service_id = "sv";
    c.server_identity = "chost:1"; // "svc"+"host:1" vs "sv"+"chost:1" naive-concat collision check
    require(tradep2p::encode_login_challenge_signed_payload(a) !=
                tradep2p::encode_login_challenge_signed_payload(c),
            "service_id/server_identity boundary must be unambiguous (length-prefix discipline)");
}

// ---------------------------------------------------------------------------
// expire_stale() prunes and prevents late lookups.
// ---------------------------------------------------------------------------

void test_expire_stale_prunes() {
    tradep2p::LoginChallengeTracker tracker;
    const auto issued = tracker.issue("svc", "host:1", "alice", 1000);
    require(tracker.outstanding_count() == 1U, "issuing must record one outstanding challenge");
    tracker.expire_stale(issued.expires_at + 1U);
    require(tracker.outstanding_count() == 0U, "expire_stale must prune a past-expiry challenge");
}

} // namespace

int main() {
    try {
        test_full_round_trip_accepted();
        test_expired_challenge_rejected();
        test_replayed_challenge_rejected();
        test_wrong_context_rejected();
        test_malformed_public_key_rejected();
        test_encoding_domain_separation();
        test_expire_stale_prunes();
        std::cout << "login unit tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "login test failure: " << error.what() << '\n';
        return 1;
    }
}
