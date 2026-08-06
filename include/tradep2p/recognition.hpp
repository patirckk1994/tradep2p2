#pragma once

// Phase 4b of the optional identity system: personal counterparty
// recognition's live proof-of-control half. See
// docs/identity-04b-counterparty-recognition.md and specs.txt SS8 for the
// design this implements. Phase 4 (history.hpp/.cpp) already provides the
// local, purely-passive storage half (a counterparty fingerprint's
// encounter/outcome history); this module is what actually establishes,
// right now, over a live connection, that the other party in a room
// currently controls the private key behind a fingerprint - without it, a
// "fingerprint" is just a label a peer could assert without proving
// anything, and history.hpp's whole guarantee ("nothing to forge, because
// the client reads its own journal") would rest on an unproven identifier.
//
// THE ONE QUESTION THIS ANSWERS, AND NO MORE (repeated here because it is
// the easiest boundary in this whole system to erode by accident, per
// specs.txt SS8.1): "does the party on the other end of this room currently
// control the private key matching this public key?" It says nothing about
// whether that party is trustworthy, human, or the same natural person who
// controlled that key yesterday. It is not identity verification.
//
// THE RECOGNITION KEY: the per-mediator pseudonym key
// (key_scope::kMediatorPseudonym, identity.hpp), never the per-trade
// ephemeral key phase 5 will add - see identity-04b's "Why this doesn't
// need phase 5" for the reasoning. Callers derive this keypair themselves
// (main.cpp/dashboard_client.cpp both do, via
// derive_ed25519_keypair(master_secret, key_scope::kMediatorPseudonym,
// mediator_id) - deliberately bypassing IdentityKeystore::
// derive_scoped_keypair()'s key-generation folding, for the same continuity
// reason main.cpp's journal signing key already bypasses it: rotating a
// service-scoped key must not silently reset accumulated counterparty
// recognition to "unknown key", which folding key_generation into this
// derivation would do on every rotation).
//
// PROOF OF CONTROL, NOT A STORED CREDENTIAL: a verifier issues a fresh
// CSPRNG nonce (never prover-chosen - see generate_recognition_nonce()) via
// RecognitionChallengeTracker::issue(), single-use and expiring. The prover
// signs a canonical, length-prefixed, domain-separated payload
// (encode_recognition_signed_payload()) binding a fixed domain label,
// protocol version, suite id, the mediator identifier, the room id, the
// nonce, and the challenge's creation/expiry times. RecognitionChallenge
// Tracker::consume() is the sole verifier-side authority on whether a
// response is fresh: it rejects (uniformly, without revealing which check
// failed - see its own comment) an unknown nonce, an expired challenge, a
// second response to an already-consumed challenge, a room-id mismatch, or
// a bad signature.
//
// ON TLS CHANNEL BINDING - A DELIBERATE, DOCUMENTED OMISSION, NOT AN
// OVERSIGHT: the phase spec asks for this handshake to bind "the TLS
// channel binding or exporter value where available". This module
// deliberately does NOT do so, and the reason is topological, not
// forgotten: clients in this codebase never connect to each other directly
// (see src/lobby.cpp) - only to the mediator. The verifier and the prover
// are therefore on two DIFFERENT TLS connections (each to the mediator),
// each with its own, connection-local exporter value that only that
// client and the mediator ever learn. A verifier has no independent way to
// check a prover-supplied exporter value from the prover's own connection
// without trusting the mediator to relay it faithfully - and the threat
// model (specs.txt SS4) already assumes the mediator may be adversarial.
// Including an unverifiable field inside the signed payload would either
// (a) go unchecked, providing no real protection while implying one, or
// (b) require trusting the one party this architecture is built to
// distrust. The freshness/single-use nonce plus explicit binding to
// room_id, mediator_id, and expiry - all independently reconstructable and
// checkable by the verifier with zero mediator cooperation - already
// provide the actual anti-replay property this handshake needs. If a future
// suite ever adds a direct (non-relayed) client-to-client transport, that
// suite id would be the right place to add real channel binding, since only
// then would both parties share one TLS connection whose exporter value
// they could each independently derive and check.
//
// SECURITY INVARIANTS:
//   - The verifier generates the nonce; the prover never supplies one -
//     enforced structurally, since RecognitionChallengeFields::nonce is
//     only ever populated by RecognitionChallengeTracker::issue().
//   - Single-use and expiring: RecognitionChallengeTracker::consume()
//     removes a challenge from its outstanding set the moment it is
//     answered (successfully or not) with a matching nonce, so a second
//     response to the same challenge always fails, and an expired challenge
//     is rejected even before its nonce is looked up.
//   - Canonical, length-prefixed, domain-separated signed payload
//     (encode_recognition_signed_payload()), reusing identity.hpp's
//     encode_derivation_info() length-prefixing discipline so that no two
//     distinct field combinations can ever serialize to the same bytes.
//   - No network calls, no file I/O anywhere in this module - it is pure
//     computation over caller-supplied bytes, exactly like identity.hpp.
//     Wire framing lives in protocol.hpp/.cpp; relaying lives in
//     lobby.cpp; this module only builds and checks the signed bytes.

#include "tradep2p/identity.hpp"
#include "tradep2p/protocol.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tradep2p {

// suite_id values. Only one exists today; the field exists from day one
// (per specs.txt SS11's "one field to add now, cheaply") so a future
// post-quantum suite can be added additively rather than requiring every
// verifier to be reissued.
constexpr std::uint16_t kRecognitionSuiteEd25519V1 = 0x0001;

inline constexpr std::string_view kRecognitionChallengeDomainLabel =
    "TRADEP2P_RECOGNITION_CHALLENGE_V1";

// How long a verifier-issued challenge remains answerable. Generous enough
// for a human to notice a prompt and respond (this is a live, interactive
// handshake, not a background poll), tight enough that a captured-but-
// unanswered challenge stops being useful quickly.
constexpr std::uint64_t kRecognitionChallengeTtlSeconds = 120;

// Matches history.hpp's kHistoryMaxMediatorIdLength / journal.hpp's
// kJournalMaxMediatorIdLength - the same opaque caller-supplied label
// (typically "host:port") used consistently across every phase that scopes
// something per-mediator.
constexpr std::size_t kRecognitionMaxMediatorIdLength = 256;

// Bounds how many challenges one RecognitionChallengeTracker will hold
// outstanding at once (issued but not yet consumed/expired) - a client only
// ever has a handful of rooms open at a time, so this is generous headroom
// against a misbehaving peer trying to exhaust memory by never responding,
// not a realistic operating limit.
constexpr std::size_t kRecognitionMaxOutstandingChallenges = 256;

// The fields bound into the signed payload - see encode_recognition_signed_
// payload() for the exact wire encoding. `mediator_id` is supplied locally
// by both the verifier (when issuing) and the prover (when signing) from
// their own knowledge of which mediator they connected to; it is never
// carried on the wire (see protocol.hpp's RecognitionChallengeMessage
// comment for why).
struct RecognitionChallengeFields {
    std::uint16_t suite_id{kRecognitionSuiteEd25519V1};
    std::uint16_t protocol_version{kProtocolVersion};
    std::string mediator_id;
    RoomId room_id{};
    RecognitionNonce nonce{};
    std::uint64_t created_at{0};
    std::uint64_t expires_at{0};
};

// Canonical, length-prefixed, domain-separated serialization of `fields` -
// the exact bytes both the prover signs and the verifier reconstructs to
// verify against. Throws std::invalid_argument if mediator_id exceeds
// kRecognitionMaxMediatorIdLength.
[[nodiscard]] std::vector<std::uint8_t> encode_recognition_signed_payload(
    const RecognitionChallengeFields& fields);

// Fresh CSPRNG nonce (RAND_bytes via identity.hpp's random_bytes()). Only
// ever called by RecognitionChallengeTracker::issue() - a prover must never
// call this to manufacture its own "challenge".
[[nodiscard]] RecognitionNonce generate_recognition_nonce();

// Signs encode_recognition_signed_payload(fields) with the prover's
// per-mediator pseudonym private key.
[[nodiscard]] Ed25519Signature sign_recognition_response(const Ed25519PrivateSeed& prover_private_seed,
                                                          const RecognitionChallengeFields& fields);

// Verifies `signature` over encode_recognition_signed_payload(fields) under
// `prover_public_key`. This alone does NOT check freshness/single-use/
// expiry - callers should route real responses through
// RecognitionChallengeTracker::consume() below, which performs this check
// only after confirming the nonce is a still-outstanding, unexpired
// challenge this tracker itself issued. Exposed standalone for testing and
// for the (rare) caller that already has a trusted, tracked
// RecognitionChallengeFields in hand.
[[nodiscard]] bool verify_recognition_response(const Ed25519PublicKey& prover_public_key,
                                                const RecognitionChallengeFields& fields,
                                                const Ed25519Signature& signature);

// sha256 of a raw 32-byte Ed25519 public key - the fingerprint convention
// this phase feeds into history.hpp's CounterpartyFingerprint (also a
// 32-byte array; the two types are layout-compatible by construction).
[[nodiscard]] std::array<std::uint8_t, 32> recognition_fingerprint(
    const Ed25519PublicKey& public_key);

// ---------------------------------------------------------------------------
// RecognitionChallengeTracker
//
// One in-memory (never persisted - a live handshake has no reason to
// survive a process restart) set of challenges THIS client has issued as a
// verifier, not yet consumed. Every RecognitionChallengeTracker is
// per-client-process, matching the CLI/dashboard's one-tracker-per-session
// convention (see main.cpp/dashboard_client.cpp).
// ---------------------------------------------------------------------------
class RecognitionChallengeTracker {
public:
    // Generates a fresh nonce, builds the full RecognitionChallengeFields
    // (created_at = now if 0, expires_at = created_at +
    // kRecognitionChallengeTtlSeconds), remembers it as outstanding, and
    // returns it ready to encode onto the wire via
    // encode_recognition_challenge(). Throws std::invalid_argument if this
    // would exceed kRecognitionMaxOutstandingChallenges (a caller should
    // prune by calling expire_stale() first, or simply retry after the
    // oldest challenges age out).
    [[nodiscard]] RecognitionChallengeFields issue(const std::string& mediator_id,
                                                    const RoomId& room_id,
                                                    std::uint64_t now = 0);

    // Verifies and single-use-consumes `response` against a previously
    // issued challenge for `mediator_id`. Returns the sha256 fingerprint of
    // response.prover_public_key on success; std::nullopt on ANY failure
    // (unknown/already-consumed nonce, room-id mismatch, expiry, or a bad
    // signature) - deliberately without distinguishing which check failed,
    // per docs/identity-04b's "malformed input ... without leaking which
    // check failed first" requirement. A matching outstanding challenge is
    // removed from the tracker whether or not the signature itself
    // verifies, so a single malformed/forged response cannot be retried
    // against the same challenge.
    [[nodiscard]] std::optional<std::array<std::uint8_t, 32>> consume(
        const std::string& mediator_id, const RecognitionResponseMessage& response,
        std::uint64_t now = 0);

    // Drops any outstanding challenge whose expiry has already passed.
    // Callers may call this periodically; consume() also applies expiry
    // per-challenge on lookup regardless, so calling this is an optimization
    // (bounding memory), never a correctness requirement.
    void expire_stale(std::uint64_t now = 0);

    [[nodiscard]] std::size_t outstanding_count() const noexcept { return outstanding_.size(); }

private:
    std::vector<RecognitionChallengeFields> outstanding_;
};

} // namespace tradep2p
