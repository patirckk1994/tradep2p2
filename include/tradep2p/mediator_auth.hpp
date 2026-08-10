#pragma once

// Mediator auth: lets ANY caller ask the mediator to prove, right now, that
// it controls a persistent ML-DSA-65 identity key - reachable over a
// dedicated, unauthenticated, stateless port (see lobby.cpp's mediator auth
// control loop), independent of the main trading protocol's pinned-TLS
// connection entirely.
//
// THE ONE QUESTION THIS ANSWERS, AND NO MORE: "does whatever answered on
// this port right now control the private key behind this public key?"
// Nothing about whether that's the same operator as yesterday, whether the
// mediator itself is trustworthy, or anything else. The mediator holds NO
// memory of who asks or why - unlike recognition.hpp's tracker (per-
// challenge, single-use, expiring, because it protects a live trade room),
// there is no state to track here at all: any caller may request a fresh
// proof at any time, as many times as they like, and the mediator answers
// identically regardless of who's asking. This is deliberate - the
// mediator does not, and must not, track or recognize clients across
// sessions (see docs/IDENTITY-PLAN.md's ground rules and mediator.hpp's own
// "coordinates turns only" framing). The CLIENT alone decides whether the
// returned public key matches anything from their own trade history (a
// previously recorded instance of this same auth key, pinned trust-on-
// first-use exactly like the receipt-signing key already is) - the
// mediator makes no claim about that itself, and cannot: it has nothing to
// compare against.
//
// WHY A SEPARATE KEY FROM THE RECEIPT-SIGNING KEY (receipt.hpp) OR THE TLS
// CERTIFICATE: the receipt key is Ed25519 and receipt-scoped, tied to the
// staged-receipt protocol specifically; the TLS certificate's private key
// is not reachable for arbitrary-message application-level signing without
// new PEM-extraction plumbing this doesn't need. This is a third, dedicated
// ML-DSA-65 identity, generated once via identity.hpp's
// generate_mldsa65_keypair() and persisted the same plaintext-on-disk way
// the receipt key already is (see lobby.cpp's
// load_or_create_mediator_auth_key(), mirroring
// load_or_create_mediator_receipt_key() exactly).

#include "tradep2p/identity.hpp"
#include "tradep2p/protocol.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace tradep2p {

inline constexpr std::string_view kMediatorAuthDomainLabel = "TRADEP2P_MEDIATOR_AUTH_V1";

constexpr std::size_t kMediatorAuthNonceLength = 32;
using MediatorAuthNonce = std::array<std::uint8_t, kMediatorAuthNonceLength>;

// Matches recognition.hpp's kRecognitionMaxMediatorIdLength (same opaque
// caller-supplied "host:port"-shaped label used consistently across every
// phase that scopes something per-mediator) - duplicated here rather than
// pulled in from recognition.hpp, since this module has no other reason to
// depend on it.
constexpr std::size_t kMediatorAuthMaxMediatorIdLength = 256;

// How long a signed proof is considered fresh by convention (mirrors
// recognition.hpp's challenge TTL). This module does not itself enforce
// expiry - there is no tracker to check against, unlike recognition's
// single-use challenges - it only signs whatever created_at/expires_at the
// caller supplies. A verifier that cares about freshness (the CLI tool
// below does) should reject a response whose expires_at has already passed
// relative to its own clock.
constexpr std::uint64_t kMediatorAuthTtlSeconds = 120;

struct MediatorAuthFields {
    std::uint16_t protocol_version{kProtocolVersion};
    std::string mediator_id;
    MediatorAuthNonce nonce{};
    std::uint64_t created_at{0};
    std::uint64_t expires_at{0};
};

// Canonical, length-prefixed, domain-separated serialization of `fields` -
// the exact bytes the mediator signs and a verifier reconstructs to check
// against. Deliberately a DIFFERENT domain label from recognition.hpp's
// encode_recognition_signed_payload(), even though the shape is similar, so
// a signature produced for one context can never be replayed as valid in
// the other. Throws std::invalid_argument if mediator_id exceeds
// kMediatorAuthMaxMediatorIdLength.
[[nodiscard]] std::vector<std::uint8_t> encode_mediator_auth_signed_payload(
    const MediatorAuthFields& fields);

// Fresh CSPRNG nonce (identity.hpp's random_bytes()). Only the CALLER
// (verifying side) generates this - the mediator never invents its own
// nonce, exactly mirroring recognition.hpp's verifier-generates-the-nonce
// invariant, for the identical reason: a self-chosen "challenge" would let
// the signer pre-compute a response before ever being asked.
[[nodiscard]] MediatorAuthNonce generate_mediator_auth_nonce();

[[nodiscard]] MlDsa65Signature sign_mediator_auth(const MlDsa65PrivateSeed& private_seed,
                                                   const MediatorAuthFields& fields);

// Verifies `signature` over encode_mediator_auth_signed_payload(fields)
// under `public_key`. Does not itself check created_at/expires_at against
// the current time - see kMediatorAuthTtlSeconds' comment.
[[nodiscard]] bool verify_mediator_auth(const MlDsa65PublicKey& public_key,
                                         const MediatorAuthFields& fields,
                                         const MlDsa65Signature& signature);

} // namespace tradep2p
