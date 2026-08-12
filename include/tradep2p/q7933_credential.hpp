#pragma once

// Credential-layer semantics for q7933 blind-signature primitive.
// 
// This module adds the missing credential-layer structures described in
// specs.txt §9.3 on top of the existing §9.3a blind-signature primitive:
//
// 1. Credential serial: a cryptographically random 32-byte value generated
//    client-side and included in the blinded message (hidden from mediator).
//
// 2. Issuance uniqueness: once per completed room/party/epoch. Enforced via
//    durable server-side storage (q7933_issuance_store).
//
// 3. Credential nullifier: derived from the hidden serial and presentation
//    scope (room_id + verifier/counterparty identity + epoch), preventing
//    cross-room replay and duplicate presentation.
//
// 4. Presentation binding: cryptographic commitment to the room and verifier
//    context, rejecting replay attempts in different rooms.
//
// Mediator learns: room X / party Y has already claimed its issuance.
// Mediator does NOT learn: this later presented credential is from room X.
//
// Serialization is versioned and length-prefixed to support future extensions.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace tradep2p::q7933_credential {

// Credential versioning for forward compatibility.
constexpr std::uint8_t kCredentialVersion = 1;

// The hidden credential serial: 32 bytes of cryptographically random data.
// Generated client-side, never revealed to mediator (included in blinded
// commitment), included in nullifier derivation and presentaton binding.
using CredentialSerial = std::array<std::uint8_t, 32>;

// Issuance context identifier: uniquely identifies which room/party/epoch
// combination this credential can be issued for. Stored by the mediator
// to enforce the one-per-context uniqueness constraint.
//
// Versioned and length-prefixed to support future credential types.
struct IssuanceContext {
    std::uint8_t version;
    // Identifies the issuer's public key (implicit in single-signer mediator model).
    std::uint8_t issuer_scope;
    // Credential epoch: allows rotating to new credentials across time periods.
    std::uint32_t epoch;
    // Room this credential can be issued for (32 bytes).
    std::array<std::uint8_t, 32> room_id;
    // Participant's slot in the room (A or B, 0 or 1).
    std::uint8_t party;

    [[nodiscard]] std::vector<std::uint8_t> encode() const;
    [[nodiscard]] static IssuanceContext decode(std::span<const std::uint8_t> bytes);
};

// Derives a domain-separated nullifier from the hidden serial and
// presentation scope. The nullifier is stable and recomputable ONLY within
// a specific presentation scope (room_id + verifier/counterparty identity +
// epoch). Different scopes produce different nullifiers, preventing both
// cross-room replay and double-counting within the same room.
//
// Nullifier = H(
//   "TRADEP2P-Q7933-CREDENTIAL-NULLIFIER-v1" ||
//   issuer_scope ||
//   epoch ||
//   presentation_scope ||
//   serial
// )
//
// Where presentation_scope typically includes:
//   - current room_id
//   - intended verifier/counterparty ephemeral key (if available)
//   - fresh challenge (if implemented)
//
// The empty presentation_scope variant is defined for testing/default cases
// where a verifier is not yet specified.
using Nullifier = std::array<std::uint8_t, 32>;

// Generate a random credential serial.
[[nodiscard]] CredentialSerial generate_serial();

// Derive a nullifier from the serial, issuer scope, epoch, and
// presentation scope. Supports both a full scope (room + verifier) and
// an empty scope (testing/generation phase).
[[nodiscard]] Nullifier derive_nullifier(
    const CredentialSerial& serial,
    std::uint8_t issuer_scope,
    std::uint32_t epoch,
    std::span<const std::uint8_t> presentation_scope);

[[nodiscard]] Nullifier derive_nullifier_empty();

// Credential payload structure (client-side internal representation).
// Versioned and length-prefixed for serialization.
struct CredentialPayload {
    std::uint8_t version;
    std::uint8_t issuer_scope;
    std::uint32_t epoch;
    CredentialSerial serial;
    // Additional fields for future extensions (marked as reserved).
    std::vector<std::uint8_t> reserved;

    [[nodiscard]] std::vector<std::uint8_t> encode() const;
    [[nodiscard]] static CredentialPayload decode(std::span<const std::uint8_t> bytes);
};

// Test/utility function: encode credential payload and serial for hashing
// during NIZK1 proof generation. The mediator never sees the serial;
// the client uses this to bind the serial into the blinded commitment.
[[nodiscard]] std::vector<std::uint8_t> encode_credential_for_blind(
    const CredentialPayload& payload);

} // namespace tradep2p::q7933_credential
