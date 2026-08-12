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

constexpr std::uint8_t kCredentialVersion = 1U;
// Epoch rotation/pruning policy is intentionally not implemented yet. Until
// it is, accepting an arbitrary client-chosen epoch would let one completed
// room mint unlimited credentials simply by incrementing the epoch. V1 is
// therefore pinned to exactly epoch zero; future rotation must change the
// server policy deliberately rather than treating this field as free input.
constexpr std::uint32_t kCredentialEpochV1 = 0U;

using CredentialSerial = std::array<std::uint8_t, 32>;

struct IssuanceContext {
    std::uint8_t version{kCredentialVersion};
    std::uint8_t issuer_scope{0U};
    std::uint32_t epoch{kCredentialEpochV1};
    std::array<std::uint8_t, 32> room_id{};
    std::uint8_t party{0U};

    [[nodiscard]] std::vector<std::uint8_t> encode() const;
    [[nodiscard]] static IssuanceContext decode(std::span<const std::uint8_t> bytes);
};

using Nullifier = std::array<std::uint8_t, 32>;

[[nodiscard]] CredentialSerial generate_serial();

[[nodiscard]] Nullifier derive_nullifier(
    const CredentialSerial& serial,
    std::uint8_t issuer_scope,
    std::uint32_t epoch,
    std::span<const std::uint8_t> presentation_scope);

[[nodiscard]] Nullifier derive_nullifier_empty();

struct CredentialPayload {
    std::uint8_t version{kCredentialVersion};
    std::uint8_t issuer_scope{0U};
    std::uint32_t epoch{kCredentialEpochV1};
    CredentialSerial serial{};
    std::vector<std::uint8_t> reserved;

    [[nodiscard]] std::vector<std::uint8_t> encode() const;
    [[nodiscard]] static CredentialPayload decode(std::span<const std::uint8_t> bytes);
};

[[nodiscard]] std::vector<std::uint8_t> encode_credential_for_blind(
    const CredentialPayload& payload);

} // namespace tradep2p::q7933_credential
