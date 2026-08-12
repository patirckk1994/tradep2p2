#pragma once

#include "tradep2p/identity.hpp"
#include "tradep2p/protocol.hpp"
#include "tradep2p/receipt.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace tradep2p::q7933_credential {

// Credential issuance happens after a room is complete and the mediator has
// already pruned that room from its live state. Authorization therefore uses
// the durable stage-4 completion receipt that both parties already receive,
// plus a fresh proof of possession of the requesting party's per-room
// ephemeral hybrid key. The proof is bound to the exact blinded target `c`,
// so a captured authorization cannot be transplanted onto somebody else's
// blind request.
inline constexpr std::string_view kIssuanceAuthorizationDomain =
    "TRADEP2P-Q7933-CREDENTIAL-ISSUANCE-AUTH-v1";
constexpr std::size_t kQ7933AuthorizationRingDegree = 512U;

struct IssuanceAuthorizationProof {
    ReceiptIssuedMessage completion_receipt;
    Ed25519Signature signature{};
    MlDsa65Signature signature_mldsa65{};
};

// Canonical bytes signed by the party. Includes the stage-4 receipt's chain
// link hash as well as room/party/epoch and the complete q7933 blinded
// target. No hidden credential serial appears here.
[[nodiscard]] std::vector<std::uint8_t> encode_issuance_authorization_payload(
    const IssuedReceipt& completion_receipt,
    Party party,
    std::uint32_t credential_epoch,
    std::span<const std::uint16_t> blinded_target);

// Client-side helper. Throws if `completion_receipt` is not a genuine stage-4
// shaped object (completed + SettlementCompleted) or its room does not match
// itself structurally. Cryptographic verification of the mediator signature
// is still performed server-side against the server's own configured receipt
// key; this helper merely builds the party proof.
[[nodiscard]] IssuanceAuthorizationProof make_issuance_authorization_proof(
    const IssuedReceipt& completion_receipt,
    Party party,
    const Ed25519PrivateSeed& ephemeral_private_seed,
    const MlDsa65PrivateSeed& ephemeral_private_seed_mldsa65,
    std::uint32_t credential_epoch,
    std::span<const std::uint16_t> blinded_target);

// Server-side verifier. The embedded receipt key is NOT trusted on its own:
// it must match the mediator's locally configured receipt keys and mediator
// id, then both mediator receipt signatures must verify. After that, the
// party proof is tried against A and B's keys from the receipt using a
// party-specific signed payload. Returns the uniquely authorized party, or
// std::nullopt on any ordinary verification failure. Malformed inputs may
// throw from the existing receipt/protocol decoders before this is called.
[[nodiscard]] std::optional<Party> verify_issuance_authorization_proof(
    const IssuanceAuthorizationProof& proof,
    std::string_view expected_mediator_id,
    const Ed25519PublicKey& expected_mediator_public_key,
    const MlDsa65PublicKey& expected_mediator_public_key_mldsa65,
    const RoomId& expected_room_id,
    std::uint32_t credential_epoch,
    std::span<const std::uint16_t> blinded_target);

// Lossless conversion helpers between the receipt module's typed object and
// its existing wire object. Kept here so lobby/dashboard do not grow another
// pair of hand-written receipt field copies just for credential issuance.
[[nodiscard]] ReceiptIssuedMessage issuance_receipt_to_wire(const IssuedReceipt& receipt);
[[nodiscard]] IssuedReceipt issuance_receipt_from_wire(const ReceiptIssuedMessage& receipt);

} // namespace tradep2p::q7933_credential
