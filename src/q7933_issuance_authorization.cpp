#include "tradep2p/q7933_issuance_authorization.hpp"

#include "tradep2p/q7933_credential.hpp"

#include <limits>
#include <stdexcept>

namespace tradep2p::q7933_credential {
namespace {

class Writer {
public:
    void u8(std::uint8_t value) { out_.push_back(value); }

    void u16(std::uint16_t value) {
        out_.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
        out_.push_back(static_cast<std::uint8_t>(value & 0xffU));
    }

    void u32(std::uint32_t value) {
        for (int shift = 24; shift >= 0; shift -= 8) {
            out_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
        }
    }

    void bytes(std::span<const std::uint8_t> value) {
        out_.insert(out_.end(), value.begin(), value.end());
    }

    void text(std::string_view value) {
        if (value.size() > std::numeric_limits<std::uint16_t>::max()) {
            throw std::invalid_argument("q7933 issuance authorization domain is too long");
        }
        u16(static_cast<std::uint16_t>(value.size()));
        out_.insert(out_.end(), value.begin(), value.end());
    }

    [[nodiscard]] std::vector<std::uint8_t> take() { return std::move(out_); }

private:
    std::vector<std::uint8_t> out_;
};

void require_stage4_shape(const IssuedReceipt& receipt) {
    if (receipt.fields.stage != ReceiptStage::SettlementCompleted || !receipt.fields.completed) {
        throw std::invalid_argument(
            "q7933 credential issuance requires a completed stage-4 receipt");
    }
}

bool verifies_for_party(const IssuedReceipt& receipt,
                        Party party,
                        std::uint32_t credential_epoch,
                        std::span<const std::uint16_t> blinded_target,
                        const Ed25519Signature& signature,
                        const MlDsa65Signature& signature_mldsa65) {
    const auto payload = encode_issuance_authorization_payload(
        receipt, party, credential_epoch, blinded_target);
    const Ed25519PublicKey& ed_key =
        party == Party::A ? receipt.fields.party_a_ephemeral_key
                          : receipt.fields.party_b_ephemeral_key;
    const MlDsa65PublicKey& ml_key =
        party == Party::A ? receipt.fields.party_a_ephemeral_key_mldsa65
                          : receipt.fields.party_b_ephemeral_key_mldsa65;
    return ed25519_verify(ed_key, payload, signature) &&
           mldsa65_verify(ml_key, payload, signature_mldsa65);
}

} // namespace

ReceiptIssuedMessage issuance_receipt_to_wire(const IssuedReceipt& receipt) {
    ReceiptIssuedMessage wire;
    wire.room_id = receipt.fields.room_id;
    wire.mediator_id = receipt.fields.mediator_id;
    wire.stage = static_cast<std::uint8_t>(receipt.fields.stage);
    wire.completed = receipt.fields.completed;
    wire.terms_commitment = receipt.fields.terms_commitment;
    wire.party_a_ephemeral_key = receipt.fields.party_a_ephemeral_key;
    wire.party_b_ephemeral_key = receipt.fields.party_b_ephemeral_key;
    wire.party_a_ephemeral_key_mldsa65 = receipt.fields.party_a_ephemeral_key_mldsa65;
    wire.party_b_ephemeral_key_mldsa65 = receipt.fields.party_b_ephemeral_key_mldsa65;
    wire.mediator_public_key = receipt.fields.mediator_public_key;
    wire.mediator_public_key_mldsa65 = receipt.fields.mediator_public_key_mldsa65;
    wire.timestamp = receipt.fields.timestamp;
    wire.nonce = receipt.fields.nonce;
    wire.previous_stage_hash = receipt.fields.previous_stage_hash;
    wire.mediator_signature = receipt.mediator_signature;
    wire.mediator_signature_mldsa65 = receipt.mediator_signature_mldsa65;
    return wire;
}

IssuedReceipt issuance_receipt_from_wire(const ReceiptIssuedMessage& wire) {
    IssuedReceipt receipt;
    receipt.fields.mediator_id = wire.mediator_id;
    receipt.fields.room_id = wire.room_id;
    receipt.fields.terms_commitment = wire.terms_commitment;
    receipt.fields.party_a_ephemeral_key = wire.party_a_ephemeral_key;
    receipt.fields.party_b_ephemeral_key = wire.party_b_ephemeral_key;
    receipt.fields.party_a_ephemeral_key_mldsa65 = wire.party_a_ephemeral_key_mldsa65;
    receipt.fields.party_b_ephemeral_key_mldsa65 = wire.party_b_ephemeral_key_mldsa65;
    receipt.fields.mediator_public_key = wire.mediator_public_key;
    receipt.fields.mediator_public_key_mldsa65 = wire.mediator_public_key_mldsa65;
    receipt.fields.stage = static_cast<ReceiptStage>(wire.stage);
    receipt.fields.completed = wire.completed;
    receipt.fields.timestamp = wire.timestamp;
    receipt.fields.nonce = wire.nonce;
    receipt.fields.previous_stage_hash = wire.previous_stage_hash;
    receipt.mediator_signature = wire.mediator_signature;
    receipt.mediator_signature_mldsa65 = wire.mediator_signature_mldsa65;
    return receipt;
}

std::vector<std::uint8_t> encode_issuance_authorization_payload(
    const IssuedReceipt& completion_receipt,
    Party party,
    std::uint32_t credential_epoch,
    std::span<const std::uint16_t> blinded_target) {
    require_stage4_shape(completion_receipt);
    if (blinded_target.size() != kQ7933AuthorizationRingDegree) {
        throw std::invalid_argument("q7933 issuance authorization target has wrong degree");
    }
    if (party != Party::A && party != Party::B) {
        throw std::invalid_argument("q7933 issuance authorization has invalid party");
    }

    const auto receipt_hash = receipt_chain_link_hash(
        completion_receipt.fields, completion_receipt.mediator_signature,
        completion_receipt.mediator_signature_mldsa65);

    Writer writer;
    writer.text(kIssuanceAuthorizationDomain);
    writer.u16(kProtocolVersion);
    writer.u8(kCredentialVersion);
    writer.u8(static_cast<std::uint8_t>(party));
    writer.u32(credential_epoch);
    writer.bytes(completion_receipt.fields.room_id);
    writer.bytes(receipt_hash);
    for (const auto coefficient : blinded_target) {
        writer.u16(coefficient);
    }
    return writer.take();
}

IssuanceAuthorizationProof make_issuance_authorization_proof(
    const IssuedReceipt& completion_receipt,
    Party party,
    const Ed25519PrivateSeed& ephemeral_private_seed,
    const MlDsa65PrivateSeed& ephemeral_private_seed_mldsa65,
    std::uint32_t credential_epoch,
    std::span<const std::uint16_t> blinded_target) {
    const auto payload = encode_issuance_authorization_payload(
        completion_receipt, party, credential_epoch, blinded_target);

    IssuanceAuthorizationProof proof;
    proof.completion_receipt = issuance_receipt_to_wire(completion_receipt);
    proof.signature = ed25519_sign(ephemeral_private_seed, payload);
    const auto ml_key = load_mldsa65_private_key(ephemeral_private_seed_mldsa65);
    proof.signature_mldsa65 = mldsa65_sign(ml_key.get(), payload);
    return proof;
}

std::optional<Party> verify_issuance_authorization_proof(
    const IssuanceAuthorizationProof& proof,
    std::string_view expected_mediator_id,
    const Ed25519PublicKey& expected_mediator_public_key,
    const MlDsa65PublicKey& expected_mediator_public_key_mldsa65,
    const RoomId& expected_room_id,
    std::uint32_t credential_epoch,
    std::span<const std::uint16_t> blinded_target) {
    if (blinded_target.size() != kQ7933AuthorizationRingDegree) {
        return std::nullopt;
    }

    const IssuedReceipt receipt = issuance_receipt_from_wire(proof.completion_receipt);
    if (receipt.fields.stage != ReceiptStage::SettlementCompleted ||
        !receipt.fields.completed ||
        receipt.fields.room_id != expected_room_id ||
        receipt.fields.mediator_id != expected_mediator_id ||
        receipt.fields.mediator_public_key != expected_mediator_public_key ||
        receipt.fields.mediator_public_key_mldsa65 != expected_mediator_public_key_mldsa65) {
        return std::nullopt;
    }

    if (!verify_receipt_hybrid(expected_mediator_public_key,
                               expected_mediator_public_key_mldsa65,
                               receipt.fields,
                               receipt.mediator_signature,
                               receipt.mediator_signature_mldsa65)) {
        return std::nullopt;
    }

    const bool party_a = verifies_for_party(receipt, Party::A, credential_epoch,
                                             blinded_target, proof.signature,
                                             proof.signature_mldsa65);
    const bool party_b = verifies_for_party(receipt, Party::B, credential_epoch,
                                             blinded_target, proof.signature,
                                             proof.signature_mldsa65);
    if (party_a == party_b) {
        return std::nullopt;
    }
    return party_a ? std::optional<Party>{Party::A}
                   : std::optional<Party>{Party::B};
}

} // namespace tradep2p::q7933_credential
