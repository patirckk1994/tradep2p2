#include "tradep2p/q7933_credential.hpp"
#include "tradep2p/q7933_issuance_authorization.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <random>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace tradep2p::q7933_credential {

CredentialSerial generate_serial() {
    CredentialSerial serial{};
    if (RAND_bytes(serial.data(), static_cast<int>(serial.size())) != 1) {
        throw std::runtime_error("q7933_credential: failed to generate random serial");
    }
    return serial;
}

std::vector<std::uint8_t> IssuanceContext::encode() const {
    std::vector<std::uint8_t> out;
    out.reserve(1 + 1 + 4 + 32 + 1); // version + issuer_scope + epoch + room_id + party

    out.push_back(version);
    out.push_back(issuer_scope);
    out.push_back(static_cast<std::uint8_t>((epoch >> 24) & 0xff));
    out.push_back(static_cast<std::uint8_t>((epoch >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((epoch >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(epoch & 0xff));
    out.insert(out.end(), room_id.begin(), room_id.end());
    out.push_back(party);

    return out;
}

IssuanceContext IssuanceContext::decode(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != 39U) { // 1 + 1 + 4 + 32 + 1
        throw std::runtime_error(
            "q7933_credential: IssuanceContext must be exactly 39 bytes, got " +
            std::to_string(bytes.size()));
    }

    IssuanceContext out{};
    std::size_t pos = 0U;

    out.version = bytes[pos++];
    out.issuer_scope = bytes[pos++];

    out.epoch = (static_cast<std::uint32_t>(bytes[pos]) << 24U) |
                (static_cast<std::uint32_t>(bytes[pos + 1U]) << 16U) |
                (static_cast<std::uint32_t>(bytes[pos + 2U]) << 8U) |
                static_cast<std::uint32_t>(bytes[pos + 3U]);
    pos += 4U;

    std::copy(bytes.begin() + static_cast<std::ptrdiff_t>(pos),
              bytes.begin() + static_cast<std::ptrdiff_t>(pos + 32U),
              out.room_id.begin());
    pos += 32U;

    out.party = bytes[pos];
    if (out.version != kCredentialVersion) {
        throw std::runtime_error("q7933_credential: unsupported IssuanceContext version");
    }
    if (out.party > 1U) {
        throw std::runtime_error("q7933_credential: invalid IssuanceContext party");
    }
    return out;
}

Nullifier derive_nullifier(
    const CredentialSerial& serial,
    std::uint8_t issuer_scope,
    std::uint32_t epoch,
    std::span<const std::uint8_t> presentation_scope) {
    const char* domain = "TRADEP2P-Q7933-CREDENTIAL-NULLIFIER-v1";
    const std::size_t domain_len = std::strlen(domain);

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw std::runtime_error("q7933_credential: EVP_MD_CTX_new failed");
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: EVP_DigestInit_ex failed");
    }

    if (EVP_DigestUpdate(mdctx, domain, domain_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: EVP_DigestUpdate (domain) failed");
    }
    if (EVP_DigestUpdate(mdctx, &issuer_scope, 1U) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: EVP_DigestUpdate (issuer_scope) failed");
    }

    const std::array<std::uint8_t, 4> epoch_bytes = {
        static_cast<std::uint8_t>((epoch >> 24U) & 0xffU),
        static_cast<std::uint8_t>((epoch >> 16U) & 0xffU),
        static_cast<std::uint8_t>((epoch >> 8U) & 0xffU),
        static_cast<std::uint8_t>(epoch & 0xffU),
    };
    if (EVP_DigestUpdate(mdctx, epoch_bytes.data(), epoch_bytes.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: EVP_DigestUpdate (epoch) failed");
    }

    if (presentation_scope.size() > std::numeric_limits<std::uint32_t>::max()) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: presentation_scope too large");
    }
    const std::uint32_t scope_len = static_cast<std::uint32_t>(presentation_scope.size());
    const std::array<std::uint8_t, 4> scope_len_bytes = {
        static_cast<std::uint8_t>((scope_len >> 24U) & 0xffU),
        static_cast<std::uint8_t>((scope_len >> 16U) & 0xffU),
        static_cast<std::uint8_t>((scope_len >> 8U) & 0xffU),
        static_cast<std::uint8_t>(scope_len & 0xffU),
    };
    if (EVP_DigestUpdate(mdctx, scope_len_bytes.data(), scope_len_bytes.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: EVP_DigestUpdate (scope length) failed");
    }
    if (!presentation_scope.empty() &&
        EVP_DigestUpdate(mdctx, presentation_scope.data(), presentation_scope.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: EVP_DigestUpdate (scope) failed");
    }

    if (EVP_DigestUpdate(mdctx, serial.data(), serial.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: EVP_DigestUpdate (serial) failed");
    }

    Nullifier out{};
    unsigned int out_len = 0U;
    if (EVP_DigestFinal_ex(mdctx, out.data(), &out_len) != 1 || out_len != out.size()) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(mdctx);
    return out;
}

Nullifier derive_nullifier_empty() {
    CredentialSerial empty_serial{};
    return derive_nullifier(empty_serial, 0U, 0U, {});
}

std::vector<std::uint8_t> CredentialPayload::encode() const {
    std::vector<std::uint8_t> out;

    out.push_back(version);
    out.push_back(issuer_scope);
    out.push_back(static_cast<std::uint8_t>((epoch >> 24U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>((epoch >> 16U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>((epoch >> 8U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(epoch & 0xffU));
    out.insert(out.end(), serial.begin(), serial.end());

    if (reserved.size() > std::numeric_limits<std::uint16_t>::max()) {
        throw std::runtime_error("q7933_credential: reserved field too large");
    }
    const std::uint16_t reserved_len = static_cast<std::uint16_t>(reserved.size());
    out.push_back(static_cast<std::uint8_t>((reserved_len >> 8U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(reserved_len & 0xffU));
    out.insert(out.end(), reserved.begin(), reserved.end());

    return out;
}

CredentialPayload CredentialPayload::decode(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 40U) {
        throw std::runtime_error(
            "q7933_credential: CredentialPayload too short, expected >=40 bytes, got " +
            std::to_string(bytes.size()));
    }

    CredentialPayload out{};
    std::size_t pos = 0U;

    out.version = bytes[pos++];
    out.issuer_scope = bytes[pos++];
    if (out.version != kCredentialVersion) {
        throw std::runtime_error("q7933_credential: unsupported CredentialPayload version");
    }

    out.epoch = (static_cast<std::uint32_t>(bytes[pos]) << 24U) |
                (static_cast<std::uint32_t>(bytes[pos + 1U]) << 16U) |
                (static_cast<std::uint32_t>(bytes[pos + 2U]) << 8U) |
                static_cast<std::uint32_t>(bytes[pos + 3U]);
    pos += 4U;

    std::copy(bytes.begin() + static_cast<std::ptrdiff_t>(pos),
              bytes.begin() + static_cast<std::ptrdiff_t>(pos + 32U),
              out.serial.begin());
    pos += 32U;

    if (pos + 2U > bytes.size()) {
        throw std::runtime_error("q7933_credential: CredentialPayload truncated at reserved length");
    }

    const std::uint16_t reserved_len =
        static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[pos]) << 8U) |
                                   static_cast<std::uint16_t>(bytes[pos + 1U]));
    pos += 2U;

    if (pos + reserved_len != bytes.size()) {
        throw std::runtime_error(
            "q7933_credential: CredentialPayload size mismatch, expected " +
            std::to_string(pos + reserved_len) + " bytes, got " +
            std::to_string(bytes.size()));
    }

    if (reserved_len > 0U) {
        out.reserved.insert(out.reserved.end(),
                            bytes.begin() + static_cast<std::ptrdiff_t>(pos),
                            bytes.begin() + static_cast<std::ptrdiff_t>(pos + reserved_len));
    }

    return out;
}

std::vector<std::uint8_t> encode_credential_for_blind(const CredentialPayload& payload) {
    const char* domain = "TRADEP2P-Q7933-CREDENTIAL-FOR-BLIND-v1";
    const std::size_t domain_len = std::strlen(domain);

    std::vector<std::uint8_t> out;
    const auto payload_bytes = payload.encode();
    out.reserve(domain_len + payload_bytes.size());
    out.insert(out.end(), domain, domain + static_cast<std::ptrdiff_t>(domain_len));
    out.insert(out.end(), payload_bytes.begin(), payload_bytes.end());
    return out;
}

namespace {

class AuthorizationWriter {
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

    AuthorizationWriter writer;
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
