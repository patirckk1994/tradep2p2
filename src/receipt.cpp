#include "tradep2p/receipt.hpp"

#include <openssl/evp.h>

#include <limits>
#include <memory>
#include <stdexcept>

namespace tradep2p {
namespace {

std::array<std::uint8_t, 32> sha256(std::span<const std::uint8_t> data) {
    struct EvpMdCtxDeleter {
        void operator()(EVP_MD_CTX* ctx) const noexcept { EVP_MD_CTX_free(ctx); }
    };
    std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter> ctx(EVP_MD_CTX_new());
    if (!ctx) {
        throw std::runtime_error("failed to allocate digest context");
    }
    std::array<std::uint8_t, 32> digest{};
    unsigned int digest_len = 0U;
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), digest.data(), &digest_len) != 1 ||
        digest_len != digest.size()) {
        throw std::runtime_error("SHA-256 digest failed");
    }
    return digest;
}

class Writer {
public:
    void u8(std::uint8_t value) { out_.push_back(value); }
    void u16(std::uint16_t value) {
        out_.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
        out_.push_back(static_cast<std::uint8_t>(value & 0xffU));
    }
    void u64(std::uint64_t value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            out_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
        }
    }
    void bytes(std::span<const std::uint8_t> value) {
        out_.insert(out_.end(), value.begin(), value.end());
    }
    void length_prefixed(std::string_view value, std::size_t maximum) {
        if (value.size() > maximum || value.size() > std::numeric_limits<std::uint16_t>::max()) {
            throw std::invalid_argument("receipt field exceeds protocol limit");
        }
        u16(static_cast<std::uint16_t>(value.size()));
        out_.insert(out_.end(), value.begin(), value.end());
    }
    [[nodiscard]] std::vector<std::uint8_t> take() { return std::move(out_); }

private:
    std::vector<std::uint8_t> out_;
};

void require_known_stage(ReceiptStage stage) {
    switch (stage) {
        case ReceiptStage::TermsAccepted:
        case ReceiptStage::RoundAcknowledged:
        case ReceiptStage::PenultimateObligationsComplete:
        case ReceiptStage::SettlementCompleted:
            return;
    }
    throw std::invalid_argument("unknown receipt stage");
}

} // namespace

const char* receipt_stage_name(ReceiptStage stage) {
    switch (stage) {
        case ReceiptStage::TermsAccepted: return "terms_accepted";
        case ReceiptStage::RoundAcknowledged: return "round_acknowledged";
        case ReceiptStage::PenultimateObligationsComplete: return "penultimate_obligations_complete";
        case ReceiptStage::SettlementCompleted: return "settlement_completed";
    }
    return "unknown";
}

std::vector<std::uint8_t> encode_receipt_ack_signed_payload(const ReceiptAckFields& fields) {
    require_known_stage(fields.stage);
    if (fields.mediator_id.size() > kReceiptMaxMediatorIdLength) {
        throw std::invalid_argument("receipt ack mediator id exceeds maximum length");
    }
    Writer writer;
    writer.length_prefixed(kReceiptAckDomainLabel, kReceiptAckDomainLabel.size());
    writer.u16(fields.protocol_version);
    writer.u16(fields.suite_id);
    writer.length_prefixed(fields.mediator_id, kReceiptMaxMediatorIdLength);
    writer.bytes(fields.room_id);
    writer.u8(static_cast<std::uint8_t>(fields.stage));
    writer.bytes(fields.terms_commitment);
    writer.u64(fields.timestamp);
    return writer.take();
}

Ed25519Signature sign_receipt_ack(const Ed25519PrivateSeed& ephemeral_private_seed,
                                   const ReceiptAckFields& fields) {
    return ed25519_sign(ephemeral_private_seed, encode_receipt_ack_signed_payload(fields));
}

bool verify_receipt_ack(const Ed25519PublicKey& ephemeral_public_key, const ReceiptAckFields& fields,
                        const Ed25519Signature& signature) {
    return ed25519_verify(ephemeral_public_key, encode_receipt_ack_signed_payload(fields), signature);
}

MlDsa65Signature sign_receipt_ack_mldsa65(const MlDsa65PrivateSeed& ephemeral_private_seed,
                                          const ReceiptAckFields& fields) {
    const std::vector<std::uint8_t> payload = encode_receipt_ack_signed_payload(fields);
    const EvpPkeyPtr key = load_mldsa65_private_key(ephemeral_private_seed);
    return mldsa65_sign(key.get(), payload);
}

bool verify_receipt_ack_mldsa65(const MlDsa65PublicKey& ephemeral_public_key,
                                const ReceiptAckFields& fields, const MlDsa65Signature& signature) {
    return mldsa65_verify(ephemeral_public_key, encode_receipt_ack_signed_payload(fields), signature);
}

bool verify_receipt_ack_hybrid(const Ed25519PublicKey& ephemeral_public_key,
                               const MlDsa65PublicKey& ephemeral_public_key_mldsa65,
                               const ReceiptAckFields& fields, const Ed25519Signature& signature,
                               const MlDsa65Signature& signature_mldsa65) {
    return verify_receipt_ack(ephemeral_public_key, fields, signature) &&
           verify_receipt_ack_mldsa65(ephemeral_public_key_mldsa65, fields, signature_mldsa65);
}

std::vector<std::uint8_t> encode_receipt_signed_payload(const ReceiptFields& fields) {
    require_known_stage(fields.stage);
    if (fields.mediator_id.size() > kReceiptMaxMediatorIdLength) {
        throw std::invalid_argument("receipt mediator id exceeds maximum length");
    }
    Writer writer;
    writer.length_prefixed(kReceiptDomainLabel, kReceiptDomainLabel.size());
    writer.u16(fields.protocol_version);
    writer.u16(fields.suite_id);
    writer.length_prefixed(fields.mediator_id, kReceiptMaxMediatorIdLength);
    writer.bytes(fields.room_id);
    writer.bytes(fields.terms_commitment);
    writer.bytes(fields.party_a_ephemeral_key);
    writer.bytes(fields.party_b_ephemeral_key);
    writer.bytes(fields.party_a_ephemeral_key_mldsa65);
    writer.bytes(fields.party_b_ephemeral_key_mldsa65);
    writer.bytes(fields.mediator_public_key);
    writer.bytes(fields.mediator_public_key_mldsa65);
    writer.u8(static_cast<std::uint8_t>(fields.stage));
    writer.u8(fields.completed ? 1U : 0U);
    writer.u64(fields.timestamp);
    writer.bytes(fields.nonce);
    writer.bytes(fields.previous_stage_hash);
    return writer.take();
}

Ed25519Signature sign_receipt(const Ed25519PrivateSeed& mediator_private_seed,
                              const ReceiptFields& fields) {
    return ed25519_sign(mediator_private_seed, encode_receipt_signed_payload(fields));
}

bool verify_receipt(const Ed25519PublicKey& mediator_public_key, const ReceiptFields& fields,
                    const Ed25519Signature& signature) {
    return ed25519_verify(mediator_public_key, encode_receipt_signed_payload(fields), signature);
}

MlDsa65Signature sign_receipt_mldsa65(const MlDsa65PrivateSeed& mediator_private_seed,
                                      const ReceiptFields& fields) {
    const std::vector<std::uint8_t> payload = encode_receipt_signed_payload(fields);
    const EvpPkeyPtr key = load_mldsa65_private_key(mediator_private_seed);
    return mldsa65_sign(key.get(), payload);
}

bool verify_receipt_mldsa65(const MlDsa65PublicKey& mediator_public_key, const ReceiptFields& fields,
                            const MlDsa65Signature& signature) {
    return mldsa65_verify(mediator_public_key, encode_receipt_signed_payload(fields), signature);
}

bool verify_receipt_hybrid(const Ed25519PublicKey& mediator_public_key,
                           const MlDsa65PublicKey& mediator_public_key_mldsa65,
                           const ReceiptFields& fields, const Ed25519Signature& signature,
                           const MlDsa65Signature& signature_mldsa65) {
    return verify_receipt(mediator_public_key, fields, signature) &&
           verify_receipt_mldsa65(mediator_public_key_mldsa65, fields, signature_mldsa65);
}

std::array<std::uint8_t, 32> receipt_chain_link_hash(
    const ReceiptFields& fields, const Ed25519Signature& mediator_signature,
    const MlDsa65Signature& mediator_signature_mldsa65) {
    std::vector<std::uint8_t> bytes = encode_receipt_signed_payload(fields);
    bytes.insert(bytes.end(), mediator_signature.begin(), mediator_signature.end());
    bytes.insert(bytes.end(), mediator_signature_mldsa65.begin(), mediator_signature_mldsa65.end());
    return sha256(bytes);
}

void verify_receipt_chain(const std::vector<IssuedReceipt>& chain,
                          const Ed25519PublicKey& mediator_public_key,
                          const MlDsa65PublicKey& mediator_public_key_mldsa65) {
    if (chain.empty()) {
        throw ReceiptChainError("receipt chain is empty");
    }

    const ReceiptFields& first = chain.front().fields;
    std::array<std::uint8_t, 32> expected_previous_hash{}; // all-zero for the first entry

    std::optional<ReceiptStage> previous_stage;
    for (const auto& entry : chain) {
        const ReceiptFields& fields = entry.fields;
        require_known_stage(fields.stage);

        if (!verify_receipt_hybrid(mediator_public_key, mediator_public_key_mldsa65, fields,
                                   entry.mediator_signature, entry.mediator_signature_mldsa65)) {
            throw ReceiptChainError("receipt signature does not verify");
        }
        if (fields.room_id != first.room_id || fields.terms_commitment != first.terms_commitment ||
            fields.party_a_ephemeral_key != first.party_a_ephemeral_key ||
            fields.party_b_ephemeral_key != first.party_b_ephemeral_key ||
            fields.party_a_ephemeral_key_mldsa65 != first.party_a_ephemeral_key_mldsa65 ||
            fields.party_b_ephemeral_key_mldsa65 != first.party_b_ephemeral_key_mldsa65 ||
            fields.mediator_public_key != first.mediator_public_key ||
            fields.mediator_public_key_mldsa65 != first.mediator_public_key_mldsa65) {
            throw ReceiptChainError(
                "receipt chain mixes entries from different rooms or parties");
        }
        if (fields.previous_stage_hash != expected_previous_hash) {
            throw ReceiptChainError("receipt chain link hash mismatch");
        }
        if (previous_stage.has_value() &&
            static_cast<std::uint8_t>(fields.stage) <= static_cast<std::uint8_t>(*previous_stage)) {
            throw ReceiptChainError("receipt chain stages do not strictly increase");
        }

        previous_stage = fields.stage;
        expected_previous_hash = receipt_chain_link_hash(fields, entry.mediator_signature,
                                                          entry.mediator_signature_mldsa65);
    }
}

Ed25519KeyPair generate_mediator_receipt_keypair() { return generate_ed25519_keypair(); }

} // namespace tradep2p
