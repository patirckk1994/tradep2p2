#include "tradep2p/disclosure.hpp"

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
            throw std::invalid_argument("disclosure field exceeds protocol limit");
        }
        u16(static_cast<std::uint16_t>(value.size()));
        out_.insert(out_.end(), value.begin(), value.end());
    }
    [[nodiscard]] std::vector<std::uint8_t> take() { return std::move(out_); }

private:
    std::vector<std::uint8_t> out_;
};

} // namespace

std::vector<std::uint8_t> encode_disclosure_signed_payload(const DisclosureFields& fields) {
    if (fields.mediator_id.size() > kDisclosureMaxMediatorIdLength) {
        throw std::invalid_argument("disclosure mediator id exceeds maximum length");
    }
    Writer writer;
    writer.length_prefixed(kDisclosureDomainLabel, kDisclosureDomainLabel.size());
    writer.u16(fields.protocol_version);
    writer.u16(fields.suite_id);
    writer.length_prefixed(fields.mediator_id, kDisclosureMaxMediatorIdLength);
    writer.bytes(fields.room_id);
    writer.bytes(fields.recipient_ephemeral_key);
    writer.bytes(fields.disclosed_chain_hash);
    writer.u64(fields.timestamp);
    writer.bytes(fields.nonce);
    return writer.take();
}

std::array<std::uint8_t, 32> disclosed_chain_hash(const std::vector<IssuedReceipt>& chain) {
    Writer writer;
    for (const auto& entry : chain) {
        writer.bytes(receipt_chain_link_hash(entry.fields, entry.mediator_signature));
    }
    return sha256(writer.take());
}

Ed25519Signature sign_disclosure(const Ed25519PrivateSeed& original_ephemeral_private_seed,
                                 const DisclosureFields& fields) {
    return ed25519_sign(original_ephemeral_private_seed, encode_disclosure_signed_payload(fields));
}

bool verify_disclosure(const Ed25519PublicKey& original_ephemeral_public_key,
                       const DisclosureFields& fields, const Ed25519Signature& signature) {
    return ed25519_verify(original_ephemeral_public_key, encode_disclosure_signed_payload(fields),
                          signature);
}

std::optional<std::string> verify_disclosure_bundle(const std::vector<IssuedReceipt>& chain,
                                                     const DisclosureFields& fields,
                                                     const Ed25519Signature& signature,
                                                     const RoomId& expected_room_id,
                                                     const Ed25519PublicKey& expected_recipient_key) {
    if (chain.empty()) {
        return "disclosed receipt chain is empty";
    }
    if (chain.size() > kDisclosureMaxChainLength) {
        return "disclosed receipt chain exceeds the maximum allowed length";
    }
    try {
        verify_receipt_chain(chain, chain.front().fields.mediator_public_key);
    } catch (const ReceiptChainError& error) {
        return std::string("disclosed receipt chain does not verify: ") + error.what();
    }
    if (disclosed_chain_hash(chain) != fields.disclosed_chain_hash) {
        return "disclosure envelope does not match the accompanying receipt chain";
    }
    if (fields.room_id != expected_room_id) {
        return "disclosure envelope is not bound to this negotiation";
    }
    if (fields.recipient_ephemeral_key != expected_recipient_key) {
        return "disclosure envelope is not bound to this recipient";
    }
    const bool valid_under_party_a =
        verify_disclosure(chain.front().fields.party_a_ephemeral_key, fields, signature);
    const bool valid_under_party_b =
        verify_disclosure(chain.front().fields.party_b_ephemeral_key, fields, signature);
    if (!valid_under_party_a && !valid_under_party_b) {
        return "disclosure envelope signature does not match either party's key in the chain";
    }
    return std::nullopt;
}

} // namespace tradep2p
