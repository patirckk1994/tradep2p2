#include "tradep2p/ephemeral.hpp"

#include <openssl/evp.h>

#include <limits>
#include <memory>
#include <stdexcept>

namespace tradep2p {
namespace {

// Duplicated locally rather than reused from journal.hpp/recognition.cpp -
// matching this codebase's established per-module convention (see
// history.cpp/recognition.cpp's identical rationale).
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
    void u32(std::uint32_t value) {
        for (int shift = 24; shift >= 0; shift -= 8) {
            out_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
        }
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
            throw std::invalid_argument("trade message field exceeds protocol limit");
        }
        u16(static_cast<std::uint16_t>(value.size()));
        out_.insert(out_.end(), value.begin(), value.end());
    }
    [[nodiscard]] std::vector<std::uint8_t> take() { return std::move(out_); }

private:
    std::vector<std::uint8_t> out_;
};

} // namespace

std::vector<std::uint8_t> encode_trade_message_context(const TradeMessageContext& context) {
    if (context.mediator_id.size() > kTradeMessageMaxMediatorIdLength) {
        throw std::invalid_argument("trade message mediator id exceeds maximum length");
    }
    Writer writer;
    writer.length_prefixed(kTradeMessageDomainLabel, kTradeMessageDomainLabel.size());
    writer.u16(context.protocol_version);
    writer.u16(context.suite_id);
    writer.length_prefixed(context.mediator_id, kTradeMessageMaxMediatorIdLength);
    writer.bytes(context.room_id);
    writer.u32(context.round);
    writer.u16(static_cast<std::uint16_t>(context.message_type));
    writer.bytes(context.payload_hash);
    writer.bytes(context.sender_ephemeral_public_key);
    writer.bytes(context.recipient);
    writer.u64(context.timestamp);
    return writer.take();
}

Ed25519KeyPair generate_ephemeral_trade_keypair() { return generate_ed25519_keypair(); }

MlDsa65KeyPair generate_ephemeral_trade_keypair_mldsa65() { return generate_mldsa65_keypair(); }

Ed25519Signature sign_trade_message(const Ed25519PrivateSeed& sender_ephemeral_private_seed,
                                     const TradeMessageContext& context) {
    const std::vector<std::uint8_t> payload = encode_trade_message_context(context);
    return ed25519_sign(sender_ephemeral_private_seed, payload);
}

bool verify_trade_message(const Ed25519PublicKey& sender_ephemeral_public_key,
                          const TradeMessageContext& context, const Ed25519Signature& signature) {
    const std::vector<std::uint8_t> payload = encode_trade_message_context(context);
    return ed25519_verify(sender_ephemeral_public_key, payload, signature);
}

MlDsa65Signature sign_trade_message_mldsa65(
    const MlDsa65PrivateSeed& sender_ephemeral_private_seed_mldsa65, const TradeMessageContext& context) {
    const std::vector<std::uint8_t> payload = encode_trade_message_context(context);
    const EvpPkeyPtr key = load_mldsa65_private_key(sender_ephemeral_private_seed_mldsa65);
    return mldsa65_sign(key.get(), payload);
}

bool verify_trade_message_mldsa65(const MlDsa65PublicKey& sender_ephemeral_public_key_mldsa65,
                                  const TradeMessageContext& context,
                                  const MlDsa65Signature& signature) {
    const std::vector<std::uint8_t> payload = encode_trade_message_context(context);
    return mldsa65_verify(sender_ephemeral_public_key_mldsa65, payload, signature);
}

bool verify_trade_message_hybrid(const Ed25519PublicKey& sender_ephemeral_public_key,
                                 const MlDsa65PublicKey& sender_ephemeral_public_key_mldsa65,
                                 const TradeMessageContext& context, const Ed25519Signature& signature,
                                 const MlDsa65Signature& signature_mldsa65) {
    return verify_trade_message(sender_ephemeral_public_key, context, signature) &&
           verify_trade_message_mldsa65(sender_ephemeral_public_key_mldsa65, context, signature_mldsa65);
}

std::array<std::uint8_t, 32> trade_payload_hash(std::span<const std::uint8_t> encoded_payload) {
    return sha256(encoded_payload);
}

} // namespace tradep2p
