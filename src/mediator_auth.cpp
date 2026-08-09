#include "tradep2p/mediator_auth.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace tradep2p {
namespace {

// Minimal length-prefixed writer, matching recognition.cpp's identical
// discipline (and identity.hpp's encode_derivation_info() before that):
// every variable-length field is prefixed with its own length so the
// encoding is injective. Duplicated locally rather than shared, matching
// this codebase's established per-module convention for these small
// self-contained helpers (see recognition.cpp's own comment on why).
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
            throw std::invalid_argument("mediator auth field exceeds protocol limit");
        }
        u16(static_cast<std::uint16_t>(value.size()));
        out_.insert(out_.end(), value.begin(), value.end());
    }
    [[nodiscard]] std::vector<std::uint8_t> take() { return std::move(out_); }

private:
    std::vector<std::uint8_t> out_;
};

} // namespace

std::vector<std::uint8_t> encode_mediator_auth_signed_payload(const MediatorAuthFields& fields) {
    if (fields.mediator_id.size() > kMediatorAuthMaxMediatorIdLength) {
        throw std::invalid_argument("mediator auth mediator id exceeds maximum length");
    }
    Writer writer;
    writer.length_prefixed(kMediatorAuthDomainLabel, kMediatorAuthDomainLabel.size());
    writer.u16(fields.protocol_version);
    writer.length_prefixed(fields.mediator_id, kMediatorAuthMaxMediatorIdLength);
    writer.bytes(fields.nonce);
    writer.u64(fields.created_at);
    writer.u64(fields.expires_at);
    return writer.take();
}

MediatorAuthNonce generate_mediator_auth_nonce() {
    MediatorAuthNonce nonce{};
    const std::vector<std::uint8_t> raw = random_bytes(nonce.size());
    std::copy(raw.begin(), raw.end(), nonce.begin());
    return nonce;
}

MlDsa65Signature sign_mediator_auth(const MlDsa65PrivateSeed& private_seed,
                                    const MediatorAuthFields& fields) {
    const std::vector<std::uint8_t> payload = encode_mediator_auth_signed_payload(fields);
    const EvpPkeyPtr key = load_mldsa65_private_key(private_seed);
    return mldsa65_sign(key.get(), payload);
}

bool verify_mediator_auth(const MlDsa65PublicKey& public_key, const MediatorAuthFields& fields,
                          const MlDsa65Signature& signature) {
    const std::vector<std::uint8_t> payload = encode_mediator_auth_signed_payload(fields);
    return mldsa65_verify(public_key, payload, signature);
}

} // namespace tradep2p
