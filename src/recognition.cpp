#include "tradep2p/recognition.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <chrono>
#include <limits>
#include <stdexcept>

namespace tradep2p {
namespace {

// ---------------------------------------------------------------------------
// SHA-256, duplicated locally rather than reused from journal.hpp's
// sha256() - pulling in journal.hpp here would drag in mediator.hpp
// (SessionState) purely for a digest helper, which this module has no other
// reason to depend on. Matches history.cpp's identical rationale for
// duplicating its own small OpenSSL helpers per-module.
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Minimal length-prefixed writer, matching identity.hpp's
// encode_derivation_info() discipline: every variable-length field is
// prefixed with its own length so the encoding is injective (no two
// distinct field combinations can ever produce identical bytes).
// ---------------------------------------------------------------------------
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
            throw std::invalid_argument("recognition field exceeds protocol limit");
        }
        u16(static_cast<std::uint16_t>(value.size()));
        out_.insert(out_.end(), value.begin(), value.end());
    }
    [[nodiscard]] std::vector<std::uint8_t> take() { return std::move(out_); }

private:
    std::vector<std::uint8_t> out_;
};

std::uint64_t now_unix_seconds() {
    return static_cast<std::uint64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
}

} // namespace

std::vector<std::uint8_t> encode_recognition_signed_payload(const RecognitionChallengeFields& fields) {
    if (fields.mediator_id.size() > kRecognitionMaxMediatorIdLength) {
        throw std::invalid_argument("recognition mediator id exceeds maximum length");
    }
    Writer writer;
    writer.length_prefixed(kRecognitionChallengeDomainLabel, kRecognitionChallengeDomainLabel.size());
    writer.u16(fields.protocol_version);
    writer.u16(fields.suite_id);
    writer.length_prefixed(fields.mediator_id, kRecognitionMaxMediatorIdLength);
    writer.bytes(fields.room_id);
    writer.bytes(fields.nonce);
    writer.u64(fields.created_at);
    writer.u64(fields.expires_at);
    return writer.take();
}

RecognitionNonce generate_recognition_nonce() {
    RecognitionNonce nonce{};
    const std::vector<std::uint8_t> raw = random_bytes(nonce.size());
    std::copy(raw.begin(), raw.end(), nonce.begin());
    return nonce;
}

Ed25519Signature sign_recognition_response(const Ed25519PrivateSeed& prover_private_seed,
                                            const RecognitionChallengeFields& fields) {
    const std::vector<std::uint8_t> payload = encode_recognition_signed_payload(fields);
    return ed25519_sign(prover_private_seed, payload);
}

bool verify_recognition_response(const Ed25519PublicKey& prover_public_key,
                                  const RecognitionChallengeFields& fields,
                                  const Ed25519Signature& signature) {
    const std::vector<std::uint8_t> payload = encode_recognition_signed_payload(fields);
    return ed25519_verify(prover_public_key, payload, signature);
}

std::array<std::uint8_t, 32> recognition_fingerprint(const Ed25519PublicKey& public_key) {
    return sha256(public_key);
}

RecognitionChallengeFields RecognitionChallengeTracker::issue(const std::string& mediator_id,
                                                                const RoomId& room_id,
                                                                std::uint64_t now) {
    if (outstanding_.size() >= kRecognitionMaxOutstandingChallenges) {
        throw std::invalid_argument("too many outstanding recognition challenges");
    }
    if (now == 0U) {
        now = now_unix_seconds();
    }
    RecognitionChallengeFields fields;
    fields.suite_id = kRecognitionSuiteEd25519V1;
    fields.protocol_version = kProtocolVersion;
    fields.mediator_id = mediator_id;
    fields.room_id = room_id;
    fields.nonce = generate_recognition_nonce();
    fields.created_at = now;
    fields.expires_at = now + kRecognitionChallengeTtlSeconds;
    outstanding_.push_back(fields);
    return fields;
}

void RecognitionChallengeTracker::expire_stale(std::uint64_t now) {
    if (now == 0U) {
        now = now_unix_seconds();
    }
    outstanding_.erase(
        std::remove_if(outstanding_.begin(), outstanding_.end(),
                        [now](const RecognitionChallengeFields& fields) {
                            return now > fields.expires_at;
                        }),
        outstanding_.end());
}

std::optional<std::array<std::uint8_t, 32>> RecognitionChallengeTracker::consume(
    const std::string& mediator_id, const RecognitionResponseMessage& response, std::uint64_t now) {
    if (now == 0U) {
        now = now_unix_seconds();
    }

    const auto it = std::find_if(
        outstanding_.begin(), outstanding_.end(), [&](const RecognitionChallengeFields& fields) {
            return fields.nonce == response.nonce && fields.room_id == response.room_id &&
                   fields.mediator_id == mediator_id;
        });
    if (it == outstanding_.end()) {
        return std::nullopt;
    }

    // Single-use: remove the moment a matching challenge is found, whether
    // or not it turns out to be expired or the signature verifies below -
    // an attacker gets exactly one attempt to answer any given challenge.
    const RecognitionChallengeFields fields = *it;
    outstanding_.erase(it);

    if (now > fields.expires_at) {
        return std::nullopt;
    }

    const auto public_key = parse_ed25519_public_key(response.prover_public_key);
    if (!public_key.has_value()) {
        return std::nullopt;
    }

    if (!verify_recognition_response(*public_key, fields, response.signature)) {
        return std::nullopt;
    }

    return recognition_fingerprint(*public_key);
}

} // namespace tradep2p
