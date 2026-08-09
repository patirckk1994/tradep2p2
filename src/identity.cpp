#include "tradep2p/identity.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace tradep2p {

// ---------------------------------------------------------------------------
// RAII deleters
// ---------------------------------------------------------------------------

void EvpPkeyDeleter::operator()(EVP_PKEY* key) const noexcept { EVP_PKEY_free(key); }
void EvpMdCtxDeleter::operator()(EVP_MD_CTX* ctx) const noexcept { EVP_MD_CTX_free(ctx); }
void EvpKdfDeleter::operator()(EVP_KDF* kdf) const noexcept { EVP_KDF_free(kdf); }
void EvpKdfCtxDeleter::operator()(EVP_KDF_CTX* ctx) const noexcept { EVP_KDF_CTX_free(ctx); }
void EvpPkeyCtxDeleter::operator()(EVP_PKEY_CTX* ctx) const noexcept { EVP_PKEY_CTX_free(ctx); }

// ---------------------------------------------------------------------------
// SensitiveBytes<N>::clear()
// ---------------------------------------------------------------------------

template <std::size_t N>
void SensitiveBytes<N>::clear() noexcept {
    OPENSSL_cleanse(bytes_.data(), bytes_.size());
}

// kMasterSecretLength, kDerivedKeyLength, kEd25519PrivateSeedLength, and
// kMlDsa65SeedLength are all 32 today, so MasterSecret/DerivedKey/
// Ed25519PrivateSeed/MlDsa65PrivateSeed are all literally the same
// SensitiveBytes<32> type - one explicit instantiation covers all four
// aliases. If any of these sizes ever diverges, a second explicit
// instantiation line must be added here for the new size.
static_assert(kMasterSecretLength == kDerivedKeyLength &&
                  kDerivedKeyLength == kEd25519PrivateSeedLength &&
                  kEd25519PrivateSeedLength == kMlDsa65SeedLength,
              "SensitiveBytes explicit instantiation below assumes these sizes match; "
              "add another `template class SensitiveBytes<N>;` line if they diverge");
template class SensitiveBytes<kMasterSecretLength>;

namespace {

[[noreturn]] void throw_openssl_error(const std::string& message) {
    const unsigned long code = ERR_get_error();
    char buffer[256]{};
    if (code != 0U) {
        ERR_error_string_n(code, buffer, sizeof(buffer));
        throw std::runtime_error(message + ": " + buffer);
    }
    throw std::runtime_error(message);
}

// Minimal big-endian writer, matching protocol.cpp's Writer convention, used
// only to build the derivation-info byte string.
void append_u8(std::vector<std::uint8_t>& out, std::uint8_t value) {
    out.push_back(value);
}

void append_u16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

} // namespace

// ---------------------------------------------------------------------------
// Derivation info encoding
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> encode_derivation_info(std::string_view label,
                                                  std::string_view identifier) {
    if (label.size() > kMaxDerivationLabelLength) {
        throw std::invalid_argument("derivation label exceeds maximum length");
    }
    if (identifier.size() > kMaxDerivationIdentifierLength) {
        throw std::invalid_argument("derivation identifier exceeds maximum length");
    }

    std::vector<std::uint8_t> out;
    out.reserve(1U + label.size() + 2U + identifier.size());
    append_u8(out, static_cast<std::uint8_t>(label.size()));
    out.insert(out.end(), label.begin(), label.end());
    append_u16(out, static_cast<std::uint16_t>(identifier.size()));
    out.insert(out.end(), identifier.begin(), identifier.end());
    return out;
}

// ---------------------------------------------------------------------------
// Random generation
// ---------------------------------------------------------------------------

MasterSecret generate_master_secret() {
    std::array<std::uint8_t, kMasterSecretLength> bytes{};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw_openssl_error("failed to generate master secret");
    }
    MasterSecret secret(bytes);
    OPENSSL_cleanse(bytes.data(), bytes.size());
    return secret;
}

std::vector<std::uint8_t> random_bytes(std::size_t length) {
    std::vector<std::uint8_t> out(length);
    if (length == 0U) {
        return out;
    }
    if (length > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::invalid_argument("random_bytes length too large");
    }
    if (RAND_bytes(out.data(), static_cast<int>(length)) != 1) {
        throw_openssl_error("failed to generate random bytes");
    }
    return out;
}

// ---------------------------------------------------------------------------
// HKDF-SHA256
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> hkdf_sha256(std::span<const std::uint8_t> secret,
                                       std::span<const std::uint8_t> salt,
                                       std::span<const std::uint8_t> info,
                                       std::size_t output_length) {
    EvpKdfPtr kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf) {
        throw_openssl_error("failed to fetch HKDF algorithm");
    }
    EvpKdfCtxPtr kctx(EVP_KDF_CTX_new(kdf.get()));
    if (!kctx) {
        throw_openssl_error("failed to create HKDF context");
    }

    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    // OSSL_PARAM_construct_octet_string wants non-const void* pointers; the
    // KDF only reads through them, but the C API is not const-correct here.
    std::array<OSSL_PARAM, 6> params{};
    std::size_t index = 0U;
    params[index++] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0U);
    params[index++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, const_cast<std::uint8_t*>(secret.data()), secret.size());
    if (!salt.empty()) {
        params[index++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, const_cast<std::uint8_t*>(salt.data()), salt.size());
    }
    if (!info.empty()) {
        params[index++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, const_cast<std::uint8_t*>(info.data()), info.size());
    }
    params[index++] = OSSL_PARAM_construct_end();

    if (EVP_KDF_CTX_set_params(kctx.get(), params.data()) <= 0) {
        throw_openssl_error("failed to set HKDF parameters");
    }

    std::vector<std::uint8_t> out(output_length);
    if (output_length > 0U &&
        EVP_KDF_derive(kctx.get(), out.data(), out.size(), nullptr) <= 0) {
        throw_openssl_error("HKDF derivation failed");
    }
    return out;
}

// ---------------------------------------------------------------------------
// Scoped key derivation
// ---------------------------------------------------------------------------

DerivedKey derive_scoped_key(const MasterSecret& master_secret,
                              std::string_view label,
                              std::string_view identifier) {
    const std::vector<std::uint8_t> info = encode_derivation_info(label, identifier);
    // No salt: HKDF treats an absent/empty salt as a zero-filled string of
    // the hash's output length, which is the standard, well-defined
    // behaviour for a single fixed secret being derived into multiple
    // independent, domain-separated subkeys via `info`.
    std::vector<std::uint8_t> raw =
        hkdf_sha256(master_secret.span(), {}, info, kDerivedKeyLength);

    std::array<std::uint8_t, kDerivedKeyLength> fixed{};
    std::copy_n(raw.begin(), kDerivedKeyLength, fixed.begin());
    OPENSSL_cleanse(raw.data(), raw.size());

    DerivedKey key(fixed);
    OPENSSL_cleanse(fixed.data(), fixed.size());
    return key;
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

EvpPkeyPtr load_ed25519_private_key(const Ed25519PrivateSeed& seed) {
    EvpPkeyPtr key(EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, seed.data(), seed.size()));
    if (!key) {
        throw_openssl_error("failed to load Ed25519 private key");
    }
    return key;
}

EvpPkeyPtr load_ed25519_public_key(const Ed25519PublicKey& public_key) {
    EvpPkeyPtr key(EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size()));
    if (!key) {
        throw_openssl_error("failed to load Ed25519 public key");
    }
    return key;
}

Ed25519KeyPair load_ed25519_keypair(const Ed25519PrivateSeed& seed) {
    const EvpPkeyPtr key = load_ed25519_private_key(seed);
    Ed25519KeyPair pair;
    pair.private_seed = Ed25519PrivateSeed(seed.bytes());
    std::size_t pub_len = pair.public_key.size();
    if (EVP_PKEY_get_raw_public_key(key.get(), pair.public_key.data(), &pub_len) != 1 ||
        pub_len != kEd25519PublicKeyLength) {
        throw_openssl_error("failed to derive Ed25519 public key from seed");
    }
    return pair;
}

std::optional<Ed25519PublicKey> parse_ed25519_public_key(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != kEd25519PublicKeyLength) {
        return std::nullopt;
    }
    Ed25519PublicKey key{};
    std::copy_n(bytes.begin(), kEd25519PublicKeyLength, key.begin());
    const bool all_zero = std::all_of(key.begin(), key.end(),
                                       [](std::uint8_t byte) { return byte == 0U; });
    if (all_zero) {
        return std::nullopt;
    }
    return key;
}

Ed25519KeyPair generate_ed25519_keypair() {
    EvpPkeyPtr key(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"));
    if (!key) {
        throw_openssl_error("failed to generate Ed25519 keypair");
    }

    Ed25519KeyPair pair;
    std::array<std::uint8_t, kEd25519PrivateSeedLength> seed_bytes{};
    std::size_t seed_len = seed_bytes.size();
    if (EVP_PKEY_get_raw_private_key(key.get(), seed_bytes.data(), &seed_len) != 1 ||
        seed_len != kEd25519PrivateSeedLength) {
        OPENSSL_cleanse(seed_bytes.data(), seed_bytes.size());
        throw_openssl_error("failed to extract Ed25519 private seed");
    }
    pair.private_seed = Ed25519PrivateSeed(seed_bytes);
    OPENSSL_cleanse(seed_bytes.data(), seed_bytes.size());

    std::size_t pub_len = pair.public_key.size();
    if (EVP_PKEY_get_raw_public_key(key.get(), pair.public_key.data(), &pub_len) != 1 ||
        pub_len != kEd25519PublicKeyLength) {
        throw_openssl_error("failed to extract Ed25519 public key");
    }
    return pair;
}

Ed25519KeyPair derive_ed25519_keypair(const MasterSecret& master_secret,
                                       std::string_view label,
                                       std::string_view identifier) {
    static_assert(kDerivedKeyLength == kEd25519PrivateSeedLength,
                  "derived scoped key must be exactly the Ed25519 raw seed length");

    DerivedKey derived = derive_scoped_key(master_secret, label, identifier);

    Ed25519KeyPair pair;
    pair.private_seed = Ed25519PrivateSeed(derived.bytes());
    derived.clear();

    const EvpPkeyPtr key = load_ed25519_private_key(pair.private_seed);
    std::size_t pub_len = pair.public_key.size();
    if (EVP_PKEY_get_raw_public_key(key.get(), pair.public_key.data(), &pub_len) != 1 ||
        pub_len != kEd25519PublicKeyLength) {
        throw_openssl_error("failed to extract Ed25519 public key from derived seed");
    }
    return pair;
}

Ed25519Signature ed25519_sign(EVP_PKEY* private_key, std::span<const std::uint8_t> message) {
    if (private_key == nullptr) {
        throw std::invalid_argument("ed25519_sign: null private key");
    }

    EvpMdCtxPtr md_ctx(EVP_MD_CTX_new());
    if (!md_ctx) {
        throw_openssl_error("failed to allocate EVP_MD_CTX");
    }
    // Ed25519's EVP_PKEY type fixes its own digest ("pure" Ed25519, PH is
    // identity) - the digest argument to EVP_DigestSignInit must be null.
    if (EVP_DigestSignInit(md_ctx.get(), nullptr, nullptr, nullptr, private_key) != 1) {
        throw_openssl_error("EVP_DigestSignInit failed");
    }

    Ed25519Signature signature{};
    std::size_t sig_len = signature.size();
    // Ed25519 has no EVP_DigestSignUpdate/Final path in OpenSSL - the whole
    // message must be passed to a single EVP_DigestSign call.
    if (EVP_DigestSign(md_ctx.get(), signature.data(), &sig_len, message.data(),
                        message.size()) != 1 ||
        sig_len != kEd25519SignatureLength) {
        throw_openssl_error("EVP_DigestSign failed");
    }
    return signature;
}

Ed25519Signature ed25519_sign(const Ed25519PrivateSeed& seed,
                               std::span<const std::uint8_t> message) {
    const EvpPkeyPtr key = load_ed25519_private_key(seed);
    return ed25519_sign(key.get(), message);
}

bool ed25519_verify(EVP_PKEY* public_key, std::span<const std::uint8_t> message,
                     const Ed25519Signature& signature) {
    if (public_key == nullptr) {
        return false;
    }

    EvpMdCtxPtr md_ctx(EVP_MD_CTX_new());
    if (!md_ctx) {
        throw_openssl_error("failed to allocate EVP_MD_CTX");
    }
    if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, nullptr, nullptr, public_key) != 1) {
        throw_openssl_error("EVP_DigestVerifyInit failed");
    }

    // One-shot verify; a return value other than 1 means "does not verify"
    // (whether due to a bad signature, a bad message, or a public key that
    // does not decode to a valid curve point) - never treat it as a thrown
    // error, since a malicious/malformed input reaching this function is an
    // expected, not exceptional, case for a verify function.
    const int result = EVP_DigestVerify(md_ctx.get(), signature.data(), signature.size(),
                                         message.data(), message.size());
    return result == 1;
}

bool ed25519_verify(const Ed25519PublicKey& public_key, std::span<const std::uint8_t> message,
                     const Ed25519Signature& signature) {
    const EvpPkeyPtr key = load_ed25519_public_key(public_key);
    return ed25519_verify(key.get(), message, signature);
}

// ---------------------------------------------------------------------------
// ML-DSA-65 (FIPS 204, post-quantum)
// ---------------------------------------------------------------------------

EvpPkeyPtr load_mldsa65_private_key(const MlDsa65PrivateSeed& seed) {
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-65", nullptr));
    if (!ctx) {
        throw_openssl_error("failed to create ML-DSA-65 keygen context");
    }
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        throw_openssl_error("EVP_PKEY_keygen_init failed for ML-DSA-65");
    }

    // "seed" is the exact OSSL_PARAM key ML-DSA-65 keygen accepts for
    // deterministic seed-based generation on this OpenSSL build - confirmed
    // via EVP_PKEY_CTX_settable_params() against OpenSSL 3.5.5, not
    // assumed. OSSL_PARAM_construct_octet_string wants a non-const void*;
    // the KDF/keygen only reads through it, matching hkdf_sha256()'s same
    // const_cast usage above for the identical reason.
    std::array<OSSL_PARAM, 2> params{};
    params[0] = OSSL_PARAM_construct_octet_string(
        "seed", const_cast<std::uint8_t*>(seed.data()), seed.size());
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(ctx.get(), params.data()) <= 0) {
        throw_openssl_error("failed to set ML-DSA-65 seed parameter");
    }

    EVP_PKEY* raw_key = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw_key) <= 0) {
        throw_openssl_error("ML-DSA-65 keygen failed");
    }
    return EvpPkeyPtr(raw_key);
}

EvpPkeyPtr load_mldsa65_public_key(const MlDsa65PublicKey& public_key) {
    // ML-DSA has no legacy fixed EVP_PKEY_* NID the way Ed25519 does (it is
    // provider-supplied), so reconstructing a public-key-only EVP_PKEY from
    // raw bytes uses the newer name-based "_ex" constructor instead of
    // EVP_PKEY_new_raw_public_key - verified against this OpenSSL build to
    // correctly round-trip (sign with a full keypair, verify against a
    // public-only key reconstructed this way from just its raw bytes).
    EvpPkeyPtr key(EVP_PKEY_new_raw_public_key_ex(
        nullptr, "ML-DSA-65", nullptr, public_key.data(), public_key.size()));
    if (!key) {
        throw_openssl_error("failed to load ML-DSA-65 public key");
    }
    return key;
}

std::optional<MlDsa65PublicKey> parse_mldsa65_public_key(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != kMlDsa65PublicKeyLength) {
        return std::nullopt;
    }
    MlDsa65PublicKey key{};
    std::copy_n(bytes.begin(), kMlDsa65PublicKeyLength, key.begin());
    const bool all_zero = std::all_of(key.begin(), key.end(),
                                       [](std::uint8_t byte) { return byte == 0U; });
    if (all_zero) {
        return std::nullopt;
    }
    return key;
}

MlDsa65KeyPair derive_mldsa65_keypair(const MasterSecret& master_secret,
                                       std::string_view label,
                                       std::string_view identifier) {
    static_assert(kDerivedKeyLength == kMlDsa65SeedLength,
                  "derived scoped key must be exactly the ML-DSA-65 seed length");

    DerivedKey derived = derive_scoped_key(master_secret, label, identifier);

    MlDsa65KeyPair pair;
    pair.private_seed = MlDsa65PrivateSeed(derived.bytes());
    derived.clear();

    const EvpPkeyPtr key = load_mldsa65_private_key(pair.private_seed);
    std::size_t pub_len = pair.public_key.size();
    if (EVP_PKEY_get_octet_string_param(key.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                         pair.public_key.data(), pair.public_key.size(),
                                         &pub_len) != 1 ||
        pub_len != kMlDsa65PublicKeyLength) {
        throw_openssl_error("failed to extract ML-DSA-65 public key from derived seed");
    }
    return pair;
}

MlDsa65Signature mldsa65_sign(EVP_PKEY* private_key, std::span<const std::uint8_t> message) {
    if (private_key == nullptr) {
        throw std::invalid_argument("mldsa65_sign: null private key");
    }

    EvpMdCtxPtr md_ctx(EVP_MD_CTX_new());
    if (!md_ctx) {
        throw_openssl_error("failed to allocate EVP_MD_CTX");
    }
    // ML-DSA is also a "pure" signature scheme (no external prehash) - the
    // digest argument to EVP_DigestSignInit must be null, same as Ed25519.
    if (EVP_DigestSignInit(md_ctx.get(), nullptr, nullptr, nullptr, private_key) != 1) {
        throw_openssl_error("EVP_DigestSignInit failed");
    }

    MlDsa65Signature signature{};
    std::size_t sig_len = signature.size();
    if (EVP_DigestSign(md_ctx.get(), signature.data(), &sig_len, message.data(),
                        message.size()) != 1 ||
        sig_len != kMlDsa65SignatureLength) {
        throw_openssl_error("EVP_DigestSign failed");
    }
    return signature;
}

bool mldsa65_verify(EVP_PKEY* public_key, std::span<const std::uint8_t> message,
                     const MlDsa65Signature& signature) {
    if (public_key == nullptr) {
        return false;
    }

    EvpMdCtxPtr md_ctx(EVP_MD_CTX_new());
    if (!md_ctx) {
        throw_openssl_error("failed to allocate EVP_MD_CTX");
    }
    if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, nullptr, nullptr, public_key) != 1) {
        throw_openssl_error("EVP_DigestVerifyInit failed");
    }

    // One-shot verify; a return value other than 1 means "does not verify" -
    // never treat it as a thrown error, matching ed25519_verify()'s exact
    // rationale (a malicious/malformed input reaching this function is
    // expected, not exceptional).
    const int result = EVP_DigestVerify(md_ctx.get(), signature.data(), signature.size(),
                                         message.data(), message.size());
    return result == 1;
}

bool mldsa65_verify(const MlDsa65PublicKey& public_key, std::span<const std::uint8_t> message,
                     const MlDsa65Signature& signature) {
    const EvpPkeyPtr key = load_mldsa65_public_key(public_key);
    return mldsa65_verify(key.get(), message, signature);
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

bool constant_time_equal(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) {
    if (a.size() != b.size()) {
        return false;
    }
    if (a.empty()) {
        return true;
    }
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

} // namespace tradep2p
