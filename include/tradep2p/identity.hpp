#pragma once

// Phase 1 of the optional identity system: cryptographic primitives only.
//
// This header introduces no persistence, no wire messages, and no change to
// any existing message type. Nothing else in the codebase calls into this
// file yet; it exists so later phases (keystore, login, per-mediator
// pseudonyms, per-trade ephemeral identities, mediator-signed receipts) have
// a single, reviewed place to get:
//   - a master identity secret (random, never derived, never transmitted),
//   - deterministic, domain-separated scoped key derivation (HKDF-SHA256
//     via OpenSSL 3's EVP_KDF, with an unambiguous length-prefixed `info`
//     encoding - see encode_derivation_info()),
//   - Ed25519 keypair generation (both deterministic-from-master and
//     freshly-random for ephemeral use), sign/verify via the one-shot
//     EVP_DigestSign/EVP_DigestVerify API (Ed25519 has no streaming
//     Update/Final path in OpenSSL),
//   - RAII ownership for the OpenSSL handle types this all requires, and
//   - constant-time comparison for anything secret-shaped.
//
// Security invariants this file is designed to uphold:
//   - The master secret is never logged, never serialized, and never used
//     directly as key material for anything other than as HKDF input.
//   - Every scoped derivation's `info` parameter is built from
//     encode_derivation_info(), which length-prefixes both the label and
//     the identifier so that e.g. label="login", id="x" cannot collide
//     with label="logi", id="nx" (naive concatenation would produce
//     identical bytes for both).
//   - Per-trade ephemeral keys (generate_ed25519_keypair()) are always
//     freshly random and are never derived from the master secret, so they
//     are unlinkable to it and to each other.
//   - Sensitive fixed-size buffers (master secret, derived keys, raw
//     Ed25519 private seeds) are wrapped in SensitiveBytes<N>, which calls
//     OPENSSL_cleanse() on destruction and on every ownership transfer away
//     from a moved-from object. This is best-effort: see the class comment
//     for what it does not guarantee.

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace tradep2p {

// ---------------------------------------------------------------------------
// Sizes
// ---------------------------------------------------------------------------

constexpr std::size_t kMasterSecretLength = 32;
constexpr std::size_t kDerivedKeyLength = 32;
constexpr std::size_t kEd25519PublicKeyLength = 32;
constexpr std::size_t kEd25519PrivateSeedLength = 32;
constexpr std::size_t kEd25519SignatureLength = 64;

// encode_derivation_info() field widths: a 1-byte label length prefix caps
// labels at 255 bytes; a 2-byte (big-endian) identifier length prefix caps
// identifiers at 65535 bytes. Both are far larger than any label/identifier
// this phase or its successors actually use.
constexpr std::size_t kMaxDerivationLabelLength = 255;
constexpr std::size_t kMaxDerivationIdentifierLength = 65535;

// ---------------------------------------------------------------------------
// RAII wrappers for OpenSSL EVP handles.
//
// Nothing in the codebase touched EVP_PKEY/EVP_MD_CTX/EVP_KDF(_CTX) before
// this phase (secure_channel.cpp only ever manages SSL_CTX/SSL/X509, which
// already have their own RAII in that file). These wrappers exist so a
// thrown exception between allocation and use can never leak the handle.
// ---------------------------------------------------------------------------

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* key) const noexcept;
};
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX* ctx) const noexcept;
};
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

struct EvpKdfDeleter {
    void operator()(EVP_KDF* kdf) const noexcept;
};
using EvpKdfPtr = std::unique_ptr<EVP_KDF, EvpKdfDeleter>;

struct EvpKdfCtxDeleter {
    void operator()(EVP_KDF_CTX* ctx) const noexcept;
};
using EvpKdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, EvpKdfCtxDeleter>;

// ---------------------------------------------------------------------------
// SensitiveBytes<N>: a fixed-size buffer that best-effort-zeroizes itself.
//
// What this DOES provide:
//   - The destructor and every move-away call OPENSSL_cleanse() on the
//     bytes, which (unlike a plain memset/std::fill) OpenSSL specifically
//     designs to survive dead-store-elimination by the optimizer.
//   - Copying is disabled by construction, so a SensitiveBytes value is
//     never silently duplicated into an un-zeroized temporary.
//
// What this DOES NOT provide (be honest about the limits):
//   - No guarantee against the OS paging the memory to swap.
//   - No guarantee against the value having been copied into CPU registers
//     or spilled to the stack by the compiler before clear() runs, nor
//     against copies made by prior std::vector reallocations if one was
//     ever involved upstream (this class itself never reallocates, but
//     callers that build a std::vector of derived key material before
//     wrapping it here should minimize that window - derive_scoped_key()
//     and derive_ed25519_keypair() below do so as tightly as practical).
//   - No mlock()/madvise(MADV_DONTDUMP) - the memory can still land in a
//     core dump or be swapped.
// This is the same "best-effort, not a hard guarantee" posture the phase
// spec asks for, not a claim of hardware-backed secret storage.
// ---------------------------------------------------------------------------
template <std::size_t N>
class SensitiveBytes {
public:
    SensitiveBytes() = default;
    explicit SensitiveBytes(const std::array<std::uint8_t, N>& bytes) : bytes_(bytes) {}

    SensitiveBytes(const SensitiveBytes&) = delete;
    SensitiveBytes& operator=(const SensitiveBytes&) = delete;

    SensitiveBytes(SensitiveBytes&& other) noexcept { *this = std::move(other); }
    SensitiveBytes& operator=(SensitiveBytes&& other) noexcept {
        if (this != &other) {
            bytes_ = other.bytes_;
            other.clear();
        }
        return *this;
    }

    ~SensitiveBytes() { clear(); }

    [[nodiscard]] std::uint8_t* data() noexcept { return bytes_.data(); }
    [[nodiscard]] const std::uint8_t* data() const noexcept { return bytes_.data(); }
    [[nodiscard]] static constexpr std::size_t size() noexcept { return N; }
    [[nodiscard]] std::span<std::uint8_t> span() noexcept { return {bytes_.data(), N}; }
    [[nodiscard]] std::span<const std::uint8_t> span() const noexcept { return {bytes_.data(), N}; }
    [[nodiscard]] const std::array<std::uint8_t, N>& bytes() const noexcept { return bytes_; }

    // Explicit early wipe, e.g. right after a private seed has been fed
    // into an EVP_PKEY and is no longer needed in raw form.
    void clear() noexcept;

private:
    std::array<std::uint8_t, N> bytes_{};
};

using MasterSecret = SensitiveBytes<kMasterSecretLength>;
using DerivedKey = SensitiveBytes<kDerivedKeyLength>;
using Ed25519PrivateSeed = SensitiveBytes<kEd25519PrivateSeedLength>;

using Ed25519PublicKey = std::array<std::uint8_t, kEd25519PublicKeyLength>;
using Ed25519Signature = std::array<std::uint8_t, kEd25519SignatureLength>;

// A keypair. The public key is not sensitive; the seed is (SensitiveBytes).
struct Ed25519KeyPair {
    Ed25519PrivateSeed private_seed;
    Ed25519PublicKey public_key{};
};

// ---------------------------------------------------------------------------
// Key-scope labels.
//
// Fixed, hard-coded ASCII identifiers for each derivation purpose in the
// key-separation tree from the phase spec. Every later phase that derives a
// scoped key MUST use one of these constants (not an ad-hoc string) as the
// `label` argument to derive_scoped_key()/derive_ed25519_keypair(), so that
// the set of labels in use stays centralized and auditable here.
// ---------------------------------------------------------------------------
namespace key_scope {
inline constexpr std::string_view kLogin = "login";                    // phase 7
inline constexpr std::string_view kMediatorPseudonym = "mediator";     // phase 6/8
inline constexpr std::string_view kLocalHistory = "local-history";    // phase 3
// The keystore's own cached, no-passphrase-required "who am I" public key
// (identifier always ""), distinct from kLogin's later per-service
// identifiers - see IdentityKeystore::create() in keystore.hpp/.cpp.
inline constexpr std::string_view kKeystoreIdentity = "keystore-identity"; // phase 2
// Deliberately no "trade" label: per-trade keys are never derived (phase 5
// generates them fresh via generate_ed25519_keypair()).
} // namespace key_scope

// ---------------------------------------------------------------------------
// Derivation-info encoding for the KDF `info`/context parameter.
//
// Format (all integers big-endian, matching this codebase's existing wire
// convention in protocol.cpp's Writer/Reader):
//
//   u8  label_len
//   u8  label_len bytes of label
//   u16 identifier_len
//   u16 identifier_len bytes of identifier
//
// This is deliberately NOT naive concatenation (label + identifier): with
// plain concatenation, label="login", identifier="x" and label="logi",
// identifier="nx" both produce the byte string "loginx", so two distinct
// derivations would collide. Length-prefixing each field makes the encoding
// injective: any two distinct (label, identifier) pairs, within the size
// limits above, always produce distinct output.
// ---------------------------------------------------------------------------
[[nodiscard]] std::vector<std::uint8_t> encode_derivation_info(
    std::string_view label, std::string_view identifier);

// ---------------------------------------------------------------------------
// Random generation
// ---------------------------------------------------------------------------

// Generates a fresh 32-byte master secret via RAND_bytes. Callers own the
// result; nothing in this file ever persists it (persistence is phase 2).
[[nodiscard]] MasterSecret generate_master_secret();

// General-purpose random bytes (RAND_bytes), for anything in this phase
// that isn't a fixed-size key/secret (e.g. building test fixtures).
[[nodiscard]] std::vector<std::uint8_t> random_bytes(std::size_t length);

// ---------------------------------------------------------------------------
// HKDF-SHA256 (OpenSSL 3.x EVP_KDF), general purpose.
// ---------------------------------------------------------------------------

// One-shot HKDF-SHA256 (extract-and-expand). `salt` may be empty (HKDF
// defines an empty salt as a zero-filled string of the hash's output
// length). Throws std::runtime_error on any OpenSSL failure.
[[nodiscard]] std::vector<std::uint8_t> hkdf_sha256(
    std::span<const std::uint8_t> secret,
    std::span<const std::uint8_t> salt,
    std::span<const std::uint8_t> info,
    std::size_t output_length);

// ---------------------------------------------------------------------------
// Scoped key derivation.
//
// derive_scoped_key() is the one function every later phase should call to
// turn (master_secret, label, identifier) into a 32-byte deterministic key:
// same inputs always yield the same output; a different label or a
// different identifier always yields a (computationally) different output.
// The master secret itself is read-only input to HKDF here - it is never
// copied out, logged, or returned.
// ---------------------------------------------------------------------------
[[nodiscard]] DerivedKey derive_scoped_key(const MasterSecret& master_secret,
                                            std::string_view label,
                                            std::string_view identifier);

// ---------------------------------------------------------------------------
// Ed25519 (OpenSSL 3.x EVP_PKEY_ED25519 interface only - no low-level API).
// ---------------------------------------------------------------------------

// Freshly random keypair via EVP_PKEY_Q_keygen. Use this, and only this,
// for per-trade ephemeral identities (phase 5): the result is unlinkable to
// any master secret and to any other keypair, by construction.
[[nodiscard]] Ed25519KeyPair generate_ed25519_keypair();

// Deterministic keypair: derives a 32-byte scoped key via derive_scoped_key
// and uses it directly as the raw Ed25519 private seed. Use for long-term
// scoped identities (login/mediator-pseudonym/local-history). Never use
// this for per-trade ephemeral keys - see generate_ed25519_keypair().
[[nodiscard]] Ed25519KeyPair derive_ed25519_keypair(const MasterSecret& master_secret,
                                                     std::string_view label,
                                                     std::string_view identifier);

// Loads an EVP_PKEY from a raw 32-byte private seed / public key. Exposed
// so callers can drive EVP_DigestSign/Verify directly when signing many
// messages under the same key without re-deriving each time.
[[nodiscard]] EvpPkeyPtr load_ed25519_private_key(const Ed25519PrivateSeed& seed);
[[nodiscard]] EvpPkeyPtr load_ed25519_public_key(const Ed25519PublicKey& public_key);

// Reconstructs a full Ed25519KeyPair (public key included) from an
// already-known raw private seed - e.g. one loaded back from a file, as
// opposed to freshly generated or HKDF-derived. Neither
// generate_ed25519_keypair() nor derive_ed25519_keypair() covers this case:
// both produce the seed themselves, but a caller restoring a previously
// persisted seed (phase 6's mediator receipt-signing key is the first use)
// needs the matching public key re-derived from it without duplicating the
// EVP_PKEY_get_raw_public_key call this file already makes twice internally.
[[nodiscard]] Ed25519KeyPair load_ed25519_keypair(const Ed25519PrivateSeed& seed);

// Validates and parses a raw public key buffer of arbitrary (e.g.
// wire-supplied, future phase) length. Rejects a buffer whose length is
// not exactly kEd25519PublicKeyLength and rejects the all-zero key
// outright (never a valid Ed25519 point encoding). A buffer that is the
// right length, non-zero, but still not a valid curve point is NOT
// rejected here - OpenSSL's Ed25519 point decompression happens lazily
// inside ed25519_verify(), which will simply return false for it; there is
// no cheap eager point-validity check exposed for Ed25519 the way there is
// for EC keys, so "invalid point" is only checkable at verify time, not at
// parse time.
[[nodiscard]] std::optional<Ed25519PublicKey> parse_ed25519_public_key(
    std::span<const std::uint8_t> bytes);

// Ed25519 has no EVP_DigestSignUpdate/Final streaming path in OpenSSL - the
// full message must be passed to one EVP_DigestSign call. These wrappers
// enforce that by taking the whole message as one span.
[[nodiscard]] Ed25519Signature ed25519_sign(const Ed25519PrivateSeed& seed,
                                             std::span<const std::uint8_t> message);
[[nodiscard]] Ed25519Signature ed25519_sign(EVP_PKEY* private_key,
                                             std::span<const std::uint8_t> message);

[[nodiscard]] bool ed25519_verify(const Ed25519PublicKey& public_key,
                                   std::span<const std::uint8_t> message,
                                   const Ed25519Signature& signature);
[[nodiscard]] bool ed25519_verify(EVP_PKEY* public_key,
                                   std::span<const std::uint8_t> message,
                                   const Ed25519Signature& signature);

// ---------------------------------------------------------------------------
// Constant-time comparison, for anything secret-shaped (derived keys, MACs,
// signatures). Backed by OpenSSL's CRYPTO_memcmp. Different-length inputs
// are simply unequal (the length itself is not treated as secret - callers
// comparing fixed-size types never hit that branch anyway).
// ---------------------------------------------------------------------------
[[nodiscard]] bool constant_time_equal(std::span<const std::uint8_t> a,
                                        std::span<const std::uint8_t> b);

} // namespace tradep2p
