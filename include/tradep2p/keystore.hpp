#pragma once

// Phase 2 of the optional identity system: an at-rest, passphrase-encrypted
// local keystore file for the master secret phase 1 (identity.hpp/identity.cpp)
// defined.
//
// This file introduces no network protocol changes. It is a purely local
// file format plus the operations the phase-2 prompt enumerates: create,
// unlock, lock, change-passphrase, export/import an encrypted backup,
// display-public-identity (without unlocking), rotate a service-scoped key
// generation counter, and destroy (best-effort shred + unlink).
//
// Security invariants (see keystore.cpp for the implementation):
//   - Passphrase -> AEAD key derivation uses Argon2id via OpenSSL 3.2+'s
//     EVP_KDF ("ARGON2ID"), which this repository's linked OpenSSL 3.5.5
//     provides. PBKDF2-HMAC-SHA256 is used ONLY as a last-resort fallback if
//     Argon2id genuinely cannot be fetched at runtime (recorded in the file
//     itself via `kdf_algorithm`, so a keystore always self-describes which
//     KDF protects it).
//   - Authenticated encryption is ChaCha20-Poly1305 (IETF, 96-bit nonce,
//     128-bit tag), matching this codebase's existing TLS 1.3 ciphersuite
//     preference order (TLS_CHACHA20_POLY1305_SHA256 listed first in
//     secure_channel.cpp's harden_context()).
//   - A fresh random nonce and a fresh random KDF salt are generated for
//     every single encryption (create, change-passphrase, rotate) - the key
//     itself also changes every time because the salt feeding Argon2id
//     changes, so nonce reuse under a fixed key never occurs by
//     construction.
//   - The AEAD tag is verified before any decrypted byte is used for
//     anything (parsed, returned, or fed into a keypair derivation). A
//     failed tag verification and a malformed/truncated file are reported
//     via two different, but equally uninformative, exception types - never
//     a partially-applied result and never a silent fallback to a fresh
//     identity.
//   - All metadata (format version, identity id, alias, created_at, KDF
//     parameters, key generation counter, cached public key) is bound into
//     the AEAD's associated data, so tampering with any header field also
//     invalidates the tag, even though most of that metadata is not secret.
//   - Every write to disk is: write a 0600-permissioned temporary file,
//     fsync it, atomically rename it over the final path, and (for brand
//     new files) refuse to replace an existing file at all - matching this
//     repository's existing tmp-then-rename convention in
//     LobbyServer::Impl::write_state_snapshot() (src/lobby.cpp), but adding
//     owner-only permissions and fsync, neither of which that display-only
//     snapshot needed.

#include "tradep2p/identity.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace tradep2p {

// ---------------------------------------------------------------------------
// Sizes / constants
// ---------------------------------------------------------------------------

constexpr std::uint16_t kKeystoreFormatVersion = 1;

constexpr std::size_t kKeystoreIdentityIdLength = 16;
constexpr std::size_t kKeystoreAeadKeyLength = 32;   // ChaCha20-Poly1305 key
constexpr std::size_t kKeystoreAeadNonceLength = 12; // IETF ChaCha20-Poly1305
constexpr std::size_t kKeystoreAeadTagLength = 16;
constexpr std::size_t kKeystoreMaxAliasLength = 255;

// Argon2id parameters (RFC 9106 section 4's "second recommended option" for
// interactive/password-hashing use: 64 MiB memory, 3 passes, 4 lanes). These
// are the defaults used by create()/change_passphrase(); they are also
// stored in the file itself so an unlock never has to guess them, and so a
// future phase could raise them for new keystores without breaking the
// ability to read older ones.
constexpr std::uint32_t kArgon2DefaultMemCostKib = 65536; // 64 MiB
constexpr std::uint32_t kArgon2DefaultIterations = 3;
constexpr std::uint32_t kArgon2DefaultLanes = 4;
constexpr std::size_t kArgon2SaltLength = 16;

// PBKDF2 fallback parameters, used ONLY if Argon2id cannot be fetched from
// the linked OpenSSL at runtime (see argon2id_available() in keystore.cpp).
// This is not expected to trigger against the OpenSSL 3.5.5 this repository
// links, which ships Argon2id - it exists purely so the code fails soft
// (with a clearly-recorded weaker KDF) rather than refusing to run at all
// against some future/older OpenSSL 3.0-3.1 build that lacks it.
constexpr std::uint32_t kPbkdf2FallbackIterations = 600000;

enum class KdfAlgorithm : std::uint8_t {
    kArgon2id = 1,
    kPbkdf2Sha256Fallback = 2,
};

enum class AeadAlgorithm : std::uint8_t {
    kChaCha20Poly1305 = 1,
};

// ---------------------------------------------------------------------------
// Exceptions.
//
// Two distinct types on purpose:
//   - KeystoreFormatError: the bytes on disk are not a well-formed keystore
//     of a version this code understands (truncated, bad magic, unsupported
//     format version, trailing/garbage bytes). No passphrase has been used
//     yet when this is thrown.
//   - KeystoreAuthenticationError: the file is structurally well-formed but
//     the AEAD tag did not verify - this covers BOTH "wrong passphrase" and
//     "tampered/corrupted ciphertext, nonce, or tag" identically and
//     deliberately: the two cases are indistinguishable to a caller, by
//     design, so neither an error message nor timing narrows the search
//     space for an attacker guessing the passphrase.
// ---------------------------------------------------------------------------

class KeystoreFormatError : public std::runtime_error {
public:
    explicit KeystoreFormatError(const std::string& message) : std::runtime_error(message) {}
};

class KeystoreAuthenticationError : public std::runtime_error {
public:
    explicit KeystoreAuthenticationError(const std::string& message)
        : std::runtime_error(message) {}
};

// Thrown by create()/import_encrypted_backup()/export_encrypted_backup()
// when the destination path already contains a file - "no silent overwrite"
// is enforced structurally (O_CREAT|O_EXCL), not by a best-effort existence
// check.
class KeystoreAlreadyExistsError : public std::runtime_error {
public:
    explicit KeystoreAlreadyExistsError(const std::string& message)
        : std::runtime_error(message) {}
};

// ---------------------------------------------------------------------------
// Public, non-secret identity summary. Returned by display_public_identity()
// (no passphrase required - every field here is stored in plaintext in the
// keystore file, since the whole point of this struct is "what a user's own
// keystore looks like to themselves, or to a UI, before they type in a
// passphrase") and mirrored as accessors on an unlocked IdentityKeystore.
// ---------------------------------------------------------------------------
struct PublicIdentity {
    std::array<std::uint8_t, kKeystoreIdentityIdLength> identity_id{};
    std::string alias;
    std::uint64_t created_at{0};
    Ed25519PublicKey identity_public_key{};
    std::uint32_t key_generation{0};
};

// ---------------------------------------------------------------------------
// IdentityKeystore
//
// One in-memory handle to (at most) one on-disk keystore file. An instance
// is either "unlocked" (holds the decrypted MasterSecret in memory) or
// "locked" (does not - lock() wipes it via SensitiveBytes' destructor
// semantics). All operations that need the master secret require the
// instance to currently be unlocked; the header-only fields (identity id,
// alias, created_at, cached public key, key generation) remain readable
// while locked, matching display_public_identity()'s no-passphrase promise.
// ---------------------------------------------------------------------------
class IdentityKeystore {
public:
    // Creates a brand-new keystore at `path`. Fails with
    // KeystoreAlreadyExistsError if a file already exists there (checked via
    // O_CREAT|O_EXCL, not a racy stat-then-write). Generates a fresh random
    // master secret (tradep2p::generate_master_secret()), a fresh random
    // 16-byte identity id, and a fresh random Argon2id salt; derives the
    // cached identity_public_key via key_scope::kKeystoreIdentity with an
    // empty identifier. Returns the new keystore already unlocked.
    [[nodiscard]] static IdentityKeystore create(const std::string& path,
                                                  const std::string& passphrase,
                                                  const std::string& alias = "");

    // Reads and decrypts an existing keystore file. Throws
    // KeystoreFormatError if the file is not well-formed, or
    // KeystoreAuthenticationError if the passphrase is wrong or the file's
    // authenticated contents have been tampered with. Returns unlocked.
    [[nodiscard]] static IdentityKeystore unlock(const std::string& path,
                                                  const std::string& passphrase);

    // Reads only the plaintext header of a keystore file - no passphrase,
    // no KDF, no decryption attempted. Still throws KeystoreFormatError for
    // a malformed file (the header itself is length-checked before use).
    [[nodiscard]] static PublicIdentity display_public_identity(const std::string& path);

    // Re-encrypts an existing keystore under a new passphrase: verifies
    // `old_passphrase` by performing a full unlock from disk (ignoring any
    // prior in-memory state), generates a fresh Argon2id salt and a fresh
    // AEAD nonce, and atomically replaces the file. At no point is an
    // intermediate plaintext-adjacent file written - the only bytes written
    // to the temporary file are the new, fully-encrypted record.
    static void change_passphrase(const std::string& path, const std::string& old_passphrase,
                                   const std::string& new_passphrase);

    // Verifies `passphrase` actually unlocks `src_path` (so a caller can't
    // export - and later rely on - a file that was already corrupt, and so
    // producing a portable backup requires proof the caller knows the
    // passphrase), then copies the current encrypted file verbatim to
    // `dest_path`. Refuses to overwrite an existing file at `dest_path`.
    // This is the ONLY export path this phase provides: plaintext export
    // does not exist in this module at all.
    static void export_encrypted_backup(const std::string& src_path,
                                         const std::string& dest_path,
                                         const std::string& passphrase);

    // Verifies `passphrase` unlocks `src_path` (rejecting a malformed or
    // tampered backup exactly like unlock() would) and, only if that
    // succeeds, atomically copies the encrypted bytes to `dest_path`.
    // Refuses to overwrite an existing file at `dest_path`.
    static void import_encrypted_backup(const std::string& src_path,
                                         const std::string& dest_path,
                                         const std::string& passphrase);

    // Best-effort local destruction: overwrites the file's on-disk bytes
    // (a zero pass, then a random pass, both the file's original length)
    // before unlinking it, and wipes this instance's in-memory master
    // secret. See keystore.cpp for the honest limitations (journaling
    // filesystems, SSD wear-leveling/copy-on-write, and OS page/swap caches
    // can all retain a copy this pass never touches).
    static void destroy(const std::string& path);
    void destroy();

    IdentityKeystore(const IdentityKeystore&) = delete;
    IdentityKeystore& operator=(const IdentityKeystore&) = delete;
    IdentityKeystore(IdentityKeystore&&) = default;
    IdentityKeystore& operator=(IdentityKeystore&&) = default;
    ~IdentityKeystore() = default;

    // Wipes the in-memory master secret (SensitiveBytes' own destructor/move
    // semantics do the actual OPENSSL_cleanse). Does not touch the file on
    // disk. is_unlocked() becomes false; header fields remain readable.
    void lock() noexcept;
    [[nodiscard]] bool is_unlocked() const noexcept { return master_secret_.has_value(); }

    // Increments this keystore's key-generation counter and atomically
    // persists it (fresh Argon2id salt, fresh AEAD key, fresh nonce - the
    // same re-encryption discipline as change_passphrase(), just without
    // changing the passphrase itself, which is why it must be supplied
    // again here rather than relying on any cached derived key). `passphrase`
    // is verified against what is currently on disk first (throwing
    // KeystoreAuthenticationError on a mismatch), so a mistyped passphrase
    // can never silently become the keystore's new passphrase as a side
    // effect of rotation. Requires the instance to be unlocked (the counter
    // lives inside the encrypted payload, alongside the master secret, so
    // its integrity is authenticated the same way the secret's is). After a
    // rotation, derive_scoped_keypair() for every (label, identifier) pair
    // yields a NEW keypair - the master secret itself is untouched.
    void rotate_service_scoped_key(const std::string& passphrase);

    // Derives an Ed25519 keypair for (label, identifier), folding in this
    // keystore's current key_generation so that rotate_service_scoped_key()
    // changes the result without changing the master secret. `label` must
    // be one of the constants in tradep2p::key_scope (phase 1's centralized
    // list), exactly as derive_ed25519_keypair() itself requires. Requires
    // the instance to be unlocked.
    [[nodiscard]] Ed25519KeyPair derive_scoped_keypair(std::string_view label,
                                                        std::string_view identifier) const;

    [[nodiscard]] const std::array<std::uint8_t, kKeystoreIdentityIdLength>& identity_id()
        const noexcept {
        return identity_id_;
    }
    [[nodiscard]] const std::string& alias() const noexcept { return alias_; }
    [[nodiscard]] std::uint64_t created_at() const noexcept { return created_at_; }
    [[nodiscard]] const Ed25519PublicKey& identity_public_key() const noexcept {
        return identity_public_key_;
    }
    [[nodiscard]] std::uint32_t key_generation() const noexcept { return key_generation_; }
    [[nodiscard]] PublicIdentity public_identity() const;

    // Throws std::logic_error if locked. The returned reference is valid
    // only for this object's lifetime and only until the next lock()/move.
    [[nodiscard]] const MasterSecret& master_secret() const;

private:
    IdentityKeystore() = default;

    std::string path_;
    std::uint16_t format_version_{kKeystoreFormatVersion};
    std::array<std::uint8_t, kKeystoreIdentityIdLength> identity_id_{};
    std::string alias_;
    std::uint64_t created_at_{0};
    Ed25519PublicKey identity_public_key_{};
    std::uint32_t key_generation_{0};

    KdfAlgorithm kdf_algorithm_{KdfAlgorithm::kArgon2id};
    std::vector<std::uint8_t> kdf_salt_;
    std::uint32_t kdf_memcost_kib_{0};
    std::uint32_t kdf_iterations_{0};
    std::uint32_t kdf_lanes_{0};

    std::optional<MasterSecret> master_secret_;

    // Loads and decrypts `path` under `passphrase` into a fresh, unlocked
    // instance. Shared by unlock()/change_passphrase()/export/import, so
    // there is exactly one code path that ever attempts an AEAD open.
    [[nodiscard]] static IdentityKeystore load(const std::string& path,
                                                const std::string& passphrase);

    // Derives a fresh Argon2id salt + AEAD key from `passphrase`, encrypts
    // (identity_id, key_generation, master_secret) under a fresh nonce, and
    // atomically writes the whole record to `path` (O_CREAT|O_EXCL when
    // `allow_overwrite` is false, tmp-then-rename when true). Returns the
    // fully-populated, unlocked instance it just wrote. This is the single
    // code path every operation that produces a new on-disk record
    // (create(), change_passphrase(), rotate_service_scoped_key()) funnels
    // through, so there is exactly one place that ever calls the AEAD seal
    // operation.
    [[nodiscard]] static IdentityKeystore build_and_write(
        const std::string& path, const std::string& passphrase, const std::string& alias,
        std::uint64_t created_at, const std::array<std::uint8_t, kKeystoreIdentityIdLength>& identity_id,
        std::uint32_t key_generation, MasterSecret master_secret, bool allow_overwrite);
};

} // namespace tradep2p
