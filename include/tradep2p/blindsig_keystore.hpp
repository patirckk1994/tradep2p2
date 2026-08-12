#pragma once

// At-rest custody for the experimental blind-signature signer's FALCON
// trapdoor. specs.txt SS9.3a explains why this gets a stricter custody
// tier than this codebase's usual operational keys: a leaked or broken
// trapdoor here lets an attacker forge arbitrary blind signatures, and
// this is unreviewed, higher-risk-than-usual key material.
//
// Deliberately the SAME security pattern as keystore.hpp's
// IdentityKeystore (Argon2id KDF, ChaCha20-Poly1305 AEAD-at-rest, fresh
// salt+nonce per write, atomic tmp-then-rename-or-O_CREAT|O_EXCL writes,
// authenticated header) - implemented as an independent sibling type
// rather than reusing IdentityKeystore directly, because that class's
// entire API is shaped around deriving keypairs via HKDF from a 32-byte
// MasterSecret (derive_scoped_keypair()), and a FALCON trapdoor
// (f,g,F,G, produced by Zf(keygen), not seed-derivable) doesn't fit that
// shape - it is an opaque blob to be stored and returned, not a seed to
// derive further keys from.
//
// Deliberately NOT included, unlike IdentityKeystore, and left as
// documented future work rather than scope creep onto an already
// unreviewed feature: key-generation rotation, encrypted export/import
// backup. See specs.txt SS9.3a's "explicitly deferred" list.
//
// Deliberately NO create-if-missing path (unlike lobby.cpp's
// load_or_create_mediator_key(), which by design auto-generates a fresh
// key so an operational service key survives unattended restarts) - a
// missing keystore here is a hard startup error. Generating a trapdoor is
// a separate, explicit, one-time operator action (`tradep2p_cli
// blindsig-keygen`), never something a mediator process does silently on
// its own.

#include "tradep2p/blindsig_falcon.hpp"
#include "tradep2p/keystore.hpp" // KeystoreFormatError / KeystoreAuthenticationError / KeystoreAlreadyExistsError

#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace tradep2p::blindsig {

constexpr std::uint16_t kBlindSigKeystoreFormatVersion = 1;

class BlindSigKeystore {
public:
    // Creates a brand-new keystore at `path`, encrypting (trapdoor,
    // public_key, b) under `passphrase`. Fails with
    // tradep2p::KeystoreAlreadyExistsError if a file already exists there
    // (O_CREAT|O_EXCL, not a racy stat-then-write). Returns unlocked.
    [[nodiscard]] static BlindSigKeystore create(const std::string& path,
                                                  const std::string& passphrase,
                                                  const FalconKeyPair& keypair,
                                                  const std::array<std::uint16_t, kRingDegree>& b);

    // Reads and decrypts an existing keystore file. Throws
    // tradep2p::KeystoreFormatError if the file is not well-formed, or
    // tradep2p::KeystoreAuthenticationError if the passphrase is wrong or
    // the file's authenticated contents have been tampered with. Returns
    // unlocked. No create-if-missing path - see file comment above.
    [[nodiscard]] static BlindSigKeystore unlock(const std::string& path,
                                                  const std::string& passphrase);

    BlindSigKeystore(const BlindSigKeystore&) = delete;
    BlindSigKeystore& operator=(const BlindSigKeystore&) = delete;
    BlindSigKeystore(BlindSigKeystore&&) = default;
    BlindSigKeystore& operator=(BlindSigKeystore&&) = default;
    ~BlindSigKeystore() = default;

    // Wipes the in-memory trapdoor. Does not touch the file on disk.
    void lock() noexcept;
    [[nodiscard]] bool is_unlocked() const noexcept { return trapdoor_.has_value(); }

    // Every accessor below throws std::logic_error if locked - a signer
    // holding a locked keystore has no business asking for any of this.
    [[nodiscard]] const FalconTrapdoor& trapdoor() const;
    [[nodiscard]] const FalconPublicKey& public_key() const;
    [[nodiscard]] const std::array<std::uint16_t, kRingDegree>& b() const;

private:
    BlindSigKeystore() = default;

    std::string path_;
    std::optional<FalconTrapdoor> trapdoor_;
    FalconPublicKey public_key_{};
    std::array<std::uint16_t, kRingDegree> b_{};
};

} // namespace tradep2p::blindsig
