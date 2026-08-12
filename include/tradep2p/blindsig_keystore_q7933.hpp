#pragma once

// At-rest custody for the experimental q=7933 BLNS23 reference signer's
// NTRU trapdoor. Deliberately the SAME security pattern as
// blindsig_keystore.hpp's BlindSigKeystore for the shipped q=12289/FALCON
// path (Argon2id KDF with a PBKDF2-SHA256 fallback, ChaCha20-Poly1305
// AEAD-at-rest, fresh salt+nonce per write, atomic O_CREAT|O_EXCL writes,
// authenticated header-as-AAD) - implemented as its own independent type
// with its own file format, per this codebase's established per-module
// convention (see blindsig_keystore.hpp's own file comment for why: blast
// radius, not code reuse, drives the isolation).
//
// Genuinely distinct from BlindSigKeystore, not a reinterpretation of it:
// different magic bytes, different payload version, and a different
// payload shape (f,g,F,G,t,B as int64_t-coefficient polynomials of degree
// 512, vs. FALCON's int8_t trapdoor + uint16_t public key/b). Do not point
// this type at a q=12289 keystore file or vice versa - decode_file() will
// reject the wrong magic outright.
//
// unlock() does more validation than BlindSigKeystore ever has, because
// this reference substrate's own math library exposes the ability to
// check it: after AEAD decryption succeeds (proving the passphrase was
// right and the ciphertext wasn't tampered), the decoded trapdoor is
// still independently re-verified against the real NTRU invariants
// (exact f*G-g*F=q, t=f*g^-1 re-derived and compared) before this type
// will call itself unlocked. A passphrase-correct, tamper-free file that
// somehow encodes a broken trapdoor (a bug elsewhere, not an attack) is
// still refused, not handed to a signer that would then produce
// signatures nobody's public key agrees with.
//
// Deliberately does NOT store or rebuild the Falcon signing tree - see
// blindsig_ntru_q7933.hpp: that stays a mediator-startup, in-memory-only
// cost, never persisted.

#include "tradep2p/blindsig_blns7933.hpp"
#include "tradep2p/keystore.hpp" // KeystoreFormatError / KeystoreAuthenticationError / KeystoreAlreadyExistsError

#include <cstdint>
#include <optional>
#include <string>

namespace tradep2p::blindsig {

constexpr std::uint16_t kQ7933KeystoreFormatVersion = 1;

class Q7933Keystore {
public:
    // Creates a brand-new keystore at `path`, encrypting (trapdoor,
    // public_key, b) under `passphrase`. Fails with
    // tradep2p::KeystoreAlreadyExistsError if a file already exists there
    // (O_CREAT|O_EXCL, not a racy stat-then-write). Validates the same
    // invariants unlock() does (degree, canonical t/b, exact fG-gF=q,
    // independently re-derived t) before ever touching the filesystem, so
    // a caller bug can't persist an already-broken keystore. Returns
    // unlocked.
    [[nodiscard]] static Q7933Keystore create(const std::string& path, const std::string& passphrase,
                                               const blns7933::TrapdoorKey& trapdoor,
                                               const blns7933::PublicKey& public_key,
                                               const blns7933::PolyQ& b);

    // Reads and decrypts an existing keystore file. Throws
    // tradep2p::KeystoreFormatError if the file is not well-formed OR if
    // its decoded trapdoor fails the NTRU/canonical invariant checks
    // described above, or tradep2p::KeystoreAuthenticationError if the
    // passphrase is wrong or the file's authenticated contents have been
    // tampered with. Returns unlocked. No create-if-missing path, same
    // reasoning as BlindSigKeystore: generating a trapdoor is a separate,
    // explicit, one-time operator action, never something a mediator does
    // silently on its own.
    [[nodiscard]] static Q7933Keystore unlock(const std::string& path, const std::string& passphrase);

    Q7933Keystore(const Q7933Keystore&) = delete;
    Q7933Keystore& operator=(const Q7933Keystore&) = delete;
    Q7933Keystore(Q7933Keystore&&) = default;
    Q7933Keystore& operator=(Q7933Keystore&&) = default;
    ~Q7933Keystore() = default;

    // Wipes the in-memory trapdoor. Does not touch the file on disk.
    // Unlike BlindSigKeystore::lock() (which honestly documents that
    // FalconTrapdoor is NOT cleansed on destruction - a real, still-open
    // gap there), this gets a genuine wipe for free: TrapdoorKey now
    // cleanses its own f/g/F/G in its own destructor on every teardown
    // path, so std::optional::reset() below is sufficient.
    void lock() noexcept;
    [[nodiscard]] bool is_unlocked() const noexcept { return trapdoor_.has_value(); }

    // Every accessor below throws std::logic_error if locked.
    [[nodiscard]] const blns7933::TrapdoorKey& trapdoor() const;
    [[nodiscard]] const blns7933::PublicKey& public_key() const;
    [[nodiscard]] const blns7933::PolyQ& b() const;

private:
    Q7933Keystore() = default;

    std::string path_;
    std::optional<blns7933::TrapdoorKey> trapdoor_;
    blns7933::PublicKey public_key_{};
    blns7933::PolyQ b_;
};

} // namespace tradep2p::blindsig
