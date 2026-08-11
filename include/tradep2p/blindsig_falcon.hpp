#pragma once

// Thin C++ wrapper around the vendored, unmodified official FALCON
// reference implementation (third_party/falcon-impl-20211101/,
// falcon-sign.info) - real NTRU trapdoor generation and Gaussian preimage
// sampling, not reimplemented. Mirrors exactly what the original research
// prototype's blind_falcon_demo.cpp already did (same FPU control word
// discipline, same RNG seeding, same oversized scratch buffer) - see
// specs.txt SS9.3a.
//
// Deliberately the ONLY place in this experimental feature that touches
// the FALCON trapdoor secret: NIZK1/NIZK2 (the zero-knowledge layer) run
// in a separate Rust sidecar process and never see f/g/F/G at all (see
// blindsig_subprocess.hpp) - keygen and sign_dyn stay in-process here so
// the trapdoor secret never crosses a process boundary.

#include "tradep2p/blindsig_wire.hpp" // kRingDegree

#include <array>
#include <cstdint>

namespace tradep2p::blindsig {

// f, g, F, G - the NTRU trapdoor secret. Never serialized in plaintext
// except by blindsig_keystore.hpp's AEAD-encrypted-at-rest custody.
struct FalconTrapdoor {
    std::array<std::int8_t, kRingDegree> f{};
    std::array<std::int8_t, kRingDegree> g{};
    std::array<std::int8_t, kRingDegree> F{};
    std::array<std::int8_t, kRingDegree> G{};
};

struct FalconPublicKey {
    std::array<std::uint16_t, kRingDegree> h{};
};

struct FalconKeyPair {
    FalconTrapdoor trapdoor;
    FalconPublicKey public_key;
};

// Zf(keygen) - real NTRU trapdoor generation, freshly OpenSSL-seeded RNG.
// Can fail (FALCON's own keygen internally retries on bad candidates but
// is not literally infallible against all inputs); throws
// std::runtime_error on failure rather than returning a sentinel, since
// there is no reasonable fallback for a caller to take in that case.
FalconKeyPair falcon_keygen();

// Zf(sign_dyn) - real Gaussian preimage sampling for the blinded target
// `target_c`. This is the signer's per-request operation; see
// blindsig_signer.cpp for why this stays fast even though NIZK1/NIZK2
// proving is slow (it is a different, unrelated operation).
std::array<std::int16_t, kRingDegree> falcon_sign_dyn(
    const FalconTrapdoor& trapdoor, const std::array<std::uint16_t, kRingDegree>& target_c);

// Zf(verify_raw) - real FALCON verification (handles the NTT+Montgomery
// conversion of the public key internally, so callers always pass the
// plain public key). Used for the self-check after blindsig-keygen
// generates a fresh keypair, and by the standalone verify path.
bool falcon_verify_raw(const std::array<std::uint16_t, kRingDegree>& target_c,
                       const std::array<std::int16_t, kRingDegree>& sig,
                       const FalconPublicKey& public_key);

} // namespace tradep2p::blindsig
