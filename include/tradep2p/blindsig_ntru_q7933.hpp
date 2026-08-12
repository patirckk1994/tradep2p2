#pragma once

// Thin host-side adapter around the audited q=7933 reference substrate.
//
// The purpose of this type is architectural containment: mediator code should
// not need to know how NTRUSolve, the Falcon LDL tree, ffSampling, or the
// reference ring implementation work. It gets an already-generated trapdoor
// and blinding polynomial B, pays the one-time signing-tree construction cost
// at startup, then exposes only sign_target()/verify_target() plus immutable
// public material.
//
// This remains behind TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL through
// cmake/BLNS7933Reference.cmake. It does NOT replace the existing q=12289
// BlindSigSigner backend yet.

#include "tradep2p/blindsig_blns7933_sign.hpp"

#include <cstdint>
#include <memory>
#include <mutex>

namespace tradep2p::blindsig {

class Q7933NTRUSigner {
public:
    // Production parameters: d=512, q=7933, sigma=232, and the BLNS23
    // signature norm bound sigma^2 * 2*n*d with n=2.
    Q7933NTRUSigner(blns7933::TrapdoorKey trapdoor, blns7933::PolyQ b);

    // Same production parameters, but lets tests/diagnostics inject a seeded
    // CryptoRng. A default-constructed CryptoRng is used by the overload above.
    Q7933NTRUSigner(blns7933::TrapdoorKey trapdoor, blns7933::PolyQ b,
                    blns7933::CryptoRng rng);

    // Explicit non-production parameter override used by the existing toy
    // dimension regression tests. Integration code should use one of the two
    // constructors above.
    Q7933NTRUSigner(blns7933::TrapdoorKey trapdoor, blns7933::PolyQ b,
                    blns7933::RingArithmetic ring,
                    blns7933::HighReal target_sigma,
                    blns7933::BigInt norm_bound_squared,
                    blns7933::CryptoRng rng);

    ~Q7933NTRUSigner();

    Q7933NTRUSigner(const Q7933NTRUSigner&) = delete;
    Q7933NTRUSigner& operator=(const Q7933NTRUSigner&) = delete;
    Q7933NTRUSigner(Q7933NTRUSigner&&) = delete;
    Q7933NTRUSigner& operator=(Q7933NTRUSigner&&) = delete;

    // Thread-safe: the immutable tree is shared, while RNG consumption and
    // ffSampling are serialized so one backend can safely sit behind more
    // than one mediator worker without duplicating/ racing RNG state.
    [[nodiscard]] blns7933::Signature sign_target(const blns7933::PolyQ& target);

    [[nodiscard]] bool verify_target(const blns7933::PolyQ& target,
                                     const blns7933::Signature& signature) const;

    [[nodiscard]] const blns7933::PublicKey& public_key() const noexcept { return public_key_; }
    [[nodiscard]] const blns7933::PolyQ& b() const noexcept { return b_; }
    [[nodiscard]] const blns7933::BigInt& norm_bound_squared() const noexcept {
        return norm_bound_squared_;
    }
    [[nodiscard]] std::size_t degree() const noexcept { return ring_.degree(); }
    [[nodiscard]] std::int64_t modulus() const noexcept { return ring_.modulus(); }

    [[nodiscard]] static blns7933::BigInt production_norm_bound_squared();

private:
    static void validate_canonical_poly(const blns7933::RingArithmetic& ring,
                                        const blns7933::PolyQ& value,
                                        const char* field_name);
    void wipe_trapdoor() noexcept;

    blns7933::RingArithmetic ring_;
    blns7933::TrapdoorKey trapdoor_;
    blns7933::PublicKey public_key_;
    blns7933::PolyQ b_;
    blns7933::BigInt norm_bound_squared_;
    std::unique_ptr<blns7933::FalconTreeNode> signing_tree_;
    blns7933::CryptoRng rng_;
    mutable std::mutex sign_mutex_;
};

} // namespace tradep2p::blindsig
