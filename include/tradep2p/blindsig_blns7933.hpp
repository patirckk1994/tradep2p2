#pragma once

// Slow, auditable reference substrate for the BLNS23/FALCON-style NTRU
// trapdoor path at the paper's parameters q=7933, d=512.
//
// IMPORTANT: this module is deliberately NOT wired into BlindSigSigner,
// BlindSigKeystore, the wire format, or the RISC0 prover path yet.  The
// existing FALCON q=12289 implementation remains the known-good experimental
// backend while this reference path is built and validated independently.
//
// The first objective here is exact ring arithmetic and explicit invariants,
// not speed.  No NTT assumptions are made: q=7933 is not a 512-dimensional
// negacyclic-NTT-friendly modulus.

#include "tradep2p/blindsig_blns7933_csprng.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <vector>

namespace tradep2p::blns7933 {

struct Parameters {
    static constexpr std::size_t degree = 512;
    static constexpr std::int64_t modulus = 7933;
    static constexpr long double sigma = 232.0L;
};

// Coefficient representation in Z_q[x]/(x^d+1).  Values returned by
// RingArithmetic are always canonicalized into [0,q).
using PolyQ = std::vector<std::int64_t>;

class RingArithmetic {
public:
    explicit RingArithmetic(std::size_t degree = Parameters::degree,
                            std::int64_t modulus = Parameters::modulus);

    [[nodiscard]] std::size_t degree() const noexcept { return degree_; }
    [[nodiscard]] std::int64_t modulus() const noexcept { return modulus_; }

    [[nodiscard]] PolyQ canonicalize(const PolyQ& a) const;
    [[nodiscard]] PolyQ add(const PolyQ& a, const PolyQ& b) const;
    [[nodiscard]] PolyQ sub(const PolyQ& a, const PolyQ& b) const;
    [[nodiscard]] PolyQ mul(const PolyQ& a, const PolyQ& b) const;

    // Multiplicative inverse in F_q[x]/(x^d+1), when it exists.  This is a
    // deliberately generic modular-linear-algebra implementation, not
    // FALCON's q=12289 NTT inversion path.
    [[nodiscard]] std::optional<PolyQ> inverse(const PolyQ& a) const;

    [[nodiscard]] bool equal(const PolyQ& a, const PolyQ& b) const;

private:
    std::size_t degree_;
    std::int64_t modulus_;

    [[nodiscard]] std::int64_t mod(std::int64_t x) const noexcept;
};

// f,g,F,G describe the NTRU trapdoor relation
//
//     f*G - g*F = q
//
// over Z[x]/(x^d+1).  We intentionally keep wider signed coefficients here
// than the current FALCON wrapper's int8 storage: this is a research/reference
// representation, not a wire or keystore format.
struct TrapdoorKey {
    std::vector<std::int64_t> f;
    std::vector<std::int64_t> g;
    std::vector<std::int64_t> F;
    std::vector<std::int64_t> G;
};

struct PublicKey {
    // BLNS23 writes A=(t,1) with t=f*g^{-1} mod q.  This orientation differs
    // from the conventional Falcon h=g*f^{-1} notation used by the existing
    // q=12289 wrapper, so this reference type deliberately calls it `t`.
    PolyQ t;
};

class NTRUTrapdoorGenerator {
public:
    explicit NTRUTrapdoorGenerator(RingArithmetic ring = RingArithmetic{});

    // Samples candidate (f,g) from the discrete Gaussian D_{Z,sigma_fg,0}
    // (sigma_fg = 1.17*sqrt(q/2n), falcon.pdf Algorithm 5), checks g is
    // invertible mod q (this type's t=f*g^-1 orientation - see
    // derive_public()), checks the quality bound gamma <= 1.17*sqrt(q)
    // (blindsig_blns7933_quality.hpp), solves fG-gF=q, reduces (F,G), and
    // resamples from scratch on any rejection - mirrors FALCON's own
    // NTRUGen restart-on-failure loop (falcon.pdf Algorithm 5), not an
    // adjust-and-retry strategy.
    //
    // RNG: `rng` must be a CryptoRng (blindsig_blns7933_csprng.hpp), backed
    // by OpenSSL's RAND_bytes for real use (its default constructor) or a
    // fixed seed for reproducible tests/diagnostics only (its explicit
    // std::uint64_t constructor - NOT secure on its own, see that
    // constructor's own doc comment). f,g ARE the secret trapdoor, so this
    // was a real, previously-open gap (this type used to take a plain
    // std::mt19937_64&, which is not cryptographically secure), now closed.
    // Precision of the sampling distribution and unpredictability of the
    // randomness feeding it are different properties - CryptoRng addresses
    // the latter; the Gaussian sampler's own 256-digit precision (see
    // blindsig_blns7933_gaussian.hpp) addresses the former.
    [[nodiscard]] TrapdoorKey generate(CryptoRng& rng) const;

    // BLNS23 public key orientation: t = f * g^{-1} mod q.
    [[nodiscard]] PublicKey derive_public(const TrapdoorKey& key) const;

    // Exact algebraic oracle for solver development: checks
    //     f*G - g*F == q  in Z[x]/(x^d+1),
    // NOT merely modulo q (where the RHS would vanish and lose information).
    // The implementation uses arbitrary-precision integer arithmetic.
    [[nodiscard]] bool verify_ntru_relation(const TrapdoorKey& key) const;

private:
    RingArithmetic ring_;
};

} // namespace tradep2p::blns7933
