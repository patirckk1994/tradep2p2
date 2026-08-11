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

#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
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
    // deliberately generic polynomial-Euclid implementation, not FALCON's
    // q=12289 NTT inversion path.
    [[nodiscard]] std::optional<PolyQ> inverse(const PolyQ& a) const;

    [[nodiscard]] bool equal(const PolyQ& a, const PolyQ& b) const;

private:
    std::size_t degree_;
    std::int64_t modulus_;

    [[nodiscard]] std::int64_t mod(std::int64_t x) const noexcept;
};

// f,g,F,G describe the usual NTRU trapdoor basis relation.  We intentionally
// keep wider signed coefficients here than the current FALCON wrapper's int8
// storage: this is a reference/research representation, not a wire format.
struct TrapdoorKey {
    std::vector<std::int64_t> f;
    std::vector<std::int64_t> g;
    std::vector<std::int64_t> F;
    std::vector<std::int64_t> G;
};

struct PublicKey {
    PolyQ h; // h = g/f in R_q when f is invertible
};

class NTRUTrapdoorGenerator {
public:
    explicit NTRUTrapdoorGenerator(RingArithmetic ring = RingArithmetic{});

    // Intentionally fails closed until NTRUGen/NTRUSolve/Reduce are ported
    // from the FALCON/GPV-style pseudocode and validated at toy scale.
    [[nodiscard]] TrapdoorKey generate(std::mt19937_64& rng) const;

    // This part is already well-defined once exact ring inversion exists.
    [[nodiscard]] PublicKey derive_public(const TrapdoorKey& key) const;

    // Exact algebraic oracle for solver development: checks
    //     f*G - g*F == q  in Z[x]/(x^d+1),
    // NOT merely modulo q (where the RHS would vanish and lose information).
    [[nodiscard]] bool verify_ntru_relation(const TrapdoorKey& key) const;

private:
    RingArithmetic ring_;
};

} // namespace tradep2p::blns7933
