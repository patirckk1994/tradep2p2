#pragma once

#include "tradep2p/blindsig_blns7933_ntrusolve.hpp"

#include <cstddef>

namespace tradep2p::blns7933 {

struct NTRUReductionDiagnostics {
    std::size_t passes{0};
    std::size_t accepted_steps{0};
    BigInt initial_squared_norm{0};
    BigInt final_squared_norm{0};
    std::size_t initial_max_bits{0};
    std::size_t final_max_bits{0};
    bool converged{false};
};

// Exact, deliberately slow baseline reducer for an NTRU solution.
//
// It only applies transformations
//
//     F <- F + k*f
//     G <- G + k*g
//
// which preserve f*G - g*F = q identically.  The current reference
// implementation performs coordinate descent where k is one negacyclic
// monomial c*x^j at a time.  The integer coefficient c is selected using
// exact cpp_int arithmetic to minimize the squared Euclidean norm along that
// coordinate.  No floating-point arithmetic, FFT, or precision heuristics are
// used here.
//
// This is a correctness/reference reducer, not yet the Falcon-quality
// reduction algorithm required for a production trapdoor sampler.
class NTRUBasisReducer {
public:
    explicit NTRUBasisReducer(std::size_t degree, BigInt q,
                              std::size_t max_passes = 64U);

    [[nodiscard]] NTRUSolution reduce(
        const ZPoly& f, const ZPoly& g, const NTRUSolution& input,
        NTRUReductionDiagnostics* diagnostics = nullptr) const;

    [[nodiscard]] static BigInt squared_norm(const ZPoly& F, const ZPoly& G);

private:
    std::size_t degree_;
    BigInt q_;
    std::size_t max_passes_;
};

} // namespace tradep2p::blns7933
