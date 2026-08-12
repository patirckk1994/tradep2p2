#pragma once

#include "tradep2p/blindsig_blns7933_ntrusolve.hpp"

#include <cstddef>

namespace tradep2p::blns7933 {

struct NTRUGlobalReductionDiagnostics {
    std::size_t rounds_attempted{0};
    std::size_t accepted_rounds{0};
    BigInt initial_squared_norm{0};
    BigInt final_squared_norm{0};
    std::size_t initial_max_bits{0};
    std::size_t final_max_bits{0};
    bool converged{false};
    bool stopped_on_non_decreasing_round{false};
};

// High-precision global Babai-style reducer for the q=7933 reference path.
//
// For the negacyclic shift basis
//
//     a_j = (x^j f, x^j g),    0 <= j < degree,
//
// this reducer forms the exact integer Gram matrix H_ij=<a_i,a_j> and
// right-hand side b_i=<a_i,(F,G)>.  It solves H*k=b in high-precision real
// arithmetic, rounds all coefficients of k at once, then applies
//
//     F <- F - k*f
//     G <- G - k*g.
//
// The floating/high-precision calculation is used ONLY to choose k.  The
// update itself, the NTRU relation check, and the squared-norm acceptance
// check are all performed with exact cpp_int arithmetic.  A round is kept
// only when the exact squared norm strictly decreases.
//
// This deliberately mirrors the mathematical target of Falcon's FFT Babai
// reduction without copying its optimized binary64/NTT/31-bit-limb
// implementation.  It is a transparent reference backend, not production
// code and not a constant-time implementation.
class NTRUGlobalBabaiReducer {
public:
    explicit NTRUGlobalBabaiReducer(std::size_t degree, BigInt q,
                                    std::size_t max_rounds = 8U);

    [[nodiscard]] NTRUSolution reduce(
        const ZPoly& f, const ZPoly& g, const NTRUSolution& input,
        NTRUGlobalReductionDiagnostics* diagnostics = nullptr) const;

private:
    std::size_t degree_;
    BigInt q_;
    std::size_t max_rounds_;
};

} // namespace tradep2p::blns7933
