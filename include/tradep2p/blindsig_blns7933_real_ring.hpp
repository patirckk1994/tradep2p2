#pragma once

// Real-coefficient (not modular, not complex/FFT) arithmetic in
// R[x]/(x^degree+1), at 256-digit precision - the substrate ffLDL*/
// ffSampling need for the LDL-tree construction and sampling.
//
// falcon.pdf's own reference implementation performs these operations in
// FFT representation for speed, but states explicitly (SS3.9.2): "the
// whole algorithm could also be executed in coefficient representation
// instead, at a price of a O(log n) penalty in speed." That is the
// deliberate choice made here, consistent with every other module in this
// reference substrate: no complex arithmetic, no FFT, exact/high-precision
// real arithmetic throughout, time traded for transparency and precision.

#include "tradep2p/blindsig_blns7933_highreal.hpp"

#include <cstddef>
#include <utility>
#include <vector>

namespace tradep2p::blns7933 {

using RealPoly = std::vector<HighReal>;

class RealRingArithmetic {
public:
    explicit RealRingArithmetic(std::size_t degree);

    [[nodiscard]] std::size_t degree() const noexcept { return degree_; }

    [[nodiscard]] RealPoly canonical_size(const RealPoly& a) const;
    [[nodiscard]] RealPoly add(const RealPoly& a, const RealPoly& b) const;
    [[nodiscard]] RealPoly sub(const RealPoly& a, const RealPoly& b) const;
    [[nodiscard]] RealPoly mul(const RealPoly& a, const RealPoly& b) const;

    // Hermitian adjoint (falcon.pdf eq. (3.6)): a*_0=a_0, a*_i=-a_{degree-i}.
    // NOT the same operation as IntegerRingArithmetic::conjugate() (Galois
    // x -> -x) - see blindsig_blns7933_quality.hpp's identical warning.
    [[nodiscard]] RealPoly hermitian_adjoint(const RealPoly& a) const;

    // The unique e in R[x]/(x^degree+1) such that e*b = a exactly (used for
    // LDL's G10 = G10/G00, falcon.pdf Algorithm 8 line 2). Solved via one
    // dense real linear system, same technique as
    // blindsig_blns7933_quality.cpp's e_f=q*f*/D computation. Throws if b
    // is singular as a real linear operator (b(zeta)=0 for some root zeta).
    [[nodiscard]] RealPoly div(const RealPoly& a, const RealPoly& b) const;

private:
    std::size_t degree_;
};

// split(f) = (f0, f1): f0_i = f_{2i}, f1_i = f_{2i+1} for 0<=i<degree/2
// (falcon.pdf eq. (3.20)-(3.21)). Pure coefficient deinterleaving - no
// transform of any kind, despite the paper naming its FFT-domain
// equivalent "splitfft" for the fast path. `f` must have exactly
// `degree` coefficients, and `degree` must be even.
[[nodiscard]] std::pair<RealPoly, RealPoly> split(const RealPoly& f);

// merge(f0,f1)(x) = f0(x^2) + x*f1(x^2) (falcon.pdf eq. (3.22)) - exact
// inverse of split(). f0 and f1 must have equal size; the result has
// twice that size.
[[nodiscard]] RealPoly merge(const RealPoly& f0, const RealPoly& f1);

} // namespace tradep2p::blns7933
