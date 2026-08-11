#pragma once

// Trapdoor-quality check for BLNS7933 candidate (f,g) pairs, matching
// FALCON's NTRUGen (Algorithm 5, falcon.pdf SS3.8.2, eq. (3.28)):
//
//     gamma = max( ||(g,-f)||,
//                  || q*f* / (f*f* + g*g*) ||,
//                  || q*g* / (f*f* + g*g*) || )   <= 1.17*sqrt(q)
//
// where f* denotes the Hermitian adjoint (falcon.pdf eq. (3.6)).
//
// The paper frames this as an FFT-domain computation (each ratio's norm is
// naturally expressed via per-root magnitudes). This module avoids complex
// arithmetic/FFT entirely: f*, g*, and D := f*f*+g*g* all have EXACT
// integer coefficient formulas (no transform needed), and for any root
// zeta of x^degree+1, e(zeta) := q*f*(zeta)/D(zeta) satisfies the
// polynomial identity e(x)*D(x) = q*f*(x) at every root simultaneously -
// since both sides have degree < degree and agree at `degree` distinct
// points, they are the SAME polynomial. So e is recovered exactly by
// solving one REAL (not modular, not complex) linear system D*e = q*f*,
// using the same high-precision dense-matrix approach already established
// in blindsig_blns7933_babai_reduce.cpp.

#include "tradep2p/blindsig_blns7933_integer_ring.hpp"

namespace tradep2p::blns7933 {

// Hermitian adjoint a* in Z[x]/(x^degree+1): a*_0 = a_0, a*_i = -a_{degree-i}
// for i=1..degree-1 (falcon.pdf eq. (3.6)). This is NOT the same operation
// as IntegerRingArithmetic::conjugate() (Galois conjugation x -> -x,
// mod-2-alternating sign flip) - the two coincide only by coincidence at
// small degree, not in general, and must not be confused with each other.
[[nodiscard]] ZPoly hermitian_adjoint(const ZPoly& a, std::size_t degree);

struct TrapdoorQuality {
    long double gs_norm{};       // gamma, falcon.pdf Algorithm 5 line 9
    long double threshold{};     // 1.17*sqrt(q), for diagnostics
    bool accepted{};             // gamma <= threshold
};

// Computes and checks gamma for candidate (f,g) at the given ring degree
// and modulus q. Throws std::runtime_error only in the practically-never
// case that f*f*+g*g* is exactly singular as a real linear operator (both
// f(zeta) and g(zeta) vanishing at the same root) - callers should treat
// that the same as a rejected candidate, not a hard error.
[[nodiscard]] TrapdoorQuality compute_trapdoor_quality(
    const ZPoly& f, const ZPoly& g, std::size_t degree, const BigInt& q);

} // namespace tradep2p::blns7933
