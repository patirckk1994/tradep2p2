#pragma once

// Exact integer-polynomial support for the BLNS23 q=7933 reference path.
//
// This is deliberately separate from RingArithmetic, which works modulo q
// with small int64_t coefficients.  NTRUSolve's recursive field-norm descent
// can create very large intermediate coefficients before basis reduction, so
// the solver must not rely on fixed-width integer arithmetic.
//
// The implementation uses Boost.Multiprecision::cpp_int as a deliberately
// slow, transparent reference backend.  A later FLINT/GMP backend can replace
// this behind the same interface if profiling or interoperability justifies
// it; solver correctness must not depend on that optimization.

#include <boost/multiprecision/cpp_int.hpp>

#include <cstddef>
#include <vector>

namespace tradep2p::blns7933 {

using BigInt = boost::multiprecision::cpp_int;
using ZPoly = std::vector<BigInt>;

// Exact arithmetic in Z[x]/(x^degree + 1).  `degree` is expected to be a
// power of two for field_norm()/NTRUSolve, but plain negacyclic arithmetic is
// valid for any non-zero degree.
class IntegerRingArithmetic {
public:
    explicit IntegerRingArithmetic(std::size_t degree);

    [[nodiscard]] std::size_t degree() const noexcept { return degree_; }

    [[nodiscard]] ZPoly canonical_size(const ZPoly& a) const;
    [[nodiscard]] ZPoly add(const ZPoly& a, const ZPoly& b) const;
    [[nodiscard]] ZPoly sub(const ZPoly& a, const ZPoly& b) const;
    [[nodiscard]] ZPoly mul(const ZPoly& a, const ZPoly& b) const;

    // Galois conjugation x -> -x in Z[x]/(x^degree+1).
    [[nodiscard]] ZPoly conjugate(const ZPoly& a) const;

    // Field norm from degree n to n/2:
    //
    //   N(f)(x^2) = f(x) f(-x).
    //
    // The returned polynomial belongs to Z[y]/(y^(n/2)+1), with coefficient
    // i corresponding to the coefficient of x^(2i) in the product above.
    // Requires degree >= 2 and a power-of-two degree.
    [[nodiscard]] ZPoly field_norm(const ZPoly& a) const;

    // Embed p(y) from the half-size ring as p(x^2) in this ring.
    [[nodiscard]] ZPoly embed_half(const ZPoly& half) const;

    [[nodiscard]] bool equal(const ZPoly& a, const ZPoly& b) const;

private:
    std::size_t degree_;
};

[[nodiscard]] bool is_power_of_two(std::size_t value) noexcept;
[[nodiscard]] std::size_t bigint_bit_length(const BigInt& value);
[[nodiscard]] std::size_t max_coefficient_bit_length(const ZPoly& poly);

} // namespace tradep2p::blns7933
