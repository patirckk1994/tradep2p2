#include "tradep2p/blindsig_blns7933_real_ring.hpp"

#include <cmath>
#include <iostream>
#include <stdexcept>

namespace {

using tradep2p::blns7933::HighReal;
using tradep2p::blns7933::RealPoly;
using tradep2p::blns7933::RealRingArithmetic;
using tradep2p::blns7933::merge;
using tradep2p::blns7933::split;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

double to_double(const HighReal& v) { return v.convert_to<double>(); }

bool approx_equal(const RealPoly& a, const RealPoly& b, double tolerance) {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::abs(to_double(a[i] - b[i])) > tolerance) {
            return false;
        }
    }
    return true;
}

void test_split_merge_are_inverses() {
    const RealPoly f{HighReal(1), HighReal(2), HighReal(3), HighReal(4),
                     HighReal(5), HighReal(6), HighReal(7), HighReal(8)};
    const auto [f0, f1] = split(f);
    require(f0.size() == 4U && f1.size() == 4U, "split must halve the degree");
    require(to_double(f0[0]) == 1.0 && to_double(f0[1]) == 3.0 &&
                to_double(f0[2]) == 5.0 && to_double(f0[3]) == 7.0,
            "f0 must be the even-indexed coefficients (eq. 3.20)");
    require(to_double(f1[0]) == 2.0 && to_double(f1[1]) == 4.0 &&
                to_double(f1[2]) == 6.0 && to_double(f1[3]) == 8.0,
            "f1 must be the odd-indexed coefficients (eq. 3.20)");

    const RealPoly reconstructed = merge(f0, f1);
    require(approx_equal(reconstructed, f, 1e-60), "merge(split(f)) must exactly reconstruct f");
}

void test_negacyclic_multiplication_toy() {
    // x^3 * x == x^4 == -1 in R[x]/(x^4+1), same relation
    // IntegerRingArithmetic's own toy test checks, over reals instead.
    const RealRingArithmetic ring(4);
    const RealPoly x3{HighReal(0), HighReal(0), HighReal(0), HighReal(1)};
    const RealPoly x1{HighReal(0), HighReal(1), HighReal(0), HighReal(0)};
    const RealPoly product = ring.mul(x3, x1);
    const RealPoly expected{HighReal(-1), HighReal(0), HighReal(0), HighReal(0)};
    require(approx_equal(product, expected, 1e-60), "negacyclic wrap must apply x^4 = -1");
}

void test_adjoint_toy() {
    // Same toy case as blindsig_blns7933_quality_tests.cpp's integer
    // version, confirming the real-valued adjoint matches the same
    // formula (eq. 3.6).
    const RealRingArithmetic ring(4);
    const RealPoly a{HighReal(1), HighReal(2), HighReal(3), HighReal(4)};
    const RealPoly expected{HighReal(1), HighReal(-4), HighReal(-3), HighReal(-2)};
    require(approx_equal(ring.hermitian_adjoint(a), expected, 1e-60),
            "hermitian_adjoint must match eq. (3.6) over reals too");
}

void test_div_inverts_mul() {
    const RealRingArithmetic ring(8);
    const RealPoly a{HighReal("1.5"), HighReal("-2.25"), HighReal(0), HighReal("3.1"),
                     HighReal(0),     HighReal("0.7"),   HighReal(-1), HighReal(2)};
    const RealPoly b{HighReal("0.9"), HighReal(1), HighReal("-0.4"), HighReal(0),
                     HighReal(2),     HighReal(0), HighReal("1.1"),  HighReal(-3)};
    const RealPoly product = ring.mul(a, b);

    // (a*b)/a should reconstruct b, and (a*b)/b should reconstruct a -
    // div() is checked against real, non-trivial polynomials, not just a
    // toy case, and from both directions.
    const RealPoly recovered_b = ring.div(product, a);
    const RealPoly recovered_a = ring.div(product, b);
    require(approx_equal(recovered_b, b, 1e-50), "div must invert mul: (a*b)/a == b");
    require(approx_equal(recovered_a, a, 1e-50), "div must invert mul: (a*b)/b == a");
}

void test_div_rejects_singular_divisor() {
    // b=0 is singular everywhere - dividing by it must fail loudly, not
    // return a garbage/zero result.
    const RealRingArithmetic ring(4);
    const RealPoly a{HighReal(1), HighReal(0), HighReal(0), HighReal(0)};
    const RealPoly zero{HighReal(0), HighReal(0), HighReal(0), HighReal(0)};
    bool threw = false;
    try {
        (void)ring.div(a, zero);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    require(threw, "dividing by the zero polynomial must throw, not silently succeed");
}

} // namespace

int main() {
    try {
        test_split_merge_are_inverses();
        test_negacyclic_multiplication_toy();
        test_adjoint_toy();
        test_div_inverts_mul();
        test_div_rejects_singular_divisor();
        std::cout << "blindsig_blns7933_real_ring_tests: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "blindsig_blns7933_real_ring_tests: FAIL: " << e.what() << '\n';
        return 1;
    }
}
