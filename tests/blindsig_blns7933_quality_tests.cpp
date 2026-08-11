#include "tradep2p/blindsig_blns7933_quality.hpp"

#include "tradep2p/blindsig_blns7933_gaussian.hpp"

#include <cmath>
#include <iostream>
#include <random>
#include <stdexcept>

namespace {

using tradep2p::blns7933::BigInt;
using tradep2p::blns7933::compute_trapdoor_quality;
using tradep2p::blns7933::hermitian_adjoint;
using tradep2p::blns7933::sample_discrete_gaussian_poly;
using tradep2p::blns7933::ZPoly;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void test_adjoint_toy() {
    // a = 1 + 2x + 3x^2 + 4x^3 in Z[x]/(x^4+1). Formula (3.6):
    // a*_0 = a_0 = 1, a*_i = -a_{4-i} for i=1,2,3.
    // a*_1 = -a_3 = -4, a*_2 = -a_2 = -3, a*_3 = -a_1 = -2.
    const ZPoly a{BigInt(1), BigInt(2), BigInt(3), BigInt(4)};
    const ZPoly expected{BigInt(1), BigInt(-4), BigInt(-3), BigInt(-2)};
    require(hermitian_adjoint(a, 4) == expected, "hermitian_adjoint must match eq. (3.6) exactly");
}

void test_adjoint_is_involution() {
    // (a*)* == a - a basic algebraic sanity check independent of the exact
    // formula's derivation.
    const ZPoly a{BigInt(5), BigInt(-3), BigInt(0), BigInt(7), BigInt(-1), BigInt(2),
                 BigInt(0), BigInt(9)};
    const ZPoly twice = hermitian_adjoint(hermitian_adjoint(a, 8), 8);
    require(twice == a, "applying the adjoint twice must return the original polynomial");
}

void test_quality_hand_computable_toy() {
    // degree=4, q=17, f=1 (constant), g=0.
    // f* = f = 1 (adjoint of a constant is itself), g* = 0.
    // D = f*f* + g*g* = 1.
    // ||(g,-f)|| = ||(0,0,0,0,-1,0,0,0)|| = 1.
    // q*f*/D = 17*1/1 = 17 (constant polynomial), norm = 17.
    // q*g*/D = 0, norm = 0.
    // gamma = max(1, 17, 0) = 17.
    const ZPoly f{BigInt(1), BigInt(0), BigInt(0), BigInt(0)};
    const ZPoly g{BigInt(0), BigInt(0), BigInt(0), BigInt(0)};
    const auto quality = compute_trapdoor_quality(f, g, 4, BigInt(17));

    const long double expected_gamma = 17.0L;
    const long double relative_error =
        std::abs(quality.gs_norm - expected_gamma) / expected_gamma;
    require(relative_error < 1e-6L, "hand-computable toy case must match gamma=17 exactly");

    // 1.17*sqrt(17) ~ 4.824 - far below gamma=17, so this candidate is
    // correctly rejected (f=1,g=0 is a degenerate, not a real trapdoor
    // candidate - the point of this test is the arithmetic, not realism).
    require(!quality.accepted, "gamma=17 must exceed the 1.17*sqrt(q) threshold at q=17");
}

void test_quality_larger_coefficients_increase_gamma() {
    // Monotonicity sanity check, independent of the exact formula: scaling
    // f,g up should not make the candidate look BETTER. Not a proof the
    // formula is right, but a real bug (e.g. an inverted comparison, a
    // sign error that cancels growth) would very plausibly break this.
    const ZPoly f_small{BigInt(1), BigInt(1), BigInt(0), BigInt(0)};
    const ZPoly g_small{BigInt(1), BigInt(-1), BigInt(0), BigInt(0)};
    const ZPoly f_large{BigInt(10), BigInt(10), BigInt(0), BigInt(0)};
    const ZPoly g_large{BigInt(10), BigInt(-10), BigInt(0), BigInt(0)};

    const auto small = compute_trapdoor_quality(f_small, g_small, 4, BigInt(17));
    const auto large = compute_trapdoor_quality(f_large, g_large, 4, BigInt(17));
    require(large.gs_norm > small.gs_norm,
            "scaling f,g up by 10x must not decrease the quality bound gamma");
}

void test_quality_threshold_matches_formula() {
    const ZPoly f{BigInt(1), BigInt(0), BigInt(0), BigInt(0)};
    const ZPoly g{BigInt(0), BigInt(0), BigInt(0), BigInt(0)};
    const auto quality = compute_trapdoor_quality(f, g, 4, BigInt(7933));
    const long double expected_threshold = 1.17L * std::sqrt(7933.0L);
    const long double relative_error =
        std::abs(quality.threshold - expected_threshold) / expected_threshold;
    require(relative_error < 1e-9L, "threshold must equal 1.17*sqrt(q) exactly");
}

void test_quality_at_real_falcon512_parameters_gives_plausible_gamma() {
    // Not a formal proof of correctness - a real, Gaussian-sampled (f,g)
    // pair at the actual d=512, q=7933 target parameters should produce a
    // gamma in a plausible range (positive, finite, not absurdly far from
    // the 1.17*sqrt(q) threshold it's being compared against) rather than
    // e.g. NaN, negative, or off by many orders of magnitude - the kind of
    // gross error a real implementation bug would produce.
    const long double sigma = 1.17L * std::sqrt(7933.0L / (2.0L * 512.0L));
    std::mt19937_64 rng(0xBEEFu);
    const auto f_raw = sample_discrete_gaussian_poly(512, sigma, rng);
    const auto g_raw = sample_discrete_gaussian_poly(512, sigma, rng);
    ZPoly f;
    ZPoly g;
    f.reserve(512);
    g.reserve(512);
    for (const auto v : f_raw) {
        f.emplace_back(v);
    }
    for (const auto v : g_raw) {
        g.emplace_back(v);
    }

    const auto quality = compute_trapdoor_quality(f, g, 512, BigInt(7933));
    require(quality.gs_norm > 0.0L, "gamma must be strictly positive for a nonzero candidate");
    require(quality.gs_norm < quality.threshold * 100.0L,
            "gamma should be within a couple orders of magnitude of the threshold for a "
            "typical Gaussian-sampled candidate, not wildly divergent");
    std::cout << "  (info) real d=512 gamma sample: " << static_cast<double>(quality.gs_norm)
              << " vs threshold " << static_cast<double>(quality.threshold)
              << (quality.accepted ? " [accepted]" : " [rejected]") << '\n';
}

} // namespace

int main() {
    try {
        test_adjoint_toy();
        test_adjoint_is_involution();
        test_quality_hand_computable_toy();
        test_quality_larger_coefficients_increase_gamma();
        test_quality_threshold_matches_formula();
        test_quality_at_real_falcon512_parameters_gives_plausible_gamma();
        std::cout << "blindsig_blns7933_quality_tests: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "blindsig_blns7933_quality_tests: FAIL: " << e.what() << '\n';
        return 1;
    }
}
