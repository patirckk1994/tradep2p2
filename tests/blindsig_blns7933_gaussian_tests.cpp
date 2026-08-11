#include "tradep2p/blindsig_blns7933_gaussian.hpp"

#include <cmath>
#include <cstdlib>
#include <iostream>
#include <random>
#include <stdexcept>
#include <vector>

namespace {

using tradep2p::blns7933::sample_discrete_gaussian;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

// Statistical evidence, not a formal proof of correctness - matches this
// project's own established distinction between what a test demonstrates
// and what it doesn't (see the wider trapdoor-sampler research). What this
// DOES catch: a hardcoded/ignored sigma, a systematically off-center
// sampler, a badly wrong variance, or an accept/reject bug that biases the
// distribution enough to move the empirical mean/variance well outside
// their expected statistical fluctuation.
struct SampleStats {
    double mean{};
    double variance{};
};

SampleStats collect_stats(long double sigma, std::size_t trials, std::mt19937_64& rng) {
    double sum = 0.0;
    double sum_sq = 0.0;
    for (std::size_t i = 0; i < trials; ++i) {
        const std::int64_t z = sample_discrete_gaussian(sigma, rng);
        sum += static_cast<double>(z);
        sum_sq += static_cast<double>(z) * static_cast<double>(z);
    }
    const double mean = sum / static_cast<double>(trials);
    const double variance = sum_sq / static_cast<double>(trials) - mean * mean;
    return SampleStats{mean, variance};
}

void test_mean_near_zero_at_falcon512_sigma() {
    // sigma_{f,g} = 1.17*sqrt(q/(2n)) at q=7933, n=512 (falcon.pdf (3.27)).
    const long double sigma = 1.17L * std::sqrt(7933.0L / (2.0L * 512.0L));
    require(sigma > 3.0L && sigma < 3.5L, "sanity check on the sigma_{f,g} constant itself");

    std::mt19937_64 rng(0xC0FFEEu);
    const auto stats = collect_stats(sigma, 10000, rng);

    // Standard error of the mean at this sample size is sigma/sqrt(n) ~
    // 3.26/100 ~ 0.033; the 0.15 bound below is > 4.5 standard errors, a
    // deliberately generous margin against flaking, not a tight
    // statistical test. (10000, not the 200000 this was first run with -
    // each accepted sample costs a 256-digit exp() evaluation and the
    // larger count took over 11 real minutes; this project is willing to
    // trade time for precision, not test-suite iteration speed for no
    // added statistical power.)
    require(std::abs(stats.mean) < 0.15, "empirical mean should be close to zero");

    const double expected_variance = static_cast<double>(sigma) * static_cast<double>(sigma);
    const double relative_error = std::abs(stats.variance - expected_variance) / expected_variance;
    require(relative_error < 0.05, "empirical variance should match sigma^2 within 5%");
}

void test_variance_scales_with_sigma() {
    // Catches a sampler that silently ignores its sigma argument (e.g. a
    // hardcoded constant left over from development/testing).
    std::mt19937_64 rng(1);
    const auto narrow = collect_stats(2.0L, 10000, rng);
    const auto wide = collect_stats(8.0L, 10000, rng);
    require(wide.variance > narrow.variance * 8.0, "variance must grow with sigma, not stay fixed");
}

void test_deterministic_given_same_rng_state() {
    // Same seed, same sequence of draws - a basic reproducibility check
    // useful for debugging, not a security property.
    std::mt19937_64 rng_a(42);
    std::mt19937_64 rng_b(42);
    for (int i = 0; i < 500; ++i) {
        const auto a = sample_discrete_gaussian(3.26L, rng_a);
        const auto b = sample_discrete_gaussian(3.26L, rng_b);
        require(a == b, "identical RNG state must produce identical samples");
    }
}

void test_rejects_nonpositive_sigma() {
    std::mt19937_64 rng(7);
    bool threw = false;
    try {
        (void)sample_discrete_gaussian(0.0L, rng);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "sigma <= 0 must be rejected, not silently treated as a point mass");
}

} // namespace

int main() {
    try {
        test_mean_near_zero_at_falcon512_sigma();
        test_variance_scales_with_sigma();
        test_deterministic_given_same_rng_state();
        test_rejects_nonpositive_sigma();
        std::cout << "blindsig_blns7933_gaussian_tests: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "blindsig_blns7933_gaussian_tests: FAIL: " << e.what() << '\n';
        return 1;
    }
}
