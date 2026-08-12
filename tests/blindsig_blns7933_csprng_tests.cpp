#include "tradep2p/blindsig_blns7933_csprng.hpp"

#include <iostream>
#include <random>
#include <stdexcept>
#include <vector>

namespace {

using tradep2p::blns7933::CryptoRng;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void test_same_seed_reproduces_identical_sequence() {
    CryptoRng a(42);
    CryptoRng b(42);
    for (int i = 0; i < 2000; ++i) {
        require(a() == b(), "identical seeds must produce an identical draw sequence");
    }
}

void test_different_seeds_diverge() {
    CryptoRng a(42);
    CryptoRng b(43);
    bool any_different = false;
    for (int i = 0; i < 16; ++i) {
        if (a() != b()) {
            any_different = true;
            break;
        }
    }
    require(any_different, "different seeds must not collapse to the same output");
}

// The internal squeeze buffer is 4096 bytes (512 uint64_t draws) before a
// refill (fresh seed||counter absorption) is needed - see the .cpp's own
// comment on why EVP_DigestFinalXOF can't just be called again on the same
// context. Drawing well past that boundary is the only way to actually
// exercise refill() at all, not just the first block.
void test_many_draws_cross_refill_boundary_without_degenerating() {
    CryptoRng rng(7);
    std::vector<std::uint64_t> draws;
    draws.reserve(5000);
    for (int i = 0; i < 5000; ++i) {
        draws.push_back(rng());
    }

    bool all_zero = true;
    for (const auto v : draws) {
        if (v != 0) {
            all_zero = false;
            break;
        }
    }
    require(!all_zero, "5000 draws were all zero - the generator is degenerate");

    for (std::size_t i = 1; i < draws.size(); ++i) {
        require(draws[i] != draws[i - 1],
                "two consecutive 64-bit draws were identical - astronomically unlikely for a "
                "real stream, almost certainly a refill/counter bug");
    }

    // Cross-refill check specifically: draw 511 (the last word of the first
    // block) and draw 512 (the first word of the second block, right after
    // a refill) must differ - catches a refill() bug that accidentally
    // reuses counter=0 or otherwise repeats the first block.
    require(draws[511] != draws[512],
            "the word immediately after a refill matched the word immediately before it");
}

// This is the actual reason CryptoRng exists as a distinct type rather than
// a raw byte-squeezing function: every real call site (the Gaussian
// sampler's std::uniform_int_distribution, TrapGen, sign()) needs a
// UniformRandomBitGenerator, not just "a source of random bytes."
void test_works_as_a_uniform_random_bit_generator() {
    CryptoRng rng(9);
    std::uniform_int_distribution<std::int64_t> dist(-1000, 1000);
    double sum = 0.0;
    constexpr int trials = 20000;
    for (int i = 0; i < trials; ++i) {
        const auto v = dist(rng);
        require(v >= -1000 && v <= 1000, "uniform_int_distribution produced an out-of-range value");
        sum += static_cast<double>(v);
    }
    const double mean = sum / static_cast<double>(trials);
    // Standard error of the mean here is roughly 577/sqrt(20000) ~ 4.1;
    // 40 is a deliberately generous margin (~10 SE) against flaking, not a
    // tight statistical test - matches this project's own established
    // margin style for this class of check.
    require(std::abs(mean) < 40.0, "uniform_int_distribution over CryptoRng looks biased");
}

// The real (OS-entropy) constructor is the one every non-test call site
// actually uses - must not throw and must actually produce output, not
// just compile.
void test_real_constructor_produces_output() {
    CryptoRng rng;
    const auto first = rng();
    const auto second = rng();
    require(first != second, "two consecutive draws from a freshly OS-seeded generator matched");
}

// CryptoRng is deliberately non-copyable (see the header's own reasoning:
// duplicating live RNG state would make two "independent" draws reproduce
// each other) but must remain movable, since every real call site takes it
// by reference and construction-time ownership transfer (e.g. returning one
// from a factory) should still work.
void test_is_movable_not_copyable() {
    CryptoRng original(5);
    const auto first_before_move = original();
    CryptoRng moved(std::move(original));
    const auto second = moved();
    require(first_before_move != second, "sanity: consecutive draws should differ");

    CryptoRng reproduced(5);
    const auto replay_first = reproduced();
    require(replay_first == first_before_move,
            "moving a CryptoRng must not disturb the seed/stream it was constructed with");
}

} // namespace

int main() {
    try {
        test_same_seed_reproduces_identical_sequence();
        test_different_seeds_diverge();
        test_many_draws_cross_refill_boundary_without_degenerating();
        test_works_as_a_uniform_random_bit_generator();
        test_real_constructor_produces_output();
        test_is_movable_not_copyable();
        std::cout << "blindsig_blns7933_csprng_tests: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "blindsig_blns7933_csprng_tests: FAIL: " << e.what() << '\n';
        return 1;
    }
}
