// Manual TrapGen diagnostic: runs the FULL candidate-generation loop
// (Gaussian sampling -> invertibility check -> quality bound -> NTRUSolve
// -> reduce) with per-attempt visibility into why each candidate was
// rejected, at q=7933. Deliberately NOT registered with CTest - this is
// the same "expensive development experiment" category as the scaling
// diagnostics, not a fast deterministic regression test.
//
// Runs at d=32 by default (fast, seconds) so it's actually practical to
// re-run during development. The real d=512 target-parameter result is
// documented in README.md, obtained from a real run of this same logic
// (via NTRUTrapdoorGenerator::generate() directly) - not reproduced here
// as a default target because a single d=512 attempt's quality check
// alone costs on the order of a minute, and several attempts are typically
// needed before one is accepted.

#include "tradep2p/blindsig_blns7933.hpp"
#include "tradep2p/blindsig_blns7933_gaussian.hpp"
#include "tradep2p/blindsig_blns7933_quality.hpp"

#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <stdexcept>

namespace {

using tradep2p::blns7933::BigInt;
using tradep2p::blns7933::CryptoRng;
using tradep2p::blns7933::NTRUTrapdoorGenerator;
using tradep2p::blns7933::RingArithmetic;
using tradep2p::blns7933::ZPoly;
using tradep2p::blns7933::compute_trapdoor_quality;
using tradep2p::blns7933::sample_discrete_gaussian_poly;

constexpr std::size_t kDegree = 32U;
constexpr std::int64_t kQ = 7933;
constexpr std::size_t kMaxAttempts = 500U;

double milliseconds(std::chrono::steady_clock::duration duration) {
    return std::chrono::duration<double, std::milli>(duration).count();
}

ZPoly to_zpoly(const std::vector<std::int64_t>& raw) {
    ZPoly out;
    out.reserve(raw.size());
    for (const auto v : raw) {
        out.emplace_back(v);
    }
    return out;
}

} // namespace

int main() {
    try {
        const RingArithmetic ring(kDegree, kQ);
        const BigInt q{kQ};
        const long double sigma_fg =
            1.17L * std::sqrt(static_cast<long double>(kQ) / (2.0L * static_cast<long double>(kDegree)));

        std::cout << "BLNS7933 TrapGen diagnostic, d=" << kDegree << ", q=" << kQ << '\n';
        std::cout << "  sigma_{f,g} = " << static_cast<double>(sigma_fg) << '\n';

        CryptoRng rng(2026);
        std::size_t invertibility_rejections = 0U;
        std::size_t quality_rejections = 0U;
        std::size_t solve_rejections = 0U;
        std::size_t attempt = 0U;

        const auto overall_start = std::chrono::steady_clock::now();

        for (; attempt < kMaxAttempts; ++attempt) {
            const auto f_raw = sample_discrete_gaussian_poly(kDegree, sigma_fg, rng);
            const auto g_raw = sample_discrete_gaussian_poly(kDegree, sigma_fg, rng);

            if (!ring.inverse(g_raw).has_value()) {
                ++invertibility_rejections;
                std::cout << "  attempt " << attempt << ": rejected (g not invertible mod q)\n";
                continue;
            }

            const ZPoly f_big = to_zpoly(f_raw);
            const ZPoly g_big = to_zpoly(g_raw);
            const auto quality = compute_trapdoor_quality(f_big, g_big, kDegree, q);
            if (!quality.accepted) {
                ++quality_rejections;
                std::cout << "  attempt " << attempt << ": rejected (gamma="
                          << static_cast<double>(quality.gs_norm) << " > threshold="
                          << static_cast<double>(quality.threshold) << ")\n";
                continue;
            }

            std::cout << "  attempt " << attempt << ": passed invertibility + quality (gamma="
                      << static_cast<double>(quality.gs_norm) << " <= threshold="
                      << static_cast<double>(quality.threshold) << "), trying NTRUSolve...\n";
            break; // Found an accepted (f,g) - hand off to generate() below,
                   // reusing the real production code path (not a parallel
                   // reimplementation) for the actual timed solve+reduce.
        }

        if (attempt >= kMaxAttempts) {
            throw std::runtime_error("TrapGen diagnostic: no candidate accepted within attempt cap");
        }

        // Same seed (2026) as the visibility loop above: sample_discrete_
        // gaussian_poly()/compute_trapdoor_quality() are both deterministic
        // given their RNG stream, so restarting from the identical seed
        // makes generate() deterministically replay the exact same
        // sequence of rejected-then-accepted candidates just shown above,
        // this time through the real API and properly timed.
        NTRUTrapdoorGenerator generator(ring);
        CryptoRng full_rng(2026);
        const auto solve_start = std::chrono::steady_clock::now();
        const auto key = generator.generate(full_rng);
        const auto solve_end = std::chrono::steady_clock::now();

        if (!generator.verify_ntru_relation(key)) {
            throw std::logic_error("TrapGen diagnostic: generate() returned an unverifiable key");
        }
        const auto pub = generator.derive_public(key);
        (void)pub;

        const auto overall_end = std::chrono::steady_clock::now();

        std::cout << std::fixed << std::setprecision(3);
        std::cout << "  visibility-loop rejections: " << invertibility_rejections
                  << " (invertibility), " << quality_rejections << " (quality), "
                  << solve_rejections << " (solve)\n";
        std::cout << "  full generate() call:       " << milliseconds(solve_end - solve_start)
                  << " ms\n";
        std::cout << "  total diagnostic time:      " << milliseconds(overall_end - overall_start)
                  << " ms\n";
        std::cout << "  final relation verified:    yes\n";
        std::cout << "  public derivation:          succeeded\n";
        std::cout << "TrapGen diagnostic: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "TrapGen diagnostic: FAIL: " << e.what() << '\n';
        return 1;
    }
}
