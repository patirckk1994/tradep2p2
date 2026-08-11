// Statistical validation of sign()'s OUTPUT distribution, not just its
// algebraic correctness (already covered by blindsig_blns7933_sign_tests.cpp
// and the sign/sign_512 diagnostics). falcon.pdf's own claim (Algorithm 10,
// line 7 comment) is specifically that "s follows a Gaussian distribution:
// s ~ D_{(c,0)+Lambda(B),sigma,0}" - this diagnostic is a first, honest,
// EMPIRICAL check of that claim against this reference substrate's actual
// ffSampling implementation. It is NOT a formal statistical-distance proof
// and does not claim to be one - see the printed caveats and README.md's
// own framing of what this establishes and what it doesn't.
//
// Two complementary checks, both operating on s (the actual signature, not
// the intermediate z - the paper's claim is about s specifically):
//
//   1. Pooled statistics across N_DIFFERENT signed messages (N different
//      cosets): pools every coefficient of every s0/s1 into one array and
//      compares the pooled mean/variance against 0/sigma^2. A generically
//      wrong sampler (wrong sigma used somewhere, a systematic bias, a
//      forgotten normalization step) should show up here.
//   2. Repeated signing of the SAME message (same coset, many independent
//      ffSampling draws): confirms the sampler is not accidentally
//      deterministic or low-entropy (a real, checkable failure mode - a
//      broken RNG wiring could produce IDENTICAL "random" signatures every
//      time without any of the algebraic checks noticing), and reports the
//      same-coset sample variance as a secondary data point.
//
// Every single signature produced by both loops is independently
// re-verified via verify() - a statistical test that silently tolerated
// even one algebraically-invalid signature would be worse than useless.

#include "tradep2p/blindsig_blns7933.hpp"
#include "tradep2p/blindsig_blns7933_sign.hpp"

#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace {

using namespace tradep2p::blns7933;

constexpr std::size_t kDegree = 512U;
constexpr std::int64_t kQ = 7933;
constexpr std::size_t kDifferentMessageSamples = 100U;
constexpr std::size_t kSameMessageSamples = 50U;

double seconds(std::chrono::steady_clock::duration duration) {
    return std::chrono::duration<double>(duration).count();
}

void pool_signature(const Signature& signature, std::vector<double>& pool) {
    for (const auto v : signature.s0) {
        pool.push_back(static_cast<double>(v));
    }
    for (const auto v : signature.s1) {
        pool.push_back(static_cast<double>(v));
    }
}

struct MeanVariance {
    double mean{};
    double variance{};
};

MeanVariance compute_mean_variance(const std::vector<double>& values) {
    double sum = 0.0;
    for (const double v : values) {
        sum += v;
    }
    const double mean = sum / static_cast<double>(values.size());
    double sum_sq_dev = 0.0;
    for (const double v : values) {
        sum_sq_dev += (v - mean) * (v - mean);
    }
    return MeanVariance{mean, sum_sq_dev / static_cast<double>(values.size())};
}

} // namespace

int main() {
    try {
        std::cout << std::fixed << std::setprecision(3);
        std::cout << "BLNS7933 sign() output-distribution diagnostic, d=" << kDegree
                  << ", q=" << kQ << '\n';

        const RingArithmetic ring(kDegree, kQ);
        NTRUTrapdoorGenerator generator(ring);
        std::mt19937_64 rng(2027);

        const auto trapgen_start = std::chrono::steady_clock::now();
        const TrapdoorKey key = generator.generate(rng);
        const auto trapgen_end = std::chrono::steady_clock::now();
        if (!generator.verify_ntru_relation(key)) {
            throw std::logic_error("TrapGen produced an unverifiable key");
        }
        const PublicKey public_key = generator.derive_public(key);
        std::cout << "  TrapGen:                " << seconds(trapgen_end - trapgen_start) << " s\n";

        const HighReal target_sigma(static_cast<double>(Parameters::sigma));
        const auto tree_start = std::chrono::steady_clock::now();
        const auto tree = build_signing_tree(ring, key, target_sigma);
        const auto tree_end = std::chrono::steady_clock::now();
        std::cout << "  build_signing_tree:     " << seconds(tree_end - tree_start) << " s\n";
        std::cout << "  (one-time cost above; every signature below reuses this same tree)\n\n";

        const long double beta_s = static_cast<long double>(Parameters::sigma) *
                                   std::sqrt(2.0L * 2.0L * static_cast<long double>(kDegree));
        const BigInt norm_bound_squared(static_cast<long long>(beta_s * beta_s));
        const double target_sigma_squared =
            static_cast<double>(Parameters::sigma) * static_cast<double>(Parameters::sigma);

        // --- Check 1: pooled statistics across many DIFFERENT messages ---
        std::vector<double> pooled_different;
        pooled_different.reserve(2U * kDegree * kDifferentMessageSamples);
        const auto different_start = std::chrono::steady_clock::now();
        for (std::size_t i = 0; i < kDifferentMessageSamples; ++i) {
            std::ostringstream message;
            message << "distribution-diagnostic-message-" << i;
            const Signature signature =
                sign(ring, key, *tree, message.str(), norm_bound_squared, rng);
            if (!verify(ring, public_key, message.str(), signature, norm_bound_squared)) {
                throw std::logic_error(
                    "distribution diagnostic: a produced signature failed its own verify() - "
                    "this should never happen, investigate immediately");
            }
            pool_signature(signature, pooled_different);
        }
        const auto different_end = std::chrono::steady_clock::now();
        const MeanVariance different_stats = compute_mean_variance(pooled_different);

        std::cout << "Check 1: " << kDifferentMessageSamples << " different messages ("
                  << seconds(different_end - different_start) << " s, "
                  << pooled_different.size() << " pooled coefficients)\n";
        std::cout << "  pooled mean:            " << different_stats.mean
                  << " (target ~0, scale sigma=" << static_cast<double>(Parameters::sigma) << ")\n";
        std::cout << "  pooled variance:        " << different_stats.variance << " (target sigma^2="
                  << target_sigma_squared << ", ratio="
                  << different_stats.variance / target_sigma_squared << ")\n";

        // --- Check 2: repeated signing of the SAME message ---
        const std::string fixed_message = "distribution-diagnostic-fixed-message";
        std::vector<Signature> same_message_signatures;
        same_message_signatures.reserve(kSameMessageSamples);
        std::vector<double> pooled_same;
        pooled_same.reserve(2U * kDegree * kSameMessageSamples);
        const auto same_start = std::chrono::steady_clock::now();
        for (std::size_t i = 0; i < kSameMessageSamples; ++i) {
            const Signature signature =
                sign(ring, key, *tree, fixed_message, norm_bound_squared, rng);
            if (!verify(ring, public_key, fixed_message, signature, norm_bound_squared)) {
                throw std::logic_error(
                    "distribution diagnostic: a same-message signature failed its own verify()");
            }
            pool_signature(signature, pooled_same);
            same_message_signatures.push_back(signature);
        }
        const auto same_end = std::chrono::steady_clock::now();

        bool all_identical = true;
        for (std::size_t i = 1; i < same_message_signatures.size(); ++i) {
            if (same_message_signatures[i].s0 != same_message_signatures[0].s0 ||
                same_message_signatures[i].s1 != same_message_signatures[0].s1) {
                all_identical = false;
                break;
            }
        }
        if (all_identical) {
            throw std::logic_error(
                "distribution diagnostic: every same-message signature was IDENTICAL - the "
                "sampler is not actually randomized, investigate the RNG wiring immediately");
        }

        const MeanVariance same_stats = compute_mean_variance(pooled_same);
        std::cout << "\nCheck 2: " << kSameMessageSamples << " signatures of the SAME message ("
                  << seconds(same_end - same_start) << " s)\n";
        std::cout << "  all identical:          no (genuine randomness confirmed)\n";
        std::cout << "  pooled mean:            " << same_stats.mean
                  << " (this coset's own natural center, not necessarily 0)\n";
        std::cout << "  pooled variance:        " << same_stats.variance << " (target sigma^2="
                  << target_sigma_squared << ", ratio="
                  << same_stats.variance / target_sigma_squared << ")\n";

        std::cout << "\nCAVEAT (worth repeating, not just in README.md): this is an empirical "
                     "moment check, not a formal statistical-distance proof, and pooled "
                     "coefficients within one signature are not independent draws, so these "
                     "variance ratios are directional evidence, not a tight statistical test.\n";

        std::cout << "\nBLNS7933 distribution diagnostic: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "BLNS7933 distribution diagnostic: FAIL: " << e.what() << '\n';
        return 1;
    }
}
