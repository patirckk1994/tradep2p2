// Full pipeline diagnostic at the ACTUAL BLNS23 target dimension: TrapGen
// -> build the signing tree -> Sign -> Verify, at d=512, q=7933. Deliberately
// NOT registered with CTest - TrapGen alone has taken ~400s in this
// project's own prior runs at this dimension, and the LDL tree
// construction's div() calls cost O(degree^3) at 256-digit precision on
// top of that - this genuinely takes real minutes, matching every other
// d=512 diagnostic in this directory (see scaling_512_diagnostic.cpp).
// See sign_diagnostic.cpp for the faster, default-practical d=32 version
// used during regular development.

#include "tradep2p/blindsig_blns7933.hpp"
#include "tradep2p/blindsig_blns7933_sign.hpp"

#include <chrono>
#include <iomanip>
#include <iostream>
#include <random>
#include <stdexcept>

namespace {

using namespace tradep2p::blns7933;

constexpr std::size_t kDegree = 512U;
constexpr std::int64_t kQ = 7933;

double seconds(std::chrono::steady_clock::duration duration) {
    return std::chrono::duration<double>(duration).count();
}

} // namespace

int main() {
    try {
        std::cout << std::fixed << std::setprecision(3);
        std::cout << "BLNS7933 full sign/verify pipeline diagnostic, d=" << kDegree
                  << ", q=" << kQ << '\n';

        const RingArithmetic ring(kDegree, kQ);
        NTRUTrapdoorGenerator generator(ring);
        std::mt19937_64 rng(4);

        const auto trapgen_start = std::chrono::steady_clock::now();
        const TrapdoorKey key = generator.generate(rng);
        const auto trapgen_end = std::chrono::steady_clock::now();
        if (!generator.verify_ntru_relation(key)) {
            throw std::logic_error("TrapGen produced an unverifiable key");
        }
        std::cout << "  TrapGen:                " << seconds(trapgen_end - trapgen_start) << " s\n";

        const PublicKey public_key = generator.derive_public(key);

        // sigma = Parameters::sigma (232) is BLNS23's own target for
        // d=512; at smaller dimensions here it is used as-is rather than
        // rederived, since this diagnostic exists to exercise the
        // pipeline's mechanics, not to claim a dimension-appropriate
        // security calibration - see README.md's own caveat on this.
        const HighReal target_sigma(static_cast<double>(Parameters::sigma));
        const auto tree_start = std::chrono::steady_clock::now();
        const auto tree = build_signing_tree(ring, key, target_sigma);
        const auto tree_end = std::chrono::steady_clock::now();
        std::cout << "  build_signing_tree:     " << seconds(tree_end - tree_start) << " s\n";

        // beta_s^2 = (sigma*sqrt(2*n*d))^2 = sigma^2 * 2*n*d - using n=2
        // (s has 2 ring-element components) per this project's own
        // Table 2 formula, d=kDegree.
        const long double beta_s = static_cast<long double>(Parameters::sigma) *
                                   std::sqrt(2.0L * 2.0L * static_cast<long double>(kDegree));
        const BigInt norm_bound_squared(static_cast<long long>(beta_s * beta_s));

        const auto sign_start = std::chrono::steady_clock::now();
        const Signature signature =
            sign(ring, key, *tree, "BLNS7933 sign/verify pipeline diagnostic", norm_bound_squared, rng);
        const auto sign_end = std::chrono::steady_clock::now();
        std::cout << "  sign:                   " << seconds(sign_end - sign_start) << " s\n";

        const bool verified = verify(ring, public_key, "BLNS7933 sign/verify pipeline diagnostic",
                                     signature, norm_bound_squared);
        if (!verified) {
            throw std::logic_error("a genuinely produced signature failed to verify");
        }
        std::cout << "  verify:                 accepted\n";

        BigInt actual_norm_squared = 0;
        for (const auto v : signature.s0) {
            actual_norm_squared += BigInt(v) * BigInt(v);
        }
        for (const auto v : signature.s1) {
            actual_norm_squared += BigInt(v) * BigInt(v);
        }
        std::cout << "  ||s||^2:                " << actual_norm_squared << " (bound "
                  << norm_bound_squared << ")\n";

        std::cout << "BLNS7933 sign/verify pipeline diagnostic: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "BLNS7933 sign/verify pipeline diagnostic: FAIL: " << e.what() << '\n';
        return 1;
    }
}
