#include "tradep2p/blindsig_blns7933_sampling.hpp"

#include "tradep2p/blindsig_blns7933_gaussian.hpp"

#include <stdexcept>

namespace tradep2p::blns7933 {
namespace {

// Handles one child slot (either a scalar leaf - the degree=1 base case,
// falcon.pdf Algorithm 11 lines 1-5 - or a subtree, requiring a further
// recursive ff_sampling call). `child_degree` is the RING DEGREE the
// child itself operates at (half of the parent's), matching the value
// ffSampling would have been called with had it received this child
// directly per falcon.pdf's own (T,n)-indexed recursion.
SamplingResult sample_child(
    const SamplingTarget& target, const FalconTreeChild& child, std::size_t child_degree,
    CryptoRng& rng) {
    if (std::holds_alternative<HighReal>(child)) {
        if (child_degree != 1U) {
            throw std::logic_error(
                "ffSampling: reached a leaf at degree>1 - tree/degree mismatch, investigate");
        }
        if (target.t0.size() != 1U || target.t1.size() != 1U) {
            throw std::logic_error("ffSampling: degree=1 target must have exactly one coefficient");
        }
        const HighReal& sigma_prime = std::get<HighReal>(child);
        const std::int64_t z0 = sample_discrete_gaussian_centered(sigma_prime, target.t0[0], rng);
        const std::int64_t z1 = sample_discrete_gaussian_centered(sigma_prime, target.t1[0], rng);
        return SamplingResult{RealPoly{HighReal(z0)}, RealPoly{HighReal(z1)}};
    }
    if (child_degree == 1U) {
        throw std::logic_error(
            "ffSampling: reached degree=1 but the tree node is not a leaf - "
            "tree/degree mismatch, investigate");
    }
    const auto& subtree = std::get<std::unique_ptr<FalconTreeNode>>(child);
    return ff_sampling(target, *subtree, child_degree, rng);
}

} // namespace

SamplingResult ff_sampling(
    const SamplingTarget& target, const FalconTreeNode& node, std::size_t degree,
    CryptoRng& rng) {
    if (degree < 2U) {
        throw std::logic_error("ff_sampling: degree must be >= 2 at an internal node");
    }
    const RealPoly& ell = node.value; // T.value = L10 at this level
    const RealRingArithmetic ring(degree);
    const std::size_t half = degree / 2U;

    // Line 7-9: t1_split = split(t1); (a,b) = ffSampling_{n/2}(t1_split,
    // T1); z1 = merge(a,b). The recursive call's OWN return pair (a,b),
    // each of degree n/2, becomes a single degree-n polynomial via
    // merge() - this is the outer function's z1, not to be confused with
    // the recursive call's own internal z1.
    const auto [t1_even, t1_odd] = split(target.t1);
    const SamplingResult inner1 =
        sample_child(SamplingTarget{t1_even, t1_odd}, node.right, half, rng);
    const RealPoly z1 = merge(inner1.z0, inner1.z1);

    // Line 10-13: t0' = t0 + (t1 - z1) (x) ell; t0_split = split(t0');
    // (c,d) = ffSampling_{n/2}(t0_split, T0); z0 = merge(c,d). Note this
    // recursion uses the ALREADY-COMPUTED z1 (via t0'), matching
    // falcon.pdf's own remark that "the recursions cannot be done in
    // parallel: the second recursion takes into account the result of
    // the first."
    const RealPoly t0_prime = ring.add(target.t0, ring.mul(ring.sub(target.t1, z1), ell));
    const auto [t0_even, t0_odd] = split(t0_prime);
    const SamplingResult inner0 =
        sample_child(SamplingTarget{t0_even, t0_odd}, node.left, half, rng);
    const RealPoly z0 = merge(inner0.z0, inner0.z1);

    return SamplingResult{z0, z1};
}

} // namespace tradep2p::blns7933
