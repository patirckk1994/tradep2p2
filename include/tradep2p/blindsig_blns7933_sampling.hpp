#pragma once

// ffSampling (falcon.pdf Algorithm 11): the randomized, tree-guided
// discrete rounding at the heart of signature generation. Given a target
// t=(t0,t1) and the Falcon tree built by build_falcon_tree(), produces
// z=(z0,z1) - NOT the naive coordinatewise round of t, which falcon.pdf
// SS3.9.1 states plainly leaks the private key (Nguyen-Regev's break of
// the original NTRUSign, catalogued in this project's own trapdoor-
// sampler research, is exactly this failure mode).
//
// Entirely in real coefficient domain, per this reference substrate's
// standing choice - see blindsig_blns7933_real_ring.hpp.

#include "tradep2p/blindsig_blns7933_csprng.hpp"
#include "tradep2p/blindsig_blns7933_ldl.hpp"

namespace tradep2p::blns7933 {

struct SamplingTarget {
    RealPoly t0;
    RealPoly t1;
};

struct SamplingResult {
    RealPoly z0;
    RealPoly z1;
};

// falcon.pdf Algorithm 11. `node` must be an internal tree node built by
// build_falcon_tree() at the given `degree` (degree > 1 is required at
// entry - the degree=1 base case is handled internally, one level down,
// by inspecting node.left/node.right's own variant before recursing, so
// this function's own parameter type never needs to represent a bare
// leaf - callers that only ever hold a tree's root, like sign(), never
// need to construct a FalconTreeChild themselves).
[[nodiscard]] SamplingResult ff_sampling(
    const SamplingTarget& target, const FalconTreeNode& node, std::size_t degree,
    CryptoRng& rng);

} // namespace tradep2p::blns7933
