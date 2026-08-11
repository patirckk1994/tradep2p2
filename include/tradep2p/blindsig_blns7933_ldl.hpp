#pragma once

// The "Falcon tree" (falcon.pdf Algorithm 8 LDL*, Algorithm 9 ffLDL*),
// entirely in real coefficient domain per this reference substrate's
// standing choice (see blindsig_blns7933_real_ring.hpp) - built once at
// keygen time from the trapdoor (f,g,F,G), consumed by ffSampling
// (blindsig_blns7933_sampling.hpp) at signing time.
//
// Self-adjoint-collapse note, worth stating up front because it is easy
// to get wrong: falcon.pdf's ffLDL* base case fires at ring degree n=2 and
// stores D00,D11 directly as leaf children WITHOUT further splitting -
// this only makes sense in FFT representation, where a self-adjoint
// degree-2 element collapses to a single real FFT value. In COEFFICIENT
// representation (what this module actually uses), a self-adjoint element
// of R[x]/(x^2+1) has adjoint a*_1=-a_1 (falcon.pdf eq. 3.6 at degree 2),
// so self-adjointness (a*=a) forces a_1=0 exactly - the element IS its
// constant coefficient. build_falcon_tree() extracts that constant term
// as the leaf scalar and defensively checks the linear term is (very
// close to) zero, rather than assuming it.

#include "tradep2p/blindsig_blns7933_real_ring.hpp"

#include <memory>
#include <variant>

namespace tradep2p::blns7933 {

struct FalconTreeNode;

// Either a leaf scalar (already sigma-normalized, see build_falcon_tree())
// or a subtree - falcon.pdf's own tree has this exact shape (leaves store
// a real sigma', internal nodes store L10 plus two children).
using FalconTreeChild = std::variant<HighReal, std::unique_ptr<FalconTreeNode>>;

struct FalconTreeNode {
    RealPoly value; // L10 at this level (falcon.pdf Algorithm 9 line 2)
    FalconTreeChild left;
    FalconTreeChild right;
};

struct GramMatrix {
    RealPoly g00;
    RealPoly g01;
    RealPoly g10;
    RealPoly g11;
};

// Builds G = B_hat * B_hat^* for B=[[g,-f],[capG,-capF]] (falcon.pdf
// Algorithm 4 lines 2-4), entirely via exact/high-precision coefficient-
// domain ring operations - see the .cpp for the closed-form entries
// (g00=g*g*+f*f*, etc.), each independently re-derivable from B*B^adjoint.
[[nodiscard]] GramMatrix build_gram_matrix(
    const RealRingArithmetic& ring, const RealPoly& f, const RealPoly& g,
    const RealPoly& cap_f, const RealPoly& cap_g);

struct LdlResult {
    RealPoly l10;
    RealPoly d00;
    RealPoly d11;
};

// LDL* decomposition of a 2x2 self-adjoint Gram matrix (falcon.pdf
// Algorithm 8): D00=G00, L10=G10/G00, D11=G11-L10 (x) L10*(x) G00, where
// (x) is ring multiplication. Throws if G00 is singular (see
// RealRingArithmetic::div()).
[[nodiscard]] LdlResult ldl(const RealRingArithmetic& ring, const GramMatrix& gram);

// Builds the full recursive Falcon tree from a Gram matrix at the given
// ring degree (falcon.pdf Algorithm 9), then normalizes every leaf in
// place: leaf <- target_sigma / sqrt(leaf) (falcon.pdf Algorithm 4 lines
// 6-7 - normalization is stated there as a separate post-processing step
// over the tree ffLDL* returns, folded in here since nothing else needs
// the un-normalized tree). `degree` must be a power of two >= 2.
[[nodiscard]] std::unique_ptr<FalconTreeNode> build_falcon_tree(
    const RealRingArithmetic& ring, const GramMatrix& gram, std::size_t degree,
    const HighReal& target_sigma);

} // namespace tradep2p::blns7933
