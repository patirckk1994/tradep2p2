#include "tradep2p/blindsig_blns7933_ldl.hpp"

#include "tradep2p/blindsig_blns7933_integer_ring.hpp"

#include <stdexcept>
#include <utility>

namespace tradep2p::blns7933 {
namespace {

// How far the leaf's linear coefficient is allowed to drift from exactly
// zero before the self-adjoint-collapse assumption (see this module's
// header comment) is treated as violated. At 256-digit precision working
// on exact-integer-derived inputs, genuine self-adjointness should hold
// to far better than this - a violation here means a real bug upstream
// (e.g. an asymmetric Gram matrix), not accumulated rounding.
bool is_negligible(const HighReal& value) {
    HighReal magnitude = value < 0 ? -value : value;
    return magnitude < HighReal("1e-100");
}

} // namespace

GramMatrix build_gram_matrix(
    const RealRingArithmetic& ring, const RealPoly& f, const RealPoly& g,
    const RealPoly& cap_f, const RealPoly& cap_g) {
    // B = [[g,-f],[cap_g,-cap_f]]; G = B_hat * B_hat^adjoint gives (see
    // this project's session notes for the full row-by-row derivation,
    // cross-checked symbolically):
    //   g00 = g*g* + f*f*
    //   g01 = g*cap_g* + f*cap_f*
    //   g10 = cap_g*g* + cap_f*f*   (= g01*, by construction)
    //   g11 = cap_g*cap_g* + cap_f*cap_f*
    const RealPoly f_adj = ring.hermitian_adjoint(f);
    const RealPoly g_adj = ring.hermitian_adjoint(g);
    const RealPoly cap_f_adj = ring.hermitian_adjoint(cap_f);
    const RealPoly cap_g_adj = ring.hermitian_adjoint(cap_g);

    GramMatrix result;
    result.g00 = ring.add(ring.mul(g, g_adj), ring.mul(f, f_adj));
    result.g01 = ring.add(ring.mul(g, cap_g_adj), ring.mul(f, cap_f_adj));
    result.g10 = ring.add(ring.mul(cap_g, g_adj), ring.mul(cap_f, f_adj));
    result.g11 = ring.add(ring.mul(cap_g, cap_g_adj), ring.mul(cap_f, cap_f_adj));
    return result;
}

LdlResult ldl(const RealRingArithmetic& ring, const GramMatrix& gram) {
    LdlResult result;
    result.d00 = gram.g00;
    result.l10 = ring.div(gram.g10, gram.g00);
    const RealPoly l10_adj = ring.hermitian_adjoint(result.l10);
    const RealPoly correction = ring.mul(ring.mul(result.l10, l10_adj), gram.g00);
    result.d11 = ring.sub(gram.g11, correction);
    return result;
}

namespace {

std::unique_ptr<FalconTreeNode> build_falcon_tree_recursive(
    const GramMatrix& gram, std::size_t degree, const HighReal& target_sigma) {
    const RealRingArithmetic ring(degree);
    const LdlResult decomposed = ldl(ring, gram);

    auto node = std::make_unique<FalconTreeNode>();
    node->value = decomposed.l10;

    if (degree == 2U) {
        // Self-adjoint collapse (see header comment): D00, D11 each have
        // adjoint_1 = -value_1 by eq. (3.6) at degree 2; self-adjointness
        // (guaranteed by Gram-matrix-diagonal construction) forces
        // value_1 = 0 exactly, leaving the constant term as the true
        // scalar leaf value.
        if (!is_negligible(decomposed.d00[1]) || !is_negligible(decomposed.d11[1])) {
            throw std::logic_error(
                "BLNS7933 Falcon tree: degree-2 diagonal entry is not self-adjoint - "
                "this should never happen for a genuine Gram matrix, investigate");
        }
        const HighReal d00_scalar = decomposed.d00[0];
        const HighReal d11_scalar = decomposed.d11[0];
        if (!(d00_scalar > 0) || !(d11_scalar > 0)) {
            throw std::logic_error(
                "BLNS7933 Falcon tree: a degree-2 Gram diagonal entry is not strictly "
                "positive - the Gram matrix is not positive definite, investigate");
        }
        // Normalization (falcon.pdf Algorithm 4 lines 6-7): leaf <-
        // sigma / sqrt(leaf). Folded in here rather than as a separate
        // tree-walk, since nothing else ever needs the un-normalized tree.
        node->left = target_sigma / sqrt(d00_scalar);
        node->right = target_sigma / sqrt(d11_scalar);
        return node;
    }

    const RealRingArithmetic half_ring(degree / 2U);
    const auto [d00_even, d00_odd] = split(decomposed.d00);
    const auto [d11_even, d11_odd] = split(decomposed.d11);

    // G0 = [[d00_even, d00_odd],[d00_odd*, d00_even]] (falcon.pdf
    // Algorithm 9 line 10 - the SAME d00_even value appears on both
    // diagonal positions, this is not a typo, see eq. (3.30)).
    GramMatrix g0;
    g0.g00 = d00_even;
    g0.g01 = d00_odd;
    g0.g10 = half_ring.hermitian_adjoint(d00_odd);
    g0.g11 = d00_even;

    GramMatrix g1;
    g1.g00 = d11_even;
    g1.g01 = d11_odd;
    g1.g10 = half_ring.hermitian_adjoint(d11_odd);
    g1.g11 = d11_even;

    node->left = build_falcon_tree_recursive(g0, degree / 2U, target_sigma);
    node->right = build_falcon_tree_recursive(g1, degree / 2U, target_sigma);
    return node;
}

} // namespace

std::unique_ptr<FalconTreeNode> build_falcon_tree(
    const RealRingArithmetic& ring, const GramMatrix& gram, std::size_t degree,
    const HighReal& target_sigma) {
    if (degree < 2U || !is_power_of_two(degree)) {
        throw std::invalid_argument("BLNS7933 Falcon tree degree must be a power of two >= 2");
    }
    (void)ring; // The top-level ring is passed for interface symmetry with
                // the rest of this module; recursion builds its own
                // half-degree rings at each level (see
                // build_falcon_tree_recursive above), since degree changes
                // at every level and RealRingArithmetic is degree-fixed.
    return build_falcon_tree_recursive(gram, degree, target_sigma);
}

} // namespace tradep2p::blns7933
