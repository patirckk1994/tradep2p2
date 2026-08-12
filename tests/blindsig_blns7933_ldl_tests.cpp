#include "tradep2p/blindsig_blns7933_ldl.hpp"

#include <cmath>
#include <iostream>
#include <stdexcept>

namespace {

using tradep2p::blns7933::FalconTreeNode;
using tradep2p::blns7933::GramMatrix;
using tradep2p::blns7933::HighReal;
using tradep2p::blns7933::LdlResult;
using tradep2p::blns7933::RealPoly;
using tradep2p::blns7933::RealRingArithmetic;
using tradep2p::blns7933::build_falcon_tree;
using tradep2p::blns7933::build_gram_matrix;
using tradep2p::blns7933::ldl;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

double to_double(const HighReal& v) { return v.convert_to<double>(); }

bool approx_equal(const RealPoly& a, const RealPoly& b, double tolerance) {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::abs(to_double(a[i] - b[i])) > tolerance) {
            return false;
        }
    }
    return true;
}

// The exact d=4, q=17 trapdoor this project's own TrapGen produced and
// verified earlier this session (f*G-g*F=17 confirmed exactly) - reused
// here rather than hand-picking arbitrary polynomials, since an arbitrary
// (f,g,F,G) is not guaranteed to give a positive-definite Gram matrix
// (sqrt() of a negative leaf would legitimately fail), and this one is
// known-good.
RealPoly real_poly(std::initializer_list<double> values) {
    RealPoly out;
    out.reserve(values.size());
    for (const double v : values) {
        out.emplace_back(HighReal(v));
    }
    return out;
}

void test_gram_matrix_ldl_reconstructs_exactly() {
    const RealRingArithmetic ring(4);
    const RealPoly f = real_poly({0, 0, -3, 0});
    const RealPoly g = real_poly({0, 1, 2, -3});
    const RealPoly cap_f = real_poly({-1, -1, 2, 1});
    const RealPoly cap_g = real_poly({0, -1, 3, 1});

    const GramMatrix gram = build_gram_matrix(ring, f, g, cap_f, cap_g);

    // G must be self-adjoint: g10 == g01* exactly (this is an algebraic
    // consequence of the B*B^adjoint construction, not assumed - a real
    // check that build_gram_matrix() is actually correct).
    require(approx_equal(gram.g10, ring.hermitian_adjoint(gram.g01), 1e-60),
            "Gram matrix must be self-adjoint: g10 == g01*");

    const LdlResult decomposed = ldl(ring, gram);

    // Reconstruct G from L,D: falcon.pdf Algorithm 8 says G = L*D*L^adjoint.
    // L = [[1,0],[L10,1]], D = diag(D00,D11). Expanding:
    //   (LDL*)_00 = D00
    //   (LDL*)_01 = D00 * L10*
    //   (LDL*)_10 = L10 * D00
    //   (LDL*)_11 = L10*D00*L10* + D11
    const RealPoly l10_adj = ring.hermitian_adjoint(decomposed.l10);
    const RealPoly reconstructed_00 = decomposed.d00;
    const RealPoly reconstructed_01 = ring.mul(decomposed.d00, l10_adj);
    const RealPoly reconstructed_10 = ring.mul(decomposed.l10, decomposed.d00);
    const RealPoly reconstructed_11 =
        ring.add(ring.mul(ring.mul(decomposed.l10, decomposed.d00), l10_adj), decomposed.d11);

    require(approx_equal(reconstructed_00, gram.g00, 1e-45), "LDL reconstruction: G00 mismatch");
    require(approx_equal(reconstructed_01, gram.g01, 1e-45), "LDL reconstruction: G01 mismatch");
    require(approx_equal(reconstructed_10, gram.g10, 1e-45), "LDL reconstruction: G10 mismatch");
    require(approx_equal(reconstructed_11, gram.g11, 1e-45), "LDL reconstruction: G11 mismatch");
}

void test_falcon_tree_structure_and_positive_leaves() {
    const RealRingArithmetic ring(4);
    const RealPoly f = real_poly({0, 0, -3, 0});
    const RealPoly g = real_poly({0, 1, 2, -3});
    const RealPoly cap_f = real_poly({-1, -1, 2, 1});
    const RealPoly cap_g = real_poly({0, -1, 3, 1});
    const GramMatrix gram = build_gram_matrix(ring, f, g, cap_f, cap_g);

    const HighReal target_sigma(10);
    const auto tree = build_falcon_tree(ring, gram, 4, target_sigma);

    require(tree != nullptr, "tree root must exist");
    require(tree->value.size() == 4U, "root L10 must be a degree-4 polynomial");

    // At degree=4, both children must be SUBTREES (degree=2 is the base
    // case ONE level down, not at the root) - see this module's header
    // comment on the self-adjoint collapse.
    require(std::holds_alternative<std::unique_ptr<FalconTreeNode>>(tree->left),
            "at degree=4, the left child must be an internal node, not a leaf yet");
    require(std::holds_alternative<std::unique_ptr<FalconTreeNode>>(tree->right),
            "at degree=4, the right child must be an internal node, not a leaf yet");

    const auto& left_subtree = std::get<std::unique_ptr<FalconTreeNode>>(tree->left);
    const auto& right_subtree = std::get<std::unique_ptr<FalconTreeNode>>(tree->right);
    require(left_subtree->value.size() == 2U, "degree-2 subtree L10 must be a degree-2 polynomial");

    // Now at degree=2, both children must be scalar leaves.
    require(std::holds_alternative<HighReal>(left_subtree->left), "degree-2 node's left must be a leaf");
    require(std::holds_alternative<HighReal>(left_subtree->right), "degree-2 node's right must be a leaf");
    require(std::holds_alternative<HighReal>(right_subtree->left), "degree-2 node's left must be a leaf");
    require(std::holds_alternative<HighReal>(right_subtree->right), "degree-2 node's right must be a leaf");

    // Every leaf must be strictly positive (it's sigma/sqrt(positive D),
    // and sigma>0) - a real, meaningful check, not just "did it not crash".
    for (const auto* node : {left_subtree.get(), right_subtree.get()}) {
        const auto& leaf_left = std::get<HighReal>(node->left);
        const auto& leaf_right = std::get<HighReal>(node->right);
        require(leaf_left > 0, "every Falcon tree leaf must be strictly positive");
        require(leaf_right > 0, "every Falcon tree leaf must be strictly positive");
    }
}

} // namespace

int main() {
    try {
        test_gram_matrix_ldl_reconstructs_exactly();
        test_falcon_tree_structure_and_positive_leaves();
        std::cout << "blindsig_blns7933_ldl_tests: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "blindsig_blns7933_ldl_tests: FAIL: " << e.what() << '\n';
        return 1;
    }
}
