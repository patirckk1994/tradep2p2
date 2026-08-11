#pragma once

#include "tradep2p/blindsig_blns7933_integer_ring.hpp"

#include <cstddef>
#include <optional>
#include <vector>

namespace tradep2p::blns7933 {

struct NTRUSolution {
    ZPoly F;
    ZPoly G;
};

struct NTRUSolverLevelDiagnostics {
    std::size_t degree{0};
    std::size_t input_max_bits{0};
    std::size_t norm_max_bits{0};
    std::size_t output_max_bits{0};
};

struct NTRUSolverDiagnostics {
    std::vector<NTRUSolverLevelDiagnostics> levels;
};

// Exact reference solver for
//
//     f*G - g*F = q    in Z[x]/(x^n + 1).
//
// This implements only the recursive field-norm solve/lift phase.  It does
// NOT reduce the resulting (F,G), does NOT judge trapdoor quality, and does
// NOT sample f/g.  Those are intentionally separate components.
class NTRUEquationSolver {
public:
    explicit NTRUEquationSolver(std::size_t degree, BigInt q);

    [[nodiscard]] std::size_t degree() const noexcept { return degree_; }
    [[nodiscard]] const BigInt& q() const noexcept { return q_; }

    [[nodiscard]] std::optional<NTRUSolution> solve(
        const ZPoly& f, const ZPoly& g, NTRUSolverDiagnostics* diagnostics = nullptr) const;

private:
    std::size_t degree_;
    BigInt q_;

    [[nodiscard]] std::optional<NTRUSolution> solve_recursive(
        const ZPoly& f, const ZPoly& g, std::size_t degree,
        NTRUSolverDiagnostics* diagnostics) const;
};

[[nodiscard]] ZPoly ntru_relation_lhs(const ZPoly& f, const ZPoly& g,
                                      const ZPoly& F, const ZPoly& G,
                                      std::size_t degree);

[[nodiscard]] bool verify_ntru_relation_exact(const ZPoly& f, const ZPoly& g,
                                              const ZPoly& F, const ZPoly& G,
                                              const BigInt& q,
                                              std::size_t degree);

} // namespace tradep2p::blns7933
