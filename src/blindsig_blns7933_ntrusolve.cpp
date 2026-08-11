#include "tradep2p/blindsig_blns7933_ntrusolve.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace tradep2p::blns7933 {
namespace {

struct BezoutResult {
    BigInt gcd;
    BigInt u;
    BigInt v;
};

BezoutResult extended_gcd(BigInt a, BigInt b) {
    const bool a_negative = a < 0;
    const bool b_negative = b < 0;
    if (a_negative) {
        a = -a;
    }
    if (b_negative) {
        b = -b;
    }

    BigInt old_r = a;
    BigInt r = b;
    BigInt old_s = 1;
    BigInt s = 0;
    BigInt old_t = 0;
    BigInt t = 1;

    while (r != 0) {
        const BigInt quotient = old_r / r;

        BigInt next = old_r - quotient * r;
        old_r = r;
        r = std::move(next);

        next = old_s - quotient * s;
        old_s = s;
        s = std::move(next);

        next = old_t - quotient * t;
        old_t = t;
        t = std::move(next);
    }

    if (a_negative) {
        old_s = -old_s;
    }
    if (b_negative) {
        old_t = -old_t;
    }

    return BezoutResult{std::move(old_r), std::move(old_s), std::move(old_t)};
}

std::size_t max_bits_pair(const ZPoly& a, const ZPoly& b) {
    return std::max(max_coefficient_bit_length(a), max_coefficient_bit_length(b));
}

} // namespace

ZPoly ntru_relation_lhs(const ZPoly& f, const ZPoly& g,
                        const ZPoly& F, const ZPoly& G,
                        std::size_t degree) {
    IntegerRingArithmetic ring(degree);
    return ring.sub(ring.mul(f, G), ring.mul(g, F));
}

bool verify_ntru_relation_exact(const ZPoly& f, const ZPoly& g,
                                const ZPoly& F, const ZPoly& G,
                                const BigInt& q,
                                std::size_t degree) {
    if (degree == 0U) {
        return false;
    }
    const ZPoly lhs = ntru_relation_lhs(f, g, F, G, degree);
    ZPoly expected(degree, BigInt{0});
    expected[0] = q;
    return lhs == expected;
}

NTRUEquationSolver::NTRUEquationSolver(std::size_t degree, BigInt q)
    : degree_(degree), q_(std::move(q)) {
    if (!is_power_of_two(degree_)) {
        throw std::invalid_argument("NTRUSolve degree must be a non-zero power of two");
    }
    if (q_ <= 0) {
        throw std::invalid_argument("NTRUSolve q must be positive");
    }
}

std::optional<NTRUSolution> NTRUEquationSolver::solve(
    const ZPoly& f, const ZPoly& g, NTRUSolverDiagnostics* diagnostics) const {
    if (diagnostics != nullptr) {
        diagnostics->levels.clear();
    }
    return solve_recursive(f, g, degree_, diagnostics);
}

std::optional<NTRUSolution> NTRUEquationSolver::solve_recursive(
    const ZPoly& f, const ZPoly& g, std::size_t degree,
    NTRUSolverDiagnostics* diagnostics) const {
    IntegerRingArithmetic ring(degree);
    const ZPoly ff = ring.canonical_size(f);
    const ZPoly gg = ring.canonical_size(g);

    std::size_t diagnostic_index = 0U;
    if (diagnostics != nullptr) {
        diagnostic_index = diagnostics->levels.size();
        diagnostics->levels.push_back(NTRUSolverLevelDiagnostics{
            degree, max_bits_pair(ff, gg), 0U, 0U});
    }

    if (degree == 1U) {
        const BezoutResult bezout = extended_gcd(ff[0], gg[0]);
        if (bezout.gcd == 0) {
            return std::nullopt;
        }
        if ((q_ % bezout.gcd) != 0) {
            return std::nullopt;
        }

        const BigInt scale = q_ / bezout.gcd;
        // bezout.u*f + bezout.v*g = gcd.  Therefore
        //   G = u*(q/gcd), F = -v*(q/gcd)
        // gives fG - gF = q.
        NTRUSolution solution;
        solution.F = ZPoly{-(bezout.v * scale)};
        solution.G = ZPoly{bezout.u * scale};

        if (!verify_ntru_relation_exact(ff, gg, solution.F, solution.G, q_, degree)) {
            throw std::logic_error("NTRUSolve base-case invariant failed");
        }
        if (diagnostics != nullptr) {
            diagnostics->levels[diagnostic_index].output_max_bits =
                max_bits_pair(solution.F, solution.G);
        }
        return solution;
    }

    const ZPoly norm_f = ring.field_norm(ff);
    const ZPoly norm_g = ring.field_norm(gg);
    if (diagnostics != nullptr) {
        diagnostics->levels[diagnostic_index].norm_max_bits = max_bits_pair(norm_f, norm_g);
    }

    const auto half_solution = solve_recursive(norm_f, norm_g, degree / 2U, diagnostics);
    if (!half_solution) {
        return std::nullopt;
    }

    // If N(f)G' - N(g)F' = q in the half-size ring, then with
    //
    //   F(x) = F'(x^2) g(-x)
    //   G(x) = G'(x^2) f(-x)
    //
    // we obtain fG - gF = q in the full ring because
    // f(x)f(-x)=N(f)(x^2) and g(x)g(-x)=N(g)(x^2).
    const ZPoly embedded_F = ring.embed_half(half_solution->F);
    const ZPoly embedded_G = ring.embed_half(half_solution->G);

    NTRUSolution solution;
    solution.F = ring.mul(embedded_F, ring.conjugate(gg));
    solution.G = ring.mul(embedded_G, ring.conjugate(ff));

    if (!verify_ntru_relation_exact(ff, gg, solution.F, solution.G, q_, degree)) {
        throw std::logic_error("NTRUSolve recursive lift invariant failed");
    }

    if (diagnostics != nullptr) {
        diagnostics->levels[diagnostic_index].output_max_bits =
            max_bits_pair(solution.F, solution.G);
    }
    return solution;
}

} // namespace tradep2p::blns7933
