#include "tradep2p/blindsig_blns7933_integer_ring.hpp"
#include "tradep2p/blindsig_blns7933_ntrusolve.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <vector>

namespace {

using tradep2p::blns7933::BigInt;
using tradep2p::blns7933::IntegerRingArithmetic;
using tradep2p::blns7933::NTRUEquationSolver;
using tradep2p::blns7933::NTRUSolverDiagnostics;
using tradep2p::blns7933::ZPoly;
using tradep2p::blns7933::verify_ntru_relation_exact;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

// Independent, intentionally tiny degree-2 oracle.  This does NOT call the
// recursive solver and does NOT use IntegerRingArithmetic for the equation.
// In Z[x]/(x^2+1),
//
//   (a0+a1*x)(b0+b1*x)
//     = (a0*b0-a1*b1) + (a0*b1+a1*b0)*x.
//
// We brute-force a bounded box for F,G.  This is only a test oracle: it is
// deliberately exponential and must never be promoted into TrapGen.
struct ToyD2Solution {
    std::int64_t F0{0};
    std::int64_t F1{0};
    std::int64_t G0{0};
    std::int64_t G1{0};
};

std::optional<ToyD2Solution> brute_force_degree_two(
    const std::array<std::int64_t, 2>& f,
    const std::array<std::int64_t, 2>& g,
    std::int64_t q,
    std::int64_t bound) {
    for (std::int64_t F0 = -bound; F0 <= bound; ++F0) {
        for (std::int64_t F1 = -bound; F1 <= bound; ++F1) {
            for (std::int64_t G0 = -bound; G0 <= bound; ++G0) {
                for (std::int64_t G1 = -bound; G1 <= bound; ++G1) {
                    const std::int64_t constant =
                        f[0] * G0 - f[1] * G1 - (g[0] * F0 - g[1] * F1);
                    const std::int64_t linear =
                        f[0] * G1 + f[1] * G0 - (g[0] * F1 + g[1] * F0);
                    if (constant == q && linear == 0) {
                        return ToyD2Solution{F0, F1, G0, G1};
                    }
                }
            }
        }
    }
    return std::nullopt;
}

void test_exact_negacyclic_multiplication() {
    IntegerRingArithmetic ring(4);
    const ZPoly result = ring.mul(ZPoly{0, 0, 0, 1}, ZPoly{0, 1});
    require(result == ZPoly({-1, 0, 0, 0}),
            "integer negacyclic multiplication must apply x^d=-1 exactly");
}

void test_field_norm_identity() {
    IntegerRingArithmetic ring(8);
    const ZPoly f{3, -2, 5, 1, -4, 0, 2, 7};
    const ZPoly norm = ring.field_norm(f);
    const ZPoly embedded = ring.embed_half(norm);
    const ZPoly direct = ring.mul(f, ring.conjugate(f));
    require(embedded == direct,
            "field norm must satisfy N(f)(x^2)=f(x)f(-x) exactly");
}

void test_base_case_success_and_failure() {
    {
        NTRUEquationSolver solver(1, BigInt{17});
        const auto solution = solver.solve(ZPoly{6}, ZPoly{5});
        require(solution.has_value(), "coprime scalar base case must solve");
        require(verify_ntru_relation_exact(ZPoly{6}, ZPoly{5},
                                           solution->F, solution->G,
                                           BigInt{17}, 1),
                "base-case solution must satisfy exact NTRU relation");
    }
    {
        NTRUEquationSolver solver(1, BigInt{17});
        const auto solution = solver.solve(ZPoly{2}, ZPoly{4});
        require(!solution.has_value(),
                "base case must fail when gcd(f,g) does not divide q");
    }
}

void test_recursive_solve_degree_two() {
    NTRUEquationSolver solver(2, BigInt{17});
    const ZPoly f{1, 1};
    const ZPoly g{1, 2};
    const auto solution = solver.solve(f, g);
    require(solution.has_value(), "degree-2 recursive NTRUSolve must succeed on toy input");
    require(verify_ntru_relation_exact(f, g, solution->F, solution->G, BigInt{17}, 2),
            "degree-2 recursive solution must satisfy exact NTRU relation");
}

void test_degree_two_against_independent_bruteforce_oracle() {
    struct Case {
        std::array<std::int64_t, 2> f;
        std::array<std::int64_t, 2> g;
    };

    const std::array<Case, 4> cases{{
        {{{1, 1}}, {{1, 2}}},
        {{{2, 1}}, {{1, 1}}},
        {{{3, -1}}, {{1, 2}}},
        {{{2, 3}}, {{1, -2}}},
    }};

    constexpr std::int64_t q = 17;
    constexpr std::int64_t search_bound = 12;

    for (const auto& c : cases) {
        const auto oracle = brute_force_degree_two(c.f, c.g, q, search_bound);
        require(oracle.has_value(),
                "independent degree-2 brute-force oracle must find a bounded solution");

        // Check the oracle with its own closed-form degree-2 equations so the
        // oracle is independent of both the recursive solver and ring helper.
        const std::int64_t constant =
            c.f[0] * oracle->G0 - c.f[1] * oracle->G1 -
            (c.g[0] * oracle->F0 - c.g[1] * oracle->F1);
        const std::int64_t linear =
            c.f[0] * oracle->G1 + c.f[1] * oracle->G0 -
            (c.g[0] * oracle->F1 + c.g[1] * oracle->F0);
        require(constant == q && linear == 0,
                "independent degree-2 oracle returned an invalid solution");

        NTRUEquationSolver solver(2, BigInt{q});
        const ZPoly f{c.f[0], c.f[1]};
        const ZPoly g{c.g[0], c.g[1]};
        const auto recursive = solver.solve(f, g);
        require(recursive.has_value(),
                "recursive solver must find a solution when the independent oracle does");
        require(verify_ntru_relation_exact(f, g, recursive->F, recursive->G,
                                           BigInt{q}, 2),
                "recursive solver solution must satisfy exact relation on oracle case");
    }
}

void test_recursive_solve_degree_eight_with_diagnostics() {
    NTRUEquationSolver solver(8, BigInt{17});
    const ZPoly f{1, 1, 0, 0, 0, 0, 0, 0};
    const ZPoly g{1, 2, 0, 0, 0, 0, 0, 0};

    NTRUSolverDiagnostics diagnostics;
    const auto solution = solver.solve(f, g, &diagnostics);
    require(solution.has_value(), "degree-8 recursive NTRUSolve must succeed on toy input");
    require(verify_ntru_relation_exact(f, g, solution->F, solution->G, BigInt{17}, 8),
            "degree-8 recursive solution must satisfy exact NTRU relation");

    require(diagnostics.levels.size() == 4,
            "degree-8 solve must record diagnostics for 8,4,2,1 recursion levels");
    const std::vector<std::size_t> expected_degrees{8, 4, 2, 1};
    for (std::size_t i = 0; i < expected_degrees.size(); ++i) {
        require(diagnostics.levels[i].degree == expected_degrees[i],
                "diagnostic recursion degree mismatch");
        require(diagnostics.levels[i].input_max_bits > 0,
                "diagnostics must record non-zero input coefficient bit length");
        require(diagnostics.levels[i].output_max_bits > 0,
                "diagnostics must record non-zero output coefficient bit length");
        if (expected_degrees[i] > 1) {
            require(diagnostics.levels[i].norm_max_bits > 0,
                    "non-base diagnostics must record field-norm coefficient bit length");
        }
    }
}

} // namespace

int main() {
    try {
        test_exact_negacyclic_multiplication();
        test_field_norm_identity();
        test_base_case_success_and_failure();
        test_recursive_solve_degree_two();
        test_degree_two_against_independent_bruteforce_oracle();
        test_recursive_solve_degree_eight_with_diagnostics();
        std::cout << "blindsig_blns7933_ntrusolve_tests: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "blindsig_blns7933_ntrusolve_tests: FAIL: " << e.what() << '\n';
        return 1;
    }
}
