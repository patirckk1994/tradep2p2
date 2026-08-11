#include "tradep2p/blindsig_blns7933_integer_ring.hpp"
#include "tradep2p/blindsig_blns7933_ntrusolve.hpp"

#include <iostream>
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
    }
}

} // namespace

int main() {
    try {
        test_exact_negacyclic_multiplication();
        test_field_norm_identity();
        test_base_case_success_and_failure();
        test_recursive_solve_degree_two();
        test_recursive_solve_degree_eight_with_diagnostics();
        std::cout << "blindsig_blns7933_ntrusolve_tests: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "blindsig_blns7933_ntrusolve_tests: FAIL: " << e.what() << '\n';
        return 1;
    }
}
