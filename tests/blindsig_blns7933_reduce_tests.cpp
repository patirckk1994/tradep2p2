#include "tradep2p/blindsig_blns7933_integer_ring.hpp"
#include "tradep2p/blindsig_blns7933_ntrusolve.hpp"
#include "tradep2p/blindsig_blns7933_reduce.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>

namespace {

using tradep2p::blns7933::BigInt;
using tradep2p::blns7933::IntegerRingArithmetic;
using tradep2p::blns7933::NTRUBasisReducer;
using tradep2p::blns7933::NTRUEquationSolver;
using tradep2p::blns7933::NTRUReductionDiagnostics;
using tradep2p::blns7933::NTRUSolution;
using tradep2p::blns7933::ZPoly;
using tradep2p::blns7933::verify_ntru_relation_exact;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <typename ExceptionT, typename Fn>
void require_throws(Fn&& fn, const char* message) {
    try {
        fn();
    } catch (const ExceptionT&) {
        return;
    }
    throw std::runtime_error(message);
}

void test_reducer_shrinks_deliberately_bloated_solution() {
    constexpr std::size_t degree = 8;
    const BigInt q{17};
    const ZPoly f{1, 1, 0, 0, 0, 0, 0, 0};
    const ZPoly g{1, 2, 0, 0, 0, 0, 0, 0};

    NTRUEquationSolver solver(degree, q);
    const auto solved = solver.solve(f, g);
    require(solved.has_value(), "toy NTRUSolve must succeed before reducer test");

    IntegerRingArithmetic ring(degree);
    const ZPoly k{100, -75, 50, -25, 30, -20, 10, -5};

    NTRUSolution bloated = *solved;
    bloated.F = ring.add(bloated.F, ring.mul(k, f));
    bloated.G = ring.add(bloated.G, ring.mul(k, g));

    require(verify_ntru_relation_exact(f, g, bloated.F, bloated.G, q, degree),
            "adding k*(f,g) must preserve exact NTRU relation before reduction");

    const BigInt bloated_norm = NTRUBasisReducer::squared_norm(bloated.F, bloated.G);

    NTRUBasisReducer reducer(degree, q, 64);
    NTRUReductionDiagnostics diagnostics;
    const NTRUSolution reduced = reducer.reduce(f, g, bloated, &diagnostics);

    require(verify_ntru_relation_exact(f, g, reduced.F, reduced.G, q, degree),
            "reducer must preserve exact NTRU relation");
    require(NTRUBasisReducer::squared_norm(reduced.F, reduced.G) < bloated_norm,
            "reducer must strictly shrink deliberately bloated solution");
    require(diagnostics.accepted_steps > 0,
            "reducer diagnostics must record at least one accepted step");
    require(diagnostics.final_squared_norm < diagnostics.initial_squared_norm,
            "reducer diagnostics must show exact squared-norm decrease");
    require(diagnostics.final_squared_norm ==
                NTRUBasisReducer::squared_norm(reduced.F, reduced.G),
            "reducer final diagnostic norm must equal recomputed exact norm");
    require(diagnostics.converged,
            "toy exact coordinate descent should reach a no-change pass");
}

void test_reducer_rejects_invalid_relation() {
    constexpr std::size_t degree = 8;
    const BigInt q{17};
    const ZPoly f{1, 1, 0, 0, 0, 0, 0, 0};
    const ZPoly g{1, 2, 0, 0, 0, 0, 0, 0};

    NTRUSolution invalid;
    invalid.F = ZPoly(degree, BigInt{0});
    invalid.G = ZPoly(degree, BigInt{0});

    NTRUBasisReducer reducer(degree, q);
    require_throws<std::invalid_argument>(
        [&] { (void)reducer.reduce(f, g, invalid); },
        "reducer must reject an input that does not satisfy fG-gF=q");
}

void test_reducer_does_not_increase_already_valid_solution() {
    constexpr std::size_t degree = 8;
    const BigInt q{17};
    const ZPoly f{1, 1, 0, 0, 0, 0, 0, 0};
    const ZPoly g{1, 2, 0, 0, 0, 0, 0, 0};

    NTRUEquationSolver solver(degree, q);
    const auto solved = solver.solve(f, g);
    require(solved.has_value(), "toy NTRUSolve must succeed before reducer monotonicity test");

    const BigInt before = NTRUBasisReducer::squared_norm(solved->F, solved->G);
    NTRUBasisReducer reducer(degree, q);
    const NTRUSolution reduced = reducer.reduce(f, g, *solved);
    const BigInt after = NTRUBasisReducer::squared_norm(reduced.F, reduced.G);

    require(after <= before, "reducer must never increase exact squared norm");
    require(verify_ntru_relation_exact(f, g, reduced.F, reduced.G, q, degree),
            "reducer monotonicity test must preserve exact NTRU relation");
}

} // namespace

int main() {
    try {
        test_reducer_shrinks_deliberately_bloated_solution();
        test_reducer_rejects_invalid_relation();
        test_reducer_does_not_increase_already_valid_solution();
        std::cout << "blindsig_blns7933_reduce_tests: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "blindsig_blns7933_reduce_tests: FAIL: " << e.what() << '\n';
        return 1;
    }
}
