#include "tradep2p/blindsig_blns7933_babai_reduce.hpp"
#include "tradep2p/blindsig_blns7933_integer_ring.hpp"
#include "tradep2p/blindsig_blns7933_ntrusolve.hpp"
#include "tradep2p/blindsig_blns7933_reduce.hpp"

#include <iostream>
#include <stdexcept>

namespace {

using tradep2p::blns7933::BigInt;
using tradep2p::blns7933::IntegerRingArithmetic;
using tradep2p::blns7933::NTRUBasisReducer;
using tradep2p::blns7933::NTRUEquationSolver;
using tradep2p::blns7933::NTRUGlobalBabaiReducer;
using tradep2p::blns7933::NTRUGlobalReductionDiagnostics;
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

NTRUSolution make_bloated_solution(std::size_t degree, const BigInt& q,
                                   const ZPoly& f, const ZPoly& g) {
    NTRUEquationSolver solver(degree, q);
    const auto solved = solver.solve(f, g);
    require(solved.has_value(), "toy NTRUSolve must succeed before global reducer test");

    IntegerRingArithmetic ring(degree);
    ZPoly k(degree, BigInt{0});
    k[0] = 100;
    k[1] = -75;
    k[2] = 50;
    k[3] = -25;
    if (degree > 4U) {
        k[4] = 30;
        k[5] = -20;
        k[6] = 10;
        k[7] = -5;
    }

    NTRUSolution bloated = *solved;
    bloated.F = ring.add(bloated.F, ring.mul(k, f));
    bloated.G = ring.add(bloated.G, ring.mul(k, g));
    require(verify_ntru_relation_exact(f, g, bloated.F, bloated.G, q, degree),
            "deliberate global-reducer bloat must preserve fG-gF=q");
    return bloated;
}

void test_global_reducer_shrinks_bloated_solution() {
    constexpr std::size_t degree = 8;
    const BigInt q{17};
    const ZPoly f{1, 1, 0, 0, 0, 0, 0, 0};
    const ZPoly g{1, 2, 0, 0, 0, 0, 0, 0};
    const NTRUSolution bloated = make_bloated_solution(degree, q, f, g);

    const BigInt before = NTRUBasisReducer::squared_norm(bloated.F, bloated.G);
    NTRUGlobalBabaiReducer reducer(degree, q, 8U);
    NTRUGlobalReductionDiagnostics diagnostics;
    const NTRUSolution reduced = reducer.reduce(f, g, bloated, &diagnostics);
    const BigInt after = NTRUBasisReducer::squared_norm(reduced.F, reduced.G);

    require(after < before,
            "global reducer must strictly shrink deliberately bloated solution");
    require(diagnostics.accepted_rounds > 0,
            "global reducer must record at least one accepted round");
    require(diagnostics.final_squared_norm == after,
            "global reducer diagnostic final norm must match exact recomputation");
    require(diagnostics.final_squared_norm < diagnostics.initial_squared_norm,
            "global reducer diagnostics must show exact norm decrease");
    require(verify_ntru_relation_exact(f, g, reduced.F, reduced.G, q, degree),
            "global reducer must preserve exact NTRU relation");
}

void test_global_then_exact_cleanup_is_monotone() {
    constexpr std::size_t degree = 8;
    const BigInt q{17};
    const ZPoly f{1, 1, 0, 0, 0, 0, 0, 0};
    const ZPoly g{1, 2, 0, 0, 0, 0, 0, 0};
    const NTRUSolution bloated = make_bloated_solution(degree, q, f, g);

    NTRUGlobalBabaiReducer global(degree, q, 8U);
    const NTRUSolution globally_reduced = global.reduce(f, g, bloated);
    const BigInt global_norm =
        NTRUBasisReducer::squared_norm(globally_reduced.F, globally_reduced.G);

    NTRUBasisReducer cleanup(degree, q, 64U);
    const NTRUSolution final = cleanup.reduce(f, g, globally_reduced);
    const BigInt final_norm = NTRUBasisReducer::squared_norm(final.F, final.G);

    require(final_norm <= global_norm,
            "exact coordinate cleanup must not undo global reduction");
    require(verify_ntru_relation_exact(f, g, final.F, final.G, q, degree),
            "global-plus-cleanup reduction must preserve exact NTRU relation");
}

void test_global_reducer_rejects_invalid_relation() {
    constexpr std::size_t degree = 8;
    const BigInt q{17};
    const ZPoly f{1, 1, 0, 0, 0, 0, 0, 0};
    const ZPoly g{1, 2, 0, 0, 0, 0, 0, 0};
    NTRUSolution invalid{ZPoly(degree, BigInt{0}), ZPoly(degree, BigInt{0})};

    NTRUGlobalBabaiReducer reducer(degree, q);
    require_throws<std::invalid_argument>(
        [&] { (void)reducer.reduce(f, g, invalid); },
        "global reducer must reject input that does not satisfy fG-gF=q");
}

} // namespace

int main() {
    try {
        test_global_reducer_shrinks_bloated_solution();
        test_global_then_exact_cleanup_is_monotone();
        test_global_reducer_rejects_invalid_relation();
        std::cout << "blindsig_blns7933_babai_reduce_tests: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "blindsig_blns7933_babai_reduce_tests: FAIL: " << e.what() << '\n';
        return 1;
    }
}
