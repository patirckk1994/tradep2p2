#include "tradep2p/blindsig_blns7933_babai_reduce.hpp"
#include "tradep2p/blindsig_blns7933_ntrusolve.hpp"
#include "tradep2p/blindsig_blns7933_reduce.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using tradep2p::blns7933::BigInt;
using tradep2p::blns7933::NTRUBasisReducer;
using tradep2p::blns7933::NTRUEquationSolver;
using tradep2p::blns7933::NTRUGlobalBabaiReducer;
using tradep2p::blns7933::NTRUGlobalReductionDiagnostics;
using tradep2p::blns7933::NTRUReductionDiagnostics;
using tradep2p::blns7933::NTRUSolverDiagnostics;
using tradep2p::blns7933::NTRUSolution;
using tradep2p::blns7933::ZPoly;
using tradep2p::blns7933::bigint_bit_length;
using tradep2p::blns7933::max_coefficient_bit_length;
using tradep2p::blns7933::verify_ntru_relation_exact;

constexpr std::int64_t kQ = 7933;

struct Timing {
    double solve_ms{0.0};
    double coordinate_ms{0.0};
    double global_ms{0.0};
    double cleanup_ms{0.0};
};

double milliseconds(std::chrono::steady_clock::duration duration) {
    return std::chrono::duration<double, std::milli>(duration).count();
}

std::size_t max_bits(const NTRUSolution& solution) {
    return std::max(max_coefficient_bit_length(solution.F),
                    max_coefficient_bit_length(solution.G));
}

void require_relation(const ZPoly& f, const ZPoly& g,
                      const NTRUSolution& solution, const BigInt& q,
                      std::size_t degree, const char* stage) {
    if (!verify_ntru_relation_exact(f, g, solution.F, solution.G, q, degree)) {
        throw std::logic_error(std::string(stage) + " broke fG-gF=q");
    }
}

void print_solver_levels(const NTRUSolverDiagnostics& diagnostics) {
    std::cout << "    recursion levels:\n";
    std::cout << "      degree  input_bits  norm_bits  output_bits\n";
    for (const auto& level : diagnostics.levels) {
        std::cout << "      " << std::setw(6) << level.degree
                  << "  " << std::setw(10) << level.input_max_bits
                  << "  " << std::setw(9) << level.norm_max_bits
                  << "  " << std::setw(11) << level.output_max_bits << '\n';
    }
}

void run_case(std::size_t degree) {
    // Deterministic, sparse candidate used only for controlled scaling of the
    // solver/reducer machinery. It is intentionally not a stand-in for the
    // eventual BLNS23 TrapGen coefficient distribution.
    ZPoly f(degree, BigInt{0});
    ZPoly g(degree, BigInt{0});
    f[0] = 1;
    f[1] = 1;
    g[0] = 1;
    g[1] = 2;

    const BigInt q{kQ};
    NTRUEquationSolver solver(degree, q);
    NTRUSolverDiagnostics solver_diagnostics;

    const auto solve_start = std::chrono::steady_clock::now();
    const auto solution = solver.solve(f, g, &solver_diagnostics);
    const auto solve_end = std::chrono::steady_clock::now();

    if (!solution) {
        throw std::runtime_error(
            "deterministic scaling candidate was rejected by NTRUSolve at degree " +
            std::to_string(degree));
    }
    require_relation(f, g, *solution, q, degree, "solver");

    const BigInt raw_norm = NTRUBasisReducer::squared_norm(solution->F, solution->G);

    // Old exact coordinate-descent path: retained as the slow correctness
    // baseline, with the same 64-pass cap used in the previous diagnostics.
    NTRUBasisReducer coordinate_reducer(degree, q, 64U);
    NTRUReductionDiagnostics coordinate_diagnostics;
    const auto coordinate_start = std::chrono::steady_clock::now();
    const NTRUSolution coordinate =
        coordinate_reducer.reduce(f, g, *solution, &coordinate_diagnostics);
    const auto coordinate_end = std::chrono::steady_clock::now();
    require_relation(f, g, coordinate, q, degree, "coordinate reducer");
    const BigInt coordinate_norm =
        NTRUBasisReducer::squared_norm(coordinate.F, coordinate.G);
    if (coordinate_norm > raw_norm) {
        throw std::logic_error("coordinate baseline increased exact squared norm");
    }

    // New global high-precision projection.  It chooses a whole polynomial k
    // in one round, but all accepted updates are still checked with cpp_int.
    NTRUGlobalBabaiReducer global_reducer(degree, q, 8U);
    NTRUGlobalReductionDiagnostics global_diagnostics;
    const auto global_start = std::chrono::steady_clock::now();
    const NTRUSolution global =
        global_reducer.reduce(f, g, *solution, &global_diagnostics);
    const auto global_end = std::chrono::steady_clock::now();
    require_relation(f, g, global, q, degree, "global reducer");
    const BigInt global_norm = NTRUBasisReducer::squared_norm(global.F, global.G);
    if (global_norm > raw_norm) {
        throw std::logic_error("global reducer increased exact squared norm");
    }

    // Finish the global result with the exact coordinate reducer.  The number
    // of cleanup steps is a useful measurement of how close the global round
    // got to the exact local optimum.
    NTRUBasisReducer cleanup_reducer(degree, q, 64U);
    NTRUReductionDiagnostics cleanup_diagnostics;
    const auto cleanup_start = std::chrono::steady_clock::now();
    const NTRUSolution cleaned =
        cleanup_reducer.reduce(f, g, global, &cleanup_diagnostics);
    const auto cleanup_end = std::chrono::steady_clock::now();
    require_relation(f, g, cleaned, q, degree, "global-plus-cleanup reducer");
    const BigInt cleaned_norm = NTRUBasisReducer::squared_norm(cleaned.F, cleaned.G);
    if (cleaned_norm > global_norm) {
        throw std::logic_error("exact cleanup increased global reducer norm");
    }

    const Timing timing{
        milliseconds(solve_end - solve_start),
        milliseconds(coordinate_end - coordinate_start),
        milliseconds(global_end - global_start),
        milliseconds(cleanup_end - cleanup_start),
    };

    std::cout << "BLNS7933 scaling case d=" << degree << ", q=" << kQ << '\n';
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "  solver:                         " << timing.solve_ms << " ms\n";
    std::cout << "  raw max coefficient bits:       " << max_bits(*solution) << '\n';
    std::cout << "  raw squared-norm bits:          " << bigint_bit_length(raw_norm) << '\n';

    std::cout << "  exact coordinate baseline:      " << timing.coordinate_ms << " ms\n";
    std::cout << "    max coefficient bits:         " << max_bits(coordinate) << '\n';
    std::cout << "    squared-norm bits:            " << bigint_bit_length(coordinate_norm) << '\n';
    std::cout << "    passes:                       " << coordinate_diagnostics.passes << '\n';
    std::cout << "    accepted steps:               "
              << coordinate_diagnostics.accepted_steps << '\n';
    std::cout << "    converged:                    "
              << (coordinate_diagnostics.converged ? "yes" : "no") << '\n';

    std::cout << "  global Babai reference:         " << timing.global_ms << " ms\n";
    std::cout << "    max coefficient bits:         " << max_bits(global) << '\n';
    std::cout << "    squared-norm bits:            " << bigint_bit_length(global_norm) << '\n';
    std::cout << "    rounds attempted:             "
              << global_diagnostics.rounds_attempted << '\n';
    std::cout << "    accepted rounds:              "
              << global_diagnostics.accepted_rounds << '\n';
    std::cout << "    converged (rounded k = 0):    "
              << (global_diagnostics.converged ? "yes" : "no") << '\n';
    std::cout << "    stopped on non-decrease:      "
              << (global_diagnostics.stopped_on_non_decreasing_round ? "yes" : "no")
              << '\n';

    std::cout << "  exact cleanup after global:     " << timing.cleanup_ms << " ms\n";
    std::cout << "    max coefficient bits:         " << max_bits(cleaned) << '\n';
    std::cout << "    squared-norm bits:            " << bigint_bit_length(cleaned_norm) << '\n';
    std::cout << "    passes:                       " << cleanup_diagnostics.passes << '\n';
    std::cout << "    accepted steps:               "
              << cleanup_diagnostics.accepted_steps << '\n';
    std::cout << "    converged:                    "
              << (cleanup_diagnostics.converged ? "yes" : "no") << '\n';

    print_solver_levels(solver_diagnostics);
    std::cout << '\n';
}

} // namespace

int main() {
    try {
        // Deliberately capped at 64 for this development stage. d=128/256/512
        // remain separate checkpoints and cannot be reached accidentally by a
        // routine diagnostic invocation.
        for (const std::size_t degree : {16U, 32U, 64U}) {
            run_case(degree);
        }
        std::cout << "BLNS7933 scaling diagnostics: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "BLNS7933 scaling diagnostics: FAIL: " << e.what() << '\n';
        return 1;
    }
}
