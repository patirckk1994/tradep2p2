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
using tradep2p::blns7933::NTRUReductionDiagnostics;
using tradep2p::blns7933::NTRUSolverDiagnostics;
using tradep2p::blns7933::ZPoly;
using tradep2p::blns7933::bigint_bit_length;
using tradep2p::blns7933::max_coefficient_bit_length;
using tradep2p::blns7933::verify_ntru_relation_exact;

constexpr std::int64_t kQ = 7933;

struct Timing {
    double solve_ms{0.0};
    double reduce_ms{0.0};
};

double milliseconds(std::chrono::steady_clock::duration duration) {
    return std::chrono::duration<double, std::milli>(duration).count();
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
    // exact solver/reducer machinery. It is intentionally not a stand-in for
    // the eventual BLNS23 TrapGen coefficient distribution.
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
    if (!verify_ntru_relation_exact(f, g, solution->F, solution->G, q, degree)) {
        throw std::logic_error("scaling diagnostic solver result broke fG-gF=q");
    }

    const BigInt raw_norm = NTRUBasisReducer::squared_norm(solution->F, solution->G);
    const std::size_t raw_max_bits = std::max(
        max_coefficient_bit_length(solution->F),
        max_coefficient_bit_length(solution->G));

    NTRUBasisReducer reducer(degree, q, 64U);
    NTRUReductionDiagnostics reduction_diagnostics;
    const auto reduce_start = std::chrono::steady_clock::now();
    const auto reduced = reducer.reduce(f, g, *solution, &reduction_diagnostics);
    const auto reduce_end = std::chrono::steady_clock::now();

    if (!verify_ntru_relation_exact(f, g, reduced.F, reduced.G, q, degree)) {
        throw std::logic_error("scaling diagnostic reducer result broke fG-gF=q");
    }
    const BigInt reduced_norm = NTRUBasisReducer::squared_norm(reduced.F, reduced.G);
    if (reduced_norm > raw_norm) {
        throw std::logic_error("scaling diagnostic reducer increased exact squared norm");
    }

    const Timing timing{
        milliseconds(solve_end - solve_start),
        milliseconds(reduce_end - reduce_start),
    };

    std::cout << "BLNS7933 scaling case d=" << degree << ", q=" << kQ << '\n';
    std::cout << "  solver: " << std::fixed << std::setprecision(3)
              << timing.solve_ms << " ms\n";
    std::cout << "  reducer: " << timing.reduce_ms << " ms\n";
    std::cout << "  raw max coefficient bits:     " << raw_max_bits << '\n';
    std::cout << "  reduced max coefficient bits: "
              << std::max(max_coefficient_bit_length(reduced.F),
                          max_coefficient_bit_length(reduced.G)) << '\n';
    std::cout << "  raw squared-norm bits:        " << bigint_bit_length(raw_norm) << '\n';
    std::cout << "  reduced squared-norm bits:    " << bigint_bit_length(reduced_norm) << '\n';
    std::cout << "  reduction passes:             " << reduction_diagnostics.passes << '\n';
    std::cout << "  accepted reduction steps:     "
              << reduction_diagnostics.accepted_steps << '\n';
    std::cout << "  reducer converged:            "
              << (reduction_diagnostics.converged ? "yes" : "no") << '\n';
    print_solver_levels(solver_diagnostics);
    std::cout << '\n';
}

} // namespace

int main() {
    try {
        // Deliberately capped at 64 for this development stage. d=128/256/512
        // are separate checkpoints and should not be reached accidentally by
        // a routine diagnostic invocation.
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
