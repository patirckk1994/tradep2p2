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

constexpr std::size_t kDegree = 128U;
constexpr std::int64_t kQ = 7933;

double milliseconds(std::chrono::steady_clock::duration duration) {
    return std::chrono::duration<double, std::milli>(duration).count();
}

std::size_t max_bits(const NTRUSolution& solution) {
    return std::max(max_coefficient_bit_length(solution.F),
                    max_coefficient_bit_length(solution.G));
}

void require_relation(const ZPoly& f, const ZPoly& g,
                      const NTRUSolution& solution, const BigInt& q,
                      const char* stage) {
    if (!verify_ntru_relation_exact(
            f, g, solution.F, solution.G, q, kDegree)) {
        throw std::logic_error(std::string(stage) + " broke fG-gF=q");
    }
}

} // namespace

int main() {
    try {
        ZPoly f(kDegree, BigInt{0});
        ZPoly g(kDegree, BigInt{0});
        f[0] = 1;
        f[1] = 1;
        g[0] = 1;
        g[1] = 2;

        const BigInt q{kQ};
        NTRUEquationSolver solver(kDegree, q);
        NTRUSolverDiagnostics solver_diagnostics;

        const auto solve_start = std::chrono::steady_clock::now();
        const auto solved = solver.solve(f, g, &solver_diagnostics);
        const auto solve_end = std::chrono::steady_clock::now();
        if (!solved) {
            throw std::runtime_error(
                "deterministic d=128 candidate was rejected by NTRUSolve");
        }
        require_relation(f, g, *solved, q, "d=128 solver");

        const BigInt raw_norm =
            NTRUBasisReducer::squared_norm(solved->F, solved->G);

        NTRUGlobalBabaiReducer global_reducer(kDegree, q, 8U);
        NTRUGlobalReductionDiagnostics global_diagnostics;
        const auto global_start = std::chrono::steady_clock::now();
        const NTRUSolution global =
            global_reducer.reduce(f, g, *solved, &global_diagnostics);
        const auto global_end = std::chrono::steady_clock::now();
        require_relation(f, g, global, q, "d=128 global reducer");

        const BigInt global_norm =
            NTRUBasisReducer::squared_norm(global.F, global.G);
        if (global_norm > raw_norm) {
            throw std::logic_error(
                "d=128 global reducer increased exact squared norm");
        }

        NTRUBasisReducer cleanup_reducer(kDegree, q, 64U);
        NTRUReductionDiagnostics cleanup_diagnostics;
        const auto cleanup_start = std::chrono::steady_clock::now();
        const NTRUSolution cleaned =
            cleanup_reducer.reduce(f, g, global, &cleanup_diagnostics);
        const auto cleanup_end = std::chrono::steady_clock::now();
        require_relation(f, g, cleaned, q, "d=128 exact cleanup");

        const BigInt cleaned_norm =
            NTRUBasisReducer::squared_norm(cleaned.F, cleaned.G);
        if (cleaned_norm > global_norm) {
            throw std::logic_error(
                "d=128 exact cleanup increased global squared norm");
        }

        std::cout << std::fixed << std::setprecision(3);
        std::cout << "BLNS7933 explicit d=128 gate, q=" << kQ << '\n';
        std::cout << "  solver:                      "
                  << milliseconds(solve_end - solve_start) << " ms\n";
        std::cout << "  raw max coefficient bits:    " << max_bits(*solved) << '\n';
        std::cout << "  raw squared-norm bits:       "
                  << bigint_bit_length(raw_norm) << '\n';
        std::cout << "  global Babai:                "
                  << milliseconds(global_end - global_start) << " ms\n";
        std::cout << "    max coefficient bits:      " << max_bits(global) << '\n';
        std::cout << "    squared-norm bits:         "
                  << bigint_bit_length(global_norm) << '\n';
        std::cout << "    rounds attempted:          "
                  << global_diagnostics.rounds_attempted << '\n';
        std::cout << "    accepted rounds:           "
                  << global_diagnostics.accepted_rounds << '\n';
        std::cout << "    converged:                 "
                  << (global_diagnostics.converged ? "yes" : "no") << '\n';
        std::cout << "    stopped on non-decrease:   "
                  << (global_diagnostics.stopped_on_non_decreasing_round
                          ? "yes" : "no") << '\n';
        std::cout << "  exact cleanup:               "
                  << milliseconds(cleanup_end - cleanup_start) << " ms\n";
        std::cout << "    max coefficient bits:      " << max_bits(cleaned) << '\n';
        std::cout << "    squared-norm bits:         "
                  << bigint_bit_length(cleaned_norm) << '\n';
        std::cout << "    passes:                    "
                  << cleanup_diagnostics.passes << '\n';
        std::cout << "    accepted steps:            "
                  << cleanup_diagnostics.accepted_steps << '\n';
        std::cout << "    converged:                 "
                  << (cleanup_diagnostics.converged ? "yes" : "no") << '\n';

        std::cout << "  recursion levels:\n";
        std::cout << "    degree  input_bits  norm_bits  output_bits\n";
        for (const auto& level : solver_diagnostics.levels) {
            std::cout << "    " << std::setw(6) << level.degree
                      << "  " << std::setw(10) << level.input_max_bits
                      << "  " << std::setw(9) << level.norm_max_bits
                      << "  " << std::setw(11) << level.output_max_bits
                      << '\n';
        }

        std::cout << "BLNS7933 d=128 diagnostic: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "BLNS7933 d=128 diagnostic: FAIL: " << e.what() << '\n';
        return 1;
    }
}
