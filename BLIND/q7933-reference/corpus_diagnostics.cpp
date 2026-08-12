#include "tradep2p/blindsig_blns7933_babai_reduce.hpp"
#include "tradep2p/blindsig_blns7933_ntrusolve.hpp"
#include "tradep2p/blindsig_blns7933_reduce.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

using tradep2p::blns7933::BigInt;
using tradep2p::blns7933::NTRUBasisReducer;
using tradep2p::blns7933::NTRUEquationSolver;
using tradep2p::blns7933::NTRUGlobalBabaiReducer;
using tradep2p::blns7933::NTRUGlobalReductionDiagnostics;
using tradep2p::blns7933::NTRUReductionDiagnostics;
using tradep2p::blns7933::NTRUSolution;
using tradep2p::blns7933::ZPoly;
using tradep2p::blns7933::bigint_bit_length;
using tradep2p::blns7933::max_coefficient_bit_length;
using tradep2p::blns7933::verify_ntru_relation_exact;

constexpr std::int64_t kQ = 7933;

struct Candidate {
    ZPoly f;
    ZPoly g;
    std::string label;
};

std::uint64_t next_xorshift(std::uint64_t& state) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

BigInt sparse_small_coefficient(std::uint64_t& state) {
    const std::uint64_t r = next_xorshift(state) & 7U;
    if (r == 0U) {
        return BigInt{1};
    }
    if (r == 1U) {
        return BigInt{-1};
    }
    return BigInt{0};
}

Candidate make_seeded_candidate(std::size_t degree, std::uint64_t seed) {
    std::uint64_t state = seed;
    Candidate candidate{
        ZPoly(degree, BigInt{0}),
        ZPoly(degree, BigInt{0}),
        "seed=" + std::to_string(seed),
    };

    for (std::size_t i = 0; i < degree; ++i) {
        candidate.f[i] = sparse_small_coefficient(state);
        candidate.g[i] = sparse_small_coefficient(state);
    }

    // Keep the deterministic corpus away from the all-zero/obviously trivial
    // corner without attempting to force NTRUSolve acceptance. Rejection is
    // a legitimate diagnostic outcome and is printed as such.
    candidate.f[0] = 1;
    candidate.g[0] = 1;
    return candidate;
}

Candidate make_anchor_candidate(std::size_t degree) {
    Candidate candidate{
        ZPoly(degree, BigInt{0}),
        ZPoly(degree, BigInt{0}),
        "known-sparse-anchor",
    };
    candidate.f[0] = 1;
    candidate.f[1] = 1;
    candidate.g[0] = 1;
    candidate.g[1] = 2;
    return candidate;
}

std::size_t hamming_weight(const ZPoly& polynomial) {
    return static_cast<std::size_t>(std::count_if(
        polynomial.begin(), polynomial.end(),
        [](const BigInt& value) { return value != 0; }));
}

std::size_t max_bits(const NTRUSolution& solution) {
    return std::max(max_coefficient_bit_length(solution.F),
                    max_coefficient_bit_length(solution.G));
}

double milliseconds(std::chrono::steady_clock::duration duration) {
    return std::chrono::duration<double, std::milli>(duration).count();
}

void require_relation(const Candidate& candidate,
                      const NTRUSolution& solution,
                      const BigInt& q,
                      std::size_t degree,
                      const char* stage) {
    if (!verify_ntru_relation_exact(candidate.f, candidate.g,
                                    solution.F, solution.G, q, degree)) {
        throw std::logic_error(std::string(stage) + " broke fG-gF=q");
    }
}

bool run_candidate(std::size_t degree, const Candidate& candidate) {
    const BigInt q{kQ};
    NTRUEquationSolver solver(degree, q);

    const auto solve_start = std::chrono::steady_clock::now();
    const auto solved = solver.solve(candidate.f, candidate.g);
    const auto solve_end = std::chrono::steady_clock::now();

    std::cout << "  " << candidate.label
              << "  wt(f)=" << hamming_weight(candidate.f)
              << "  wt(g)=" << hamming_weight(candidate.g);

    if (!solved) {
        std::cout << "  REJECT"
                  << "  solve=" << std::fixed << std::setprecision(3)
                  << milliseconds(solve_end - solve_start) << " ms\n";
        return false;
    }

    require_relation(candidate, *solved, q, degree, "corpus solver");
    const BigInt raw_norm =
        NTRUBasisReducer::squared_norm(solved->F, solved->G);

    NTRUGlobalBabaiReducer global_reducer(degree, q, 8U);
    NTRUGlobalReductionDiagnostics global_diagnostics;
    const auto global_start = std::chrono::steady_clock::now();
    const NTRUSolution global = global_reducer.reduce(
        candidate.f, candidate.g, *solved, &global_diagnostics);
    const auto global_end = std::chrono::steady_clock::now();
    require_relation(candidate, global, q, degree, "corpus global reducer");

    const BigInt global_norm =
        NTRUBasisReducer::squared_norm(global.F, global.G);
    if (global_norm > raw_norm) {
        throw std::logic_error(
            "corpus global reducer increased exact squared norm");
    }

    NTRUBasisReducer cleanup_reducer(degree, q, 64U);
    NTRUReductionDiagnostics cleanup_diagnostics;
    const auto cleanup_start = std::chrono::steady_clock::now();
    const NTRUSolution cleaned = cleanup_reducer.reduce(
        candidate.f, candidate.g, global, &cleanup_diagnostics);
    const auto cleanup_end = std::chrono::steady_clock::now();
    require_relation(candidate, cleaned, q, degree, "corpus exact cleanup");

    const BigInt cleaned_norm =
        NTRUBasisReducer::squared_norm(cleaned.F, cleaned.G);
    if (cleaned_norm > global_norm) {
        throw std::logic_error(
            "corpus exact cleanup increased global squared norm");
    }

    std::cout << "  ACCEPT"
              << "  solve=" << std::fixed << std::setprecision(3)
              << milliseconds(solve_end - solve_start) << " ms"
              << "  raw_bits=" << max_bits(*solved)
              << "/" << bigint_bit_length(raw_norm)
              << "  global=" << milliseconds(global_end - global_start) << " ms"
              << "  rounds=" << global_diagnostics.accepted_rounds
              << "  global_bits=" << max_bits(global)
              << "/" << bigint_bit_length(global_norm)
              << "  cleanup=" << milliseconds(cleanup_end - cleanup_start) << " ms"
              << "  steps=" << cleanup_diagnostics.accepted_steps
              << "  final_bits=" << max_bits(cleaned)
              << "/" << bigint_bit_length(cleaned_norm)
              << "  cleanup_converged="
              << (cleanup_diagnostics.converged ? "yes" : "no")
              << '\n';
    return true;
}

void run_degree(std::size_t degree) {
    // Fixed seeds make this a reproducible corpus, not a random benchmark.
    constexpr std::array<std::uint64_t, 5> seeds{
        0x79330001ULL,
        0x79330002ULL,
        0x79330003ULL,
        0x79330004ULL,
        0x79330005ULL,
    };

    std::cout << "BLNS7933 deterministic corpus d=" << degree
              << ", q=" << kQ << '\n';

    std::size_t accepted = 0U;
    std::size_t attempted = 0U;

    ++attempted;
    accepted += run_candidate(degree, make_anchor_candidate(degree)) ? 1U : 0U;

    for (const std::uint64_t seed : seeds) {
        ++attempted;
        accepted += run_candidate(
            degree, make_seeded_candidate(degree, seed)) ? 1U : 0U;
    }

    std::cout << "  summary: accepted=" << accepted
              << " rejected=" << (attempted - accepted)
              << " attempted=" << attempted << "\n\n";
}

} // namespace

int main() {
    try {
        for (const std::size_t degree : {16U, 32U, 64U}) {
            run_degree(degree);
        }
        std::cout << "BLNS7933 deterministic corpus diagnostics: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "BLNS7933 deterministic corpus diagnostics: FAIL: "
                  << e.what() << '\n';
        return 1;
    }
}
