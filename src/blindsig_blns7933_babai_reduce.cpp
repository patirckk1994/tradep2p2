#include "tradep2p/blindsig_blns7933_babai_reduce.hpp"

#include "tradep2p/blindsig_blns7933_reduce.hpp"

#include <boost/multiprecision/cpp_dec_float.hpp>

#include <algorithm>
#include <ios>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace tradep2p::blns7933 {
namespace {

using HighReal = boost::multiprecision::number<
    boost::multiprecision::cpp_dec_float<256>>;
using RealMatrix = std::vector<std::vector<HighReal>>;

HighReal to_high_real(const BigInt& value) {
    return HighReal(value.convert_to<std::string>());
}

HighReal real_abs(const HighReal& value) {
    return value < 0 ? -value : value;
}

BigInt round_to_bigint(const HighReal& value) {
    using boost::multiprecision::ceil;
    using boost::multiprecision::floor;

    const HighReal half("0.5");
    HighReal rounded;
    if (value >= 0) {
        rounded = floor(value + half);
    } else {
        rounded = ceil(value - half);
    }
    return BigInt(rounded.str(0, std::ios_base::fixed));
}

ZPoly negacyclic_shift(const ZPoly& a, std::size_t shift, std::size_t degree) {
    if (a.size() > degree) {
        throw std::invalid_argument("global reducer polynomial exceeds ring degree");
    }
    if (degree == 0U || shift >= degree) {
        throw std::invalid_argument("invalid global reducer negacyclic shift");
    }

    ZPoly out(degree, BigInt{0});
    for (std::size_t i = 0; i < a.size(); ++i) {
        const std::size_t k = i + shift;
        if (k < degree) {
            out[k] += a[i];
        } else {
            out[k - degree] -= a[i];
        }
    }
    return out;
}

BigInt dot_exact(const ZPoly& a, const ZPoly& b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("global reducer dot-product size mismatch");
    }
    BigInt result = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        result += a[i] * b[i];
    }
    return result;
}

BigInt pair_dot_exact(const ZPoly& a0, const ZPoly& a1,
                      const ZPoly& b0, const ZPoly& b1) {
    return dot_exact(a0, b0) + dot_exact(a1, b1);
}

std::vector<HighReal> solve_real_system(RealMatrix matrix,
                                        std::vector<HighReal> rhs) {
    const std::size_t n = matrix.size();
    if (rhs.size() != n) {
        throw std::invalid_argument("global reducer linear-system size mismatch");
    }
    for (const auto& row : matrix) {
        if (row.size() != n) {
            throw std::invalid_argument("global reducer Gram matrix is not square");
        }
    }

    for (std::size_t col = 0; col < n; ++col) {
        std::size_t pivot = col;
        HighReal pivot_abs = real_abs(matrix[col][col]);
        for (std::size_t row = col + 1; row < n; ++row) {
            const HighReal candidate_abs = real_abs(matrix[row][col]);
            if (candidate_abs > pivot_abs) {
                pivot = row;
                pivot_abs = candidate_abs;
            }
        }
        if (pivot_abs == 0) {
            throw std::logic_error("global reducer Gram matrix is singular");
        }
        if (pivot != col) {
            std::swap(matrix[pivot], matrix[col]);
            std::swap(rhs[pivot], rhs[col]);
        }

        const HighReal pivot_value = matrix[col][col];
        for (std::size_t row = col + 1; row < n; ++row) {
            if (matrix[row][col] == 0) {
                continue;
            }
            const HighReal factor = matrix[row][col] / pivot_value;
            matrix[row][col] = 0;
            for (std::size_t j = col + 1; j < n; ++j) {
                matrix[row][j] -= factor * matrix[col][j];
            }
            rhs[row] -= factor * rhs[col];
        }
    }

    std::vector<HighReal> solution(n, HighReal{0});
    for (std::size_t ii = n; ii-- > 0;) {
        HighReal value = rhs[ii];
        for (std::size_t j = ii + 1; j < n; ++j) {
            value -= matrix[ii][j] * solution[j];
        }
        if (matrix[ii][ii] == 0) {
            throw std::logic_error("global reducer encountered zero back-substitution pivot");
        }
        solution[ii] = value / matrix[ii][ii];
    }
    return solution;
}

bool all_zero(const ZPoly& polynomial) {
    return std::all_of(polynomial.begin(), polynomial.end(),
                       [](const BigInt& value) { return value == 0; });
}

} // namespace

NTRUGlobalBabaiReducer::NTRUGlobalBabaiReducer(std::size_t degree, BigInt q,
                                               std::size_t max_rounds)
    : degree_(degree), q_(std::move(q)), max_rounds_(max_rounds) {
    if (!is_power_of_two(degree_)) {
        throw std::invalid_argument(
            "global NTRU reducer degree must be a non-zero power of two");
    }
    if (q_ <= 0) {
        throw std::invalid_argument("global NTRU reducer q must be positive");
    }
    if (max_rounds_ == 0U) {
        throw std::invalid_argument("global NTRU reducer max_rounds must be non-zero");
    }
}

NTRUSolution NTRUGlobalBabaiReducer::reduce(
    const ZPoly& f, const ZPoly& g, const NTRUSolution& input,
    NTRUGlobalReductionDiagnostics* diagnostics) const {
    IntegerRingArithmetic ring(degree_);
    const ZPoly ff = ring.canonical_size(f);
    const ZPoly gg = ring.canonical_size(g);

    NTRUSolution out{
        ring.canonical_size(input.F),
        ring.canonical_size(input.G),
    };

    if (!verify_ntru_relation_exact(ff, gg, out.F, out.G, q_, degree_)) {
        throw std::invalid_argument(
            "global NTRU reducer input does not satisfy fG-gF=q");
    }

    if (diagnostics != nullptr) {
        *diagnostics = NTRUGlobalReductionDiagnostics{};
        diagnostics->initial_squared_norm =
            NTRUBasisReducer::squared_norm(out.F, out.G);
        diagnostics->initial_max_bits =
            std::max(max_coefficient_bit_length(out.F),
                     max_coefficient_bit_length(out.G));
    }

    // Build the full negacyclic shift basis once. The exact Gram matrix is
    // constant across all reduction rounds; only the projection RHS changes.
    std::vector<ZPoly> shifted_f;
    std::vector<ZPoly> shifted_g;
    shifted_f.reserve(degree_);
    shifted_g.reserve(degree_);
    for (std::size_t shift = 0; shift < degree_; ++shift) {
        shifted_f.push_back(negacyclic_shift(ff, shift, degree_));
        shifted_g.push_back(negacyclic_shift(gg, shift, degree_));
    }

    RealMatrix gram(degree_, std::vector<HighReal>(degree_, HighReal{0}));
    for (std::size_t i = 0; i < degree_; ++i) {
        for (std::size_t j = i; j < degree_; ++j) {
            const BigInt exact = pair_dot_exact(
                shifted_f[i], shifted_g[i], shifted_f[j], shifted_g[j]);
            const HighReal value = to_high_real(exact);
            gram[i][j] = value;
            gram[j][i] = value;
        }
    }

    bool converged = false;
    bool stopped_non_decreasing = false;
    std::size_t rounds_attempted = 0U;
    std::size_t accepted_rounds = 0U;

    for (; rounds_attempted < max_rounds_; ++rounds_attempted) {
        std::vector<HighReal> rhs(degree_, HighReal{0});
        for (std::size_t i = 0; i < degree_; ++i) {
            rhs[i] = to_high_real(pair_dot_exact(
                shifted_f[i], shifted_g[i], out.F, out.G));
        }

        const std::vector<HighReal> projected = solve_real_system(gram, rhs);
        ZPoly k(degree_, BigInt{0});
        for (std::size_t i = 0; i < degree_; ++i) {
            k[i] = round_to_bigint(projected[i]);
        }

        if (all_zero(k)) {
            converged = true;
            ++rounds_attempted;
            break;
        }

        const BigInt before = NTRUBasisReducer::squared_norm(out.F, out.G);
        NTRUSolution candidate{
            ring.sub(out.F, ring.mul(k, ff)),
            ring.sub(out.G, ring.mul(k, gg)),
        };

        if (!verify_ntru_relation_exact(
                ff, gg, candidate.F, candidate.G, q_, degree_)) {
            throw std::logic_error(
                "global NTRU reducer changed the exact NTRU relation");
        }

        const BigInt after =
            NTRUBasisReducer::squared_norm(candidate.F, candidate.G);
        if (after >= before) {
            stopped_non_decreasing = true;
            ++rounds_attempted;
            break;
        }

        out = std::move(candidate);
        ++accepted_rounds;
    }

    if (!verify_ntru_relation_exact(ff, gg, out.F, out.G, q_, degree_)) {
        throw std::logic_error(
            "global NTRU reducer final exact relation check failed");
    }

    if (diagnostics != nullptr) {
        diagnostics->rounds_attempted = rounds_attempted;
        diagnostics->accepted_rounds = accepted_rounds;
        diagnostics->final_squared_norm =
            NTRUBasisReducer::squared_norm(out.F, out.G);
        diagnostics->final_max_bits =
            std::max(max_coefficient_bit_length(out.F),
                     max_coefficient_bit_length(out.G));
        diagnostics->converged = converged;
        diagnostics->stopped_on_non_decreasing_round = stopped_non_decreasing;
    }

    return out;
}

} // namespace tradep2p::blns7933
