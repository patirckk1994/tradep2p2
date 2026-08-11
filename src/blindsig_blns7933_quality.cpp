#include "tradep2p/blindsig_blns7933_quality.hpp"

#include <boost/multiprecision/cpp_dec_float.hpp>

#include <stdexcept>
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

// Gaussian elimination with partial pivoting at 256-digit precision.
// `matrix` is square (degree x degree); solves matrix * x = rhs. Mirrors
// blindsig_blns7933_babai_reduce.cpp's solve_real_system(), duplicated
// rather than shared across translation units to keep each module
// independently readable/auditable - both are short and this project
// already accepts that tradeoff elsewhere (see e.g. dot_exact-style
// helpers).
std::vector<HighReal> solve_real_system(RealMatrix matrix, std::vector<HighReal> rhs) {
    const std::size_t n = rhs.size();
    for (std::size_t col = 0; col < n; ++col) {
        std::size_t pivot = col;
        HighReal best = real_abs(matrix[col][col]);
        for (std::size_t row = col + 1; row < n; ++row) {
            const HighReal candidate = real_abs(matrix[row][col]);
            if (candidate > best) {
                best = candidate;
                pivot = row;
            }
        }
        if (best == 0) {
            throw std::runtime_error(
                "BLNS7933 trapdoor-quality linear system is singular (f,g share a root - "
                "reject this candidate and resample)");
        }
        if (pivot != col) {
            std::swap(matrix[pivot], matrix[col]);
            std::swap(rhs[pivot], rhs[col]);
        }
        for (std::size_t row = col + 1; row < n; ++row) {
            const HighReal factor = matrix[row][col] / matrix[col][col];
            if (factor == 0) {
                continue;
            }
            for (std::size_t j = col; j < n; ++j) {
                matrix[row][j] -= factor * matrix[col][j];
            }
            rhs[row] -= factor * rhs[col];
        }
    }

    std::vector<HighReal> x(n);
    for (std::size_t i = n; i-- > 0;) {
        HighReal sum = rhs[i];
        for (std::size_t j = i + 1; j < n; ++j) {
            sum -= matrix[i][j] * x[j];
        }
        x[i] = sum / matrix[i][i];
    }
    return x;
}

// Column `col` of the (degree x degree) real matrix representing
// "multiply by poly" in Z[x]/(x^degree+1) - mirrors
// RingArithmetic::inverse()'s identical basis-vector construction for the
// modular case (blindsig_blns7933.cpp), reused here for the REAL case.
RealMatrix negacyclic_multiplication_matrix(const ZPoly& poly, std::size_t degree,
                                            const IntegerRingArithmetic& ring) {
    RealMatrix matrix(degree, std::vector<HighReal>(degree));
    for (std::size_t col = 0; col < degree; ++col) {
        ZPoly basis(degree, BigInt{0});
        basis[col] = 1;
        const ZPoly column = ring.mul(poly, basis);
        for (std::size_t row = 0; row < degree; ++row) {
            matrix[row][col] = to_high_real(column[row]);
        }
    }
    return matrix;
}

} // namespace

ZPoly hermitian_adjoint(const ZPoly& a, std::size_t degree) {
    if (a.size() != degree) {
        throw std::invalid_argument("hermitian_adjoint requires a canonically-sized polynomial");
    }
    ZPoly out(degree, BigInt{0});
    out[0] = a[0];
    for (std::size_t i = 1; i < degree; ++i) {
        out[degree - i] = -a[i];
    }
    return out;
}

TrapdoorQuality compute_trapdoor_quality(
    const ZPoly& f, const ZPoly& g, std::size_t degree, const BigInt& q) {
    IntegerRingArithmetic ring(degree);
    const ZPoly ff = ring.canonical_size(f);
    const ZPoly gg = ring.canonical_size(g);

    // ||(g,-f)|| via falcon.pdf (3.9)+(3.10): the coefficient-domain inner
    // product coincides with the plain Euclidean dot product, so this term
    // needs no transform at all - just sum of squared coefficients.
    BigInt sum_sq = 0;
    for (const auto& c : ff) {
        sum_sq += c * c;
    }
    for (const auto& c : gg) {
        sum_sq += c * c;
    }
    const HighReal direct_norm = sqrt(to_high_real(sum_sq));

    const ZPoly f_adj = hermitian_adjoint(ff, degree);
    const ZPoly g_adj = hermitian_adjoint(gg, degree);
    const ZPoly d_poly = ring.add(ring.mul(ff, f_adj), ring.mul(gg, g_adj));

    const RealMatrix matrix = negacyclic_multiplication_matrix(d_poly, degree, ring);

    std::vector<HighReal> rhs_f(degree);
    std::vector<HighReal> rhs_g(degree);
    for (std::size_t i = 0; i < degree; ++i) {
        rhs_f[i] = to_high_real(q * f_adj[i]);
        rhs_g[i] = to_high_real(q * g_adj[i]);
    }

    const auto e_f = solve_real_system(matrix, rhs_f);
    const auto e_g = solve_real_system(matrix, rhs_g);

    HighReal e_f_sq = 0;
    HighReal e_g_sq = 0;
    for (std::size_t i = 0; i < degree; ++i) {
        e_f_sq += e_f[i] * e_f[i];
        e_g_sq += e_g[i] * e_g[i];
    }
    const HighReal norm_ef = sqrt(e_f_sq);
    const HighReal norm_eg = sqrt(e_g_sq);

    HighReal gamma = direct_norm;
    if (norm_ef > gamma) {
        gamma = norm_ef;
    }
    if (norm_eg > gamma) {
        gamma = norm_eg;
    }

    const HighReal threshold = HighReal("1.17") * sqrt(to_high_real(q));

    TrapdoorQuality result;
    result.gs_norm = gamma.convert_to<long double>();
    result.threshold = threshold.convert_to<long double>();
    result.accepted = gamma <= threshold;
    return result;
}

} // namespace tradep2p::blns7933
