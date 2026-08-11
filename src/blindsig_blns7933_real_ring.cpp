#include "tradep2p/blindsig_blns7933_real_ring.hpp"

#include <stdexcept>
#include <utility>

namespace tradep2p::blns7933 {
namespace {

using RealMatrix = std::vector<std::vector<HighReal>>;

HighReal real_abs(const HighReal& value) {
    return value < 0 ? -value : value;
}

// Gaussian elimination with partial pivoting at 256-digit precision.
// Duplicated (not shared) across this reference substrate's modules that
// need it, matching the established precedent in
// blindsig_blns7933_quality.cpp: each module stays independently
// auditable rather than depending on a shared solver implementation.
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
                "BLNS7933 real-ring division is singular (divisor vanishes at some root)");
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

} // namespace

RealRingArithmetic::RealRingArithmetic(std::size_t degree) : degree_(degree) {
    if (degree_ == 0) {
        throw std::invalid_argument("BLNS7933 real ring degree must be non-zero");
    }
}

RealPoly RealRingArithmetic::canonical_size(const RealPoly& a) const {
    if (a.size() > degree_) {
        throw std::invalid_argument("real-ring input polynomial exceeds ring degree");
    }
    RealPoly out(degree_, HighReal(0));
    for (std::size_t i = 0; i < a.size(); ++i) {
        out[i] = a[i];
    }
    return out;
}

RealPoly RealRingArithmetic::add(const RealPoly& a, const RealPoly& b) const {
    const RealPoly aa = canonical_size(a);
    const RealPoly bb = canonical_size(b);
    RealPoly out(degree_);
    for (std::size_t i = 0; i < degree_; ++i) {
        out[i] = aa[i] + bb[i];
    }
    return out;
}

RealPoly RealRingArithmetic::sub(const RealPoly& a, const RealPoly& b) const {
    const RealPoly aa = canonical_size(a);
    const RealPoly bb = canonical_size(b);
    RealPoly out(degree_);
    for (std::size_t i = 0; i < degree_; ++i) {
        out[i] = aa[i] - bb[i];
    }
    return out;
}

RealPoly RealRingArithmetic::mul(const RealPoly& a, const RealPoly& b) const {
    const RealPoly aa = canonical_size(a);
    const RealPoly bb = canonical_size(b);
    RealPoly out(degree_, HighReal(0));

    // Deliberately O(d^2): transparent reference arithmetic, no NTT/FFT -
    // mirrors IntegerRingArithmetic::mul()'s identical structure and
    // identical reasoning, just over HighReal instead of modular int64_t.
    for (std::size_t i = 0; i < degree_; ++i) {
        if (aa[i] == 0) {
            continue;
        }
        for (std::size_t j = 0; j < degree_; ++j) {
            if (bb[j] == 0) {
                continue;
            }
            const HighReal product = aa[i] * bb[j];
            const std::size_t k = i + j;
            if (k < degree_) {
                out[k] += product;
            } else {
                out[k - degree_] -= product;
            }
        }
    }
    return out;
}

RealPoly RealRingArithmetic::hermitian_adjoint(const RealPoly& a) const {
    const RealPoly aa = canonical_size(a);
    RealPoly out(degree_, HighReal(0));
    out[0] = aa[0];
    for (std::size_t i = 1; i < degree_; ++i) {
        out[degree_ - i] = -aa[i];
    }
    return out;
}

RealPoly RealRingArithmetic::div(const RealPoly& a, const RealPoly& b) const {
    const RealPoly aa = canonical_size(a);
    const RealPoly bb = canonical_size(b);

    RealMatrix matrix(degree_, std::vector<HighReal>(degree_));
    for (std::size_t col = 0; col < degree_; ++col) {
        RealPoly basis(degree_, HighReal(0));
        basis[col] = HighReal(1);
        const RealPoly column = mul(bb, basis);
        for (std::size_t row = 0; row < degree_; ++row) {
            matrix[row][col] = column[row];
        }
    }

    return solve_real_system(std::move(matrix), aa);
}

std::pair<RealPoly, RealPoly> split(const RealPoly& f) {
    if (f.empty() || (f.size() % 2U) != 0U) {
        throw std::invalid_argument("split() requires a non-empty, even-length polynomial");
    }
    const std::size_t half = f.size() / 2U;
    RealPoly f0(half);
    RealPoly f1(half);
    for (std::size_t i = 0; i < half; ++i) {
        f0[i] = f[2U * i];
        f1[i] = f[2U * i + 1U];
    }
    return {std::move(f0), std::move(f1)};
}

RealPoly merge(const RealPoly& f0, const RealPoly& f1) {
    if (f0.size() != f1.size()) {
        throw std::invalid_argument("merge() requires f0 and f1 of equal size");
    }
    const std::size_t half = f0.size();
    RealPoly out(2U * half);
    for (std::size_t i = 0; i < half; ++i) {
        out[2U * i] = f0[i];
        out[2U * i + 1U] = f1[i];
    }
    return out;
}

} // namespace tradep2p::blns7933
