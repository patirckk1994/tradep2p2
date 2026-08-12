#include "tradep2p/blindsig_blns7933.hpp"

#include "tradep2p/blindsig_blns7933_babai_reduce.hpp"
#include "tradep2p/blindsig_blns7933_gaussian.hpp"
#include "tradep2p/blindsig_blns7933_ntrusolve.hpp"
#include "tradep2p/blindsig_blns7933_quality.hpp"
#include "tradep2p/blindsig_blns7933_reduce.hpp"

#include <algorithm>
#include <cmath>
#include <utility>

namespace tradep2p::blns7933 {
namespace {

std::int64_t scalar_mod(std::int64_t x, std::int64_t q) noexcept {
    x %= q;
    if (x < 0) {
        x += q;
    }
    return x;
}

std::optional<std::int64_t> scalar_inverse(std::int64_t a, std::int64_t q) {
    a = scalar_mod(a, q);
    std::int64_t t = 0;
    std::int64_t new_t = 1;
    std::int64_t r = q;
    std::int64_t new_r = a;

    while (new_r != 0) {
        const std::int64_t quotient = r / new_r;
        const std::int64_t next_t = t - quotient * new_t;
        t = new_t;
        new_t = next_t;
        const std::int64_t next_r = r - quotient * new_r;
        r = new_r;
        new_r = next_r;
    }
    if (r != 1) {
        return std::nullopt;
    }
    return scalar_mod(t, q);
}

void require_size_at_most(const PolyQ& a, std::size_t degree, const char* what) {
    if (a.size() > degree) {
        throw std::invalid_argument(std::string(what) + " polynomial exceeds ring degree");
    }
}

ZPoly to_zpoly(const std::vector<std::int64_t>& input) {
    ZPoly out;
    out.reserve(input.size());
    for (const auto coefficient : input) {
        out.emplace_back(coefficient);
    }
    return out;
}

} // namespace

RingArithmetic::RingArithmetic(std::size_t degree, std::int64_t modulus)
    : degree_(degree), modulus_(modulus) {
    if (degree_ == 0) {
        throw std::invalid_argument("BLNS7933 ring degree must be non-zero");
    }
    if (modulus_ <= 2) {
        throw std::invalid_argument("BLNS7933 modulus must be greater than two");
    }
}

std::int64_t RingArithmetic::mod(std::int64_t x) const noexcept {
    return scalar_mod(x, modulus_);
}

PolyQ RingArithmetic::canonicalize(const PolyQ& a) const {
    require_size_at_most(a, degree_, "input");
    PolyQ out(degree_, 0);
    for (std::size_t i = 0; i < a.size(); ++i) {
        out[i] = mod(a[i]);
    }
    return out;
}

PolyQ RingArithmetic::add(const PolyQ& a, const PolyQ& b) const {
    const PolyQ aa = canonicalize(a);
    const PolyQ bb = canonicalize(b);
    PolyQ out(degree_, 0);
    for (std::size_t i = 0; i < degree_; ++i) {
        out[i] = mod(aa[i] + bb[i]);
    }
    return out;
}

PolyQ RingArithmetic::sub(const PolyQ& a, const PolyQ& b) const {
    const PolyQ aa = canonicalize(a);
    const PolyQ bb = canonicalize(b);
    PolyQ out(degree_, 0);
    for (std::size_t i = 0; i < degree_; ++i) {
        out[i] = mod(aa[i] - bb[i]);
    }
    return out;
}

PolyQ RingArithmetic::mul(const PolyQ& a, const PolyQ& b) const {
    const PolyQ aa = canonicalize(a);
    const PolyQ bb = canonicalize(b);
    PolyQ out(degree_, 0);

    // Deliberately O(d^2): transparent reference arithmetic with no NTT.
    for (std::size_t i = 0; i < degree_; ++i) {
        for (std::size_t j = 0; j < degree_; ++j) {
            const std::size_t k = i + j;
            const std::int64_t product = aa[i] * bb[j];
            if (k < degree_) {
                out[k] = mod(out[k] + product);
            } else {
                out[k - degree_] = mod(out[k - degree_] - product);
            }
        }
    }
    return out;
}

std::optional<PolyQ> RingArithmetic::inverse(const PolyQ& a) const {
    const PolyQ aa = canonicalize(a);

    // Reference implementation by explicit linear algebra. Multiplication by
    // `a` in R_q is a dxd negacyclic matrix M. Solve M*x = 1 with modular
    // Gaussian elimination. O(d^3) is intentionally accepted here: this is
    // the slow correctness oracle, not the eventual signing hot path.
    std::vector<std::vector<std::int64_t>> aug(
        degree_, std::vector<std::int64_t>(degree_ + 1U, 0));

    for (std::size_t col = 0; col < degree_; ++col) {
        PolyQ basis(degree_, 0);
        basis[col] = 1;
        const PolyQ image = mul(aa, basis);
        for (std::size_t row = 0; row < degree_; ++row) {
            aug[row][col] = image[row];
        }
    }
    aug[0][degree_] = 1;

    for (std::size_t col = 0; col < degree_; ++col) {
        std::size_t pivot = col;
        while (pivot < degree_ && aug[pivot][col] == 0) {
            ++pivot;
        }
        if (pivot == degree_) {
            return std::nullopt;
        }
        if (pivot != col) {
            std::swap(aug[pivot], aug[col]);
        }

        const auto inv_pivot = scalar_inverse(aug[col][col], modulus_);
        if (!inv_pivot) {
            return std::nullopt;
        }
        for (std::size_t j = col; j <= degree_; ++j) {
            aug[col][j] = mod(aug[col][j] * *inv_pivot);
        }

        for (std::size_t row = 0; row < degree_; ++row) {
            if (row == col) {
                continue;
            }
            const std::int64_t factor = aug[row][col];
            if (factor == 0) {
                continue;
            }
            for (std::size_t j = col; j <= degree_; ++j) {
                aug[row][j] = mod(aug[row][j] - factor * aug[col][j]);
            }
        }
    }

    PolyQ result(degree_, 0);
    for (std::size_t i = 0; i < degree_; ++i) {
        result[i] = aug[i][degree_];
    }

    PolyQ one(degree_, 0);
    one[0] = 1;
    if (!equal(mul(aa, result), one)) {
        throw std::logic_error("BLNS7933 reference inversion self-check failed");
    }
    return result;
}

bool RingArithmetic::equal(const PolyQ& a, const PolyQ& b) const {
    return canonicalize(a) == canonicalize(b);
}

NTRUTrapdoorGenerator::NTRUTrapdoorGenerator(RingArithmetic ring)
    : ring_(std::move(ring)) {}

TrapdoorKey NTRUTrapdoorGenerator::generate(CryptoRng& rng) const {
    const std::size_t degree = ring_.degree();
    const BigInt q{ring_.modulus()};
    // sigma_{f,g} = 1.17*sqrt(q/2n), falcon.pdf eq. (3.27) - chosen so
    // E[||(f,g)||] = 1.17*sqrt(q), the same constant the quality bound
    // below compares gamma against.
    const long double sigma_fg =
        1.17L * std::sqrt(static_cast<long double>(ring_.modulus()) /
                          (2.0L * static_cast<long double>(degree)));

    const NTRUEquationSolver solver(degree, q);
    const NTRUGlobalBabaiReducer global_reducer(degree, q);
    const NTRUBasisReducer cleanup_reducer(degree, q);

    for (;;) {
        const std::vector<std::int64_t> f_raw =
            sample_discrete_gaussian_poly(degree, sigma_fg, rng);
        const std::vector<std::int64_t> g_raw =
            sample_discrete_gaussian_poly(degree, sigma_fg, rng);

        // Check g invertible mod q FIRST (cheap relative to the quality
        // bound below) - this type's t=f*g^-1 orientation needs g
        // invertible, the mirror image of FALCON's own h=g*f^-1
        // convention checking f instead (falcon.pdf Algorithm 5 line 7).
        if (!ring_.inverse(g_raw).has_value()) {
            continue;
        }

        ZPoly f_big = to_zpoly(f_raw);
        ZPoly g_big = to_zpoly(g_raw);

        // Quality bound: gamma <= 1.17*sqrt(q) (falcon.pdf Algorithm 5
        // lines 9-11). A singular quality system (f,g sharing a root) is
        // treated as a rejection, not a hard failure - see
        // compute_trapdoor_quality()'s own header comment.
        bool quality_singular = false;
        bool quality_accepted = false;
        try {
            quality_accepted = compute_trapdoor_quality(f_big, g_big, degree, q).accepted;
        } catch (const std::runtime_error&) {
            quality_singular = true;
        }
        if (quality_singular || !quality_accepted) {
            continue;
        }

        // Solve fG - gF = q. NTRUEquationSolver already applies FALCON's
        // own coprime-resultant rejection at the deepest recursion level
        // (blindsig_blns7933_ntrusolve.cpp) - a std::nullopt here is a
        // legitimate candidate rejection, not an error.
        const auto solved = solver.solve(f_big, g_big);
        if (!solved) {
            continue;
        }

        // Reduce (F,G): global high-precision Babai round(s), then exact
        // coordinate cleanup as a backstop - the identical two-stage
        // pipeline already validated at d=128/256/512 by this project's
        // own scaling diagnostics, not a new reduction strategy invented
        // here.
        const NTRUSolution globally_reduced = global_reducer.reduce(f_big, g_big, *solved);
        const NTRUSolution cleaned = cleanup_reducer.reduce(f_big, g_big, globally_reduced);

        TrapdoorKey key;
        key.f = f_raw;
        key.g = g_raw;
        key.F.reserve(degree);
        key.G.reserve(degree);
        for (const auto& coefficient : cleaned.F) {
            key.F.push_back(static_cast<std::int64_t>(coefficient));
        }
        for (const auto& coefficient : cleaned.G) {
            key.G.push_back(static_cast<std::int64_t>(coefficient));
        }

        // Never return an unverified trapdoor - re-check the exact
        // relation one final time on the values actually being returned,
        // independent of whatever checks ran inside the solver/reducers.
        if (!verify_ntru_relation(key)) {
            throw std::logic_error(
                "BLNS7933 TrapGen produced a candidate failing its own final relation check "
                "- this should never happen, investigate");
        }
        return key;
    }
}

PublicKey NTRUTrapdoorGenerator::derive_public(const TrapdoorKey& key) const {
    if (key.f.size() > ring_.degree() || key.g.size() > ring_.degree()) {
        throw std::invalid_argument("BLNS7933 trapdoor polynomial exceeds ring degree");
    }
    const auto g_inv = ring_.inverse(key.g);
    if (!g_inv) {
        throw std::runtime_error("BLNS7933 trapdoor g is not invertible modulo q");
    }
    return PublicKey{ring_.mul(key.f, *g_inv)};
}

bool NTRUTrapdoorGenerator::verify_ntru_relation(const TrapdoorKey& key) const {
    return verify_ntru_relation_exact(
        to_zpoly(key.f), to_zpoly(key.g), to_zpoly(key.F), to_zpoly(key.G),
        BigInt{ring_.modulus()}, ring_.degree());
}

} // namespace tradep2p::blns7933
