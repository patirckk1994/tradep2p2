#include "tradep2p/blindsig_blns7933_integer_ring.hpp"

#include <boost/multiprecision/integer.hpp>

#include <stdexcept>
#include <string>

namespace tradep2p::blns7933 {
namespace {

void require_size_at_most(const ZPoly& a, std::size_t degree, const char* what) {
    if (a.size() > degree) {
        throw std::invalid_argument(std::string(what) + " polynomial exceeds ring degree");
    }
}

} // namespace

bool is_power_of_two(std::size_t value) noexcept {
    return value != 0U && (value & (value - 1U)) == 0U;
}

std::size_t bigint_bit_length(const BigInt& value) {
    if (value == 0) {
        return 0U;
    }
    const BigInt magnitude = value < 0 ? -value : value;
    return static_cast<std::size_t>(boost::multiprecision::msb(magnitude)) + 1U;
}

std::size_t max_coefficient_bit_length(const ZPoly& poly) {
    std::size_t result = 0U;
    for (const auto& coefficient : poly) {
        const std::size_t bits = bigint_bit_length(coefficient);
        if (bits > result) {
            result = bits;
        }
    }
    return result;
}

IntegerRingArithmetic::IntegerRingArithmetic(std::size_t degree)
    : degree_(degree) {
    if (degree_ == 0U) {
        throw std::invalid_argument("BLNS7933 integer ring degree must be non-zero");
    }
}

ZPoly IntegerRingArithmetic::canonical_size(const ZPoly& a) const {
    require_size_at_most(a, degree_, "input");
    ZPoly out(degree_, BigInt{0});
    for (std::size_t i = 0; i < a.size(); ++i) {
        out[i] = a[i];
    }
    return out;
}

ZPoly IntegerRingArithmetic::add(const ZPoly& a, const ZPoly& b) const {
    const ZPoly aa = canonical_size(a);
    const ZPoly bb = canonical_size(b);
    ZPoly out(degree_, BigInt{0});
    for (std::size_t i = 0; i < degree_; ++i) {
        out[i] = aa[i] + bb[i];
    }
    return out;
}

ZPoly IntegerRingArithmetic::sub(const ZPoly& a, const ZPoly& b) const {
    const ZPoly aa = canonical_size(a);
    const ZPoly bb = canonical_size(b);
    ZPoly out(degree_, BigInt{0});
    for (std::size_t i = 0; i < degree_; ++i) {
        out[i] = aa[i] - bb[i];
    }
    return out;
}

ZPoly IntegerRingArithmetic::mul(const ZPoly& a, const ZPoly& b) const {
    const ZPoly aa = canonical_size(a);
    const ZPoly bb = canonical_size(b);
    ZPoly out(degree_, BigInt{0});

    // Deliberately O(n^2).  The solver's first implementation values exact,
    // inspectable arithmetic over asymptotic performance.
    for (std::size_t i = 0; i < degree_; ++i) {
        for (std::size_t j = 0; j < degree_; ++j) {
            const std::size_t k = i + j;
            const BigInt product = aa[i] * bb[j];
            if (k < degree_) {
                out[k] += product;
            } else {
                out[k - degree_] -= product; // x^degree == -1
            }
        }
    }
    return out;
}

ZPoly IntegerRingArithmetic::conjugate(const ZPoly& a) const {
    ZPoly out = canonical_size(a);
    for (std::size_t i = 1; i < degree_; i += 2U) {
        out[i] = -out[i];
    }
    return out;
}

ZPoly IntegerRingArithmetic::field_norm(const ZPoly& a) const {
    if (degree_ < 2U || !is_power_of_two(degree_)) {
        throw std::invalid_argument("field_norm requires a power-of-two degree >= 2");
    }

    const ZPoly aa = canonical_size(a);
    const ZPoly product = mul(aa, conjugate(aa));

    // f(x)f(-x) is invariant under x -> -x, so all odd coefficients must
    // vanish exactly.  Treat any violation as an implementation error rather
    // than silently discarding information.
    for (std::size_t i = 1; i < degree_; i += 2U) {
        if (product[i] != 0) {
            throw std::logic_error("field_norm produced a non-zero odd coefficient");
        }
    }

    const std::size_t half_degree = degree_ / 2U;
    ZPoly out(half_degree, BigInt{0});
    for (std::size_t i = 0; i < half_degree; ++i) {
        out[i] = product[2U * i];
    }
    return out;
}

ZPoly IntegerRingArithmetic::embed_half(const ZPoly& half) const {
    if (degree_ < 2U || !is_power_of_two(degree_)) {
        throw std::invalid_argument("embed_half requires a power-of-two degree >= 2");
    }
    const std::size_t half_degree = degree_ / 2U;
    if (half.size() > half_degree) {
        throw std::invalid_argument("half-size polynomial exceeds degree/2");
    }

    ZPoly out(degree_, BigInt{0});
    for (std::size_t i = 0; i < half.size(); ++i) {
        out[2U * i] = half[i];
    }
    return out;
}

bool IntegerRingArithmetic::equal(const ZPoly& a, const ZPoly& b) const {
    return canonical_size(a) == canonical_size(b);
}

} // namespace tradep2p::blns7933
