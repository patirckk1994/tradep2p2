#include "tradep2p/blindsig_blns7933_reduce.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace tradep2p::blns7933 {
namespace {

ZPoly negacyclic_shift(const ZPoly& a, std::size_t shift, std::size_t degree) {
    if (a.size() > degree) {
        throw std::invalid_argument("reducer polynomial exceeds ring degree");
    }
    if (degree == 0U || shift >= degree) {
        throw std::invalid_argument("invalid reducer negacyclic shift");
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

BigInt dot(const ZPoly& a, const ZPoly& b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("reducer dot-product size mismatch");
    }
    BigInt out = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        out += a[i] * b[i];
    }
    return out;
}

BigInt pair_dot(const ZPoly& F, const ZPoly& G,
                const ZPoly& sf, const ZPoly& sg) {
    return dot(F, sf) + dot(G, sg);
}

BigInt pair_squared_norm(const ZPoly& a, const ZPoly& b) {
    return dot(a, a) + dot(b, b);
}

void add_scaled_in_place(ZPoly& dst, const ZPoly& src, const BigInt& scale) {
    if (dst.size() != src.size()) {
        throw std::invalid_argument("reducer scaled-add size mismatch");
    }
    for (std::size_t i = 0; i < dst.size(); ++i) {
        dst[i] += scale * src[i];
    }
}

BigInt exact_delta(const BigInt& c, const BigInt& linear,
                   const BigInt& quadratic) {
    // ||v + c*w||^2 - ||v||^2 = 2*c*<v,w> + c^2*||w||^2.
    return BigInt{2} * c * linear + c * c * quadratic;
}

BigInt best_integer_coordinate(const BigInt& linear, const BigInt& quadratic) {
    if (quadratic <= 0) {
        throw std::logic_error("reducer encountered non-positive coordinate norm");
    }

    // The real minimizer is -linear/quadratic.  cpp_int division truncates
    // toward zero, so the nearest integer minimizer must be one of q-1,q,q+1.
    const BigInt q = (-linear) / quadratic;
    BigInt best = q;
    BigInt best_delta = exact_delta(best, linear, quadratic);

    for (const BigInt candidate : {q - 1, q + 1}) {
        const BigInt delta = exact_delta(candidate, linear, quadratic);
        if (delta < best_delta || (delta == best_delta && candidate < best)) {
            best = candidate;
            best_delta = delta;
        }
    }
    return best;
}

} // namespace

NTRUBasisReducer::NTRUBasisReducer(std::size_t degree, BigInt q,
                                   std::size_t max_passes)
    : degree_(degree), q_(std::move(q)), max_passes_(max_passes) {
    if (!is_power_of_two(degree_)) {
        throw std::invalid_argument("NTRU reducer degree must be a non-zero power of two");
    }
    if (q_ <= 0) {
        throw std::invalid_argument("NTRU reducer q must be positive");
    }
    if (max_passes_ == 0U) {
        throw std::invalid_argument("NTRU reducer max_passes must be non-zero");
    }
}

BigInt NTRUBasisReducer::squared_norm(const ZPoly& F, const ZPoly& G) {
    if (F.size() != G.size()) {
        throw std::invalid_argument("NTRU reducer norm size mismatch");
    }
    return pair_squared_norm(F, G);
}

NTRUSolution NTRUBasisReducer::reduce(
    const ZPoly& f, const ZPoly& g, const NTRUSolution& input,
    NTRUReductionDiagnostics* diagnostics) const {
    IntegerRingArithmetic ring(degree_);
    const ZPoly ff = ring.canonical_size(f);
    const ZPoly gg = ring.canonical_size(g);

    NTRUSolution out{
        ring.canonical_size(input.F),
        ring.canonical_size(input.G),
    };

    if (!verify_ntru_relation_exact(ff, gg, out.F, out.G, q_, degree_)) {
        throw std::invalid_argument("NTRU reducer input does not satisfy fG-gF=q");
    }

    if (diagnostics != nullptr) {
        *diagnostics = NTRUReductionDiagnostics{};
        diagnostics->initial_squared_norm = squared_norm(out.F, out.G);
        diagnostics->initial_max_bits =
            std::max(max_coefficient_bit_length(out.F), max_coefficient_bit_length(out.G));
    }

    std::size_t accepted_steps = 0U;
    std::size_t passes = 0U;
    bool converged = false;

    for (; passes < max_passes_; ++passes) {
        bool changed = false;

        for (std::size_t shift = 0; shift < degree_; ++shift) {
            const ZPoly sf = negacyclic_shift(ff, shift, degree_);
            const ZPoly sg = negacyclic_shift(gg, shift, degree_);
            const BigInt quadratic = pair_squared_norm(sf, sg);
            if (quadratic == 0) {
                continue;
            }

            const BigInt linear = pair_dot(out.F, out.G, sf, sg);
            const BigInt c = best_integer_coordinate(linear, quadratic);
            if (c == 0) {
                continue;
            }

            const BigInt delta = exact_delta(c, linear, quadratic);
            if (delta >= 0) {
                continue;
            }

            const BigInt before = squared_norm(out.F, out.G);
            add_scaled_in_place(out.F, sf, c);
            add_scaled_in_place(out.G, sg, c);
            const BigInt after = squared_norm(out.F, out.G);

            if (after >= before || after - before != delta) {
                throw std::logic_error("NTRU reducer exact norm-decrease invariant failed");
            }
            if (!verify_ntru_relation_exact(ff, gg, out.F, out.G, q_, degree_)) {
                throw std::logic_error("NTRU reducer changed the exact NTRU relation");
            }

            ++accepted_steps;
            changed = true;
        }

        if (!changed) {
            converged = true;
            ++passes; // report the final no-change pass as executed
            break;
        }
    }

    if (!verify_ntru_relation_exact(ff, gg, out.F, out.G, q_, degree_)) {
        throw std::logic_error("NTRU reducer final exact relation check failed");
    }

    if (diagnostics != nullptr) {
        diagnostics->passes = passes;
        diagnostics->accepted_steps = accepted_steps;
        diagnostics->final_squared_norm = squared_norm(out.F, out.G);
        diagnostics->final_max_bits =
            std::max(max_coefficient_bit_length(out.F), max_coefficient_bit_length(out.G));
        diagnostics->converged = converged;
    }

    return out;
}

} // namespace tradep2p::blns7933
