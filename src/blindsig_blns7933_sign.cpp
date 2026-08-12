#include "tradep2p/blindsig_blns7933_sign.hpp"

#include "tradep2p/blindsig_blns7933_sampling.hpp"

#include <boost/multiprecision/cpp_int.hpp>

#include <stdexcept>
#include <utility>

namespace tradep2p::blns7933 {
namespace {

RealPoly to_real_poly(const std::vector<std::int64_t>& raw) {
    RealPoly out;
    out.reserve(raw.size());
    for (const auto v : raw) {
        out.emplace_back(HighReal(v));
    }
    return out;
}

// Rounds a RealPoly to the nearest-integer PolyQ, throwing if any
// coefficient is further than `tolerance` from an integer - a genuine
// correctness check (see this file's header comment on why s must come
// out exactly integer), not a formality.
PolyQ round_to_polyq(const RealPoly& real, const HighReal& tolerance) {
    PolyQ out;
    out.reserve(real.size());
    for (const auto& coefficient : real) {
        const HighReal rounded = boost::multiprecision::round(coefficient);
        const HighReal residual = coefficient - rounded;
        const HighReal magnitude = residual < 0 ? -residual : residual;
        if (magnitude > tolerance) {
            throw std::logic_error(
                "BLNS7933 sign(): (t-z).B did not come out integer within tolerance - "
                "this should never happen given the algebraic identity it relies on, investigate");
        }
        out.push_back(static_cast<std::int64_t>(rounded.convert_to<long long>()));
    }
    return out;
}

} // namespace

std::unique_ptr<FalconTreeNode> build_signing_tree(
    const RingArithmetic& ring, const TrapdoorKey& key, const HighReal& target_sigma) {
    const std::size_t degree = ring.degree();
    const RealRingArithmetic real_ring(degree);
    const RealPoly f = to_real_poly(key.f);
    const RealPoly g = to_real_poly(key.g);
    const RealPoly cap_f = to_real_poly(key.F);
    const RealPoly cap_g = to_real_poly(key.G);
    const GramMatrix gram = build_gram_matrix(real_ring, f, g, cap_f, cap_g);
    return build_falcon_tree(real_ring, gram, degree, target_sigma);
}

PolyQ hash_to_point(const RingArithmetic& ring, const std::string& message) {
    // Deterministic, NOT a cryptographic hash-to-point - see this file's
    // header comment. Sufficient for testing the algebraic sign/verify
    // relation; a real HashToPoint (falcon.pdf Algorithm 3, SHAKE256-
    // based) is a separate piece of work, not attempted here.
    PolyQ out(ring.degree(), 0);
    std::uint64_t state = std::hash<std::string>{}(message);
    for (std::size_t i = 0; i < ring.degree(); ++i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = static_cast<std::int64_t>(state % static_cast<std::uint64_t>(ring.modulus()));
    }
    return out;
}

Signature sign(
    const RingArithmetic& ring, const TrapdoorKey& key, const FalconTreeNode& tree,
    const std::string& message, const BigInt& norm_bound_squared, CryptoRng& rng,
    std::size_t max_attempts) {
    const std::size_t degree = ring.degree();
    const RealRingArithmetic real_ring(degree);
    const HighReal q_real(ring.modulus());

    const PolyQ c = hash_to_point(ring, message);
    const RealPoly c_real = to_real_poly(c);
    const RealPoly g_real = to_real_poly(key.g);
    const RealPoly f_real = to_real_poly(key.f);
    const RealPoly cap_g_real = to_real_poly(key.G);
    const RealPoly cap_f_real = to_real_poly(key.F);

    // Target for THIS project's A=(f*g^-1,1) convention (see this
    // header's own derivation comment): t0=-c*capG/q, t1=c*g/q.
    const RealPoly c_cap_g = real_ring.mul(c_real, cap_g_real);
    const RealPoly c_g = real_ring.mul(c_real, g_real);
    RealPoly t0(degree);
    RealPoly t1(degree);
    for (std::size_t i = 0; i < degree; ++i) {
        t0[i] = -c_cap_g[i] / q_real;
        t1[i] = c_g[i] / q_real;
    }

    const HighReal rounding_tolerance("1e-40");

    for (std::size_t attempt = 0; attempt < max_attempts; ++attempt) {
        const SamplingResult z = ff_sampling(SamplingTarget{t0, t1}, tree, degree, rng);

        // s = (0,c) - z.B, B=[[g,-f],[capG,-capF]]:
        //   s0 = -(z0*g + z1*capG)
        //   s1 = c + z0*f + z1*capF
        const RealPoly z0_g = real_ring.mul(z.z0, g_real);
        const RealPoly z1_cap_g = real_ring.mul(z.z1, cap_g_real);
        const RealPoly s0_real = real_ring.sub(RealPoly(degree, HighReal(0)),
                                               real_ring.add(z0_g, z1_cap_g));

        const RealPoly z0_f = real_ring.mul(z.z0, f_real);
        const RealPoly z1_cap_f = real_ring.mul(z.z1, cap_f_real);
        const RealPoly s1_real = real_ring.add(c_real, real_ring.add(z0_f, z1_cap_f));

        const PolyQ s0 = round_to_polyq(s0_real, rounding_tolerance);
        const PolyQ s1 = round_to_polyq(s1_real, rounding_tolerance);

        BigInt norm_squared = 0;
        for (const auto v : s0) {
            norm_squared += BigInt(v) * BigInt(v);
        }
        for (const auto v : s1) {
            norm_squared += BigInt(v) * BigInt(v);
        }
        if (norm_squared <= norm_bound_squared) {
            return Signature{s0, s1};
        }
    }
    throw std::runtime_error(
        "BLNS7933 sign(): exceeded max_attempts without producing a signature within the norm bound");
}

bool verify(
    const RingArithmetic& ring, const PublicKey& public_key, const std::string& message,
    const Signature& signature, const BigInt& norm_bound_squared) {
    BigInt norm_squared = 0;
    for (const auto v : signature.s0) {
        norm_squared += BigInt(v) * BigInt(v);
    }
    for (const auto v : signature.s1) {
        norm_squared += BigInt(v) * BigInt(v);
    }
    if (norm_squared > norm_bound_squared) {
        return false;
    }

    // A.s = c (mod q), A=(t_pub,1): t_pub*s0 + s1 == c (mod q).
    const PolyQ c = hash_to_point(ring, message);
    const PolyQ lhs = ring.add(ring.mul(public_key.t, signature.s0), signature.s1);
    return ring.equal(lhs, c);
}

} // namespace tradep2p::blns7933
