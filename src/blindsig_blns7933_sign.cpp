#include "tradep2p/blindsig_blns7933_sign.hpp"

#include "tradep2p/blindsig_blns7933_sampling.hpp"

#include <boost/multiprecision/cpp_int.hpp>

#include <openssl/err.h>
#include <openssl/evp.h>

#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace tradep2p::blns7933 {
namespace {

constexpr std::size_t kShakePrefixChunkBytes = 4096U;

[[noreturn]] void throw_openssl_error(const std::string& message) {
    const unsigned long code = ERR_get_error();
    char buffer[256]{};
    if (code != 0U) {
        ERR_error_string_n(code, buffer, sizeof(buffer));
        throw std::runtime_error(message + ": " + buffer);
    }
    throw std::runtime_error(message);
}

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX* ctx) const noexcept { EVP_MD_CTX_free(ctx); }
};
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

// Return the first `output_size` bytes of SHAKE256(message). OpenSSL's
// EVP_DigestFinalXOF() is a one-shot finalization API, so hash_to_point()
// grows the requested prefix and replays the absorption when rejection
// sampling needs more bytes. That is deliberately a little slower than a
// multi-call squeeze API, but it is portable across the OpenSSL versions
// this reference target already supports and yields the exact contiguous
// SHAKE stream rather than inventing a refill construction.
std::vector<std::uint8_t> shake256_prefix(const std::string& message, std::size_t output_size) {
    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) {
        throw_openssl_error("BLNS7933 hash_to_point: EVP_MD_CTX_new failed");
    }
    if (EVP_DigestInit_ex(ctx.get(), EVP_shake256(), nullptr) != 1) {
        throw_openssl_error("BLNS7933 hash_to_point: EVP_DigestInit_ex(SHAKE256) failed");
    }
    if (!message.empty() &&
        EVP_DigestUpdate(ctx.get(), message.data(), message.size()) != 1) {
        throw_openssl_error("BLNS7933 hash_to_point: EVP_DigestUpdate(message) failed");
    }

    std::vector<std::uint8_t> out(output_size);
    if (EVP_DigestFinalXOF(ctx.get(), out.data(), out.size()) != 1) {
        throw_openssl_error("BLNS7933 hash_to_point: EVP_DigestFinalXOF failed");
    }
    return out;
}

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
    // FALCON-style unbiased coefficient extraction, reparametrized for the
    // supplied modulus: SHAKE256(message), consume 16-bit big-endian words,
    // reject w >= 5*q, then reduce modulo q. Because the accepted interval
    // contains exactly five complete residue classes, reduction introduces
    // no modulo bias. At the real BLNS23 q=7933, 5*q=39665 < 2^16.
    //
    // This deliberately remains the deterministic *plain-message* helper:
    // it has no per-signature salt field in its API. The blind-signature
    // path does not call it at all; it signs an already-blinded target via
    // sign_target().
    const std::int64_t q = ring.modulus();
    if (q <= 0 || q > (65535 / 5)) {
        throw std::invalid_argument(
            "BLNS7933 hash_to_point: modulus must satisfy 0 < 5*q < 2^16");
    }
    const auto reject_at = static_cast<std::uint32_t>(5 * q);
    const auto q_u32 = static_cast<std::uint32_t>(q);

    PolyQ out;
    out.reserve(ring.degree());

    std::size_t prefix_size = kShakePrefixChunkBytes;
    std::vector<std::uint8_t> stream = shake256_prefix(message, prefix_size);
    std::size_t pos = 0;

    while (out.size() < ring.degree()) {
        if (pos + 2U > stream.size()) {
            const std::size_t old_size = stream.size();
            if (old_size > std::numeric_limits<std::size_t>::max() - kShakePrefixChunkBytes) {
                throw std::length_error("BLNS7933 hash_to_point: SHAKE256 prefix length overflow");
            }
            prefix_size = old_size + kShakePrefixChunkBytes;
            stream = shake256_prefix(message, prefix_size);
            pos = old_size;
        }

        const auto w = static_cast<std::uint32_t>(
            (static_cast<std::uint32_t>(stream[pos]) << 8U) |
            static_cast<std::uint32_t>(stream[pos + 1U]));
        pos += 2U;

        if (w < reject_at) {
            out.push_back(static_cast<std::int64_t>(w % q_u32));
        }
    }
    return out;
}

Signature sign_target(
    const RingArithmetic& ring, const TrapdoorKey& key, const FalconTreeNode& tree,
    const PolyQ& target, const BigInt& norm_bound_squared, CryptoRng& rng,
    std::size_t max_attempts) {
    const std::size_t degree = ring.degree();
    const RealRingArithmetic real_ring(degree);
    const HighReal q_real(ring.modulus());

    const PolyQ& c = target;
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

Signature sign(
    const RingArithmetic& ring, const TrapdoorKey& key, const FalconTreeNode& tree,
    const std::string& message, const BigInt& norm_bound_squared, CryptoRng& rng,
    std::size_t max_attempts) {
    return sign_target(ring, key, tree, hash_to_point(ring, message), norm_bound_squared, rng,
                        max_attempts);
}

bool verify_target(
    const RingArithmetic& ring, const PublicKey& public_key, const PolyQ& target,
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

    // A.s = target (mod q), A=(t_pub,1): t_pub*s0 + s1 == target (mod q).
    const PolyQ lhs = ring.add(ring.mul(public_key.t, signature.s0), signature.s1);
    return ring.equal(lhs, target);
}

bool verify(
    const RingArithmetic& ring, const PublicKey& public_key, const std::string& message,
    const Signature& signature, const BigInt& norm_bound_squared) {
    return verify_target(ring, public_key, hash_to_point(ring, message), signature, norm_bound_squared);
}

} // namespace tradep2p::blns7933
