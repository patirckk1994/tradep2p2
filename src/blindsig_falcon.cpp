#include "tradep2p/blindsig_falcon.hpp"

#include <openssl/rand.h>

#include <memory>
#include <stdexcept>

// inner.h is C99 and uses the `restrict` keyword directly in declarations -
// not valid C++ syntax (only `__restrict__` is, as a compiler extension).
// Mapping it here rather than modifying the vendored FALCON source at all -
// exactly the pattern the original research prototype's
// blind_falcon_demo.cpp already established.
#define restrict __restrict__
extern "C" {
#include "inner.h"
}
#undef restrict

namespace tradep2p::blindsig {
namespace {

constexpr unsigned kLogN = 9; // n = 2^9 = 512 = kRingDegree

// Generously oversized on purpose (this codebase's "resource naive"
// experimental posture, not a production performance target) rather than
// computing the exact minimum from FALCON_KEYGEN_TEMP_9 (28672 bytes) or
// sign_dyn's documented 72*2^logn = 36864-byte requirement. 1 MiB comfortably
// covers both plus verify_raw's much smaller 2*2^logn requirement.
constexpr std::size_t kTmpBytes = 1u << 20;

std::unique_ptr<std::uint8_t[]> aligned_tmp() {
    // A plain new[] of uint8_t is already suitably aligned for uint64_t on
    // every mainstream ABI - FALCON's own test harness uses ordinary
    // stack/static uint8_t arrays the same way.
    return std::make_unique<std::uint8_t[]>(kTmpBytes);
}

// Seeds a SHAKE256 context from OpenSSL's CSPRNG, matching the rest of this
// codebase's randomness source and the original research prototype's own
// seed_from_openssl() exactly.
void seed_from_openssl(inner_shake256_context& sc) {
    std::uint8_t seed[48];
    if (RAND_bytes(seed, sizeof seed) != 1) {
        throw std::runtime_error("blindsig: RAND_bytes failed while seeding FALCON keygen/sign RNG");
    }
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, seed, sizeof seed);
    inner_shake256_flip(&sc);
}

} // namespace

FalconKeyPair falcon_keygen() {
    auto tmp = aligned_tmp();

    inner_shake256_context rng;
    seed_from_openssl(rng);

    FalconKeyPair result;
    // Zf(keygen) itself returns void - FALCON's reference implementation
    // handles degenerate NTRU candidates via internal retries and always
    // eventually succeeds; RAND_bytes failure above (during seeding) is the
    // only real failure mode this function has to report.
    const unsigned oldcw = set_fpu_cw(2);
    Zf(keygen)(&rng, result.trapdoor.f.data(), result.trapdoor.g.data(),
              result.trapdoor.F.data(), result.trapdoor.G.data(),
              result.public_key.h.data(), kLogN, tmp.get());
    set_fpu_cw(oldcw);

    return result;
}

std::array<std::int16_t, kRingDegree> falcon_sign_dyn(
    const FalconTrapdoor& trapdoor, const std::array<std::uint16_t, kRingDegree>& target_c) {
    auto tmp = aligned_tmp();

    inner_shake256_context rng;
    seed_from_openssl(rng);

    std::array<std::int16_t, kRingDegree> sig{};
    const unsigned oldcw = set_fpu_cw(2);
    Zf(sign_dyn)(sig.data(), &rng, trapdoor.f.data(), trapdoor.g.data(),
                trapdoor.F.data(), trapdoor.G.data(), target_c.data(), kLogN, tmp.get());
    set_fpu_cw(oldcw);

    return sig;
}

bool falcon_verify_raw(const std::array<std::uint16_t, kRingDegree>& target_c,
                       const std::array<std::int16_t, kRingDegree>& sig,
                       const FalconPublicKey& public_key) {
    auto tmp = aligned_tmp();

    // Zf(verify_raw) requires the public key in NTT + Montgomery form -
    // converted here, on a copy, so callers always pass the plain public
    // key and never have to track conversion state themselves.
    std::array<std::uint16_t, kRingDegree> h_ntt = public_key.h;
    Zf(to_ntt_monty)(h_ntt.data(), kLogN);

    const int ok = Zf(verify_raw)(target_c.data(), sig.data(), h_ntt.data(), kLogN, tmp.get());
    return ok != 0;
}

} // namespace tradep2p::blindsig
