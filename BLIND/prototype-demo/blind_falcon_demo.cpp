// Blind-Falcon algebraic-core prototype. READ README_PROTOTYPE.md FIRST.
//
// NOT A BLIND SIGNATURE SCHEME. NOT SECURE. NOT FOR ANY REAL USE.
//
// Tests one thing: does A*s = B*r + H(G(r), mu) round-trip correctly using
// FALCON's real, vendored trapdoor generation and Gaussian preimage
// sampling (Zf(keygen)/Zf(sign_dyn)/Zf(verify_raw)), with a hand-rolled
// (deliberately naive, O(n^2) schoolbook) blinding step layered on top.
//
// No zero-knowledge proof anywhere in this file. The "signature" this
// produces reveals (rho, r, s) in the clear - zero blindness, zero
// anonymity. See README_PROTOTYPE.md for exactly what that means and why
// it's still a useful, low-risk thing to have built.

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

// inner.h is C99 and uses the `restrict` keyword directly in declarations -
// not valid C++ syntax (only `__restrict__` is, as a compiler extension).
// Mapping it here rather than modifying the vendored FALCON source at all.
#define restrict __restrict__
extern "C" {
#include "inner.h"
}
#undef restrict

namespace {

// FALCON-512's own standard parameters - NOT the paper's (q=7933, d=512).
// See README_PROTOTYPE.md for why reusing FALCON's real, vetted parameters
// is the more conservative choice here, not a shortcut.
constexpr unsigned kLogN = 9; // n = 2^9 = 512
constexpr std::size_t kN = std::size_t{1} << kLogN;
constexpr std::uint16_t kQ = 12289;

// Generously oversized on purpose ("resource naive" - see README) rather
// than computing the exact minimum from FALCON_KEYGEN_TEMP_9 / the sign_dyn
// doc comment's 72*2^logn bytes. 64-bit aligned, as every FALCON tmp buffer
// requires.
constexpr std::size_t kTmpBytes = 1u << 20; // 1 MiB, far more than needed

std::unique_ptr<std::uint8_t[], void (*)(std::uint8_t*)> aligned_tmp() {
    // A plain new[] of uint8_t is already suitably aligned for uint64_t on
    // every mainstream ABI (new always returns max-aligned memory for the
    // requested type's alignment class in practice for arrays of a
    // fundamental type) - FALCON's own test harness uses ordinary stack/
    // static uint8_t arrays the same way.
    return {new std::uint8_t[kTmpBytes], [](std::uint8_t* p) { delete[] p; }};
}

void fail(const char* what) {
    std::fprintf(stderr, "FATAL: %s\n", what);
    std::exit(1);
}

// Seeds a SHAKE256 context from OpenSSL's CSPRNG (the same secure-
// randomness source used throughout the parent tradep2p2 project) rather
// than FALCON's own Zf(get_seed)() - either would be fine; this keeps the
// "normal library" story consistent across this whole research thread.
void seed_from_openssl(inner_shake256_context& sc) {
    std::uint8_t seed[48];
    if (RAND_bytes(seed, sizeof seed) != 1) {
        fail("RAND_bytes failed");
    }
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, seed, sizeof seed);
    inner_shake256_flip(&sc);
}

// Naive (deliberately - see README) negacyclic polynomial multiplication
// mod q in Z_q[X]/(X^n+1): schoolbook O(n^2), no NTT/FFT. X^n = -1 in this
// ring, so a term that would land at exponent n+k wraps to exponent k with
// a sign flip. This is the standard, well-known reduction rule for this
// exact ring family (the same one FALCON itself, and the paper, both use)
// - not a novel technique, just the un-optimized way to apply it.
std::vector<std::uint16_t> poly_mul_mod_q(
    const std::vector<std::uint16_t>& b, const std::vector<std::int32_t>& r) {
    std::vector<std::int64_t> acc(kN, 0);
    for (std::size_t i = 0; i < kN; ++i) {
        if (b[i] == 0) {
            continue;
        }
        for (std::size_t j = 0; j < kN; ++j) {
            if (r[j] == 0) {
                continue;
            }
            const std::int64_t term =
                static_cast<std::int64_t>(b[i]) * static_cast<std::int64_t>(r[j]);
            const std::size_t raw = i + j;
            if (raw < kN) {
                acc[raw] += term;
            } else {
                acc[raw - kN] -= term; // X^n = -1
            }
        }
    }
    std::vector<std::uint16_t> out(kN);
    for (std::size_t i = 0; i < kN; ++i) {
        std::int64_t v = acc[i] % static_cast<std::int64_t>(kQ);
        if (v < 0) {
            v += kQ;
        }
        out[i] = static_cast<std::uint16_t>(v);
    }
    return out;
}

std::vector<std::uint16_t> add_mod_q(const std::vector<std::uint16_t>& a,
                                     const std::vector<std::uint16_t>& b) {
    std::vector<std::uint16_t> out(kN);
    for (std::size_t i = 0; i < kN; ++i) {
        out[i] = static_cast<std::uint16_t>((a[i] + b[i]) % kQ);
    }
    return out;
}

// B: the paper's second, uniformly random, non-trapdoored public element
// (simplified here to a single ring element - see README_PROTOTYPE.md).
std::vector<std::uint16_t> random_ring_element(inner_shake256_context& rng) {
    std::vector<std::uint16_t> out(kN);
    for (std::size_t i = 0; i < kN;) {
        std::uint8_t buf[2];
        inner_shake256_extract(&rng, buf, sizeof buf);
        const std::uint16_t candidate =
            static_cast<std::uint16_t>((buf[0] | (static_cast<std::uint16_t>(buf[1]) << 8)) % kQ);
        // Plain rejection sampling for an unbiased uniform value mod q -
        // q=12289 isn't a power of two, so a naive mod would be very
        // slightly biased without this; this is the standard fix, not a
        // clever trick.
        if ((buf[0] | (static_cast<std::uint16_t>(buf[1]) << 8)) <
            (65536u / kQ) * kQ) {
            out[i++] = candidate;
        }
    }
    return out;
}

// r: the paper's own explicit parameter choice - coefficients uniform in
// {-2,-1,0,1,2} (specs.txt-adjacent citation: paper section "Parameter
// selection", Dsigma0 = uniform distribution over Rq with coefficients
// between -2 and 2). Simplified to a single ring element, not a length-2
// vector - see README_PROTOTYPE.md.
std::vector<std::int32_t> sample_short_r(inner_shake256_context& rng) {
    std::vector<std::int32_t> out(kN);
    for (std::size_t i = 0; i < kN; ++i) {
        std::uint8_t b;
        inner_shake256_extract(&rng, &b, 1);
        out[i] = static_cast<std::int32_t>(b % 5) - 2; // uniform in [-2, 2]
    }
    return out;
}

// H(G(r), mu): hashes r (serialized as its coefficients) to get G(r), then
// hashes G(r) together with mu, then maps that digest onto a ring element
// via FALCON's OWN hash_to_point_vartime() - reusing existing, tested
// library code for "turn a hash into a ring point" rather than inventing a
// new one.
std::vector<std::uint16_t> hash_to_ring(const std::vector<std::int32_t>& r,
                                        const std::string& mu,
                                        std::vector<std::uint8_t>* rho_out) {
    // G(r) = SHA-256(serialized r)
    std::vector<std::uint8_t> r_bytes(kN * 2);
    for (std::size_t i = 0; i < kN; ++i) {
        const auto v = static_cast<std::uint16_t>(r[i] + 2); // shift to unsigned
        r_bytes[2 * i] = static_cast<std::uint8_t>(v & 0xff);
        r_bytes[2 * i + 1] = static_cast<std::uint8_t>(v >> 8);
    }
    std::uint8_t rho[SHA256_DIGEST_LENGTH];
    SHA256(r_bytes.data(), r_bytes.size(), rho);
    if (rho_out != nullptr) {
        rho_out->assign(rho, rho + sizeof rho);
    }

    // H(rho, mu) = SHA-256(rho || mu), then expand that digest through
    // FALCON's hash_to_point_vartime (SHAKE256-based) to get a ring point -
    // this is exactly FALCON's own message-hashing step, just fed our
    // composite digest instead of a message hash directly.
    std::vector<std::uint8_t> h_input(rho, rho + sizeof rho);
    h_input.insert(h_input.end(), mu.begin(), mu.end());
    std::uint8_t h_digest[SHA256_DIGEST_LENGTH];
    SHA256(h_input.data(), h_input.size(), h_digest);

    inner_shake256_context sc;
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, h_digest, sizeof h_digest);
    inner_shake256_flip(&sc);
    std::vector<std::uint16_t> point(kN);
    Zf(hash_to_point_vartime)(&sc, point.data(), kLogN);
    return point;
}

// Deterministic short polynomial (coefficients uniform in [-2,2], same
// distribution as sample_short_r) derived from a seed + domain label,
// rather than consumed from a live RNG stream - so both this generator
// and the zkVM guest checking it later derive IDENTICAL values from the
// same `coins`. SHA-256(seed || label) seeds a SHAKE256 XOF, exactly the
// same construction pattern as hash_to_ring() above.
std::vector<std::int32_t> short_poly_from_seed(const std::vector<std::uint8_t>& seed,
                                               const std::string& label) {
    std::vector<std::uint8_t> input(seed);
    input.insert(input.end(), label.begin(), label.end());
    std::uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(input.data(), input.size(), digest);

    inner_shake256_context sc;
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, digest, sizeof digest);
    inner_shake256_flip(&sc);

    std::vector<std::int32_t> out(kN);
    for (std::size_t i = 0; i < kN; ++i) {
        std::uint8_t b;
        inner_shake256_extract(&sc, &b, 1);
        out[i] = static_cast<std::int32_t>(b % 5) - 2; // uniform in [-2, 2]
    }
    return out;
}

std::vector<std::uint16_t> to_u16_mod_q(const std::vector<std::int32_t>& v) {
    std::vector<std::uint16_t> out(kN);
    for (std::size_t i = 0; i < kN; ++i) {
        std::int64_t x = v[i] % static_cast<std::int64_t>(kQ);
        if (x < 0) {
            x += kQ;
        }
        out[i] = static_cast<std::uint16_t>(x);
    }
    return out;
}

// "Encryption to the sky" (paper's own term, footnote 6): a real Ring-LWE
// dual-style encryption (a*u+e1, pk*u+e2+message) over the SAME ring
// already in use - but pk is just a fresh random ring element (no matching
// secret key is ever generated), exactly matching the paper's description
// that decryption is never performed and the "public key" need not even be
// validly constructed. Two independent ciphertexts (own u/e1/e2 each, own
// domain-separated seed labels) rather than one, since r (512 small
// coefficients) and SHA-256(mu) (256 bits) together don't fit one ring
// element at a safe noise margin without a denser custom packing scheme -
// deliberately not invented here; two plain ciphertexts is the simpler,
// safer choice. `u, e1, e2` all deterministically derived from `coins` via
// short_poly_from_seed(), never generated independently, so the guest can
// recompute and check the exact same ciphertext bytes.
struct EncryptToTheSky {
    std::vector<std::uint16_t> a, pk;
    std::vector<std::uint16_t> ct1_r, ct2_r;
    std::vector<std::uint16_t> ct1_mu, ct2_mu;
};

EncryptToTheSky encrypt_to_the_sky(inner_shake256_context& rng,
                                   const std::vector<std::int32_t>& r,
                                   const std::string& mu,
                                   const std::vector<std::uint8_t>& coins) {
    EncryptToTheSky out;
    out.a = random_ring_element(rng);
    out.pk = random_ring_element(rng);

    const auto u_r = short_poly_from_seed(coins, "u_r");
    const auto e1_r = short_poly_from_seed(coins, "e1_r");
    const auto e2_r = short_poly_from_seed(coins, "e2_r");
    const auto ct1_r_i32 = poly_mul_mod_q(out.a, u_r);
    std::vector<std::int32_t> ct1_r_signed(kN);
    for (std::size_t i = 0; i < kN; ++i) {
        ct1_r_signed[i] = static_cast<std::int32_t>(ct1_r_i32[i]) + e1_r[i];
    }
    out.ct1_r = to_u16_mod_q(ct1_r_signed);
    const auto pku_r = poly_mul_mod_q(out.pk, u_r);
    std::vector<std::int32_t> ct2_r_signed(kN);
    for (std::size_t i = 0; i < kN; ++i) {
        ct2_r_signed[i] = static_cast<std::int32_t>(pku_r[i]) + e2_r[i] + r[i];
    }
    out.ct2_r = to_u16_mod_q(ct2_r_signed);

    // Message for ct_mu: SHA-256(mu)'s 256 bits, one bit per coefficient
    // (the standard, safest LWE message encoding - 0 or 1, maximal noise
    // margin), padded with zeros in the remaining 256 of 512 slots.
    std::uint8_t mu_digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const std::uint8_t*>(mu.data()), mu.size(), mu_digest);
    std::vector<std::int32_t> mu_bits(kN, 0);
    for (int i = 0; i < SHA256_DIGEST_LENGTH * 8; ++i) {
        const int byte_index = i / 8;
        const int bit_index = i % 8;
        mu_bits[static_cast<std::size_t>(i)] = (mu_digest[byte_index] >> bit_index) & 1;
    }

    const auto u_mu = short_poly_from_seed(coins, "u_mu");
    const auto e1_mu = short_poly_from_seed(coins, "e1_mu");
    const auto e2_mu = short_poly_from_seed(coins, "e2_mu");
    const auto ct1_mu_i32 = poly_mul_mod_q(out.a, u_mu);
    std::vector<std::int32_t> ct1_mu_signed(kN);
    for (std::size_t i = 0; i < kN; ++i) {
        ct1_mu_signed[i] = static_cast<std::int32_t>(ct1_mu_i32[i]) + e1_mu[i];
    }
    out.ct1_mu = to_u16_mod_q(ct1_mu_signed);
    const auto pku_mu = poly_mul_mod_q(out.pk, u_mu);
    std::vector<std::int32_t> ct2_mu_signed(kN);
    for (std::size_t i = 0; i < kN; ++i) {
        ct2_mu_signed[i] = static_cast<std::int32_t>(pku_mu[i]) + e2_mu[i] + mu_bits[i];
    }
    out.ct2_mu = to_u16_mod_q(ct2_mu_signed);

    return out;
}

} // namespace

int main() {
    std::printf("blind-falcon algebraic-core prototype (n=%zu, q=%u)\n", kN, kQ);
    std::printf("NOT SECURE - see README_PROTOTYPE.md\n\n");

    auto tmp = aligned_tmp();
    std::uint8_t* tt = tmp.get();

    // --- Signer: FALCON keygen (real trapdoor generation, vendored code) ---
    inner_shake256_context signer_rng;
    seed_from_openssl(signer_rng);

    std::vector<std::int8_t> f(kN), g(kN), F(kN), G(kN);
    std::vector<std::uint16_t> h(kN);
    unsigned oldcw = set_fpu_cw(2);
    Zf(keygen)(&signer_rng, f.data(), g.data(), F.data(), G.data(), h.data(), kLogN, tt);
    set_fpu_cw(oldcw);
    std::printf("[signer] FALCON keygen done (real NTRU trapdoor)\n");

    // The paper's second, non-trapdoored public element B.
    std::vector<std::uint16_t> B = random_ring_element(signer_rng);
    std::printf("[signer] generated blinding element B\n");

    // --- User: blind a message ---
    inner_shake256_context user_rng;
    seed_from_openssl(user_rng);

    const std::string mu = "blind-falcon algebraic-core demo message";
    std::vector<std::int32_t> r = sample_short_r(user_rng);
    std::vector<std::uint8_t> rho;
    std::vector<std::uint16_t> hash_term = hash_to_ring(r, mu, &rho);
    std::vector<std::uint16_t> Br = poly_mul_mod_q(B, r);
    std::vector<std::uint16_t> c = add_mod_q(Br, hash_term);
    std::printf("[user]   blinded target c = B*r + H(G(r),mu) computed\n");

    // --- User: "encryption to the sky" of (r, mu) - the NIZK1 half this
    // session deferred until now. See encrypt_to_the_sky()'s comment. ---
    std::vector<std::uint8_t> coins(32);
    if (RAND_bytes(coins.data(), static_cast<int>(coins.size())) != 1) {
        fail("RAND_bytes failed for coins");
    }
    const EncryptToTheSky ciphertext = encrypt_to_the_sky(user_rng, r, mu, coins);
    std::printf("[user]   encryption-to-the-sky of (r,mu) computed\n");

    // --- Signer: FALCON preimage sample for the BLINDED target c ---
    // (No NIZK1 here - see README_PROTOTYPE.md. The signer in a real
    // deployment would refuse to sign without first verifying a proof that
    // c is well-formed; this prototype skips straight to signing.)
    std::vector<std::int16_t> sig(kN);
    oldcw = set_fpu_cw(2);
    Zf(sign_dyn)(sig.data(), &signer_rng, f.data(), g.data(), F.data(), G.data(),
                c.data(), kLogN, tt);
    set_fpu_cw(oldcw);
    std::printf("[signer] FALCON preimage sample for c done (real Gaussian sampler)\n");

    // --- User: finalize (no NIZK2 - reveals rho, r, sig in the clear) ---
    // In the real scheme, sig=s and r would stay hidden behind a NIZK
    // proving knowledge of them without revealing them. Here they're just
    // handed over directly, so this "signature" has zero blindness.
    std::printf("[user]   finalized: signature = (rho, r, sig) revealed in the clear\n\n");

    // --- Anyone: verify ---
    // rho = G(r) is public; recompute the same target independently and
    // check it against FALCON's own verify_raw() (real, vendored
    // verification code, not reimplemented).
    std::vector<std::int32_t> r_check = r; // a verifier who was HANDED r directly (no ZK)
    std::vector<std::uint16_t> hash_term_check = hash_to_ring(r_check, mu, nullptr);
    std::vector<std::uint16_t> Br_check = poly_mul_mod_q(B, r_check);
    std::vector<std::uint16_t> c_check = add_mod_q(Br_check, hash_term_check);

    std::vector<std::uint16_t> h_ntt = h;
    Zf(to_ntt_monty)(h_ntt.data(), kLogN);
    const int ok = Zf(verify_raw)(c_check.data(), sig.data(), h_ntt.data(), kLogN, tt);

    std::printf("verify_raw(): %s\n", ok ? "PASS - relation holds" : "FAIL");
    std::printf("\nReminder: PASS here means the algebraic relation A*s = B*r +\n"
                "H(G(r),mu) round-trips through real FALCON trapdoor sampling.\n"
                "It does NOT mean this is a secure blind signature - there is no\n"
                "zero-knowledge layer in this file at all. See README_PROTOTYPE.md.\n");

    // Dump the values needed to build a real NIZK2 (nizk2_zkvm/) over this
    // exact instance - r and sig are what NIZK2 must hide; B, h, rho, mu
    // are the public statement. Plain (non-NTT) h, since the zkVM guest
    // does its own naive schoolbook multiplication, not FALCON's NTT.
    if (ok) {
        std::FILE* out = std::fopen("nizk2_instance.json", "w");
        if (out == nullptr) {
            fail("could not open nizk2_instance.json for writing");
        }
        auto dump_u16 = [out](const char* name, const std::vector<std::uint16_t>& v) {
            std::fprintf(out, "\"%s\":[", name);
            for (std::size_t i = 0; i < v.size(); ++i) {
                std::fprintf(out, "%s%u", i ? "," : "", v[i]);
            }
            std::fprintf(out, "],");
        };
        auto dump_i16 = [out](const char* name, const std::vector<std::int16_t>& v) {
            std::fprintf(out, "\"%s\":[", name);
            for (std::size_t i = 0; i < v.size(); ++i) {
                std::fprintf(out, "%s%d", i ? "," : "", v[i]);
            }
            std::fprintf(out, "],");
        };
        auto dump_i32 = [out](const char* name, const std::vector<std::int32_t>& v) {
            std::fprintf(out, "\"%s\":[", name);
            for (std::size_t i = 0; i < v.size(); ++i) {
                std::fprintf(out, "%s%d", i ? "," : "", v[i]);
            }
            std::fprintf(out, "],");
        };
        auto dump_bytes = [out](const char* name, const std::vector<std::uint8_t>& v) {
            std::fprintf(out, "\"%s\":[", name);
            for (std::size_t i = 0; i < v.size(); ++i) {
                std::fprintf(out, "%s%u", i ? "," : "", v[i]);
            }
            std::fprintf(out, "],");
        };
        std::fprintf(out, "{");
        dump_u16("h", h);          // public: signer's FALCON public key
        dump_u16("b", B);          // public: blinding element
        dump_u16("c", c);          // public: the blinded target sent to the signer (NIZK1)
        dump_i32("r", r);          // PRIVATE: must stay hidden
        dump_i16("sig", sig);      // PRIVATE: must stay hidden (this is s2)
        // Encryption-to-the-sky (NIZK1's extractability half) - a, pk and
        // both ciphertexts are public (the signer receives them exactly
        // like c); coins is PRIVATE (it determines u/e1/e2 deterministically,
        // same as r/mu, and must never be revealed - the guest recomputes
        // and checks against these public ciphertexts without it ever
        // leaving the private input).
        dump_u16("enc_a", ciphertext.a);
        dump_u16("enc_pk", ciphertext.pk);
        dump_u16("ct1_r", ciphertext.ct1_r);
        dump_u16("ct2_r", ciphertext.ct2_r);
        dump_u16("ct1_mu", ciphertext.ct1_mu);
        dump_u16("ct2_mu", ciphertext.ct2_mu);
        dump_bytes("coins", coins); // PRIVATE
        std::fprintf(out, "\"rho\":[");
        for (std::size_t i = 0; i < rho.size(); ++i) {
            std::fprintf(out, "%s%u", i ? "," : "", rho[i]);
        }
        std::fprintf(out, "],");   // public
        std::fprintf(out, "\"mu\":\"%s\"", mu.c_str()); // PRIVATE (for NIZK1's purposes)
        std::fprintf(out, "}\n");
        std::fclose(out);
        std::printf("\nWrote nizk2_instance.json for the zkVM proof (nizk2_zkvm/)\n");
    }
    return ok ? 0 : 1;
}
