// "Encryption to the sky" (paper's footnote 6: the PKE "public key" need
// not be validly generated, since decryption is never performed in the
// live protocol - only in the security proof's own extraction argument).
// A standard LPR-style (Lyubashevsky-Peikert-Regev) Ring-LWE dual
// encryption, ported function-for-function from the original C++
// prototype's encrypt_to_the_sky() (see that function's own comment for
// the full design rationale: two independent ciphertexts rather than one
// densely packed one, u/e1/e2 deterministically derived from `coins` via
// domain-separated seed labels so both sides derive identical values).
//
// generate_ciphertexts() and check_encryption() share one implementation
// (check_encryption regenerates via generate_ciphertexts() and compares)
// rather than being two hand-synced copies of the same math - the guest
// only ever calls check_encryption(); generate_ciphertexts() is what the
// client-role CLI command calls to produce a request in the first place.

use crate::ntt::poly_mul_mod_q_ntt;
use crate::{N, Q};
use sha2::{Digest, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

// Deterministic uniform-in-[-bound,bound] polynomial: SHA-256(seed ||
// label) seeds a SHAKE256 XOF, one byte per coefficient, mapped via
// `% (2*bound+1) - bound`. `bound` must be small enough that `2*bound+1
// <= 256` (one XOF byte per coefficient) - true for every bound actually
// used in this module.
fn bounded_poly_from_seed(seed: &[u8], label: &str, bound: i64) -> Vec<i64> {
    let modulus = 2 * bound + 1;
    let mut input = Vec::with_capacity(seed.len() + label.len());
    input.extend_from_slice(seed);
    input.extend_from_slice(label.as_bytes());
    let digest: [u8; 32] = Sha256::digest(&input).into();

    let mut shake = Shake256::default();
    shake.update(&digest);
    let mut reader = shake.finalize_xof();
    let mut out = Vec::with_capacity(N);
    for _ in 0..N {
        let mut b = [0u8; 1];
        reader.read(&mut b);
        out.push((b[0] as i64 % modulus) - bound);
    }
    out
}

// The blinding vector r's own bound - fixed by the protocol (matches the
// paper's D_sigma0 parameter choice and NIZK1/NIZK2's own r_in_bounds()
// check, which specifically requires every coefficient in [-2,2]). Used
// both by the CLI's `r` sampling and, historically, by this module's own
// encryption noise before that was widened - see ENCRYPTION_NOISE_BOUND
// below for why those needed to stop sharing one distribution.
pub fn short_poly_from_seed(seed: &[u8], label: &str) -> Vec<i64> {
    bounded_poly_from_seed(seed, label, 2)
}

// Encryption-to-the-sky's own noise (u, e1, e2) - deliberately NOT the
// same [-2,2] bound as r above. Originally it was (both used
// short_poly_from_seed), which independently-verified lattice-hardness
// estimation (lattice-estimator, real run, not hand-derived) showed was
// too thin: ~102 bits (rough) / ~125 bits (full) at q=12289 - noticeably
// below FALCON-512's own ~121-146 bit margin at the same modulus. r
// itself has to stay small (it's what NIZK1/NIZK2 bound and prove), but
// this encryption's noise has no such constraint - nothing ever decrypts
// these ciphertexts in the real protocol (paper's footnote 6: the
// "public key" need not even be validly generated), so there is no
// correctness cost to using much larger noise here. Bound 8 was chosen
// by sweeping bounds 2/4/8/12/16/20/24/32 through the same estimator and
// picking the smallest one with comfortable margin above both FALCON's
// own numbers and a 128-bit floor on both rough and full estimates:
// bound=8 measures ~146/166 bits (rough/full).
const ENCRYPTION_NOISE_BOUND: i64 = 8;

fn encryption_noise_from_seed(seed: &[u8], label: &str) -> Vec<i64> {
    bounded_poly_from_seed(seed, label, ENCRYPTION_NOISE_BOUND)
}

// Mirrors the original C++ prototype's random_ring_element(): rejection
// sampling for an unbiased uniform value mod q (q=12289 isn't a power of
// two, so a naive mod would be very slightly biased without this).
// Seed-derived (via a SHAKE256 XOF, same seed-to-stream construction as
// short_poly_from_seed) rather than consumed from a live RNG context, so
// the CLI can derive `a`/`pk` deterministically from a single fresh
// random seed per invocation.
pub fn uniform_poly_from_seed(seed: &[u8], label: &str) -> Vec<i64> {
    let mut input = Vec::with_capacity(seed.len() + label.len());
    input.extend_from_slice(seed);
    input.extend_from_slice(label.as_bytes());
    let digest: [u8; 32] = Sha256::digest(&input).into();

    let mut shake = Shake256::default();
    shake.update(&digest);
    let mut reader = shake.finalize_xof();
    let mut out = Vec::with_capacity(N);
    while out.len() < N {
        let mut buf = [0u8; 2];
        reader.read(&mut buf);
        let w = (buf[0] as u32) | ((buf[1] as u32) << 8);
        if w < (65536u32 / Q as u32) * Q as u32 {
            out.push((w % Q as u32) as i64);
        }
    }
    out
}

fn mul_add(a: &[i64], u: &[i64], noise: &[i64]) -> Vec<i64> {
    let product = poly_mul_mod_q_ntt(a, u);
    (0..N).map(|i| product[i] + noise[i]).collect()
}

fn reduce_mod_q(v: &[i64]) -> Vec<i64> {
    v.iter().map(|&x| x.rem_euclid(Q)).collect()
}

fn mu_to_bits(mu: &str) -> Vec<i64> {
    let mu_digest: [u8; 32] = Sha256::digest(mu.as_bytes()).into();
    let mut mu_bits = vec![0i64; N];
    for (i, bit) in mu_bits.iter_mut().enumerate().take(256) {
        let byte_index = i / 8;
        let bit_index = i % 8;
        *bit = ((mu_digest[byte_index] >> bit_index) & 1) as i64;
    }
    mu_bits
}

pub struct Ciphertexts {
    pub ct1_r: Vec<i64>,
    pub ct2_r: Vec<i64>,
    pub ct1_mu: Vec<i64>,
    pub ct2_mu: Vec<i64>,
}

/// Computes the encryption-to-the-sky ciphertexts for (r, mu) under
/// (a, pk, coins). Called by the client role to produce a fresh request,
/// and internally by check_encryption() to verify a claimed one - see
/// this module's own comment for why those share one implementation.
pub fn generate_ciphertexts(coins: &[u8], r: &[i64], mu: &str, a: &[i64], pk: &[i64]) -> Ciphertexts {
    let u_r = encryption_noise_from_seed(coins, "u_r");
    let e1_r = encryption_noise_from_seed(coins, "e1_r");
    let e2_r = encryption_noise_from_seed(coins, "e2_r");
    let ct1_r = mul_add(a, &u_r, &e1_r);
    let pku_r = poly_mul_mod_q_ntt(pk, &u_r);
    let ct2_r: Vec<i64> = (0..N).map(|i| pku_r[i] + e2_r[i] + r[i]).collect();

    let mu_bits = mu_to_bits(mu);
    let u_mu = encryption_noise_from_seed(coins, "u_mu");
    let e1_mu = encryption_noise_from_seed(coins, "e1_mu");
    let e2_mu = encryption_noise_from_seed(coins, "e2_mu");
    let ct1_mu = mul_add(a, &u_mu, &e1_mu);
    let pku_mu = poly_mul_mod_q_ntt(pk, &u_mu);
    let ct2_mu: Vec<i64> = (0..N).map(|i| pku_mu[i] + e2_mu[i] + mu_bits[i]).collect();

    Ciphertexts {
        ct1_r: reduce_mod_q(&ct1_r),
        ct2_r: reduce_mod_q(&ct2_r),
        ct1_mu: reduce_mod_q(&ct1_mu),
        ct2_mu: reduce_mod_q(&ct2_mu),
    }
}

/// Recomputes both ciphertexts from (coins, r, mu, a, pk) exactly as the
/// generating side did, and returns whether they match the publicly
/// claimed ciphertexts - without ever needing to expose coins/r/mu to do
/// so. This is the check the NIZK1 guest runs.
#[allow(clippy::too_many_arguments)]
pub fn check_encryption(
    coins: &[u8],
    r: &[i64],
    mu: &str,
    a: &[i64],
    pk: &[i64],
    claimed_ct1_r: &[i64],
    claimed_ct2_r: &[i64],
    claimed_ct1_mu: &[i64],
    claimed_ct2_mu: &[i64],
) -> bool {
    let computed = generate_ciphertexts(coins, r, mu, a, pk);
    computed.ct1_r == reduce_mod_q(claimed_ct1_r)
        && computed.ct2_r == reduce_mod_q(claimed_ct2_r)
        && computed.ct1_mu == reduce_mod_q(claimed_ct1_mu)
        && computed.ct2_mu == reduce_mod_q(claimed_ct2_mu)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    // Regression test replacing the original research prototype's
    // standalone enc_verify.rs tool: cross-checks generate/check against
    // each other (self-consistency) AND runs a negative control
    // (corrupting r must make the check fail) - a check that always
    // passes regardless of input would be worse than useless.
    #[test]
    fn check_encryption_accepts_genuine_and_rejects_corrupted() {
        let mut rng = rand::thread_rng();
        let mut coins = [0u8; 32];
        rng.fill_bytes(&mut coins);
        let a_seed = { let mut s = [0u8; 32]; rng.fill_bytes(&mut s); s };
        let pk_seed = { let mut s = [0u8; 32]; rng.fill_bytes(&mut s); s };
        let a = uniform_poly_from_seed(&a_seed, "a");
        let pk = uniform_poly_from_seed(&pk_seed, "pk");

        let r: Vec<i64> = (0..N as i64).map(|i| ((i * 7 + 3) % 5) - 2).collect();
        let mu = "regression-test message";

        let ct = generate_ciphertexts(&coins, &r, mu, &a, &pk);
        assert!(check_encryption(
            &coins, &r, mu, &a, &pk, &ct.ct1_r, &ct.ct2_r, &ct.ct1_mu, &ct.ct2_mu
        ));

        let mut bad_r = r.clone();
        bad_r[0] = (bad_r[0] + 1).rem_euclid(5) - 2;
        assert!(
            !check_encryption(&coins, &bad_r, mu, &a, &pk, &ct.ct1_r, &ct.ct2_r, &ct.ct1_mu, &ct.ct2_mu),
            "negative control: corrupted r must be rejected, not silently accepted"
        );
    }
}
