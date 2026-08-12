// "Encryption to the sky" (paper's footnote 6: the PKE "public key" need
// not be validly generated, since decryption is never performed in the
// live protocol - only in the security proof's own extraction argument).
// Ported structurally unchanged from the q=12289 sibling crate
// (blindsig-prover/prover-core/src/enc.rs) - a standard LPR-style
// (Lyubashevsky-Peikert-Regev) Ring-LWE dual encryption, q-agnostic in
// its STRUCTURE (only the underlying ring multiplication and modulus
// differ here). generate_ciphertexts() and check_encryption() share one
// implementation (check_encryption regenerates via generate_ciphertexts()
// and compares) rather than being two hand-synced copies of the same
// math - the guest only ever calls check_encryption().
//
// SECURITY-PARAMETER RE-VERIFICATION: ENCRYPTION_NOISE_BOUND below was
// originally chosen (bound=8) via a lattice-estimator sweep AT q=12289
// (the q=12289 sibling's own ~146/166-bit rough/full margin). Re-run at
// this crate's real q=7933 (github.com/malb/lattice-estimator,
// LWE.Parameters(n=512, q=7933, Xs=Xe=ND.Uniform(-8,8))): rough ~157.1
// bits (min across usvp/dual_hybrid/arora-gb), full ~176.4 bits (min
// across all attacks including bdd/dual/bkw/mitm) - BOTH HIGHER than the
// q=12289 numbers, not lower. This makes sense once you work through it:
// a smaller modulus means the SAME absolute noise bound is proportionally
// larger noise relative to q, which makes the LWE instance harder, not
// easier - the intuition that "smaller q means less margin" (this file's
// own earlier, unverified caveat) was backwards. bound=8 is confirmed
// sound at q=7933 with a real margin, not carried over on faith.
const ENCRYPTION_NOISE_BOUND: i64 = 8;

use crate::poly_mul::poly_mul_mod_q_schoolbook;
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
// check, which specifically requires every coefficient in [-2,2]). Not a
// q-dependent choice, so unchanged from the sibling crate.
pub fn short_poly_from_seed(seed: &[u8], label: &str) -> Vec<i64> {
    bounded_poly_from_seed(seed, label, 2)
}

fn encryption_noise_from_seed(seed: &[u8], label: &str) -> Vec<i64> {
    bounded_poly_from_seed(seed, label, ENCRYPTION_NOISE_BOUND)
}

// Mirrors the sibling crate's random_ring_element(): rejection sampling
// for an unbiased uniform value mod q (q=7933 isn't a power of two
// either, so a naive mod would be very slightly biased without this).
// Seed-derived (via a SHAKE256 XOF) rather than consumed from a live RNG
// context, so the CLI can derive `a`/`pk` deterministically from a single
// fresh random seed per invocation.
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
    let product = poly_mul_mod_q_schoolbook(a, u);
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
/// and internally by check_encryption() to verify a claimed one.
pub fn generate_ciphertexts(coins: &[u8], r: &[i64], mu: &str, a: &[i64], pk: &[i64]) -> Ciphertexts {
    let u_r = encryption_noise_from_seed(coins, "u_r");
    let e1_r = encryption_noise_from_seed(coins, "e1_r");
    let e2_r = encryption_noise_from_seed(coins, "e2_r");
    let ct1_r = mul_add(a, &u_r, &e1_r);
    let pku_r = poly_mul_mod_q_schoolbook(pk, &u_r);
    let ct2_r: Vec<i64> = (0..N).map(|i| pku_r[i] + e2_r[i] + r[i]).collect();

    let mu_bits = mu_to_bits(mu);
    let u_mu = encryption_noise_from_seed(coins, "u_mu");
    let e1_mu = encryption_noise_from_seed(coins, "e1_mu");
    let e2_mu = encryption_noise_from_seed(coins, "e2_mu");
    let ct1_mu = mul_add(a, &u_mu, &e1_mu);
    let pku_mu = poly_mul_mod_q_schoolbook(pk, &u_mu);
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

    // Same regression shape as the q=12289 sibling: cross-checks
    // generate/check against each other (self-consistency) AND runs a
    // negative control (corrupting r must make the check fail) - a check
    // that always passes regardless of input would be worse than useless.
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
