// NIZK1 guest program - see main.rs and swift-purring-wozniak.md for full
// context. Structurally UNCHANGED in logic from the q=12289 sibling
// (blindsig-prover/methods/guest/src/bin/nizk1.rs): the blinding relation
// c=B*r+H(G(r),mu) and the "encryption to the sky" extractability check
// are both independent of which signature scheme eventually consumes
// this proof's `c` - they operate purely on the shared ring
// Z_q[X]/(X^N+1) and don't reference t/s0/s1 at all. Only the underlying
// multiplication (prover_core::poly_mul, schoolbook - see that module's
// own comment for why NTT isn't available at this modulus) and the
// ENCRYPTION_NOISE_BOUND (prover_core::enc, still pending its own
// q=7933 lattice-estimator resweep - see that module's own caveat)
// differ from the sibling.
//
// WHAT THIS PROVES: given public (c, B, a, pk, ct1_r, ct2_r, ct1_mu,
// ct2_mu) and PRIVATE (r, mu, coins), knowledge of a short r and a message
// mu such that:
//   1. c = B*r + H(G(r), mu)                       ("well-formedness")
//   2. ||r|| bounded, matching how it was sampled
//   3. (ct1_r,ct2_r,ct1_mu,ct2_mu) = Enc(r,mu; a,pk,coins)   ("encryption
//      to the sky" - the extractability argument the paper's security
//      proof depends on, see prover_core::enc)
// without revealing r, mu, or coins.

use prover_core::{add_mod_q, enc, g_of_r, h_of_rho_mu, hash_to_point, poly_mul::poly_mul_mod_q_schoolbook, r_in_bounds};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Nizk1Input {
    b: Vec<u16>,      // public: blinding element B
    c: Vec<u16>,      // public: the blinded target the signer receives
    enc_a: Vec<u16>,  // public: encryption param a
    enc_pk: Vec<u16>, // public: encryption "public key" (encryption to the sky)
    ct1_r: Vec<u16>,
    ct2_r: Vec<u16>,
    ct1_mu: Vec<u16>,
    ct2_mu: Vec<u16>, // public: the four ciphertext components
    r: Vec<i32>,      // PRIVATE
    mu: String,       // PRIVATE - this IS blindness
    coins: Vec<u8>,   // PRIVATE
}

#[derive(Serialize)]
struct Nizk1PublicOutput {
    b: Vec<u16>,
    c: Vec<u16>,
    enc_a: Vec<u16>,
    enc_pk: Vec<u16>,
    ct1_r: Vec<u16>,
    ct2_r: Vec<u16>,
    ct1_mu: Vec<u16>,
    ct2_mu: Vec<u16>,
    valid: bool,
}

fn to_i64(v: &[u16]) -> Vec<i64> {
    v.iter().map(|&x| x as i64).collect()
}

fn main() {
    let input: Nizk1Input = env::read();

    // 1. r's own norm bound.
    let bounded = r_in_bounds(&input.r);

    // 2. Well-formedness: recompute c from the private r, mu and check it
    //    against the public c the signer actually received.
    let r_i64: Vec<i64> = input.r.iter().map(|&x| x as i64).collect();
    let b_i64 = to_i64(&input.b);
    let br = poly_mul_mod_q_schoolbook(&b_i64, &r_i64);

    let rho = g_of_r(&input.r);
    let h_digest = h_of_rho_mu(&rho, &input.mu);
    let hash_term = hash_to_point(&h_digest);
    let c_check = add_mod_q(&br, &hash_term);

    let c_matches = c_check
        .iter()
        .zip(input.c.iter())
        .all(|(&computed, &claimed)| computed == claimed as i64);

    // 3. Encryption-to-the-sky: recompute all four ciphertext components
    //    from (coins, r, mu) and check them against the public ciphertexts
    //    - see prover_core::enc for exactly what this does and doesn't
    //    guarantee, and its own caveat about the noise bound's security
    //    margin not yet being re-verified at q=7933.
    let a_i64 = to_i64(&input.enc_a);
    let pk_i64 = to_i64(&input.enc_pk);
    let encryption_matches = enc::check_encryption(
        &input.coins,
        &r_i64,
        &input.mu,
        &a_i64,
        &pk_i64,
        &to_i64(&input.ct1_r),
        &to_i64(&input.ct2_r),
        &to_i64(&input.ct1_mu),
        &to_i64(&input.ct2_mu),
    );

    let valid = bounded && c_matches && encryption_matches;

    // Only values the signer already had before this proof arrived are
    // ever committed. r, mu, coins never are.
    env::commit(&Nizk1PublicOutput {
        b: input.b,
        c: input.c,
        enc_a: input.enc_a,
        enc_pk: input.enc_pk,
        ct1_r: input.ct1_r,
        ct2_r: input.ct2_r,
        ct1_mu: input.ct1_mu,
        ct2_mu: input.ct2_mu,
        valid,
    });
}
