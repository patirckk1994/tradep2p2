// NIZK1 guest program - see tradep2p2/specs.txt SS9.3a and
// pq-blind-sig-research/RESEARCH_STATUS.md for full context, including
// the paper's own admission that nobody, including its authors, had
// published a concrete instantiation of this proof before this research.
//
// WHAT THIS PROVES: given public (c, B, a, pk, ct1_r, ct2_r, ct1_mu,
// ct2_mu) and PRIVATE (r, mu, coins), knowledge of a short r and a message
// mu such that:
//   1. c = B*r + H(G(r), mu)                       ("well-formedness")
//   2. ||r|| bounded, matching how it was sampled
//   3. (ct1_r,ct2_r,ct1_mu,ct2_mu) = Enc(r,mu; a,pk,coins)   ("encryption
//      to the sky" - the extractability argument the paper's security
//      proof depends on, see prover_core::enc)
// without revealing r, mu, or coins. This is the full NIZK1 statement
// from the paper's Fig 4 (3).
//
// Ported unchanged in logic from the original research prototype - only
// the import path changed (nizk2_guest -> prover_core).

use prover_core::{add_mod_q, enc, g_of_r, h_of_rho_mu, hash_to_point, ntt, r_in_bounds};
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
    let br = ntt::poly_mul_mod_q_ntt(&b_i64, &r_i64);

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
    //    guarantee.
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
