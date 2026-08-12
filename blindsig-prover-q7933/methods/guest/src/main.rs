// NIZK2 guest program - proves knowledge of (r, s0, s1) satisfying THIS
// PROJECT'S OWN q=7933 signature relation WITHOUT revealing them, by
// having the zkVM prove this exact check ran correctly on hidden inputs.
//
// Structurally the same shape as the q=12289 sibling's own NIZK2 guest
// (blindsig-prover/methods/guest/src/main.rs: recompute the blinded
// target c0, then check the signature relation and norm bound against
// it) - but the relation itself is NOT FALCON's own h*s2+s1=c0. This
// scheme's trapdoor uses A=(t,1), t=f*g^-1 mod q (see
// blindsig_blns7933.hpp's PublicKey/derive_public(), built and
// empirically validated earlier this session on this same branch), so
// the analogous relation is t*s0+s1=c (mod q) - and unlike FALCON's own
// wire format (which only transmits s2 and recovers s1 implicitly via
// the verification equation, a size optimization), this scheme's
// Signature{s0,s1} carries BOTH halves explicitly (matching
// blindsig_blns7933_sign.cpp's own verify(), which takes the full
// Signature struct) - so this guest checks the relation directly rather
// than deriving one half from the other.
//
// Polynomial multiplication uses prover_core::poly_mul (schoolbook, NOT
// NTT - q=7933 does not support a standard radix-2 NTT at N=512; see
// prover_core::poly_mul's own module comment and this project's Phase 2
// cycle-count measurement, methods/guest/src/bin/poly_mul_cycle_bench.rs).

use prover_core::{
    add_mod_q, g_of_r, h_of_rho_mu, hash_to_point, poly_mul::poly_mul_mod_q_schoolbook,
    r_in_bounds,
    relation::{norm_squared, relation_holds},
    NORM_BOUND_SQUARED,
};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Nizk2Input {
    t: Vec<u16>,  // public: signer's q=7933 public key, t = f*g^-1 mod q
    b: Vec<u16>,  // public: blinding element B
    r: Vec<i32>,  // PRIVATE - must never be committed
    s0: Vec<i32>, // PRIVATE - must never be committed
    s1: Vec<i32>, // PRIVATE - must never be committed
    rho: Vec<u8>, // public
    mu: String,   // public
}

#[derive(Serialize)]
struct Nizk2PublicOutput {
    t: Vec<u16>,
    b: Vec<u16>,
    rho: Vec<u8>,
    mu: String,
    valid: bool,
}

fn main() {
    let input: Nizk2Input = env::read();

    // 1. Prove knowledge of r consistent with the PUBLIC rho: recompute
    //    G(r) ourselves (from the PRIVATE r) and check it matches.
    let rho_check = g_of_r(&input.r);
    let rho_matches = rho_check.as_slice() == input.rho.as_slice();

    // 2. r's own norm bound - each coefficient must be in [-2,2], matching
    //    how it was sampled.
    let bounded = r_in_bounds(&input.r);

    // 3. Recompute the blinded target c = B*r + H(rho,mu).
    let r_i64: Vec<i64> = input.r.iter().map(|&x| x as i64).collect();
    let b_i64: Vec<i64> = input.b.iter().map(|&x| x as i64).collect();
    let br = poly_mul_mod_q_schoolbook(&b_i64, &r_i64);
    let h_digest = h_of_rho_mu(&input.rho, &input.mu);
    let hash_term: Vec<i64> = hash_to_point(&h_digest);
    let c = add_mod_q(&br, &hash_term);

    // 4. This scheme's own signature relation: t*s0 + s1 == c (mod q) -
    //    see prover_core::relation for the shared implementation (also
    //    unit-tested there against a real, genuinely-produced C++
    //    q7933-reference signature, not just self-consistency).
    let t_i64: Vec<i64> = input.t.iter().map(|&x| x as i64).collect();
    let s0_i64: Vec<i64> = input.s0.iter().map(|&x| x as i64).collect();
    let s1_i64: Vec<i64> = input.s1.iter().map(|&x| x as i64).collect();
    let relation_ok = relation_holds(&t_i64, &s0_i64, &s1_i64, &c);
    let short_enough = norm_squared(&s0_i64, &s1_i64) <= NORM_BOUND_SQUARED;

    let valid = rho_matches && bounded && relation_ok && short_enough;

    // Only the PUBLIC values ever get committed - r, s0, s1 (the private
    // witness) are never written to the journal, anywhere, by design.
    env::commit(&Nizk2PublicOutput {
        t: input.t,
        b: input.b,
        rho: input.rho,
        mu: input.mu,
        valid,
    });
}
