// NIZK2 guest program - proves knowledge of (r, s2) satisfying the
// blind-FALCON relation WITHOUT revealing them, by having the zkVM prove
// this exact check ran correctly on hidden inputs. Ported unchanged in
// logic from the original research prototype
// (pq-blind-sig-research/prototype/nizk2_zkvm/methods/guest/src/main.rs)
// - only the import path changed (nizk2_guest -> prover_core, since the
// shared arithmetic now lives in its own crate, see prover-core/src/lib.rs).
//
// This mirrors FALCON's REAL verify_raw()/is_short() check (see
// third_party/falcon-impl-20211101/vrfy.c, common.c) as faithfully as a
// from-scratch Rust reimplementation can - not a novel invented check.
//
// Polynomial multiplication uses prover_core::ntt - a faithful port of
// FALCON's own NTT, cross-validated against a schoolbook reference (see
// prover-core's own #[cfg(test)] suite) before ever being used here.

use prover_core::{add_mod_q, g_of_r, h_of_rho_mu, hash_to_point, ntt, r_in_bounds, L2_BOUND, N, Q};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Nizk2Input {
    h: Vec<u16>,   // public: signer's FALCON public key
    b: Vec<u16>,   // public: blinding element B
    r: Vec<i32>,   // PRIVATE - must never be committed
    sig: Vec<i16>, // PRIVATE (this is s2) - must never be committed
    rho: Vec<u8>,  // public
    mu: String,    // public
}

#[derive(Serialize)]
struct Nizk2PublicOutput {
    h: Vec<u16>,
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

    // 3. Recompute the blinded target c0 = B*r + H(rho,mu).
    let r_i64: Vec<i64> = input.r.iter().map(|&x| x as i64).collect();
    let b_i64: Vec<i64> = input.b.iter().map(|&x| x as i64).collect();
    let br = ntt::poly_mul_mod_q_ntt(&b_i64, &r_i64);
    let h_digest = h_of_rho_mu(&input.rho, &input.mu);
    let hash_term: Vec<i64> = hash_to_point(&h_digest);
    let c0 = add_mod_q(&br, &hash_term);

    // 4. FALCON's own check, reimplemented faithfully (vrfy.c's
    //    verify_raw()/is_short()): -s1 = s2*h - c0 mod q, normalize to
    //    balanced range, check the aggregate L2 norm.
    let s2_i64: Vec<i64> = input.sig.iter().map(|&x| x as i64).collect();
    let h_i64: Vec<i64> = input.h.iter().map(|&x| x as i64).collect();
    let s2h = ntt::poly_mul_mod_q_ntt(&s2_i64, &h_i64);
    let mut neg_s1: Vec<i64> = (0..N).map(|i| (s2h[i] - c0[i]).rem_euclid(Q)).collect();
    for v in neg_s1.iter_mut() {
        if *v > Q / 2 {
            *v -= Q;
        }
    }
    let mut sq_sum: i64 = 0;
    for i in 0..N {
        sq_sum += neg_s1[i] * neg_s1[i];
        sq_sum += s2_i64[i] * s2_i64[i];
    }
    let short_enough = sq_sum <= L2_BOUND;

    let valid = rho_matches && bounded && short_enough;

    // Only the PUBLIC values ever get committed - r and sig (the private
    // witness) are never written to the journal, anywhere, by design.
    env::commit(&Nizk2PublicOutput {
        h: input.h,
        b: input.b,
        rho: input.rho,
        mu: input.mu,
        valid,
    });
}
