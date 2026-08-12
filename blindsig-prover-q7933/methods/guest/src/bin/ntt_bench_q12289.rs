// PHASE 2 EMPIRICAL GATE - comparison arm, q=12289 via the EXISTING,
// UNTOUCHED sibling crate's real NTT multiplication
// (blindsig-prover/prover-core/src/ntt.rs, depended on here read-only via
// a path dependency renamed to `prover_core_q12289` - that crate's own
// files are never modified by this project).
//
// Deliberately the SAME benchmark shape as ../main.rs's schoolbook-at-
// q=7933 version (5 multiplications of degree-512 polynomials, same
// dependency chain between the 5 calls) so the two cycle counts are a
// true apples-to-apples comparison of "schoolbook at 7933" vs "NTT at
// 12289" - not confounded by any other difference in what each guest
// does. See swift-purring-wozniak.md's Phase 2 for what this measurement
// decides.

use prover_core_q12289::hash_to_point;
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};

fn main() {
    let a = hash_to_point(&Sha256::digest(b"poly_mul_bench a").into());
    let b = hash_to_point(&Sha256::digest(b"poly_mul_bench b").into());
    let c = hash_to_point(&Sha256::digest(b"poly_mul_bench c").into());
    let d = hash_to_point(&Sha256::digest(b"poly_mul_bench d").into());
    let e = hash_to_point(&Sha256::digest(b"poly_mul_bench e").into());

    let r1 = prover_core_q12289::ntt::poly_mul_mod_q_ntt(&a, &b);
    let r2 = prover_core_q12289::ntt::poly_mul_mod_q_ntt(&c, &d);
    let r3 = prover_core_q12289::ntt::poly_mul_mod_q_ntt(&r1, &e);
    let r4 = prover_core_q12289::ntt::poly_mul_mod_q_ntt(&r2, &a);
    let r5 = prover_core_q12289::ntt::poly_mul_mod_q_ntt(&r3, &r4);

    let mut acc: i64 = 0;
    for v in r5 {
        acc = acc.wrapping_add(v);
    }
    env::commit(&acc);
}
