// CYCLE-COUNT MICROBENCHMARK, kept as a permanent, re-runnable diagnostic
// (paired with ntt_bench_q12289.rs, same benchmark shape, different
// algorithm/modulus) - matching this project's own established pattern of
// keeping manual diagnostics around rather than discarding them once
// their first question is answered (see e.g. the C++ q7933-reference
// track's trapgen_diagnostic.cpp/sign_diagnostic.cpp).
//
// This is what answered the empirical question the whole q=7933 guest
// port's Phase 2 gate existed to ask (see swift-purring-wozniak.md): is
// schoolbook multiplication at q=7933 an actual zkVM-proving-cost
// problem, given a real radix-2 NTT is structurally impossible at this
// modulus/degree (see prover-core/src/poly_mul.rs)? Real measured result:
// schoolbook was 14.46x more cycles than NTT for this benchmark shape
// (36,964,015 vs 2,557,148 cycles) - within this project's "roughly an
// order of magnitude" threshold for proceeding with schoolbook as the
// final answer, not the "two+ orders of magnitude" that would have
// triggered reconsidering Karatsuba. Run again with
// `cargo run -p methods --release --example cycle_count` if this ever
// needs reconfirming (e.g. after a risc0-zkvm version bump).
//
// UPDATE: schoolbook is no longer what the real guest uses - Karatsuba
// (poly_mul_mod_q_karatsuba) replaced it as the production choice after
// this same benchmark shape showed a real, measured speedup - see
// karatsuba_cycle_bench.rs, this file's own direct sibling/successor.
// Kept as a permanent historical record of the Phase 2 measurement above,
// same reasoning as ntt_bench_q12289.rs.
//
// Shape: 5 schoolbook multiplications, matching NIZK1's real call count
// (1 for the blinding relation's B*r, plus 4 inside check_encryption's
// two mul_add/poly_mul pairs) - NIZK1 is the heavier of the two real
// guests (see main.rs/bin/nizk1.rs), so this is the representative case,
// not an arbitrary pick. Inputs are deterministic (hash_to_point of fixed
// literal seeds) so this binary needs no env::read() input at all - it
// only exists to be executed and have its cycle count measured, not
// proven meaningfully.

use prover_core::{hash_to_point, poly_mul::poly_mul_mod_q_schoolbook};
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};

fn main() {
    let a = hash_to_point(&Sha256::digest(b"poly_mul_bench a").into());
    let b = hash_to_point(&Sha256::digest(b"poly_mul_bench b").into());
    let c = hash_to_point(&Sha256::digest(b"poly_mul_bench c").into());
    let d = hash_to_point(&Sha256::digest(b"poly_mul_bench d").into());
    let e = hash_to_point(&Sha256::digest(b"poly_mul_bench e").into());

    let r1 = poly_mul_mod_q_schoolbook(&a, &b);
    let r2 = poly_mul_mod_q_schoolbook(&c, &d);
    let r3 = poly_mul_mod_q_schoolbook(&r1, &e);
    let r4 = poly_mul_mod_q_schoolbook(&r2, &a);
    let r5 = poly_mul_mod_q_schoolbook(&r3, &r4);

    // Commit a small digest of the result so the compiler can't optimize
    // any of the above away as dead code.
    let mut acc: i64 = 0;
    for v in r5 {
        acc = acc.wrapping_add(v);
    }
    env::commit(&acc);
}
