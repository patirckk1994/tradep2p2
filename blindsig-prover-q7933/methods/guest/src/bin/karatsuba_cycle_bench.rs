// CYCLE-COUNT MICROBENCHMARK for Karatsuba multiplication at q=7933 -
// the direct successor to poly_mul_cycle_bench.rs (schoolbook), same
// benchmark shape (5 multiplications matching NIZK1's real call count),
// so the two are directly, fairly comparable. Kept as a permanent,
// re-runnable diagnostic, same reasoning as its sibling.
//
// Run via `cargo run -p methods --release --example cycle_count` (update
// that file to measure this ELF too) or directly with
// risc0_zkvm::default_executor().

use prover_core::{hash_to_point, poly_mul::poly_mul_mod_q_karatsuba};
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};

fn main() {
    let a = hash_to_point(&Sha256::digest(b"poly_mul_bench a").into());
    let b = hash_to_point(&Sha256::digest(b"poly_mul_bench b").into());
    let c = hash_to_point(&Sha256::digest(b"poly_mul_bench c").into());
    let d = hash_to_point(&Sha256::digest(b"poly_mul_bench d").into());
    let e = hash_to_point(&Sha256::digest(b"poly_mul_bench e").into());

    let r1 = poly_mul_mod_q_karatsuba(&a, &b);
    let r2 = poly_mul_mod_q_karatsuba(&c, &d);
    let r3 = poly_mul_mod_q_karatsuba(&r1, &e);
    let r4 = poly_mul_mod_q_karatsuba(&r2, &a);
    let r5 = poly_mul_mod_q_karatsuba(&r3, &r4);

    let mut acc: i64 = 0;
    for v in r5 {
        acc = acc.wrapping_add(v);
    }
    env::commit(&acc);
}
