// PHASE 2 EMPIRICAL GATE - measures real zkVM execution cycle counts
// (via RISC0's execute-only path, NOT a full STARK prove - see
// risc0_zkvm::default_executor()'s own docs) for the benchmark guests
// this crate builds: schoolbook and Karatsuba multiplication at q=7933
// vs. the existing, real NTT multiplication at q=12289
// (NTT_BENCH_Q12289_ELF, methods/guest/src/bin/ntt_bench_q12289.rs) -
// same benchmark shape (5 degree-512 polynomial multiplications) across
// all three, different algorithm/modulus.
//
// Run: cargo run -p methods --release --example cycle_count
//
// FIXED A REAL STALENESS BUG while adding the Karatsuba measurement:
// this file originally read `methods::Q7933_GUEST_ELF` for the
// schoolbook benchmark, back when methods/guest/src/main.rs WAS that
// benchmark. main.rs was later repurposed into the real NIZK2 guest
// (Phase 3), and the schoolbook benchmark moved to its own
// bin/poly_mul_cycle_bench.rs - but this file's constant reference was
// never updated, so re-running it as-is would have silently measured the
// real NIZK2 guest's cycles instead of the intended benchmark, without
// any compile error (Q7933_GUEST_ELF still exists, just means something
// different now). Caught by reading this file carefully before reusing
// it, not by a failure at runtime.

use methods::{KARATSUBA_CYCLE_BENCH_ELF, NTT_BENCH_Q12289_ELF, POLY_MUL_CYCLE_BENCH_ELF};
use risc0_zkvm::{default_executor, ExecutorEnv};

fn measure(label: &str, elf: &[u8]) -> u64 {
    let env = ExecutorEnv::builder().build().unwrap();
    let session = default_executor().execute(env, elf).unwrap();
    let cycles = session.cycles();
    println!("{label}: {cycles} cycles");
    cycles
}

fn main() {
    let ntt_cycles = measure("NTT at q=12289 (5x poly_mul_mod_q_ntt)", NTT_BENCH_Q12289_ELF);
    let schoolbook_cycles = measure(
        "schoolbook at q=7933 (5x poly_mul_mod_q_schoolbook)",
        POLY_MUL_CYCLE_BENCH_ELF,
    );
    let karatsuba_cycles = measure(
        "Karatsuba at q=7933 (5x poly_mul_mod_q_karatsuba)",
        KARATSUBA_CYCLE_BENCH_ELF,
    );

    println!(
        "schoolbook/NTT cycle ratio: {:.2}x",
        schoolbook_cycles as f64 / ntt_cycles as f64
    );
    println!(
        "karatsuba/NTT cycle ratio:  {:.2}x",
        karatsuba_cycles as f64 / ntt_cycles as f64
    );
    println!(
        "karatsuba/schoolbook speedup: {:.2}x fewer cycles",
        schoolbook_cycles as f64 / karatsuba_cycles as f64
    );
}
