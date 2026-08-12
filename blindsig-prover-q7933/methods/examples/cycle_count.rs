// PHASE 2 EMPIRICAL GATE - measures real zkVM execution cycle counts
// (via RISC0's execute-only path, NOT a full STARK prove - see
// risc0_zkvm::default_executor()'s own docs) for the two benchmark guests
// this crate builds: schoolbook multiplication at q=7933
// (Q7933_GUEST_ELF, methods/guest/src/main.rs) vs. the existing, real NTT
// multiplication at q=12289 (NTT_BENCH_Q12289_ELF,
// methods/guest/src/bin/ntt_bench_q12289.rs) - same benchmark shape (5
// degree-512 polynomial multiplications), different algorithm/modulus.
//
// Run: cargo run -p methods --release --example cycle_count
//
// The result decides whether schoolbook is the final answer for this
// project's q=7933 port, or whether a faster non-NTT approach (Karatsuba)
// needs to be built instead - see swift-purring-wozniak.md's Phase 2.

use methods::{NTT_BENCH_Q12289_ELF, Q7933_GUEST_ELF};
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
    let schoolbook_cycles = measure("schoolbook at q=7933 (5x poly_mul_mod_q_schoolbook)", Q7933_GUEST_ELF);

    let ratio = schoolbook_cycles as f64 / ntt_cycles as f64;
    println!("schoolbook/NTT cycle ratio: {ratio:.2}x");
}
