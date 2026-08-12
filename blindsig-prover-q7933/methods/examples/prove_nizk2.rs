// PHASE 4: a real, complete local zkVM prove + verify for NIZK2 at
// q=7933, using a GENUINE q7933-reference-produced signature as the
// witness - not a fabricated (t,s0,s1) triple. The signature was
// produced by BLIND/q7933-reference/rust_crosscheck_dump_512.cpp via the
// new sign_target() API (added specifically so a real signer can sign an
// opaque blinded target without ever hashing a message itself), signing
// the EXACT c=B*r+H(rho,mu) this file's own blinded_target_data.rs
// computed using the real guest-side computation path (r=0, so this is a
// degenerate-but-genuine blinding instance - see that file's own
// comment). C++-side sign_target()/verify_target() already accepted this
// signature before the data file was written; this is the same relation
// re-checked inside a real zkVM guest.
//
// Run: RUST_LOG=info cargo run -p methods --release --example prove_nizk2
// (real STARK proving - the q=12289 sibling's own NIZK2 takes ~100s; this
// guest does 1 real multiplication (t*s0), now via Karatsuba rather than
// schoolbook - see poly_mul.rs's own comments for the real, measured
// cycle-count improvement this bought.)
//
// LIVE PROGRESS: see prove_nizk1.rs's own comment on RUST_LOG and why it
// reaches the actual proving work (the external r0vm subprocess), not
// just this process.

use risc0_zkvm::{default_prover, ExecutorEnv};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

include!("data/blinded_target_data.rs"); // B, R, RHO, MU, C (this file's own module doc)
include!("data/rust_crosscheck_data.rs"); // T, S0, S1, TARGET_C, BLINDED_S0, BLINDED_S1

fn prove_with_ticker(env: ExecutorEnv, elf: &[u8]) -> (risc0_zkvm::Receipt, f64) {
    let start = Instant::now();
    let done = Arc::new(AtomicBool::new(false));
    let done_ticker = done.clone();
    let ticker = std::thread::spawn(move || {
        while !done_ticker.load(Ordering::Relaxed) {
            eprint!("\r  ...still proving, {:>6.1}s elapsed", start.elapsed().as_secs_f64());
            std::io::stderr().flush().ok();
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        eprintln!();
    });
    let receipt = default_prover().prove(env, elf).unwrap().receipt;
    done.store(true, Ordering::Relaxed);
    ticker.join().ok();
    (receipt, start.elapsed().as_secs_f64())
}

// Mirrors methods/guest/src/main.rs's own Nizk2Input/Nizk2PublicOutput
// exactly - same duplication-on-purpose convention as prove_nizk1.rs.
#[derive(Serialize)]
struct Nizk2Input {
    t: Vec<u16>,
    b: Vec<u16>,
    r: Vec<i32>,
    s0: Vec<i32>,
    s1: Vec<i32>,
    rho: Vec<u8>,
    mu: String,
}

#[derive(Deserialize)]
struct Nizk2PublicOutput {
    #[allow(dead_code)]
    t: Vec<u16>,
    #[allow(dead_code)]
    b: Vec<u16>,
    #[allow(dead_code)]
    rho: Vec<u8>,
    #[allow(dead_code)]
    mu: String,
    valid: bool,
}

fn to_u16(v: &[i64]) -> Vec<u16> {
    v.iter().map(|&x| x.rem_euclid(7933) as u16).collect()
}

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .try_init();

    let input = Nizk2Input {
        t: to_u16(&T),
        b: to_u16(&B),
        r: R.to_vec(),
        s0: BLINDED_S0.iter().map(|&x| x as i32).collect(),
        s1: BLINDED_S1.iter().map(|&x| x as i32).collect(),
        rho: RHO.to_vec(),
        mu: MU.to_string(),
    };

    println!("Proving NIZK2 at q=7933 (real STARK proving, this will take a while)...");
    println!("(set RUST_LOG=info or RUST_LOG=debug for live segment-by-segment progress)");
    let env = ExecutorEnv::builder().write(&input).unwrap().build().unwrap();
    let (receipt, elapsed) = prove_with_ticker(env, methods::Q7933_GUEST_ELF);
    println!("NIZK2 prove: {elapsed:.1}s");

    receipt.verify(methods::Q7933_GUEST_ID).expect("receipt must verify");
    println!("NIZK2 receipt: verified");

    let output: Nizk2PublicOutput = receipt.journal.decode().unwrap();
    println!("NIZK2 committed valid = {}", output.valid);
    assert!(
        output.valid,
        "a genuine, C++-signed, C++-verified signature must also be valid inside the guest"
    );
    println!("PASS: real end-to-end NIZK2 prove+verify at q=7933, valid=true, using a genuine q7933-reference signature");
}
