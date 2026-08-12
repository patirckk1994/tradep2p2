// PHASE 4: a real, complete local zkVM prove + verify for NIZK1 at
// q=7933 - fully self-contained (NIZK1 never touches the signature
// scheme at all, only the blinding relation + encryption-to-the-sky, so
// no C++ cross-language data is needed here, unlike prove_nizk2.rs).
//
// Run: RUST_LOG=info cargo run -p methods --release --example prove_nizk1
// (real STARK proving - expect this to take a while, now Karatsuba
// rather than schoolbook - see poly_mul.rs's own comments for the real,
// measured cycle-count improvement this bought.)
//
// LIVE PROGRESS: RUST_LOG=info (or =debug for more detail) shows real
// segment-by-segment progress, not just a spinner - the actual proving
// work happens inside the external r0vm subprocess (default features =
// IPC, not the in-process LocalProver), which has its own
// tracing_subscriber reading RUST_LOG from the environment it inherits
// (confirmed by inspecting the r0vm binary directly - it links
// tracing-subscriber's EnvFilter::from_default_env - not assumed). This
// process's own tracing_subscriber below covers this process's own
// tracing calls (currently none) and matches the q=12289 sibling's own
// prover/src/main.rs setup; the always-visible elapsed-time ticker
// beneath it works regardless of RUST_LOG.

use prover_core::{add_mod_q, enc, g_of_r, h_of_rho_mu, hash_to_point, poly_mul::poly_mul_mod_q_karatsuba};
use risc0_zkvm::{default_prover, ExecutorEnv};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

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

// Mirrors methods/guest/src/bin/nizk1.rs's own Nizk1Input/Nizk1PublicOutput
// exactly - same duplication-on-purpose convention the q=12289 sibling's
// own prover/src/schema.rs already established ("so the schema can be
// visually diffed" against the guest's own struct).
#[derive(Serialize)]
struct Nizk1Input {
    b: Vec<u16>,
    c: Vec<u16>,
    enc_a: Vec<u16>,
    enc_pk: Vec<u16>,
    ct1_r: Vec<u16>,
    ct2_r: Vec<u16>,
    ct1_mu: Vec<u16>,
    ct2_mu: Vec<u16>,
    r: Vec<i32>,
    mu: String,
    coins: Vec<u8>,
}

#[derive(Deserialize)]
struct Nizk1PublicOutput {
    #[allow(dead_code)]
    b: Vec<u16>,
    #[allow(dead_code)]
    c: Vec<u16>,
    #[allow(dead_code)]
    enc_a: Vec<u16>,
    #[allow(dead_code)]
    enc_pk: Vec<u16>,
    #[allow(dead_code)]
    ct1_r: Vec<u16>,
    #[allow(dead_code)]
    ct2_r: Vec<u16>,
    #[allow(dead_code)]
    ct1_mu: Vec<u16>,
    #[allow(dead_code)]
    ct2_mu: Vec<u16>,
    valid: bool,
}

fn to_u16(v: &[i64]) -> Vec<u16> {
    v.iter().map(|&x| x.rem_euclid(7933) as u16).collect()
}

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .try_init();

    // Fixed, reproducible seed - matches this whole project's own
    // established diagnostic convention (fixed seeds throughout the C++
    // q7933-reference track) rather than fresh OS randomness, so this
    // example's result is exactly reproducible run to run.
    let coins: [u8; 32] = Sha256::digest(b"prove_nizk1 example coins").into();

    let r_i64 = enc::short_poly_from_seed(&coins, "r");
    let mu = "prove_nizk1 example message";

    let a_seed: [u8; 32] = Sha256::digest(b"prove_nizk1 example a").into();
    let pk_seed: [u8; 32] = Sha256::digest(b"prove_nizk1 example pk").into();
    let a = enc::uniform_poly_from_seed(&a_seed, "a");
    let pk = enc::uniform_poly_from_seed(&pk_seed, "pk");

    let b_seed: [u8; 32] = Sha256::digest(b"prove_nizk1 example b").into();
    let b = enc::uniform_poly_from_seed(&b_seed, "b");

    let ct = enc::generate_ciphertexts(&coins, &r_i64, mu, &a, &pk);

    // Recompute c exactly as the guest itself will (see main.rs/nizk1.rs's
    // own identical computation) - this is what a genuine client would
    // send the signer, and what the guest re-derives and checks.
    let br = poly_mul_mod_q_karatsuba(&b, &r_i64);
    let r_i32: Vec<i32> = r_i64.iter().map(|&x| x as i32).collect();
    let rho = g_of_r(&r_i32);
    let h_digest = h_of_rho_mu(&rho, mu);
    let hash_term = hash_to_point(&h_digest);
    let c = add_mod_q(&br, &hash_term);

    let input = Nizk1Input {
        b: to_u16(&b),
        c: to_u16(&c),
        enc_a: to_u16(&a),
        enc_pk: to_u16(&pk),
        ct1_r: to_u16(&ct.ct1_r),
        ct2_r: to_u16(&ct.ct2_r),
        ct1_mu: to_u16(&ct.ct1_mu),
        ct2_mu: to_u16(&ct.ct2_mu),
        r: r_i32,
        mu: mu.to_string(),
        coins: coins.to_vec(),
    };

    println!("Proving NIZK1 at q=7933 (real STARK proving, this will take a while)...");
    println!("(set RUST_LOG=info or RUST_LOG=debug for live segment-by-segment progress)");
    let env = ExecutorEnv::builder().write(&input).unwrap().build().unwrap();
    let (receipt, elapsed) = prove_with_ticker(env, methods::NIZK1_ELF);
    println!("NIZK1 prove: {elapsed:.1}s");

    receipt.verify(methods::NIZK1_ID).expect("receipt must verify");
    println!("NIZK1 receipt: verified");

    let output: Nizk1PublicOutput = receipt.journal.decode().unwrap();
    println!("NIZK1 committed valid = {}", output.valid);
    assert!(output.valid, "a genuinely well-formed NIZK1 instance must be valid");
    println!("PASS: real end-to-end NIZK1 prove+verify at q=7933, valid=true");
}
