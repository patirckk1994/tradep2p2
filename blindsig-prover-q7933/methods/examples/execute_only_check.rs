// Cheap execute-only check of the REAL NIZK1 and NIZK2 guest binaries
// (main.rs / bin/nizk1.rs) - as opposed to prove_nizk1.rs/prove_nizk2.rs's
// full STARK proving, or cycle_count.rs's separate, simpler benchmark
// guests (poly_mul in a loop, not the real relation-checking logic).
//
// This is the first time the ACTUAL guest code (env::read() deserializing
// the real Nizk1Input/Nizk2Input structs, the real relation/encryption
// checks, env::commit()) has been executed at all, in any form - the
// host-side unit tests (prover-core/tests/) only ever exercised the
// EXTRACTED relation_holds()/norm_squared() functions directly, never the
// guest binary's own control flow or the host<->guest serialization
// boundary. default_executor().execute() runs the identical guest code
// against identical inputs as a full prove would, just without spending
// the time generating an actual STARK proof - same bug-catching power,
// a fraction of the cost.
//
// Run: cargo run -p methods --release --example execute_only_check

use prover_core::{add_mod_q, enc, g_of_r, h_of_rho_mu, hash_to_point, poly_mul::poly_mul_mod_q_schoolbook};
use risc0_zkvm::{default_executor, ExecutorEnv};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

// Must match bin/nizk1.rs's own Nizk1PublicOutput EXACTLY, field-for-field
// in order - postcard's encoding is positional, so a struct that only
// declares a suffix of the real fields misreads the whole byte stream
// from the start, not just the missing fields (caught by this exact
// check on the first run: decoding with only `valid: bool` produced
// DeserializeBadBool, not a clean "missing field" error).
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

// Must match main.rs's own Nizk2PublicOutput exactly - same reasoning as
// Nizk1PublicOutput above.
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

include!("data/blinded_target_data.rs"); // B, R, RHO, MU, C
include!("data/rust_crosscheck_data.rs"); // T, S0, S1, TARGET_C, BLINDED_S0, BLINDED_S1

fn check_nizk1() {
    let coins: [u8; 32] = Sha256::digest(b"execute_only_check nizk1 coins").into();
    let r_i64 = enc::short_poly_from_seed(&coins, "r");
    let mu = "execute_only_check nizk1 message";

    let a_seed: [u8; 32] = Sha256::digest(b"execute_only_check nizk1 a").into();
    let pk_seed: [u8; 32] = Sha256::digest(b"execute_only_check nizk1 pk").into();
    let a = enc::uniform_poly_from_seed(&a_seed, "a");
    let pk = enc::uniform_poly_from_seed(&pk_seed, "pk");

    let b_seed: [u8; 32] = Sha256::digest(b"execute_only_check nizk1 b").into();
    let b = enc::uniform_poly_from_seed(&b_seed, "b");

    let ct = enc::generate_ciphertexts(&coins, &r_i64, mu, &a, &pk);

    let br = poly_mul_mod_q_schoolbook(&b, &r_i64);
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

    let env = ExecutorEnv::builder().write(&input).unwrap().build().unwrap();
    let session = default_executor().execute(env, methods::NIZK1_ELF).unwrap();
    println!("NIZK1 execute: {} cycles", session.cycles());
    let output: Nizk1PublicOutput = session.journal.decode().unwrap();
    println!("NIZK1 committed valid = {}", output.valid);
    assert!(output.valid, "NIZK1 guest rejected a genuinely well-formed instance");
    println!("PASS: real NIZK1 guest code executes correctly end-to-end\n");
}

fn check_nizk2() {
    let input = Nizk2Input {
        t: to_u16(&T),
        b: to_u16(&B),
        r: R.to_vec(),
        s0: BLINDED_S0.iter().map(|&x| x as i32).collect(),
        s1: BLINDED_S1.iter().map(|&x| x as i32).collect(),
        rho: RHO.to_vec(),
        mu: MU.to_string(),
    };

    let env = ExecutorEnv::builder().write(&input).unwrap().build().unwrap();
    let session = default_executor().execute(env, methods::Q7933_GUEST_ELF).unwrap();
    println!("NIZK2 execute: {} cycles", session.cycles());
    let output: Nizk2PublicOutput = session.journal.decode().unwrap();
    println!("NIZK2 committed valid = {}", output.valid);
    assert!(
        output.valid,
        "NIZK2 guest rejected a genuine, C++-signed, C++-verified signature"
    );
    println!("PASS: real NIZK2 guest code executes correctly end-to-end, using a genuine q7933-reference signature\n");
}

fn main() {
    check_nizk1();
    check_nizk2();
    println!("ALL EXECUTE-ONLY CHECKS PASSED - both real guest binaries run correctly on real inputs");
}
