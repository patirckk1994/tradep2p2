// The five subcommand implementations. Every function here returns a
// serde_json::Value and NEVER panics on attacker-influenced input (a
// malformed --pi1-in/--pi2-in file, garbage stdin) - failures fold into
// {"ok":false,"error":...} or, for the two verify commands, into
// {"ok":true,"verified":false,"reason":...} (see module comment in
// main.rs for why that distinction matters to the C++ caller). main()
// wraps every call in catch_unwind as a last-resort net on top of this.

use crate::hex_codec::{bytes_to_hex, hex_to_bytes, hex_to_u16_vec};
use crate::schema::*;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use serde_json::{json, Value};
use std::io::Read;
use std::time::Instant;

fn err(msg: impl Into<String>) -> Value {
    json!({"ok": false, "error": msg.into()})
}

fn read_stdin() -> Result<String, String> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| format!("failed to read stdin: {e}"))?;
    Ok(buf)
}

// Progress goes to stderr, on a ticker thread, exactly like the original
// research prototype's host tools - but on stderr, not stdout, since
// stdout here must stay a single parseable JSON object for the C++
// caller.
fn prove_with_ticker(
    env: ExecutorEnv,
    elf: &[u8],
) -> Result<(risc0_zkvm::Receipt, f64), String> {
    let prover = default_prover();
    let start = Instant::now();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done_ticker = done.clone();
    let ticker = std::thread::spawn(move || {
        use std::io::Write;
        let tick_start = Instant::now();
        while !done_ticker.load(std::sync::atomic::Ordering::Relaxed) {
            eprint!("\r  ...still proving, {:>6.1}s elapsed", tick_start.elapsed().as_secs_f64());
            std::io::stderr().flush().ok();
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        eprintln!();
    });

    let result = prover.prove(env, elf);
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    ticker.join().ok();

    let prove_info = result.map_err(|e| format!("proving failed: {e}"))?;
    Ok((prove_info.receipt, start.elapsed().as_secs_f64()))
}

fn write_receipt(receipt: &Receipt, path: &str) -> Result<u64, String> {
    let bytes = bincode::serde::encode_to_vec(receipt, bincode::config::standard())
        .map_err(|e| format!("failed to serialize receipt: {e}"))?;
    std::fs::write(path, &bytes).map_err(|e| format!("failed to write {path}: {e}"))?;
    Ok(bytes.len() as u64)
}

// Loading + verifying + decoding a receipt file are all treated as
// "the submission was bad", never a tool crash - this path is fed files
// that ultimately originate from a network peer (via the C++ signer's
// --pi1-in, or anyone's --pi2-in), so it must degrade to a clean
// verified:false rather than propagate a parser/deserializer panic.
fn load_and_verify_receipt<T>(path: &str, image_id: [u32; 8]) -> Result<T, String>
where
    T: for<'de> serde::Deserialize<'de>,
{
    let bytes = std::fs::read(path).map_err(|e| format!("could not read {path}: {e}"))?;
    let (receipt, _): (Receipt, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
            .map_err(|e| format!("receipt file is not a valid receipt: {e}"))?;
    receipt
        .verify(image_id)
        .map_err(|e| format!("receipt did not verify: {e}"))?;
    receipt
        .journal
        .decode::<T>()
        .map_err(|e| format!("committed journal did not match the expected shape: {e}"))
}

fn u16_eq(a: &[u16], b: &[u16]) -> bool {
    a == b
}

// ---------------------------------------------------------------------
// user-blind
// ---------------------------------------------------------------------

pub fn user_blind(b_hex: &str, mu: String) -> Value {
    let b_u16 = match hex_to_u16_vec(b_hex) {
        Ok(v) if v.len() == prover_core::N => v,
        Ok(v) => return err(format!("--b-hex decoded to {} values, expected {}", v.len(), prover_core::N)),
        Err(e) => return err(format!("bad --b-hex: {e}")),
    };
    let b_i64: Vec<i64> = b_u16.iter().map(|&x| x as i64).collect();

    // Four independent 32-byte OS-random seeds - kept independent
    // (rather than all derived from one seed) to mirror the original
    // research prototype's design exactly: r/a/pk come from live
    // randomness, coins is its own independent 32 random bytes (the
    // paper's own named PKE randomness parameter).
    let mut r_seed = [0u8; 32];
    let mut coins = [0u8; 32];
    let mut a_seed = [0u8; 32];
    let mut pk_seed = [0u8; 32];
    for buf in [&mut r_seed, &mut coins, &mut a_seed, &mut pk_seed] {
        if getrandom::getrandom(buf).is_err() {
            return err("failed to obtain OS randomness");
        }
    }

    let r_i64 = prover_core::enc::short_poly_from_seed(&r_seed, "r");
    let r_i32: Vec<i32> = r_i64.iter().map(|&x| x as i32).collect();

    let rho = prover_core::g_of_r(&r_i32);
    let h_digest = prover_core::h_of_rho_mu(&rho, &mu);
    let hash_term = prover_core::hash_to_point(&h_digest);
    let br = prover_core::ntt::poly_mul_mod_q_ntt(&b_i64, &r_i64);
    let c = prover_core::add_mod_q(&br, &hash_term);

    let a = prover_core::enc::uniform_poly_from_seed(&a_seed, "a");
    let pk = prover_core::enc::uniform_poly_from_seed(&pk_seed, "pk");
    let ct = prover_core::enc::generate_ciphertexts(&coins, &r_i64, &mu, &a, &pk);

    let to_u16 = |v: &[i64]| -> Vec<u16> { v.iter().map(|&x| x as u16).collect() };

    let instance = BlindInstance {
        public: PublicBlindRequest {
            b: b_u16,
            c: to_u16(&c),
            rho_hex: bytes_to_hex(&rho),
            enc_a: to_u16(&a),
            enc_pk: to_u16(&pk),
            ct1_r: to_u16(&ct.ct1_r),
            ct2_r: to_u16(&ct.ct2_r),
            ct1_mu: to_u16(&ct.ct1_mu),
            ct2_mu: to_u16(&ct.ct2_mu),
        },
        private: PrivateBlindWitness {
            r: r_i32,
            mu,
            coins_hex: bytes_to_hex(&coins),
        },
    };

    match serde_json::to_value(&instance) {
        Ok(mut v) => {
            v.as_object_mut().unwrap().insert("ok".to_string(), json!(true));
            v
        }
        Err(e) => err(format!("internal: failed to serialize instance: {e}")),
    }
}

// ---------------------------------------------------------------------
// user-prove-nizk1
// ---------------------------------------------------------------------

pub fn user_prove_nizk1(pi1_out: &str) -> Value {
    let raw = match read_stdin() {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let instance: BlindInstance = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => return err(format!("bad instance JSON on stdin: {e}")),
    };
    let coins = match hex_to_bytes(&instance.private.coins_hex) {
        Ok(v) => v,
        Err(e) => return err(format!("bad coins_hex: {e}")),
    };

    let input = Nizk1Input {
        b: instance.public.b,
        c: instance.public.c,
        enc_a: instance.public.enc_a,
        enc_pk: instance.public.enc_pk,
        ct1_r: instance.public.ct1_r,
        ct2_r: instance.public.ct2_r,
        ct1_mu: instance.public.ct1_mu,
        ct2_mu: instance.public.ct2_mu,
        r: instance.private.r,
        mu: instance.private.mu,
        coins,
    };

    let env = match ExecutorEnv::builder().write(&input) {
        Ok(b) => match b.build() {
            Ok(e) => e,
            Err(e) => return err(format!("failed to build executor env: {e}")),
        },
        Err(e) => return err(format!("failed to write guest input: {e}")),
    };

    eprintln!("proving NIZK1 (blinding relation + encryption-to-the-sky)...");
    let (receipt, elapsed) = match prove_with_ticker(env, methods::NIZK1_ELF) {
        Ok(r) => r,
        Err(e) => return err(e),
    };

    if let Err(e) = receipt.verify(methods::NIZK1_ID) {
        return err(format!("self-generated receipt failed to verify (this should never happen): {e}"));
    }

    let size_bytes = match write_receipt(&receipt, pi1_out) {
        Ok(n) => n,
        Err(e) => return err(e),
    };

    json!({
        "ok": true,
        "elapsed_seconds": elapsed,
        "pi1_path": pi1_out,
        "pi1_size_bytes": size_bytes,
    })
}

// ---------------------------------------------------------------------
// signer-verify-nizk1
// ---------------------------------------------------------------------

pub fn signer_verify_nizk1(pi1_in: &str) -> Value {
    let raw = match read_stdin() {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let expected: Nizk1ExpectedPublic = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => return err(format!("bad expected-fields JSON on stdin: {e}")),
    };

    let output: Nizk1PublicOutput = match load_and_verify_receipt(pi1_in, methods::NIZK1_ID) {
        Ok(o) => o,
        Err(reason) => return json!({"ok": true, "verified": false, "reason": reason}),
    };

    if !output.valid {
        return json!({"ok": true, "verified": false, "reason": "guest computed valid=false"});
    }
    let fields_match = u16_eq(&output.b, &expected.b)
        && u16_eq(&output.c, &expected.c)
        && u16_eq(&output.enc_a, &expected.enc_a)
        && u16_eq(&output.enc_pk, &expected.enc_pk)
        && u16_eq(&output.ct1_r, &expected.ct1_r)
        && u16_eq(&output.ct2_r, &expected.ct2_r)
        && u16_eq(&output.ct1_mu, &expected.ct1_mu)
        && u16_eq(&output.ct2_mu, &expected.ct2_mu);
    if !fields_match {
        return json!({
            "ok": true, "verified": false,
            "reason": "receipt is valid but its committed public values do not match what was submitted"
        });
    }

    json!({"ok": true, "verified": true})
}

// ---------------------------------------------------------------------
// user-finalize-prove-nizk2
// ---------------------------------------------------------------------

pub fn user_finalize_prove_nizk2(pi2_out: &str) -> Value {
    let raw = match read_stdin() {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let req: FinalizeNizk2Request = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => return err(format!("bad request JSON on stdin: {e}")),
    };
    let rho = match hex_to_bytes(&req.rho_hex) {
        Ok(v) => v,
        Err(e) => return err(format!("bad rho_hex: {e}")),
    };

    let input = Nizk2Input {
        h: req.h,
        b: req.b,
        r: req.r,
        sig: req.s,
        rho,
        mu: req.mu,
    };

    let env = match ExecutorEnv::builder().write(&input) {
        Ok(b) => match b.build() {
            Ok(e) => e,
            Err(e) => return err(format!("failed to build executor env: {e}")),
        },
        Err(e) => return err(format!("failed to write guest input: {e}")),
    };

    eprintln!("proving NIZK2 (final signature relation)...");
    let (receipt, elapsed) = match prove_with_ticker(env, methods::BLINDSIG_GUEST_ELF) {
        Ok(r) => r,
        Err(e) => return err(e),
    };

    if let Err(e) = receipt.verify(methods::BLINDSIG_GUEST_ID) {
        return err(format!("self-generated receipt failed to verify (this should never happen): {e}"));
    }

    let size_bytes = match write_receipt(&receipt, pi2_out) {
        Ok(n) => n,
        Err(e) => return err(e),
    };

    json!({
        "ok": true,
        "elapsed_seconds": elapsed,
        "pi2_path": pi2_out,
        "pi2_size_bytes": size_bytes,
    })
}

// ---------------------------------------------------------------------
// verify-signature
// ---------------------------------------------------------------------

pub fn verify_signature(pi2_in: &str) -> Value {
    let raw = match read_stdin() {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let expected: VerifySignatureExpected = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => return err(format!("bad expected-fields JSON on stdin: {e}")),
    };
    let expected_rho = match hex_to_bytes(&expected.rho_hex) {
        Ok(v) => v,
        Err(e) => return err(format!("bad rho_hex: {e}")),
    };

    let output: Nizk2PublicOutput = match load_and_verify_receipt(pi2_in, methods::BLINDSIG_GUEST_ID) {
        Ok(o) => o,
        Err(reason) => return json!({"ok": true, "verified": false, "reason": reason}),
    };

    let fields_match = u16_eq(&output.h, &expected.h)
        && u16_eq(&output.b, &expected.b)
        && output.rho == expected_rho
        && output.mu == expected.mu;

    json!({"ok": true, "verified": output.valid && fields_match})
}
