// The five q=7933 sidecar subcommands. The shape intentionally mirrors
// blindsig-prover/prover/src/commands.rs, but the arithmetic and NIZK2
// schema are this branch's own: q=7933 Karatsuba multiplication, public
// key t=f*g^-1, and explicit signature halves s0/s1.

use crate::hex_codec::{bytes_to_hex, hex_to_bytes, hex_to_u16_vec};
use crate::schema::*;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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

fn validate_u16_poly(name: &str, v: &[u16]) -> Result<(), String> {
    if v.len() != prover_core::N {
        return Err(format!("{name} has {} coefficients, expected {}", v.len(), prover_core::N));
    }
    if let Some((i, value)) = v
        .iter()
        .enumerate()
        .find(|(_, value)| (**value as i64) >= prover_core::Q)
    {
        return Err(format!("{name}[{i}]={value} is outside canonical range 0..{}", prover_core::Q));
    }
    Ok(())
}

fn validate_i32_poly(name: &str, v: &[i32]) -> Result<(), String> {
    if v.len() != prover_core::N {
        return Err(format!("{name} has {} coefficients, expected {}", v.len(), prover_core::N));
    }
    Ok(())
}

fn validate_nizk1_instance(instance: &BlindInstance, coins: &[u8]) -> Result<(), String> {
    validate_u16_poly("b", &instance.public.b)?;
    validate_u16_poly("c", &instance.public.c)?;
    validate_u16_poly("enc_a", &instance.public.enc_a)?;
    validate_u16_poly("enc_pk", &instance.public.enc_pk)?;
    validate_u16_poly("ct1_r", &instance.public.ct1_r)?;
    validate_u16_poly("ct2_r", &instance.public.ct2_r)?;
    validate_u16_poly("ct1_mu", &instance.public.ct1_mu)?;
    validate_u16_poly("ct2_mu", &instance.public.ct2_mu)?;
    validate_i32_poly("r", &instance.private.r)?;
    if coins.len() != 32 {
        return Err(format!("coins_hex decoded to {} bytes, expected 32", coins.len()));
    }
    Ok(())
}

fn deterministic_seed(root: &[u8], label: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tradep2p-q7933-cli-deterministic-test-v1\0");
    h.update(label);
    h.update([0u8]);
    h.update(root);
    h.finalize().into()
}

fn blind_seeds(deterministic_seed_hex: Option<&str>) -> Result<([u8; 32], [u8; 32], [u8; 32], [u8; 32]), String> {
    if let Some(seed_hex) = deterministic_seed_hex {
        let root = hex_to_bytes(seed_hex).map_err(|e| format!("bad --deterministic-seed-hex: {e}"))?;
        if root.len() != 32 {
            return Err(format!(
                "--deterministic-seed-hex decoded to {} bytes, expected exactly 32",
                root.len()
            ));
        }
        eprintln!("WARNING: deterministic test seed enabled; never use this mode for a real credential");
        return Ok((
            deterministic_seed(&root, b"r"),
            deterministic_seed(&root, b"coins"),
            deterministic_seed(&root, b"a"),
            deterministic_seed(&root, b"pk"),
        ));
    }

    let mut r_seed = [0u8; 32];
    let mut coins = [0u8; 32];
    let mut a_seed = [0u8; 32];
    let mut pk_seed = [0u8; 32];
    for buf in [&mut r_seed, &mut coins, &mut a_seed, &mut pk_seed] {
        getrandom::getrandom(buf).map_err(|_| "failed to obtain OS randomness".to_string())?;
    }
    Ok((r_seed, coins, a_seed, pk_seed))
}

// ---------------------------------------------------------------------
// user-blind
// ---------------------------------------------------------------------

pub fn user_blind(b_hex: &str, mu: String, deterministic_seed_hex: Option<&str>) -> Value {
    let b_u16 = match hex_to_u16_vec(b_hex) {
        Ok(v) => v,
        Err(e) => return err(format!("bad --b-hex: {e}")),
    };
    if let Err(e) = validate_u16_poly("--b-hex", &b_u16) {
        return err(e);
    }
    let b_i64: Vec<i64> = b_u16.iter().map(|&x| x as i64).collect();

    let (r_seed, coins, a_seed, pk_seed) = match blind_seeds(deterministic_seed_hex) {
        Ok(v) => v,
        Err(e) => return err(e),
    };

    let r_i64 = prover_core::enc::short_poly_from_seed(&r_seed, "r");
    let r_i32: Vec<i32> = r_i64.iter().map(|&x| x as i32).collect();

    let rho = prover_core::g_of_r(&r_i32);
    let h_digest = prover_core::h_of_rho_mu(&rho, &mu);
    let hash_term = prover_core::hash_to_point(&h_digest);
    let br = prover_core::poly_mul::poly_mul_mod_q_karatsuba(&b_i64, &r_i64);
    let c = prover_core::add_mod_q(&br, &hash_term);

    let a = prover_core::enc::uniform_poly_from_seed(&a_seed, "a");
    let pk = prover_core::enc::uniform_poly_from_seed(&pk_seed, "pk");
    let ct = prover_core::enc::generate_ciphertexts(&coins, &r_i64, &mu, &a, &pk);

    let to_u16 = |v: &[i64]| -> Vec<u16> {
        v.iter()
            .map(|&x| x.rem_euclid(prover_core::Q) as u16)
            .collect()
    };

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
    if let Err(e) = validate_nizk1_instance(&instance, &coins) {
        return err(e);
    }

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

    eprintln!("proving q=7933 NIZK1 (blinding relation + encryption-to-the-sky)...");
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
    let fields_match = output.b == expected.b
        && output.c == expected.c
        && output.enc_a == expected.enc_a
        && output.enc_pk == expected.enc_pk
        && output.ct1_r == expected.ct1_r
        && output.ct2_r == expected.ct2_r
        && output.ct1_mu == expected.ct1_mu
        && output.ct2_mu == expected.ct2_mu;
    if !fields_match {
        return json!({
            "ok": true,
            "verified": false,
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
    if let Err(e) = validate_u16_poly("t", &req.t) {
        return err(e);
    }
    if let Err(e) = validate_u16_poly("b", &req.b) {
        return err(e);
    }
    if let Err(e) = validate_i32_poly("r", &req.r) {
        return err(e);
    }
    if let Err(e) = validate_i32_poly("s0", &req.s0) {
        return err(e);
    }
    if let Err(e) = validate_i32_poly("s1", &req.s1) {
        return err(e);
    }
    if !prover_core::r_in_bounds(&req.r) {
        return err("r is outside the protocol coefficient bound [-2,2]");
    }
    let rho = match hex_to_bytes(&req.rho_hex) {
        Ok(v) if v.len() == 32 => v,
        Ok(v) => return err(format!("rho_hex decoded to {} bytes, expected 32", v.len())),
        Err(e) => return err(format!("bad rho_hex: {e}")),
    };

    // Any signature satisfying the total norm bound necessarily satisfies
    // this per-coefficient bound. Rejecting impossible inputs here avoids
    // spending minutes proving a statement that can only commit false.
    let individually_possible = req.s0.iter().chain(req.s1.iter()).all(|&x| {
        let x64 = i64::from(x);
        x64 * x64 <= prover_core::NORM_BOUND_SQUARED
    });
    if !individually_possible {
        return err("s0/s1 contains a coefficient that alone exceeds the q=7933 signature norm bound");
    }

    let input = Nizk2Input {
        t: req.t,
        b: req.b,
        r: req.r,
        s0: req.s0,
        s1: req.s1,
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

    eprintln!("proving q=7933 NIZK2 (t*s0+s1 relation + norm bound)...");
    let (receipt, elapsed) = match prove_with_ticker(env, methods::Q7933_GUEST_ELF) {
        Ok(r) => r,
        Err(e) => return err(e),
    };

    if let Err(e) = receipt.verify(methods::Q7933_GUEST_ID) {
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
        Ok(v) if v.len() == 32 => v,
        Ok(v) => return err(format!("rho_hex decoded to {} bytes, expected 32", v.len())),
        Err(e) => return err(format!("bad rho_hex: {e}")),
    };

    let output: Nizk2PublicOutput = match load_and_verify_receipt(pi2_in, methods::Q7933_GUEST_ID) {
        Ok(o) => o,
        Err(reason) => return json!({"ok": true, "verified": false, "reason": reason}),
    };

    let fields_match = output.t == expected.t
        && output.b == expected.b
        && output.rho == expected_rho
        && output.mu == expected.mu;

    json!({"ok": true, "verified": output.valid && fields_match})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_seed_derivation_is_stable_and_domain_separated() {
        let root: Vec<u8> = (0u8..32u8).collect();
        let r1 = deterministic_seed(&root, b"r");
        let r2 = deterministic_seed(&root, b"r");
        let coins = deterministic_seed(&root, b"coins");
        assert_eq!(r1, r2);
        assert_ne!(r1, coins);
    }

    #[test]
    fn rejects_noncanonical_ring_coefficient() {
        let mut p = vec![0u16; prover_core::N];
        p[17] = prover_core::Q as u16;
        assert!(validate_u16_poly("p", &p).is_err());
    }
}
