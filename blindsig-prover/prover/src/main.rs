// blindsig-prover: the experimental blind-FALCON sidecar CLI. See
// tradep2p2/specs.txt SS9.3a and REVIEW_REQUEST.md (in the original
// research directory) for what this proves and why it's a separate
// process rather than something linked into the C++ mediator/client.
//
// Contract with the C++ callers (blindsig_subprocess.cpp): stdout is
// ALWAYS exactly one JSON object, on success or failure - never a Rust
// panic backtrace, never partial output. Progress/logging goes to
// stderr. This file's job is almost entirely enforcing that contract;
// the actual cryptographic logic lives in commands.rs and, underneath
// that, in prover-core (shared with the zkVM guest - see
// prover-core/src/lib.rs's module comment for why that sharing matters).
//
// Subcommands: user-blind, user-prove-nizk1, signer-verify-nizk1,
// user-finalize-prove-nizk2, verify-signature. See specs.txt SS9.3a for
// what each proves and the asymmetric cost model (proving is slow and
// entirely client-side; the signer's per-request cost is fast).

mod commands;
mod hex_codec;
mod schema;

use serde_json::{json, Value};

fn get_flag(args: &[String], name: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().cloned();
        }
    }
    None
}

fn print_json_and_exit(v: &Value) -> ! {
    let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
    println!("{}", v);
    std::process::exit(if ok { 0 } else { 1 });
}

fn run(subcommand: &str, args: &[String]) -> Value {
    match subcommand {
        "user-blind" => {
            let b_hex = match get_flag(args, "--b-hex") {
                Some(v) => v,
                None => return json!({"ok": false, "error": "missing --b-hex"}),
            };
            let mu = match (get_flag(args, "--mu"), get_flag(args, "--mu-file")) {
                (Some(m), _) => m,
                (None, Some(path)) => match std::fs::read_to_string(&path) {
                    Ok(s) => s,
                    Err(e) => return json!({"ok": false, "error": format!("could not read --mu-file {path}: {e}")}),
                },
                (None, None) => return json!({"ok": false, "error": "missing --mu or --mu-file"}),
            };
            commands::user_blind(&b_hex, mu)
        }
        "user-prove-nizk1" => {
            let out = match get_flag(args, "--pi1-out") {
                Some(v) => v,
                None => return json!({"ok": false, "error": "missing --pi1-out"}),
            };
            commands::user_prove_nizk1(&out)
        }
        "signer-verify-nizk1" => {
            let inp = match get_flag(args, "--pi1-in") {
                Some(v) => v,
                None => return json!({"ok": false, "error": "missing --pi1-in"}),
            };
            commands::signer_verify_nizk1(&inp)
        }
        "user-finalize-prove-nizk2" => {
            let out = match get_flag(args, "--pi2-out") {
                Some(v) => v,
                None => return json!({"ok": false, "error": "missing --pi2-out"}),
            };
            commands::user_finalize_prove_nizk2(&out)
        }
        "verify-signature" => {
            let inp = match get_flag(args, "--pi2-in") {
                Some(v) => v,
                None => return json!({"ok": false, "error": "missing --pi2-in"}),
            };
            commands::verify_signature(&inp)
        }
        other => json!({
            "ok": false,
            "error": format!(
                "unknown subcommand '{other}'; expected one of: user-blind, user-prove-nizk1, \
                 signer-verify-nizk1, user-finalize-prove-nizk2, verify-signature"
            )
        }),
    }
}

fn main() {
    // RISC0's own tracing output goes wherever RUST_LOG points it
    // (stderr by default via the standard fmt subscriber) - never stdout.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .try_init();

    let args: Vec<String> = std::env::args().collect();
    let subcommand = match args.get(1) {
        Some(s) => s.clone(),
        None => print_json_and_exit(&json!({
            "ok": false,
            "error": "usage: blindsig-prover <subcommand> [flags]"
        })),
    };
    let rest = args[2..].to_vec();

    // Last-resort safety net: this tool's stdout contract (always one
    // JSON object) must hold even if something below panics - both
    // verify subcommands process attacker-influenced files, so a crafted
    // input triggering an unexpected panic must still produce clean
    // JSON, not a bare non-zero exit with a Rust backtrace on stderr
    // that the C++ caller has no way to act on.
    let result = std::panic::catch_unwind(move || run(&subcommand, &rest));
    match result {
        Ok(v) => print_json_and_exit(&v),
        Err(_) => print_json_and_exit(&json!({"ok": false, "error": "internal error (panic) - see stderr"})),
    }
}
