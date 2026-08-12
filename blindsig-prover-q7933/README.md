# q=7933 RISC0 prover workspace

This workspace is the q=7933 BLNS23 counterpart of `../blindsig-prover/`.
It is intentionally separate from the shipped q=12289/FALCON path.

## Current checkpoint

The q=7933 guest/core path has now completed both real local STARK proof
checkpoints on the reference development machine:

- NIZK1: 689.0 s, receipt verified, committed `valid=true`.
- NIZK2: 294.2 s, receipt verified, committed `valid=true`, using the
  genuine q=7933 C++ `sign_target()` signature fixture.

The separate C++ reference substrate's plain-message `hash_to_point()`
has also been upgraded from its old `std::hash`/LCG placeholder to the
SHAKE256 rejection-sampling construction. Blind signing continues to use
`sign_target()` and does not hash a message inside the signer.

The q=7933 host CLI is now present and builds on the reference machine.
Its deterministic fast harness passed, and a real CLI NIZK2 run produced
a roughly 2 MiB receipt which `verify-signature` accepted with
`{"ok":true,"verified":true}`. The first instrumented NIZK2 harness run
also caught a host-integration bug: with `RUST_LOG=info`, tracing output
could contaminate stdout before the JSON response. The CLI now explicitly
routes tracing to stderr and explicitly flushes its single JSON stdout
response before exit. This is exactly the subprocess contract the future
C++ mediator relies on.

These are implementation/execution checkpoints, not a claim that the
remaining distributional/security-reduction validation work is complete.

## Workspace layout

- `prover-core/`: q=7933 arithmetic shared by native host code and guests.
- `methods/guest/`: NIZK1/NIZK2 RISC0 guest programs.
- `methods/examples/`: execution/proving/cross-language diagnostics.
- `prover/`: JSON-over-stdio host CLI for C++ mediator/client integration.
- `scripts/test_cli_deterministic.sh`: deterministic CLI regression harness.
- `scripts/analyze_cli_artifacts.py`: post-run inspection of retained CLI artifacts.

## CLI contract

Build:

```sh
cargo build -p blindsig-prover-q7933 --release
```

Binary:

```text
target/release/blindsig-prover-q7933
```

Subcommands intentionally mirror the q=12289 sidecar:

```text
user-blind --b-hex <hex> --mu <msg>
user-prove-nizk1 --pi1-out PATH
signer-verify-nizk1 --pi1-in PATH
user-finalize-prove-nizk2 --pi2-out PATH
verify-signature --pi2-in PATH
```

q=7933-specific differences are explicit in the JSON schemas: the public
key is `t` (not FALCON `h`) and NIZK2 carries both signature halves `s0`
and `s1`.

`user-blind` also accepts `--deterministic-seed-hex <64 hex chars>` for
regression tests. That switch deterministically derives the otherwise
independent `r`, encryption coins, `a`, and `pk` seeds with SHA-256 domain
separation. It prints a warning to stderr and must never be used for a
real credential.

stdout is always exactly one JSON object; progress and RISC0 logging go
to stderr.

## Deterministic CLI harness

The harness stores every request, response, stderr stream, receipt, exit
code, and a final SHA-256 manifest for later analysis.

Fast/no-proof pass:

```sh
bash scripts/test_cli_deterministic.sh fast
```

Real NIZK1 CLI proof/verify:

```sh
RUST_LOG=info bash scripts/test_cli_deterministic.sh nizk1
```

Real NIZK2 CLI proof/verify using the committed genuine C++ signature
fixture:

```sh
RUST_LOG=info bash scripts/test_cli_deterministic.sh nizk2
```

Both:

```sh
RUST_LOG=info bash scripts/test_cli_deterministic.sh full
```

By default artifacts land in `cli-test-artifacts/`; pass a second argument
to choose another directory. The fast mode runs `user-blind` twice with
identical inputs and requires byte-equivalent parsed JSON, then checks the
CLI's failure contract. The proof modes additionally persist `pi1.receipt`
or `pi2.receipt` and require the corresponding verify subcommand to return
`{"ok":true,"verified":true}`.

For an interrupted or partially-failed harness run, inspect everything it
left behind without rerunning an expensive proof:

```sh
python3 scripts/analyze_cli_artifacts.py cli-test-artifacts-nizk2
```

## Integration boundary

The Rust-side Phase 0 integration prerequisite is now complete enough to
hand to the C++ side: the stable subprocess entry point exists, q=7933
schemas are explicit, deterministic/error-contract testing exists, and
both underlying RISC0 guests have completed real STARK proof checkpoints.

The next repository phase is therefore the mediator-side q=7933 adapter:
a thin C++ wrapper over the existing trapdoor/signing substrate, a new
versioned encrypted keystore for `{f,g,F,G,t,B}`, and a long-lived signing
tree built once at mediator startup rather than once per signature. The
existing q=12289/FALCON keystore and signer path remain untouched.
