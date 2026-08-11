# BLIND — experimental post-quantum blind-signature research & integration

This folder holds the research and reviewer-facing documentation for the
experimental blind-signature primitive described in `specs.txt` §9.3a. The
actual code lives elsewhere in this repo:

- `../blindsig-prover/` — the Rust workspace implementing NIZK1 and NIZK2
  (RISC0 zkVM proofs) over real FALCON-512 trapdoor sampling. Built,
  release-tested, and independently regression-tested (NTT correctness,
  encryption negative control) as of this writing.
- `../third_party/falcon-impl-20211101/` — the vendored, unmodified
  official FALCON C reference implementation both the Rust and C++ sides
  build against.
- `../include/tradep2p/blindsig_*.hpp` / `../src/blindsig_*.cpp` — the C++
  integration into the mediator/client. **In progress, not complete** —
  see "Current status" below before assuming anything here is wired up.

Read `REVIEW_REQUEST.md` if you're reviewing the cryptography.
Read `RESEARCH_STATUS.md` for the full research history and open
questions (parameter fidelity is the big one — see that file).

## Current status (branch `PQR-BLINDSIG`) — NOT finished, NOT deployable

Being upfront rather than letting this folder imply more than is true:

**Done and independently verified right now (compiled AND runtime-tested, not just written):**
- The `blindsig-prover` CLI (`user-blind`, `user-prove-nizk1`,
  `signer-verify-nizk1`, `user-finalize-prove-nizk2`, `verify-signature`)
  builds and runs. A real NIZK1 proof has been generated and verified
  end-to-end (212.1s, 1.73MB receipt).
- `blindsig_wire.hpp/cpp` (wire structs, codec, chunk reassembly) —
  compiles clean against the real headers.
- `blindsig_falcon.hpp/cpp` (the FALCON keygen/sign/verify wrapper) —
  compiles AND runtime-verified: 3 fresh-keypair sign+verify round-trips,
  plus a correct negative control (a signature must not verify against an
  unrelated random target - it doesn't).
- `blindsig_keystore.hpp/cpp` (AEAD-encrypted trapdoor custody) —
  compiles AND runtime-verified: create/unlock round-trips exactly,
  creating over an existing file is rejected, wrong passphrase is
  rejected, a tampered ciphertext byte is rejected.

**Not done yet — this is the majority of the actual integration:**
- The subprocess bridge to `blindsig-prover` (`blindsig_subprocess.hpp/cpp`)
- The mediator's signing queue (`blindsig_signer.hpp/cpp`)
- The client-side session logic (`blindsig_client.hpp/cpp`)
- `CMakeLists.txt` wiring (the `TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL`
  option doesn't exist yet - none of the files above are built into any
  binary yet, they've only been compile-checked standalone)
- Any of `lobby.cpp` / `main.cpp` / `http_dashboard.cpp` actually calling
  into any of the above
- `setup_mediator.sh` flags
- The `specs.txt` §9.3a section itself, and the §11 rewrite explaining
  why this was built ahead of independent review
- Unit tests, a full build pass, and live end-to-end verification

**In short: there is no way to actually run a blind signature through the
mediator/client yet.** The cryptographic primitive (the Rust side) works
and has been tested in isolation; nothing in the C++ application calls it.
Don't test "the feature" — there isn't one to test yet. If you want to
exercise the cryptography directly, use the `blindsig-prover` CLI per
`REVIEW_REQUEST.md`'s build instructions.

## The one rule that governs all of this

Never expose a "blind signature" control — anywhere, however experimental —
that skips the NIZK1/NIZK2 zero-knowledge layer. The raw algebraic step
alone (`BLIND/prototype-demo/blind_falcon_demo.cpp`) reveals `(ρ, r, s)` in
the clear and has zero blindness. It exists only as a test that the
underlying algebra round-trips through a real FALCON trapdoor, never as
something a user could mistake for the real feature.
