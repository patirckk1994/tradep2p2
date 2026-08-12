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

**Done and independently verified right now (compiled AND runtime-tested with real cryptography, not just written):**
- The `blindsig-prover` CLI, `blindsig_wire`, `blindsig_falcon`,
  `blindsig_keystore`, and `blindsig_subprocess` — each compiled and
  runtime-tested on its own (fresh-keypair sign/verify with a correct
  negative control; keystore create/unlock/reject-wrong-passphrase/
  reject-tampering; the subprocess bridge tested against a real
  `sleep`-based timeout-kill and a real `blindsig-prover` invocation).
- `blindsig_signer.hpp/cpp` — **a full real end-to-end test**: real
  FALCON keypair, real `user-blind`, a real 216.7s NIZK1 proof,
  `BlindSigSigner` verifying it via the sidecar and signing with real
  `falcon_sign_dyn` — the resulting signature genuinely verifies. Plus a
  tamper-rejection case and a queue-capacity case, both correct.
- `blindsig_client.hpp/cpp` — written, compiles clean; not yet driven
  through a full live round-trip (needs the wiring below to test via a
  real connection — its internal logic reuses the same sidecar calls
  already proven correct above).
- `CMakeLists.txt` — **the whole thing now builds through real CMake**,
  both `TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL=ON` and the default `OFF`
  configure, build, and pass the full 12-suite `ctest` clean. Confirmed
  via `nm`/`strings` that the OFF build has zero `blindsig`/`falcon`/
  `nlohmann` symbols anywhere — the compile gate genuinely gates.

**Not done yet:**
- Any of `lobby.cpp` / `main.cpp` / `http_dashboard.cpp` actually calling
  into any of the above (dispatch() case, startup passphrase prompt, CLI
  REPL commands, dashboard routes+checkbox)
- `setup_mediator.sh` flags
- The `specs.txt` §9.3a section itself, and the §11 rewrite explaining
  why this was built ahead of independent review
- Dedicated permanent unit tests (`blindsig_wire_tests.cpp`/
  `blindsig_keystore_tests.cpp`), and a live end-to-end pass through the
  REAL mediator+client over an actual connection

**In short: the cryptographic core is now solid and proven against real
data, but there is still no way to run a blind signature through the
mediator/client yet** — nothing in `lobby.cpp`/`main.cpp`/
`http_dashboard.cpp` calls any of this. Don't test "the feature" — there
isn't one to test yet. If you want to exercise the cryptography directly,
use the `blindsig-prover` CLI per `REVIEW_REQUEST.md`'s build
instructions.

## The one rule that governs all of this

Never expose a "blind signature" control — anywhere, however experimental —
that skips the NIZK1/NIZK2 zero-knowledge layer. The raw algebraic step
alone (`BLIND/prototype-demo/blind_falcon_demo.cpp`) reveals `(ρ, r, s)` in
the clear and has zero blindness. It exists only as a test that the
underlying algebra round-trips through a real FALCON trapdoor, never as
something a user could mistake for the real feature.
