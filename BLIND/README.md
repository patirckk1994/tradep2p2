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
  integration into the mediator, CLI client, and dashboard. **Complete and
  live-tested** — see "Current status" below.
- `standalone-math/` (this folder) — a self-contained extraction of the
  NTT multiplication and "encryption to the sky" construction, with no
  dependency on the rest of this repo, intended for wider public
  cryptographic review beyond the QRL-adjacent review this folder was
  originally built for. See `standalone-math/README.md`.

Read `REVIEW_REQUEST.md` if you're reviewing the cryptography.
Read `RESEARCH_STATUS.md` for the full research history and open
questions (parameter fidelity is the big one — see that file).

## Current status (branch `PQR-BLINDSIG`) — cryptographic core AND integration complete, NOT independently reviewed, NOT merged

Being upfront rather than letting this folder imply more or less than is
true:

**Done and independently verified with real cryptography, not just
written or unit-tested:**
- The `blindsig-prover` CLI, `blindsig_wire`, `blindsig_falcon`,
  `blindsig_keystore`, `blindsig_subprocess`, `blindsig_signer`, and
  `blindsig_client` — each compiled and runtime-tested (fresh-keypair
  sign/verify with a correct negative control; keystore create/unlock/
  reject-wrong-passphrase/reject-tampering; the subprocess bridge tested
  against a real timeout-kill; the signer tested against a real ~217s
  NIZK1 proof it genuinely verifies and signs).
- `CMakeLists.txt` — both `TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL=ON` and
  the default `OFF` configure, build, and pass the full `ctest` suite
  clean (14/14 on ON, 12/12 on OFF). Confirmed via `nm`/`strings` that the
  OFF build has zero `blindsig`/`falcon`/`nlohmann` symbols anywhere — the
  compile gate genuinely gates.
- `lobby.cpp`/`main.cpp` — the mediator-side signer wiring, the interactive
  passphrase-gated startup, and the CLI's `/blindsig info|request|status`
  REPL commands. Driven through a **real live end-to-end test**: an actual
  mediator process and an actual client process over a real TLS
  connection, through a real ~150s NIZK1 proof, real network chunk
  submission, real mediator verify+sign, real ~100s NIZK2 proof, and real
  independent self-verification via the sidecar's own `verify-signature`
  call — reaching `stage: ready` with a genuine credential. (This also
  caught and fixed a real client-side wake-pipe bug, since fixed.)
- `http_dashboard.cpp`/`dashboard_client.hpp/cpp` — a live, gated dashboard
  panel (`POST /api/blindsig/info`, `POST /api/blindsig/request`,
  `GET /api/blindsig/state`), driven through the same kind of real live
  test as above but via the actual HTTP API: real mediator, real dashboard
  process, real ~200s proving cycle, reaching `stage: ready` with a
  genuine self-verified credential.
- `setup_mediator.sh` — `--blindsig-enable`/`--blindsig-keystore-file`/
  `--blindsig-prover-path`/`--blindsig-queue-size` flags.
- `specs.txt` §9.3a (new section) plus the §9.3/§10/§11 edits explaining
  why this was built ahead of independent review, honestly.
- Dedicated permanent unit tests: `blindsig_wire_tests.cpp` (codec/chunk-
  assembler edge cases) and `blindsig_keystore_tests.cpp` (custody/tamper
  checks).

**Not done, and not planned as part of this integration:**
- Independent cryptographic review of any of the above — that's what this
  folder and `REVIEW_REQUEST.md` are for. Nothing here should be read as
  self-certification.
- specs.txt §9.3's actual credential/reputation application (token↔room
  mapping, epoch rotation, aggregate disclosure) — out of scope by design,
  this integration is the primitive only.
- A trapdoor sampler built for BLNS23's own actual parameters (`q=7933`,
  not FALCON's `q=12289`) — a separate, still-in-progress research/
  engineering track, not part of this folder.

**In short: this is a complete, working, off-by-default, unreviewed
experimental feature** — a real blind signature can be requested and
produced through either the CLI or the browser dashboard, over a real
network connection, and the result genuinely verifies. "Unreviewed" is
doing real work in that sentence, not a formality — see
`REVIEW_REQUEST.md` for what we'd most like scrutinized.

## The one rule that governs all of this

Never expose a "blind signature" control — anywhere, however experimental —
that skips the NIZK1/NIZK2 zero-knowledge layer. The raw algebraic step
alone (`BLIND/prototype-demo/blind_falcon_demo.cpp`) reveals `(ρ, r, s)` in
the clear and has zero blindness. It exists only as a test that the
underlying algebra round-trips through a real FALCON trapdoor, never as
something a user could mistake for the real feature.
