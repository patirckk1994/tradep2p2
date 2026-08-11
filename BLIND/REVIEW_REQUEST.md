# Review request: lattice-based blind signature prototype (NIZK1 + NIZK2)

Thank you for taking a look at this. Short version: this is a research
prototype of the blind signature scheme from Beullens, Lyubashevsky,
Nguyen & Seiler, *Lattice-Based Blind Signatures: Short, Efficient, and
Round-Optimal* (CCS 2023, [eprint 2023/077](https://eprint.iacr.org/2023/077)).
We'd like your read on whether the construction and its simplifications are
sound, specifically the parts we designed ourselves rather than ported from
existing code.

**This is a genuine feature branch of a real project (`PQR-BLINDSIG`), not
deployed.** It's compiled out of the default build entirely
(`TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL`, off by default — this repo's first
compile-time feature gate) and, even when compiled in, disabled again unless
separately opted into at runtime. See `specs.txt` §9.3a for the full honest
account, including *why* we chose to build this ahead of your review landing
rather than wait — that was a deliberate call by the project lead, not an
oversight. No urgency on our end — take whatever time makes sense.

## What we actually want reviewed, in priority order

1. **The "encryption to the sky" construction**
   (`blindsig-prover/prover-core/src/enc.rs`). This is the part we designed
   from scratch, not ported from anywhere — see below for the exact shape
   and why. This is the single thing we're least confident about and most
   want your eyes on.
2. **Whether the NIZK1/NIZK2 split as implemented actually proves what the
   paper's Fig. 4 requires** — see "What's proven, precisely" below.
3. **Parameter choices** — we used FALCON-512's own standard `(q=12289,
   n=512)` instead of the paper's `(q=7933, n=512)`, and simplified the
   paper's `1×2` vectors `B`/`r` to single ring elements. Both deliberate,
   both explained below — are they actually safe substitutions, or do they
   quietly break something in the paper's security proof? (See
   `RESEARCH_STATUS.md`'s "What's NOT resolved: parameter fidelity"
   section — we know this is open, we don't have a confident answer
   ourselves.)
4. Anything else that jumps out. We have our own list of known gaps (see
   `RESEARCH_STATUS.md`'s roadmap section) but you're likely to find things
   we didn't think to look for.

## What's proven, precisely

**NIZK2** (`blindsig-prover/methods/guest/src/main.rs`) - given public
`(h, B, ρ, µ)`, proves knowledge of private `r, s` such that
`A·s = B·r + H(ρ,µ)`, `‖s‖` and `‖r‖` bounded, without revealing `r` or `s`.
`h` is the signer's real FALCON public key; the norm bound is FALCON-512's
actual `l2bound[9] = 34034726` (matches the paper's own cited `βs`).

**NIZK1** (`blindsig-prover/methods/guest/src/bin/nizk1.rs`) - given public
`(B, c, a, pk, ct1_r, ct2_r, ct1_mu, ct2_mu)`, proves knowledge of private
`r, µ, coins` such that:
- `c = B·r + H(G(r),µ)` (well-formedness of the blinded target)
- `‖r‖` bounded
- `(ct1_r,ct2_r,ct1_mu,ct2_mu) = Enc(r,µ; a,pk,coins)` (the extractability
  argument - see below)

without revealing `r`, `µ`, or `coins`.

Both are implemented as RISC0 zkVM guest programs - the "proof" is that an
ordinary Rust program (the guest) executed correctly on hidden inputs,
verified via a real STARK receipt. `blindsig-prover/prover/src/commands.rs`
drives proving/verification (via the `blindsig-prover` CLI's
`user-prove-nizk1`/`signer-verify-nizk1`/`user-finalize-prove-nizk2`/
`verify-signature` subcommands) and includes an empirical check (grep the
serialized receipt for the private witness bytes) confirming `r`/`s`/`µ`/
`coins` never appear in it - not a formal ZK proof of the zkVM's own
soundness, just an empirical sanity check we thought was better than
nothing.

## The encryption-to-the-sky construction, precisely

The paper's own footnote 6 says the "public key" for this step need not be
validly constructed - it's never decrypted in the live protocol, only
(in the paper's own security proof) in the reduction's simulation. Given
that, we built:

- Two independent Ring-LWE "dual" (LPR-style) ciphertexts over the SAME
  ring already in use (`Z_12289[X]/(X^512+1)`) - one encrypting `r`
  directly (its coefficients are already small, `[-2,2]`), one encrypting
  `SHA-256(µ)` (256 bits, one bit per ring coefficient, the remaining 256
  of 512 slots zero-padded).
- `pk` and the shared parameter `a` are both freshly random ring elements
  - no real keypair is ever generated, matching the paper's footnote.
- Each ciphertext: `(a·u + e1, pk·u + e2 + message)`, with `u, e1, e2` all
  short polynomials (coefficients uniform in `[-2,2]`) derived
  deterministically from a 32-byte `coins` value via a domain-separated
  hash-expand (`short_poly_from_seed()` - the same function used both to
  generate a fresh request and, inside the guest, to check one).

We split into two ciphertexts rather than one because `r` (512 coefficients
needing ~3 bits each) and `SHA-256(µ)` (256 bits) don't fit one ring
element at a safe noise margin without a denser custom packing scheme,
which we deliberately didn't invent - two plain ciphertexts felt like the
lower-risk choice. Whether that reasoning holds, whether the noise margins
are actually adequate, and whether this construction genuinely provides
the extraction property the paper's security proof needs from it - that's
exactly the kind of thing we're not qualified to self-certify, hence this
request.

**Verification methodology, if useful context**: before either the NTT
optimization or this encryption construction were used inside the actual
(slow, ~100-212s) zkVM guest, both were independently verified against a
fast native reference - `blindsig-prover/prover-core`'s own test suite
cross-checks the NTT port against a schoolbook multiplication on 200 random
trials, and cross-checks the encryption logic against real generated
ciphertexts, plus a negative control (corrupting one coefficient of `r` and
confirming the check then correctly fails, rather than passing vacuously).

## Everything else, for context

- `RESEARCH_STATUS.md` (this folder) - the full research log: what we
  verified about the papers themselves, the LaZer/LaBRADOR library
  connection, what's tractable vs. not, and a roadmap of what we think has
  to be true before this would be responsible to expose beyond an
  experimental, off-by-default feature - independent review (this) is
  item #3 on that list.
- `specs.txt` §9.3a (in the repo root) - how this is actually wired into
  the mediator/client as an experimental feature: compile-time AND
  runtime gating, the language-boundary decision (separate Rust sidecar
  process, not linked into the C++ binary), key custody for the signer's
  trapdoor, and the one rule that can't be relaxed (never expose a "blind
  signature" control that skips this zero-knowledge layer).
- `prototype-demo/` (this folder) - the algebraic-core-only demo, no ZK,
  for testing that the blinding relation round-trips through a real FALCON
  trapdoor. Not what's actually used for signing - see `blindsig-prover/`.
- `../third_party/falcon-impl-20211101/` - vendored, unmodified official
  FALCON reference implementation (`falcon-sign.info`) - real trapdoor
  generation and Gaussian preimage sampling, not reimplemented by us.

## How to build and run

```sh
cd BLIND/prototype-demo && make && ./blind-falcon-demo   # writes a fresh instance JSON
cd ../../blindsig-prover
cargo build --release
# See prover/src/main.rs for the 5 subcommands (user-blind, user-prove-nizk1,
# signer-verify-nizk1, user-finalize-prove-nizk2, verify-signature) and their
# JSON input/output shapes.
```

Needs a Rust toolchain plus the RISC0 zkVM toolchain (`rzup`, see
[risczero.com](https://risczero.com)) to build the guest programs. GCC and
OpenSSL for the C++ side.

Thank you again - genuinely appreciate you looking at this.
