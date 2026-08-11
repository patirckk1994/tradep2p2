# Standalone extraction: NTT multiplication + "encryption to the sky"

Two self-contained pieces of Rust math, extracted from a larger experimental
post-quantum blind-signature implementation, specifically so they can be
reviewed on their own — no zkVM toolchain, no RISC0, no larger project to
pull in. `cargo test` is enough to build and exercise both.

## Context, briefly

This is part of a prototype of the blind signature scheme from Beullens,
Lyubashevsky, Nguyen & Seiler, *Lattice-Based Blind Signatures: Short,
Efficient, and Round-Optimal* (CCS 2023,
[eprint 2023/077](https://eprint.iacr.org/2023/077)). The construction is
based on FALCON's own NTRU trapdoor and hash-and-sign structure, adapted for
blindness via a zero-knowledge proof of a blinded relation. That proof needs
an *extractability* argument, and the standard technique for it is
"encryption to the sky": the prover additionally encrypts its private
witness under a public key that need not even be validly generated, since
(per the paper's own footnote 6) decryption is never performed in the real
protocol — only inside the security proof's own reduction/simulation.

`enc.rs` is our from-scratch implementation of that idea for this specific
construction. It is **not** ported from any reference implementation — the
paper describes the technique in general terms, not this exact
instantiation. That makes it the piece we're least confident about and most
want independent eyes on.

`ntt.rs`/`ntt_tables.rs` are a supporting dependency: `enc.rs` needs fast
polynomial multiplication in `Z_q[X]/(X^512+1)`, `q=12289` (FALCON's own
modulus). This is a direct, function-by-function port of FALCON's own
NTT-based multiplication from its official reference C implementation, not
a redesign — included here mainly so `enc.rs` builds and runs standalone,
but also open to review in its own right.

## What we'd most like scrutinized

1. **Does `enc.rs`'s construction actually give a sound extractability
   argument for the relation it's meant to support?** Two independent
   Ring-LWE "dual" (LPR-style) ciphertexts over the same ring already in
   use — one encrypting the blinding vector `r` directly (coefficients
   already small, `[-2,2]`), one encrypting `SHA-256(µ)` (256 bits, one bit
   per ring coefficient, remaining slots zero). `pk` and the shared
   parameter `a` are both freshly random ring elements — no real keypair is
   ever generated, matching the paper's footnote 6. Each ciphertext is
   `(a·u + e1, pk·u + e2 + message)`, with `u, e1, e2` all short polynomials
   deterministically derived from a 32-byte `coins` value via a
   domain-separated hash-expand (`encryption_noise_from_seed()` — the same
   function used both to generate a fresh request and, on the verifying
   side, to check one against a claim).
2. **Is splitting into two separate ciphertexts (rather than one densely
   packed one) actually sound, and does it lose anything the proof needs?**
   `r` (512 coefficients, ~3 bits each) and `SHA-256(µ)` (256 bits) don't
   fit one ring element at a safe noise margin without a denser custom
   packing scheme, which we deliberately didn't invent. Two plain
   ciphertexts felt like the lower-risk engineering choice — whether that
   reasoning actually holds cryptographically is exactly what we can't
   self-certify.
3. **Is the noise bound (`[-8,8]`, `ENCRYPTION_NOISE_BOUND` in `enc.rs`)
   actually adequate?** It's deliberately *not* the same `[-2,2]` bound as
   `r` itself — an earlier version reused `r`'s own sampler for this noise
   too, which independently-run lattice-hardness estimation
   ([lattice-estimator](https://github.com/malb/lattice-estimator), a real
   run, not hand-derived) showed was too thin: roughly 102 bits (rough
   estimate) / 125 bits (full estimate) at `q=12289`, noticeably below
   FALCON-512's own ~121–146 bit margin at the same modulus. Since nothing
   ever decrypts these ciphertexts (footnote 6 again), there's no
   correctness cost to using larger noise here — `[-8,8]` was chosen by
   sweeping several bounds through the same estimator and picking the
   smallest one with comfortable margin above both FALCON's own numbers and
   a 128-bit floor on both rough and full estimates (`[-8,8]` measures
   ~146/166 bits). Worth independent judgment regardless — the estimator
   only checks raw problem hardness, not whether this specific construction
   actually reduces to it cleanly.
4. Anything else that jumps out, including in the NTT port — it's a direct
   translation of working C, but a translation error that still passes a
   200-random-trial cross-check against a schoolbook reference (see
   `ntt.rs`'s own test) is exactly the kind of thing worth a second set of
   eyes regardless.

## Provenance

Both `enc.rs` and `ntt.rs`/`ntt_tables.rs` are byte-for-byte identical to
the versions running in the parent project — extracted via `diff`-verified
file copy, not retyped, specifically to avoid introducing a transcription
error while preparing this for review. If you find a discrepancy between
what's described above and what the code actually does, trust the code and
flag it — that would itself be a real finding.

## How to build and run

```sh
cargo test --release
```

No external toolchain beyond a normal Rust install (`rustup`/`cargo`).
Dependencies are deliberately minimal: `sha2` and `sha3` only (`rand` as a
dev-dependency, for the test suite's random trials). Two tests exist:

- `ntt::tests::ntt_multiply_matches_schoolbook_on_200_random_trials` — cross
  checks the NTT-based multiplication against a plain O(n²) schoolbook
  reference on 200 random trials.
- `enc::tests::check_encryption_accepts_genuine_and_rejects_corrupted` —
  confirms `check_encryption()` accepts a genuinely generated ciphertext set
  and rejects a corrupted one (a check that always passes regardless of
  input would be worse than useless).

Neither test is a substitute for the review above — they confirm the code
does what it's documented to do, not that what it's documented to do is
cryptographically sound.

## Feedback

If you find something, or just have questions about the construction,
opening an issue against the parent repository is the most reliable way to
reach the people who can act on it.
