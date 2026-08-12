# BLNS23 q=7933 reference substrate

This directory is intentionally isolated from the live experimental blind-signature path.

The existing `PQR-BLINDSIG` implementation continues to use the vendored official FALCON-512 implementation at q=12289. Nothing in `BlindSigSigner`, `BlindSigKeystore`, the wire format, or the RISC0 prover sidecar uses this reference substrate yet.

Current purpose:

- exact, generic negacyclic ring arithmetic for `Z_q[x]/(x^d+1)`;
- paper parameters `q=7933`, `d=512`, `sigma=232`;
- deliberately slow, non-NTT polynomial multiplication;
- deliberately slow modular inversion by explicit linear algebra;
- exact arbitrary-precision integer arithmetic for the recursive NTRU solver;
- exact `fG - gF = q` trapdoor-relation checking;
- recursive field-norm `NTRUSolve` with Falcon-style candidate rejection at the deepest resultant step;
- an exact coordinate-descent reducer retained as a slow correctness/cleanup oracle;
- a global Babai-style reference reducer which forms the exact negacyclic Gram system, solves its real projection at 256 decimal digits, rounds a whole polynomial `k`, and accepts the update only after exact `cpp_int` relation and norm checks;
- an independent degree-2 brute-force oracle used to test the distinction between direct equation solvability and TrapGen candidate acceptance;
- a discrete Gaussian sampler `D_{Z,sigma,0}` (`blindsig_blns7933_gaussian.hpp`), by rejection sampling evaluated at 256-digit precision (not `double`, for both the Gaussian PDF and the accept/reject comparison - see that header's own comment for why this specific spot is where floating-point bias historically became a real, exploitable weakness in other lattice signature implementations);
- a Falcon-style trapdoor-quality bound (`blindsig_blns7933_quality.hpp`): the Hermitian adjoint (exact, no transform needed) and `gamma = max(||(g,-f)||, ||q*f*/(f*f*+g*g*)||, ||q*g*/(f*f*+g*g*)||) <= 1.17*sqrt(q)` (falcon.pdf Algorithm 5, eq. (3.28)), computed via one real (not complex/FFT) linear solve at 256-digit precision - see that header's comment for why the FFT-domain formula reduces to a real linear system here;
- a working `NTRUTrapdoorGenerator::generate()`: samples candidate `(f,g)`, checks `g` invertible mod `q` (this type's `t=f*g^-1` orientation), checks the quality bound, solves `fG-gF=q`, reduces `(F,G)`, and restarts from scratch on any rejection - mirroring FALCON's own NTRUGen restart loop;
- real-coefficient ring arithmetic at 256-digit precision (`blindsig_blns7933_real_ring.hpp`): add/sub/mul/Hermitian-adjoint/division (via one dense real linear solve, same technique as the quality bound above) plus the `split`/`merge` operators (falcon.pdf eq. (3.20)-(3.22)) - pure coefficient deinterleaving, no transform of any kind, despite the paper's own "splitfft"/"mergefft" naming for its FFT-optimized fast path;
- the recursive "Falcon tree" (`blindsig_blns7933_ldl.hpp`, falcon.pdf Algorithms 8-9, `LDL*`/`ffLDL*`), built and sigma-normalized entirely in coefficient domain - verified by exactly reconstructing `G=LDL*` from its own decomposition, not merely "did it not crash";
- `ffSampling` (`blindsig_blns7933_sampling.hpp`, falcon.pdf Algorithm 11) - the randomized, tree-guided discrete rounding at the heart of signature generation, walking the Falcon tree in coefficient domain;
- a working `sign()`/`verify()` (`blindsig_blns7933_sign.hpp`) tying all of the above together, using a target-vector formula derived (and symbolically verified with SymPy, not just by hand) specifically for THIS project's `A=(f*g^-1,1)` orientation - see that header's own comment for the full derivation, since FALCON's own published formula assumes the opposite `h=g*f^-1` convention and does not carry over unchanged;
- explicit manual scaling/corpus/TrapGen/sign diagnostics kept outside CTest so expensive development experiments cannot run accidentally.

Neither reducer is a production implementation. The coordinate reducer is intentionally slow; the global reducer intentionally favors transparency and high precision over Falcon's optimized FFT/NTT/31-bit-limb engineering. The 256-digit projection is used only to choose the reduction polynomial: all state-changing updates and acceptance decisions are checked with exact integer arithmetic.

**Update: signature generation and verification now work end-to-end.** A real, produced-by-this-code signature verifies against the real `A.s=c (mod q)` relation and the real norm bound - see "Sign/Verify: a working end-to-end pipeline" below. This is NOT yet a claim that the `sigma=232` preconditions give the full BLNS23/FALCON *security* guarantee (distributional/statistical-distance validation, discussed in "Next implementation order", is still open) - it is a claim that the algebra, the tree construction, and the sampling recursion are all correctly wired together and produce something a real verifier accepts, which was the open question this stage of the roadmap existed to answer.

**Resolved: the RNG.** `generate()`, `sign()`, and every Gaussian sampler now take a `CryptoRng&` (`blindsig_blns7933_csprng.hpp`/`.cpp`), not `std::mt19937_64&`. `CryptoRng` seeds from OpenSSL's `RAND_bytes` for real use (its default constructor), or - for reproducible tests/diagnostics only, explicitly documented as not a substitute for real entropy - a fixed integer seed, then squeezes output via `SHAKE256(seed || counter)` in fixed-size blocks, re-absorbing with an incremented counter on each refill (OpenSSL's `EVP_DigestFinalXOF` does not support being called more than once per context to continue squeezing - verified empirically against the linked OpenSSL build before relying on it, not assumed from documentation). This follows the same "seed a SHAKE-family PRNG from OS entropy" pattern this project's own FALCON wrapper (`blindsig_falcon.cpp`) already established, rather than inventing a different construction. Non-copyable (duplicating live RNG state would make two "independent" draws reproduce each other), movable. Adds `OpenSSL::Crypto` as a real dependency of this previously Boost-only standalone target - both CMake build paths updated. This is a distinct property from the numerical-precision questions above - precision affects whether the *distribution* is right, RNG quality affects whether the *actual secret* is unpredictable - both are now addressed.

CUDA is intentionally not used in the reference path. At the current stage, exact `cpp_int` arithmetic and a small high-precision dense solve are more valuable for auditability than GPU acceleration. A GPU backend would only be considered later for clearly isolated performance work after the mathematical path is validated.

## Standalone build

```sh
cmake -S BLIND/q7933-reference -B build-q7933-reference
cmake --build build-q7933-reference -j
ctest --test-dir build-q7933-reference --output-on-failure
```

This standalone target exists specifically so development of the q=7933 reference implementation cannot accidentally change the live blind-signature path before its invariants are understood.

## Whole-repo experimental checkpoint

From the repository root:

```sh
cmake --preset blns7933-root
cmake --build --preset blns7933-root --parallel 2
ctest --preset blns7933-root --output-on-failure
```

The q=7933 reference targets are still separate from the main `tradep2p` library; the preset merely compiles and tests them alongside the full experimental blind-signature tree.

The current whole-repo checkpoint is 24/24 tests passing, now including the CryptoRng, discrete Gaussian sampler, trapdoor-quality-bound, real-ring-arithmetic, Falcon-tree, and full sign/verify tests alongside the q=7933 reference, NTRUSolve, exact reducer, and global Babai reducer tests. (This preset doesn't set an explicit `CMAKE_BUILD_TYPE`, so the Gaussian/quality tests - the two most floating-point-heavy suites - run noticeably slower here, ~4 minutes each, than under the standalone build's `-DCMAKE_BUILD_TYPE=Release`, where each is under a minute. Same correctness either way, just optimization level.)

## Controlled scaling diagnostics: d=16/32/64

The first manual diagnostics executable compares the exact coordinate baseline, the 256-digit global reduction, and exact coordinate cleanup at `d=16`, `32`, and `64` with `q=7933`:

```sh
./build-blns7933-root/tradep2p_blns7933_scaling_diagnostics
```

It is deliberately **not** registered with CTest. The deterministic sparse anchor has validated the global reducer through `d=64`: the global step reduces the lifted solution in one accepted round on the current anchor while the coordinate reducer remains only a slow correctness/cleanup oracle. The executable hard-checks `fG-gF=q` after the solver and after every reduction stage, checks exact squared-norm monotonicity, and prints recursion-level coefficient growth, global rounds, coordinate cleanup work, and wall-clock timings.

## Deterministic small-coefficient corpus

A second manual executable exercises a reproducible corpus at `d=16`, `32`, and `64`. Each degree includes the known sparse anchor plus five fixed-seed sparse small-coefficient candidates.

```sh
cmake --build --preset blns7933-root \
  --target tradep2p_blns7933_corpus_diagnostics \
  --parallel 2

./build-blns7933-root/tradep2p_blns7933_corpus_diagnostics
```

Candidate rejection is expected behavior and is reported as `REJECT`, not as a test failure. For every accepted candidate, the diagnostic requires exact `fG-gF=q` preservation through the global reducer and cleanup, exact non-increasing squared norms, and reports solver/reducer timing, coefficient/norm bit lengths, global rounds, cleanup steps, and convergence status.

The first recorded corpus run accepted 1/6 candidates at `d=16`, 5/6 at `d=32`, and 5/6 at `d=64`. These counts are **not** an acceptance-rate estimate: the corpus is tiny and deterministic. More importantly for the current checkpoint, all accepted non-anchor `d=64` candidates were reduced from raw coefficient sizes above 200 bits to roughly 9-10 bits in one accepted global round, followed by small exact cleanup, while preserving the exact NTRU relation.

This corpus is still a development diagnostic, not the final BLNS23 key distribution. It exists to move beyond the single `f=1+x, g=1+2x` anchor before opening larger dimension gates.

## Explicit d=128 gate

The `d=128` gate deliberately omits the expensive direct coordinate baseline and measures only:

`NTRUSolve -> global Babai reduction -> exact coordinate cleanup`.

```sh
cmake --build --preset blns7933-root \
  --target tradep2p_blns7933_scaling_128_diagnostic \
  --parallel 2

./build-blns7933-root/tradep2p_blns7933_scaling_128_diagnostic
```

The first recorded `d=128` run completed successfully: the deterministic anchor solved in about 9 ms, the global reduction in about 122 ms, one global round was accepted, and exact cleanup converged with the final coefficients at 12 bits and final squared-norm length at 25 bits.

## Explicit d=256 gate

`d=256` uses the same deterministic sparse anchor and staged exact postconditions, remains outside CTest, and skips the raw coordinate baseline.

```sh
cmake --build --preset blns7933-root \
  --target tradep2p_blns7933_scaling_256_diagnostic \
  --parallel 2

./build-blns7933-root/tradep2p_blns7933_scaling_256_diagnostic
```

The first recorded `d=256` run completed successfully: the solver took about 34 ms, the 256-digit global reducer about 781 ms, and exact cleanup about 77 ms. The lifted solution grew to 268-bit coefficients / a 544-bit squared-norm representation; one accepted global round reduced it to 12-bit coefficients and a 25-bit squared norm, after which four coordinate-cleanup steps converged. Exact `fG-gF=7933` and non-increasing norm checks held throughout.

This is still a machinery and precision checkpoint only. A successful `d=256` anchor does not by itself validate TrapGen sampling, trapdoor quality, or the BLNS23 Gaussian preimage sampler.

## Explicit d=512 gate

`d=512` is the first diagnostic at the actual BLNS23 ring dimension. It intentionally changes nothing else: the same sparse deterministic anchor, the same eight-round global-reducer cap, the same exact relation and norm postconditions, and the same exact coordinate cleanup backstop are used.

```sh
cmake --build --preset blns7933-root \
  --target tradep2p_blns7933_scaling_512_diagnostic \
  --parallel 2

./build-blns7933-root/tradep2p_blns7933_scaling_512_diagnostic
```

This target is deliberately manual-only and answers one narrow question before random candidate generation is introduced: can the current transparent `cpp_int` NTRUSolve plus 256-digit global reduction machinery survive the actual `d=512, q=7933` algebra while retaining exact postconditions? (Answer, since confirmed below: yes.)

## TrapGen: candidate generation, now implemented

`NTRUTrapdoorGenerator::generate()` (`blindsig_blns7933.hpp`/`.cpp`) is a real, working candidate-generation loop: sample `(f,g)` from `D_{Z,sigma_fg,0}` (`sigma_fg = 1.17*sqrt(q/2n)`) -> check `g` invertible mod `q` -> check `gamma <= 1.17*sqrt(q)` -> `NTRUSolve` -> reduce -> verify the exact relation one final time -> return, restarting from a fresh sample on any rejection. This is the step the earlier roadmap below called "TrapGen" - it now exists, is tested, and has been run at the real target parameters, not just toy dimensions.

```sh
cmake --build --preset blns7933-root \
  --target tradep2p_blns7933_trapgen_diagnostic \
  --parallel 2

./build-blns7933-root/tradep2p_blns7933_trapgen_diagnostic
```

The diagnostic runs at `d=32` by default (fast - typically well under a second, one or two rejected candidates before an accept) with per-attempt visibility into exactly why a candidate was rejected (invertibility vs. quality bound, with the actual `gamma` value printed).

**Real result at the actual `d=512, q=7933` target parameters** (via `NTRUTrapdoorGenerator::generate()` directly, seed `3`): succeeded in **402.567 seconds**, final exact relation verified, public-key derivation (`t = f*g^-1 mod q`) succeeded. The dominant cost by far is the quality-bound check (`compute_trapdoor_quality()`'s 256-digit real linear solve, roughly 30-60s per candidate at `d=512`) rather than `NTRUSolve` or reduction (each under 2s) - most of the wall-clock time across a run is spent evaluating rejected candidates' `gamma`, not on the eventual accepted one. This is a one-time cost per generated trapdoor (key generation, not per-signature), and squarely inside this project's stated tolerance for slow-but-correct over fast-but-approximate.

**What this does and does not establish.** It establishes that a real, uniformly-sampled-from-the-correct-distribution `(f,g,F,G)` satisfying FALCON's own keygen acceptance criteria can be produced at the real BLNS23 parameters, with every step checked exactly. On its own it does not establish that the *signing* side works - see the next section, which is where that gap gets closed.

## Sign/Verify: a working end-to-end pipeline

`blindsig_blns7933_sign.hpp` ties together TrapGen, the Falcon tree, and `ffSampling` into a real `sign()`/`verify()` pair. This is the piece the previous version of this README flagged as the actual remaining gap - a trapdoor keypair alone doesn't sign anything - and it is now closed at the reference-substrate level (still not wired into `BlindSigSigner`, see "Not done" below).

**The target-vector derivation required real work, not a copy-paste from falcon.pdf.** FALCON's own Sign (Algorithm 10) targets `t=(-c*F/q, c*f/q)` for ITS OWN `h=g*f^-1` public-key convention. This project's trapdoor uses BLNS23's own `A=(f*g^-1,1)` orientation instead (see `blindsig_blns7933.hpp`'s `PublicKey`) - a different relation, so FALCON's formula does not carry over unchanged. Working through the algebra (and cross-checking symbolically with SymPy, not just by hand) gives, for this project's own convention:

```
t = (-c*capG/q, c*g/q)
```

which lands at `t.B = (0,c)` exactly (`B=[[g,-f],[capG,-capF]]`), and makes `s=(t-z).B` satisfy `f*s0+g*s1 == g*c (mod q)` for any integer `z` - exactly the coset condition equivalent to `A.s=c`. Swapping `f<->g` and `capF<->capG` relative to FALCON's own published formula is deliberate, not a typo.

**A genuinely non-obvious correctness property, worth stating plainly:** despite `t` and the whole `ffSampling` computation being real-valued (fractional), `s=(t-z).B` comes out an EXACT integer, because `t.B=(0,c)` exactly and `z.B` is an integer combination of `B`'s integer rows. `sign()` rounds to the nearest integer and checks the rounding residual is negligible (not just truncating and hoping) - this passed on every test run so far, which is itself evidence the real-arithmetic pipeline upstream is behaving correctly.

```sh
cmake --build --preset blns7933-root \
  --target tradep2p_blns7933_sign_diagnostic \
  --parallel 2

./build-blns7933-root/tradep2p_blns7933_sign_diagnostic
```

Runs the full pipeline (TrapGen -> build the signing tree -> Sign -> Verify) at `d=32, q=7933` by default. **First recorded run**: TrapGen 0.197s, tree construction 0.019s, sign 0.147s, verify accepted, `||s||^2=2,826,717` comfortably inside the bound `6,889,472` (`beta_s^2 = sigma^2*2*n*d` with `n=2`, `sigma=232`, `d=32` - the real Table 2 formula, not rederived for this dimension).

**Real result at the actual `d=512, q=7933` target parameters** (`tradep2p_blns7933_sign_512_diagnostic`, same pipeline, no shortcuts, seed `4`): succeeded end-to-end in **4m29s total** - TrapGen 233.0s, `build_signing_tree` 33.0s (the LDL tree's `div()` cost, dominated by its top-level call, same order of cost as the quality-bound module's own d=512 measurement), `sign` 2.75s, `verify`: **accepted**, `||s||^2=51,497,427` comfortably within the bound `110,231,552` (~47% of it - a healthy margin, not a borderline pass). This is a genuine, complete signature produced and independently verified at the actual BLNS23 target parameters, not a toy dimension or a hand-fed anchor - the first time this reference substrate has closed the full loop (TrapGen -> tree -> sign -> verify) at real scale.

**What this does and does not establish.** It establishes that a genuine, produced-by-this-code signature satisfies the real `A.s=c (mod q)` relation and the real norm bound, and that a tampered signature or a signature checked against the wrong message is correctly rejected (see `blindsig_blns7933_sign_tests.cpp`). It does **not** establish that the *distribution* of `s` matches what BLNS23's own security proof needs - see the next section, which is a first empirical pass at exactly that question.

## Distribution diagnostic: an empirical first pass at `s`'s statistics

Everything above only checks that `sign()`'s output is algebraically correct (right relation, right norm bound, genuine rejection of tampering) - none of it checks that `s`'s actual distribution matches what BLNS23's/falcon.pdf's own security argument requires: `s ~ D_{(c,0)+Lambda(B),sigma,0}`, a discrete Gaussian of parameter `sigma=232` centered on the message's coset. `distribution_diagnostic.cpp`/`distribution_512_diagnostic.cpp` are a first, honest, **empirical moment check** against that claim - not a formal statistical-distance proof - built on top of the already-tested `sign()`/`verify()` pair, reusing one precomputed Falcon tree across many signatures (the tree is a one-time per-keypair cost; each `sign()` call is cheap once it exists).

Two complementary checks, both pooling every coefficient of every produced `s0`/`s1` and comparing against the target `sigma^2`:

1. **Different messages** (many distinct cosets): pooled mean should be near 0 by symmetry across random targets, pooled variance should track `sigma^2`.
2. **Same message, repeated** (same coset, many independent `ffSampling` draws): confirms the sampler is not accidentally deterministic or low-entropy - a real, checkable failure mode a broken RNG wiring could produce without any algebraic check noticing - and reports the same-coset sample variance as a secondary data point.

Every sampled signature in both loops is independently re-verified via `verify()`, so a run that silently tolerated even one algebraically-invalid signature would fail loudly, not just report a bad statistic.

```sh
cmake --build --preset blns7933-root \
  --target tradep2p_blns7933_distribution_diagnostic tradep2p_blns7933_distribution_512_diagnostic \
  --parallel 2

./build-blns7933-root/tradep2p_blns7933_distribution_diagnostic       # d=32,  1000 + 200 samples, ~3 min
./build-blns7933-root/tradep2p_blns7933_distribution_512_diagnostic   # d=512, 100 + 50 samples, ~11 min
```

**First recorded results, both clean and consistent with each other:**

| | d=32 (1000 + 200 samples) | d=512 (100 + 50 samples) |
|---|---|---|
| Check 1 pooled mean (target ~0, scale `sigma=232`) | -1.363 | -0.044 |
| Check 1 pooled variance / `sigma^2` (target 1.0) | 0.998 | 0.997 |
| Check 2 pooled variance / `sigma^2` (target 1.0) | 0.987 | 0.995 |
| Check 2 all-identical guard | passed (genuinely randomized) | passed (genuinely randomized) |

**What this does and does not establish.** Both means sit well within noise of 0 relative to `sigma=232`, and both variance ratios sit within half a percent of the target `sigma^2` at the real `d=512` target dimension specifically, not just at toy scale - real, positive evidence the tree-sampled output is landing on the right Gaussian, at the parameters that actually matter. It is **not** a formal statistical-distance bound, does not check higher moments or the covariance structure `ffSampling`'s security argument actually depends on, and pooled coefficients within one signature are not independent draws (so the naive variance-ratio precision overstates the test's real statistical power) - a rigorous treatment would need a proper statistical-distance estimate (e.g. via Renyi divergence or a KS-type test against the true discrete Gaussian CDF) rather than first- and second-moment matching. Side-channel/constant-time considerations and a from-scratch security rederivation remain entirely open - see the roadmap below.

## zkVM guest port: NIZK1/NIZK2 at q=7933

Everything above is the C++ math substrate (trapdoor generation, sign/verify, distributional validation, a real CSPRNG). It produces genuine signatures but not a *blind* signature scheme - that requires the RISC0 zkVM guest circuits (NIZK1/NIZK2) that make the blinding relation and the signature relation provable in zero knowledge. The shipped `PQR-BLINDSIG` feature's guests (`blindsig-prover/`) hardcode FALCON's own NTT arithmetic at `q=12289`. This section covers porting them to a new, parallel workspace, `blindsig-prover-q7933/`, at this branch's real `q=7933` - **the shipped `q=12289` feature is never touched.**

**Why this isn't "port FALCON's NTT to a new modulus" (which is impossible)**: reading `blindsig-prover/` directly and the original research prototype's own `README_PROTOTYPE.md` revealed that the guest was *originally* built with plain O(n²) schoolbook polynomial multiplication, and it worked correctly - NTT was added later purely as a zkVM proving-speed optimization (~57x fewer multiply operations), cross-checked against the schoolbook version on 200 random trials before being trusted. Separately, `q=7933` cannot support a standard radix-2 NTT at `d=512` at all (`7932=2²·3·661`, not divisible by 1024 - established earlier in this project's own research). So this port brings back the already-once-correct schoolbook approach, reparametrized for `q=7933`, and swaps the guest's verification relation from FALCON's `h·s2+s1≡c` to this branch's own `t·s0+s1≡c` (`A=(t,1)`, `t=f·g⁻¹ mod q`) with the real norm bound `110,231,552` validated earlier in this file.

A further, important discovery from reading the guest code directly: **the guest never touches trapdoor/signing code at all.** Real signing happens only on the host side (C++), and `t`/`s0`/`s1` cross into the Rust prover as plain data. The guest only re-derives public values from a witness and checks relations - no FFI boundary to redesign, a far more contained port than it first looked.

### Phase 1: pure-Rust arithmetic (`blindsig-prover-q7933/prover-core/`)

`N=512` (unchanged), `Q=7933` (changed). `poly_mul.rs` promotes the q=12289 sibling's own already-cross-checked-on-200-trials schoolbook reference (previously buried in a `#[cfg(test)]` module) into a real, public function - verified here with two hand-computable cases (including one that specifically exercises the negacyclic `X^N=-1` wraparound sign flip: `X^510 * X^3 = -X^1`) plus property checks (identity, distributivity). `hash_to_point()` reparametrizes the sibling's own **real, SHAKE256-based** construction (not the C++ substrate's own deliberately-simplified placeholder) - `5*Q` rejection threshold computed from the `Q` const rather than hardcoded, since there's no FALCON C source at q=7933 to diff against. `NORM_BOUND_SQUARED=110_231_552` replaces FALCON's `L2_BOUND`. The verification relation itself lives in `relation.rs` (`relation_holds()`/`norm_squared()`), shared between the guest and this crate's own tests rather than inlined only in the guest - mirrors how `enc.rs`'s `generate_ciphertexts()`/`check_encryption()` already share one implementation.

### Phase 2: empirical gate - real cycle counts, not a full prove first

Before committing to schoolbook as the final answer, measured real RISC0 execute-only cycle counts (`methods/examples/cycle_count.rs`, `risc0_zkvm::default_executor()` - reports cycles without running the full STARK prover) for two benchmark guests doing the identical shape of work (5 degree-512 polynomial multiplications, same dependency chain): schoolbook-at-q=7933 vs. the *existing, untouched* sibling crate's real NTT-at-q=12289 (depended on read-only via a `package =`-renamed path dependency, for a true apples-to-apples comparison).

**Real result: 36,964,015 cycles (schoolbook) vs. 2,557,148 cycles (NTT) - a 14.46x ratio.** Within this project's own decision gate (roughly an order of magnitude → proceed with schoolbook, matching the standing "never trade precision for speed" rule; two-plus orders of magnitude would have triggered reconsidering Karatsuba). The benchmark guests are kept as permanent, re-runnable diagnostics (`methods/guest/src/bin/{poly_mul_cycle_bench,ntt_bench_q12289}.rs`), matching this project's own established pattern.

### Phase 3: full guest logic port

`main.rs` (NIZK2) and `bin/nizk1.rs` (NIZK1) ported with the same input/commit structure as the sibling. NIZK1 is structurally unchanged (the blinding relation and encryption-to-the-sky check never reference the signature scheme at all) beyond swapping in schoolbook multiplication. NIZK2's relation swaps to `t·s0+s1≡c (mod q)`, and - a real, substantive difference from FALCON's own wire format - this scheme's `Signature{s0,s1}` carries **both** halves explicitly (matching `blindsig_blns7933_sign.cpp`'s own `verify()`), unlike FALCON's own format, which only transmits `s2` and recovers `s1` implicitly via the verification equation as a size optimization.

**`enc.rs`'s `ENCRYPTION_NOISE_BOUND` re-swept at the real `q=7933`** (re-cloned `github.com/malb/lattice-estimator`, same bound-sweep methodology the sibling's own bound=8 was chosen with): `LWE.Parameters(n=512, q=7933, Xs=Xe=ND.Uniform(-8,8))` gives **rough ~157.1 bits, full ~176.4 bits** - both *higher* than the sibling's own q=12289 numbers (146/166 bits), not lower. This is real, not assumed: a smaller modulus means the same absolute noise bound is proportionally larger relative to `q`, making the LWE instance *harder*, not easier - the opposite of this file's own first-draft (unverified) caveat, which assumed the reverse. `bound=8` is confirmed sound at q=7933 with real margin, not carried over on faith.

**A genuinely necessary addition, not scope creep**: `sign()`/`verify()` (`blindsig_blns7933_sign.hpp`/`.cpp`) gained `sign_target()`/`verify_target()` overloads that take a raw target polynomial directly, instead of always hashing a message internally. A real blind signer only ever receives an opaque blinded target `c` from the client and must never hash a message itself - the existing message-based `sign()`/`verify()` are now thin wrappers over these. This was required to produce a genuine end-to-end NIZK2 test (see Phase 4) and closes a real gap in the eventual `BlindSigSigner` wiring, not just test scaffolding.

**Real cross-language correctness tests** (`prover-core/tests/{real_signature_tests,blinded_relation_tests}.rs`), using signatures the C++ side's own `sign()`/`sign_target()` and `verify()`/`verify_target()` genuinely produced and accepted (`BLIND/q7933-reference/rust_crosscheck_dump_512.cpp`, real `d=512` TrapGen run, seed 4) - **not fabricated Rust-side data**: the ported `relation_holds()`/`norm_squared()` accept both a plain (`c=hash_to_point(message)`) and a genuinely blinded (`c=B·r+H(rho,mu)`, computed via the exact guest-side computation path) real signature, and correctly reject a tampered target. 16/16 `prover-core` tests passing.

### Phase 4: real execution of the actual guest binaries

The plan's original bar for this phase was a full local STARK prove for both guests. A real attempt was made: switching `risc0-zkvm` to the in-process `LocalProver` with CUDA (a real NVIDIA GPU is present on the dev machine, RTX 5070/Blackwell/`sm_120`), including installing a side-by-side CUDA 12.8 toolkit (the only line new enough for `sm_120` but old enough for `risc0-sys` 1.5.0's own CUDA kernel headers - CUDA 13.x's reorganized headers don't build them at all) and patching a real glibc/CUDA `math_functions.h` `noexcept` conflict. Compiling RISC0's own CUDA circuit kernels crashed the dev machine's RAM twice - once at default `cargo` parallelism, once even at `-j 2`. The external-`r0vm`-subprocess CPU path works (confirmed non-destructive: ~20 of 24 cores, ~2GB RAM) but a full NIZK1 prove there was still running, with no completion in sight, after being let run for a while earlier in this same work.

Given that, the bar this phase actually needed to clear got re-examined: does a full STARK *prove* add correctness confidence beyond a cheap *execute-only* run (`risc0_zkvm::default_executor()`, seconds not minutes/hours - it runs the identical guest code against identical inputs, just without spending time generating the actual proof)? No - both exercise the same guest binary the same way; the STARK proof adds cryptographic assurance FOR A VERIFIER, and real proving-time numbers, neither of which bears on whether the ported code is correct. And critically, **neither the full prove nor the earlier cycle-count benchmarks had ever actually executed the real `main.rs`/`bin/nizk1.rs` guest binaries at all** - the benchmarks used separate, simpler guests (poly_mul in a loop), and the cross-language unit tests only ever exercised the extracted `relation_holds()`/`norm_squared()` functions on the host, never the guest's own `env::read()`/control-flow/`env::commit()` path or the host↔guest serialization boundary.

So Phase 4 became: a real `execute_only_check.rs` example (`methods/examples/`) running the *actual* `NIZK1_ELF` and `Q7933_GUEST_ELF` (the real `main.rs`/`bin/nizk1.rs`, not benchmarks) against real inputs via `default_executor().execute()`. **It caught a genuine bug on the first run**: the output-decoding struct only declared `valid: bool` instead of all 9 fields the guest actually commits - `postcard`'s encoding is positional, so decoding a truncated struct misreads the entire byte stream from the start (`DeserializeBadBool`, not a helpful "missing field" error), not a hypothetical failure mode. Fixed, reran clean:

```sh
cargo run -p methods --release --example execute_only_check
```

**Real results, both clean, ~16s total including compile:**

| | NIZK1 | NIZK2 |
|---|---|---|
| cycles | 36,512,588 | 11,034,289 |
| committed `valid` | `true` | `true` |
| witness | synthetic-but-real (self-consistent `r`/`mu`/`coins`/encryption) | **genuine**: the real `sign_target()`-produced, `verify_target()`-accepted blinded signature from `rust_crosscheck_dump_512.cpp` |

NIZK2's result is the more meaningful one: the actual RISC-V guest, executing the actual ported Rust relation logic, independently recomputed the blinded target and checked `t·s0+s1≡c` plus the norm bound against a signature produced by entirely separate, independently-written C++ code - and agreed. Combined with the cross-language unit tests (16/16, Phase 3), this is real end-to-end correctness evidence for both guests, even though no STARK proof was actually generated.

**What this does and does not establish.** It establishes that the real guest code (not a stand-in) runs correctly, deserializes real inputs correctly, and commits the correct result on both a synthetic-but-real NIZK1 instance and a genuinely cross-language-verified NIZK2 instance.

**UPDATE: a real, complete local STARK prove was subsequently run and completed.** After Phase 5's Karatsuba optimization (below), the user ran `prove_nizk1.rs` themselves on this same dev machine (CPU/external-`r0vm` path, `RUST_LOG=info` for live progress) - **real result: 689.0s (~11.5 minutes), receipt genuinely verified, `valid=true`.** This is faster than the Karatsuba-adjusted extrapolation below (~18 minutes) predicted, and the first real, complete, measured end-to-end zkVM proof this whole track has produced - not an estimate. `Receipt::verify()` was reached and passed for real, not just exercised in code that never got there. NIZK2's own real prove time remains unmeasured (expected considerably shorter, given its own lower cycle count - see Phase 5), and CUDA-accelerated proving remains blocked on this dev machine's RAM specifically (a hardware/environment fact, not a correctness question, not pursued further given the CPU path now has a real, acceptable measured time).

### Phase 5: Karatsuba multiplication - a real, measured speedup over schoolbook

Schoolbook cleared Phase 2's gate (14.46x vs NTT, within the "proceed" threshold), but the gate was never "schoolbook is optimal," only "schoolbook isn't a two-orders-of-magnitude problem." Karatsuba's algorithm (`poly_mul.rs`: split each operand into low/high halves, 3 half-size recursive multiplications instead of schoolbook's equivalent 4, O(n^log2(3))~=O(n^1.585) instead of O(n^2)) is a real, buildable improvement with no modulus constraint - unlike NTT, it doesn't care that q=7933 isn't NTT-friendly.

**Verification before trusting it anywhere near a guest, same discipline as everything else in this track**: the same two hand-computable cases schoolbook itself was checked against (plain and negacyclic-wraparound), a dedicated check that Karatsuba's own recursive base case matches schoolbook in isolation, and - the real cross-check - **200 random trials against the trusted schoolbook oracle**, byte-identical results required, same methodology the q=12289 sibling used for its own NTT-vs-schoolbook check. All passing. `relation.rs`'s own existing self-consistent-instance test was kept deliberately still using schoolbook to independently construct its expected value (not routed through `relation_holds()`, which now calls Karatsuba) - one more real cross-check landing "for free."

**Real cycle-count results** (`cargo run -p methods --release --example cycle_count`, updated to a 3-way comparison; `karatsuba_cycle_bench.rs` added as `poly_mul_cycle_bench.rs`'s direct sibling):

| | NTT @ q=12289 | schoolbook @ q=7933 | Karatsuba @ q=7933 |
|---|---|---|---|
| cycles (5-multiplication benchmark) | 2,557,148 | 36,960,910 | 12,268,110 |
| ratio vs. NTT | 1.0x | 14.45x | **4.80x** |

Karatsuba cuts the cycle count by **3.01x** versus schoolbook, dropping the ratio to NTT from 14.45x to 4.80x. Wired into every production call site (`relation.rs`, `enc.rs`, both real guests `main.rs`/`bin/nizk1.rs`, and the example harnesses that must match the guest's own computation exactly). Re-running Phase 4's execute-only check against the real guest binaries with Karatsuba now in place, still using the same genuine C++-signed data, confirms no regression: **NIZK1 13,491,045 cycles (was 36,512,588), NIZK2 5,352,320 cycles (was 11,034,289), both still `valid=true`.** The real guests' own speedup (2.71x/2.06x) is somewhat less than the pure-multiplication benchmark's 3.01x, as expected - hashing/encryption overhead doesn't shrink with the multiplication algorithm.

**Extrapolated (not measured) real-world implication**: the earlier ~66-minute full-client-round-trip estimate (Phase 4's own honest extrapolation from the q=12289 sibling's real ~200s/~100s prove times) drops to roughly **~26 minutes** by the same method, scaled by each guest's own real cycle-count improvement. **This was subsequently confirmed by an actual measurement, not just extrapolation - see Phase 4's own update: a real NIZK1 prove completed in 689.0s (~11.5 minutes), somewhat faster than this ~18-minute-for-NIZK1-alone extrapolation predicted.**

`schoolbook_raw`/`karatsuba_raw`'s base-case threshold (32) is a reasonable, not precisely tuned, starting point - `KARATSUBA_BASE_CASE` in `poly_mul.rs` is easy to sweep for a real zkVM-cycle-optimal value if that margin matters later, using the same `cycle_count.rs` harness.

### Explicitly deferred

Wiring the new q7933 prover into the C++ side (`blindsig_subprocess.cpp`, `lobby.cpp`, the dashboard) and a full multi-subcommand host CLI (`blindsig-prover-q7933/prover/`, mirroring the sibling's JSON-over-stdio subcommands) - both distinct, later "coexistence" work, only sensible once the guest side (this section) is itself proven correct end-to-end, which it now is (execute-only, see Phase 4). Multi-modulus/CRT-based NTT - a bigger, riskier win than Karatsuba (could approach NTT-level speed, but needs safe auxiliary-prime selection and CRT reconstruction, its own real verification burden) - not pursued since Karatsuba already brought the ratio down to a comfortable 4.80x. A full local STARK prove (real proving-time numbers, full receipt verification) - blocked on hardware, not correctness, on the current dev machine (see Phase 4's own account); `prove_nizk1.rs`/`prove_nizk2.rs` already exist (now with live `RUST_LOG`-driven progress and an always-on elapsed-time ticker) and are ready to run on hardware that can actually finish either the CPU or CUDA path.

## Next implementation order

1. ~~Keep the exact ring, NTRUSolve, oracle, coordinate-reducer, and global-reducer tests green.~~ Done, and now also covers the Gaussian sampler and quality-bound modules.
2. ~~Keep the deterministic small-coefficient corpus as a reproducible regression diagnostic.~~ Done.
3. ~~Run the explicit `d=512, q=7933` deterministic gate.~~ Done.
4. ~~Implement a separate candidate-generation/TrapGen diagnostic loop with explicit rejection reasons and trapdoor-quality measurements.~~ Done - see "TrapGen" above. `generate()` itself (not just the diagnostic) has been run successfully at `d=512, q=7933`.
5. ~~Tie candidate quality acceptance to the BLNS23/Falcon-style Gaussian sampling requirements.~~ Done - `sigma_{f,g}` sampling plus the `gamma` quality bound, both per falcon.pdf Algorithm 5.
6. ~~Add toy `ffLDL` / preimage sampling behind a separate interface.~~ Done - see "Sign/Verify: a working end-to-end pipeline" above. `ffLDL*`/`ffSampling` (falcon.pdf Algorithms 8/9/11) are implemented entirely in real coefficient domain, and a full `sign()`/`verify()` round trip has been run successfully at both toy scale and the real `d=512, q=7933` target.
7. ~~Validate distributional properties at the actual parameters.~~ First pass done - see "Distribution diagnostic" above. Empirical mean/variance moment-matching against the target Gaussian, run at both `d=32` (1000+200 samples) and the real `d=512` target (100+50 samples), both clean (variance ratios within 0.5% of `sigma^2` at `d=512`). This is a first empirical pass, not a formal statistical-distance proof - a rigorous treatment (Renyi divergence or KS-type CDF test, covariance structure, not just first/second moments) remains open if this scheme is ever pushed toward a real security claim.
8. ~~Replace `std::mt19937_64` with a real CSPRNG.~~ Done - see "Resolved: the RNG" above. `CryptoRng` (`blindsig_blns7933_csprng.hpp`/`.cpp`), OpenSSL `RAND_bytes`-seeded SHAKE256 squeeze construction, used by `generate()`, `sign()`, and both Gaussian samplers alike.
9. `hash_to_point()` (`blindsig_blns7933_sign.hpp`) is a deterministic placeholder, explicitly NOT a cryptographic hash-to-point - a real one (falcon.pdf Algorithm 3, SHAKE256-based, with a random salt per signature) is separate, unstarted work. Currently signing the same message twice targets the identical `c`, differing only in ffSampling's own randomized draw - real FALCON signatures additionally randomize `c` itself via a fresh salt each time.
10. ~~zkVM guest circuit (NIZK1/NIZK2) port to q=7933.~~ Done - see "zkVM guest port: NIZK1/NIZK2 at q=7933" above. New parallel workspace `blindsig-prover-q7933/`; Karatsuba multiplication (schoolbook first, then a real, cycle-count-measured 3.01x improvement over it, not assumed); real relation swap; `sign_target()`/`verify_target()` added; encryption noise bound re-verified via lattice-estimator at the real q=7933; the real guest binaries executed end-to-end (execute-only, not a full STARK prove - a real local hardware constraint, not a correctness gap; see Phase 4 for the full account) against real, C++-signed data. This is the piece that makes it an actual blind signature scheme, not just a plain one at q=7933.
11. Only after all of the above, design an explicit backend adapter for `BlindSigSigner` and a new keystore format/version if required.

Do not silently reinterpret the current q=12289 keystore as q=7933 key material: the existing at-rest format is explicitly a `FalconTrapdoor` and should remain so until a deliberate migration/versioning design exists.
