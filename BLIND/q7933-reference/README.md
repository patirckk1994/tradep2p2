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

**Known, unresolved gap: the RNG.** Every test/diagnostic here passes `std::mt19937_64` - not a cryptographically secure generator - into `generate()`. That's fine for the statistical/correctness testing this module exists for so far, but `f,g` ARE the secret trapdoor; this needs a real CSPRNG (e.g. this project's existing OpenSSL `RAND_bytes` usage elsewhere) before `generate()`'s output should be trusted for anything beyond development. This is a distinct property from the numerical-precision questions above - precision affects whether the *distribution* is right, RNG quality affects whether the *actual secret* is unpredictable - and only the former is addressed so far.

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

The current whole-repo checkpoint is 23/23 tests passing, now including the discrete Gaussian sampler, trapdoor-quality-bound, real-ring-arithmetic, Falcon-tree, and full sign/verify tests alongside the q=7933 reference, NTRUSolve, exact reducer, and global Babai reducer tests. (This preset doesn't set an explicit `CMAKE_BUILD_TYPE`, so the Gaussian/quality tests - the two most floating-point-heavy suites - run noticeably slower here, ~4 minutes each, than under the standalone build's `-DCMAKE_BUILD_TYPE=Release`, where each is under a minute. Same correctness either way, just optimization level.)

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

## Next implementation order

1. ~~Keep the exact ring, NTRUSolve, oracle, coordinate-reducer, and global-reducer tests green.~~ Done, and now also covers the Gaussian sampler and quality-bound modules.
2. ~~Keep the deterministic small-coefficient corpus as a reproducible regression diagnostic.~~ Done.
3. ~~Run the explicit `d=512, q=7933` deterministic gate.~~ Done.
4. ~~Implement a separate candidate-generation/TrapGen diagnostic loop with explicit rejection reasons and trapdoor-quality measurements.~~ Done - see "TrapGen" above. `generate()` itself (not just the diagnostic) has been run successfully at `d=512, q=7933`.
5. ~~Tie candidate quality acceptance to the BLNS23/Falcon-style Gaussian sampling requirements.~~ Done - `sigma_{f,g}` sampling plus the `gamma` quality bound, both per falcon.pdf Algorithm 5.
6. ~~Add toy `ffLDL` / preimage sampling behind a separate interface.~~ Done - see "Sign/Verify: a working end-to-end pipeline" above. `ffLDL*`/`ffSampling` (falcon.pdf Algorithms 8/9/11) are implemented entirely in real coefficient domain, and a full `sign()`/`verify()` round trip has been run successfully at both toy scale and the real `d=512, q=7933` target.
7. ~~Validate distributional properties at the actual parameters.~~ First pass done - see "Distribution diagnostic" above. Empirical mean/variance moment-matching against the target Gaussian, run at both `d=32` (1000+200 samples) and the real `d=512` target (100+50 samples), both clean (variance ratios within 0.5% of `sigma^2` at `d=512`). This is a first empirical pass, not a formal statistical-distance proof - a rigorous treatment (Renyi divergence or KS-type CDF test, covariance structure, not just first/second moments) remains open if this scheme is ever pushed toward a real security claim.
8. Replace `std::mt19937_64` with a real CSPRNG before `generate()`'s or `sign()`'s output is trusted for anything beyond development/testing - see the RNG caveat above. Not yet done. `sign()` inherits this same gap: ffSampling's randomness quality matters just as much as TrapGen's.
9. `hash_to_point()` (`blindsig_blns7933_sign.hpp`) is a deterministic placeholder, explicitly NOT a cryptographic hash-to-point - a real one (falcon.pdf Algorithm 3, SHAKE256-based, with a random salt per signature) is separate, unstarted work. Currently signing the same message twice targets the identical `c`, differing only in ffSampling's own randomized draw - real FALCON signatures additionally randomize `c` itself via a fresh salt each time.
10. **Actual blocker to "replace FALCON" in the live blind-signature protocol**: the zkVM guest circuit (NIZK1/NIZK2, `blindsig-prover/methods/`) still hardcodes NTT arithmetic for `q=12289` - everything in this file gives a plain (non-blind) signature scheme at `q=7933`, not yet a blind one. Porting the guest circuits to a non-NTT strategy compatible with `q=7933` is unstarted and is a larger, separate piece of work than anything above.
11. Only after all of the above, design an explicit backend adapter for `BlindSigSigner` and a new keystore format/version if required.

Do not silently reinterpret the current q=12289 keystore as q=7933 key material: the existing at-rest format is explicitly a `FalconTrapdoor` and should remain so until a deliberate migration/versioning design exists.
