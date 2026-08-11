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
- explicit manual scaling/corpus/TrapGen diagnostics kept outside CTest so expensive development experiments cannot run accidentally.

Neither reducer is a production implementation. The coordinate reducer is intentionally slow; the global reducer intentionally favors transparency and high precision over Falcon's optimized FFT/NTT/31-bit-limb engineering. The 256-digit projection is used only to choose the reduction polynomial: all state-changing updates and acceptance decisions are checked with exact integer arithmetic. This is not yet a claim that the `sigma=232` **signing/preimage-sampling** preconditions have been achieved - `generate()` produces a trapdoor `(f,g,F,G)` satisfying FALCON's own keygen acceptance criteria; it does not yet sample signatures, which is a separate, still-unbuilt piece (BLNS23's `NTRU.SamplePre`, see "Next implementation order" below).

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

The current whole-repo checkpoint is 20/20 tests passing, now including the discrete Gaussian sampler and trapdoor-quality-bound tests alongside the q=7933 reference, NTRUSolve, exact reducer, and global Babai reducer tests. (This preset doesn't set an explicit `CMAKE_BUILD_TYPE`, so the Gaussian/quality tests - the two most floating-point-heavy suites - run noticeably slower here, ~4 minutes each, than under the standalone build's `-DCMAKE_BUILD_TYPE=Release`, where each is under a minute. Same correctness either way, just optimization level.)

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

**What this does and does not establish.** It establishes that a real, uniformly-sampled-from-the-correct-distribution `(f,g,F,G)` satisfying FALCON's own keygen acceptance criteria can be produced at the real BLNS23 parameters, with every step checked exactly. It does **not** establish that the *signing* side works: BLNS23's actual preimage sampler (`NTRU.SamplePre`, the paper's own `sigma=232` requirement) is a different, still-unbuilt component - see the updated roadmap below.

## Next implementation order

1. ~~Keep the exact ring, NTRUSolve, oracle, coordinate-reducer, and global-reducer tests green.~~ Done, and now also covers the Gaussian sampler and quality-bound modules.
2. ~~Keep the deterministic small-coefficient corpus as a reproducible regression diagnostic.~~ Done.
3. ~~Run the explicit `d=512, q=7933` deterministic gate.~~ Done.
4. ~~Implement a separate candidate-generation/TrapGen diagnostic loop with explicit rejection reasons and trapdoor-quality measurements.~~ Done - see "TrapGen" above. `generate()` itself (not just the diagnostic) has been run successfully at `d=512, q=7933`.
5. ~~Tie candidate quality acceptance to the BLNS23/Falcon-style Gaussian sampling requirements.~~ Done - `sigma_{f,g}` sampling plus the `gamma` quality bound, both per falcon.pdf Algorithm 5.
6. **Next real step**: add toy `ffLDL` / preimage sampling behind a separate interface - BLNS23's `NTRU.SamplePre`, the paper's own `sigma=232` requirement, is what actually produces signatures. Nothing in this module samples a signature yet; `generate()` only produces the trapdoor keypair.
7. Validate distributional properties and the `sigma=232` proof obligations at the actual parameters, once (6) exists - not yet meaningful before there's a sampler to validate.
8. Replace `std::mt19937_64` with a real CSPRNG before `generate()`'s output is trusted for anything beyond development/testing - see the RNG caveat above. Not yet done.
9. Only after all of the above, design an explicit backend adapter for `BlindSigSigner` and a new keystore format/version if required.

Do not silently reinterpret the current q=12289 keystore as q=7933 key material: the existing at-rest format is explicitly a `FalconTrapdoor` and should remain so until a deliberate migration/versioning design exists.
