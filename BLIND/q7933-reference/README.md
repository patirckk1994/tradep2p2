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
- explicit manual scaling/corpus diagnostics kept outside CTest so expensive development experiments cannot run accidentally.

The full NTRU trapdoor generator itself is **not implemented yet**. `NTRUTrapdoorGenerator::generate()` still throws intentionally because candidate `f,g` sampling, trapdoor-quality acceptance, and the final BLNS23 `NTRU.SamplePre` path have not been implemented or validated.

Neither reducer is a production implementation. The coordinate reducer is intentionally slow; the global reducer intentionally favors transparency and high precision over Falcon's optimized FFT/NTT/31-bit-limb engineering. The 256-digit projection is used only to choose the reduction polynomial: all state-changing updates and acceptance decisions are checked with exact integer arithmetic. This is not yet a claim that the `sigma=232` sampling preconditions have been achieved.

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

## Controlled scaling diagnostics: d=16/32/64

The first manual diagnostics executable compares the exact coordinate baseline, the 256-digit global reduction, and exact coordinate cleanup at `d=16`, `32`, and `64` with `q=7933`:

```sh
./build-blns7933-root/tradep2p_blns7933_scaling_diagnostics
```

It is deliberately **not** registered with CTest. The deterministic sparse anchor has validated the global reducer through `d=64`: the global step reduces the lifted solution in a handful of rounds while the coordinate reducer remains only a slow correctness/cleanup oracle. The executable hard-checks `fG-gF=q` after the solver and after every reduction stage, checks exact squared-norm monotonicity, and prints recursion-level coefficient growth, global rounds, coordinate cleanup work, and wall-clock timings.

## Explicit d=128 gate

The next-size gate is a separate executable so `d=128` cannot be reached accidentally by the routine `d=16/32/64` diagnostic. It deliberately omits the expensive direct coordinate baseline and measures only:

`NTRUSolve -> global Babai reduction -> exact coordinate cleanup`.

Build and run it explicitly:

```sh
cmake --build --preset blns7933-root \
  --target tradep2p_blns7933_scaling_128_diagnostic \
  --parallel 2

./build-blns7933-root/tradep2p_blns7933_scaling_128_diagnostic
```

The same exact NTRU relation and monotonic-norm postconditions are enforced at `d=128`.

## Deterministic small-coefficient corpus

A second manual executable exercises a reproducible corpus at `d=16`, `32`, and `64`. Each degree includes the known sparse anchor plus five fixed-seed sparse small-coefficient candidates.

```sh
cmake --build --preset blns7933-root \
  --target tradep2p_blns7933_corpus_diagnostics \
  --parallel 2

./build-blns7933-root/tradep2p_blns7933_corpus_diagnostics
```

Candidate rejection is expected behavior and is reported as `REJECT`, not as a test failure. For every accepted candidate, the diagnostic requires exact `fG-gF=q` preservation through the global reducer and cleanup, exact non-increasing squared norms, and reports solver/reducer timing, coefficient/norm bit lengths, global rounds, cleanup steps, and convergence status.

This corpus is still a development diagnostic, not the final BLNS23 key distribution. It exists to move beyond the single `f=1+x, g=1+2x` anchor before opening larger dimension gates.

## Next implementation order

1. Keep the exact ring, NTRUSolve, oracle, coordinate-reducer, and global-reducer tests green.
2. Run the deterministic small-coefficient corpus through `d=64` and inspect acceptance/rejection plus reducer behavior.
3. Run the explicit `d=128` gate. If its solver growth, global rounds, exact cleanup work, and runtime remain sane, add a separate `d=256` gate.
4. Run a single deterministic `d=512, q=7933` diagnostic before implementing a random TrapGen rejection loop.
5. Add candidate `f,g` generation and trapdoor-quality analysis tied to the BLNS23/Falcon-style Gaussian sampling requirements; exact equation correctness alone is not sufficient.
6. Add toy `ffLDL` / preimage sampling behind a separate interface.
7. Validate distributional properties and the `sigma=232` proof obligations at the actual parameters.
8. Only after that, design an explicit backend adapter for `BlindSigSigner` and a new keystore format/version if required.

Do not silently reinterpret the current q=12289 keystore as q=7933 key material: the existing at-rest format is explicitly a `FalconTrapdoor` and should remain so until a deliberate migration/versioning design exists.
