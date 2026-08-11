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
- an exact coordinate-descent reference reducer which preserves the NTRU relation at every accepted step;
- an independent degree-2 brute-force oracle used to test the distinction between direct equation solvability and TrapGen candidate acceptance.

The full NTRU trapdoor generator itself is **not implemented yet**. `NTRUTrapdoorGenerator::generate()` still throws intentionally because candidate `f,g` sampling, trapdoor-quality acceptance, and the final BLNS23 `NTRU.SamplePre` path have not been implemented or validated.

The current reducer is a correctness baseline, not a claim that Falcon-quality reduction or the `sigma=232` sampling preconditions have been achieved.

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

## Controlled scaling diagnostics

A manual diagnostics executable measures the exact solver and baseline reducer at `d=16`, `32`, and `64` with `q=7933`:

```sh
./build-blns7933-root/tradep2p_blns7933_scaling_diagnostics
```

It is deliberately **not** registered with CTest, so routine test runs cannot accidentally become scaling benchmarks. The diagnostic candidate is deterministic and sparse; it is not intended to represent the eventual BLNS23 TrapGen key distribution. The executable hard-checks `fG-gF=q` before and after reduction and prints recursion-level coefficient bit growth, raw/reduced norm bit lengths, reduction passes/steps, and wall-clock timings.

The current scaling checkpoint is intentionally capped at `d=64`. `d=128`, `256`, and `512` are separate explicit development gates.

## Next implementation order

1. Keep the exact ring, NTRUSolve, oracle, and reducer tests green.
2. Inspect controlled scaling diagnostics through `d=64`.
3. If coefficient growth and runtime remain understandable, add separate `d=128` and `d=256` diagnostic gates before attempting `d=512`.
4. Add trapdoor-quality analysis tied to the BLNS23/Falcon-style Gaussian sampling requirements; exact equation correctness alone is not sufficient.
5. Add toy `ffLDL` / preimage sampling behind a separate interface.
6. Validate distributional properties and the `sigma=232` proof obligations at the actual parameters.
7. Only after that, design an explicit backend adapter for `BlindSigSigner` and a new keystore format/version if required.

Do not silently reinterpret the current q=12289 keystore as q=7933 key material: the existing at-rest format is explicitly a `FalconTrapdoor` and should remain so until a deliberate migration/versioning design exists.
