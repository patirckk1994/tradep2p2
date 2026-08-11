# BLNS23 q=7933 reference substrate

This directory is intentionally isolated from the live experimental blind-signature path.

The existing `PQR-BLINDSIG` implementation continues to use the vendored official FALCON-512 implementation at q=12289.  Nothing in `BlindSigSigner`, `BlindSigKeystore`, the wire format, or the RISC0 prover sidecar uses this reference substrate yet.

Current purpose:

- exact, generic negacyclic ring arithmetic for `Z_q[x]/(x^d+1)`;
- paper parameters `q=7933`, `d=512`, `sigma=232`;
- deliberately slow, non-NTT polynomial multiplication;
- deliberately slow modular inversion by explicit linear algebra;
- exact `fG - gF = q` trapdoor-relation checking;
- a fail-closed seam for the future `NTRUGen/NTRUSolve/Reduce` port.

The NTRU trapdoor generator itself is **not implemented yet**. `NTRUTrapdoorGenerator::generate()` throws intentionally until the FALCON/GPV-style pseudocode has been ported and validated at toy dimensions first.

## Standalone build

```sh
cmake -S BLIND/q7933-reference -B build-q7933-reference
cmake --build build-q7933-reference -j
ctest --test-dir build-q7933-reference --output-on-failure
```

This standalone target exists specifically so development of the q=7933 reference implementation cannot accidentally change the production/experimental build graph before its invariants are understood.

## Next implementation order

1. Keep the exact ring tests green.
2. Port toy-dimension `NTRUSolve` and `Reduce` from the generic FALCON/GPV-style pseudocode.
3. Cross-check every returned `(f,g,F,G)` with the exact relation oracle.
4. Add toy `ffLDL` / preimage sampling behind a separate interface.
5. Validate distributional properties before scaling to d=512.
6. Only after that, design an explicit backend adapter for `BlindSigSigner` and a new keystore format/version if required.

Do not silently reinterpret the current q=12289 keystore as q=7933 key material: the existing at-rest format is explicitly a `FalconTrapdoor` and should remain so until a deliberate migration/versioning design exists.
