# PQ Blind Signatures — Research Status

**This is the research log, now living inside the `tradep2p2` repo itself**
(originally written in a separate, isolated research directory — moved here,
with paths updated, now that the primitive is being wired into this repo as
an experimental, off-by-default feature; see `specs.txt` §9.3a and the
`PQR-BLINDSIG` branch for the in-progress integration, and `README.md` in
this folder for the current status of that integration specifically — this
file is the *research* history, not a live status page).

**Target paper:** Beullens, Lyubashevsky, Nguyen, Seiler, *Lattice-Based Blind
Signatures: Short, Efficient, and Round-Optimal*, CCS 2023 / [eprint
2023/077](https://eprint.iacr.org/2023/077). Referenced by name and link only
in this repo — the PDF itself isn't redistributed here (ACM/CCS-published
paper; eprint preprints are fine to read and cite, but a public repo
redistributing the PDF is a different question we didn't need to answer by
just linking it instead).

**Context:** exploring whether this scheme could ever be implemented for
TradeP2P/UMBRA's optional unlinkable-reputation layer (`specs.txt` §9.3).
This started as a feasibility investigation and grew into a working
prototype of both NIZK1 and NIZK2 (see below), independently verified, and
is now being wired into this repo itself as an explicit, informed,
ahead-of-independent-review decision — see `specs.txt` §11 for the honest
account of that call.

---

## What we confirmed is real

Both papers checked directly against primary sources, not taken on faith
from secondhand summaries:

- **Beullens/Lyubashevsky/Nguyen/Seiler** (eprint 2023/077, CCS 2023) — 22KB
  signatures, ~2.5 years of published cryptanalysis exposure.
- **BRaccoon** (eprint 2026/1084, May 2026) — produces signatures
  syntactically identical to a standard scheme, but only weeks old with
  essentially no independent scrutiny.
- **Parallel ROS attack** (PKC 2024) — broke three blind-signature schemes,
  including a lattice-based one, that had already cleared peer review. Real
  reminder that "looked sound for a year" isn't the same as safe.

## The exact protocol (extracted from the paper, Fig. 4)

```
Signer: T (trapdoor, secret), B ∈ R_q^{1×2}, pk        User: A, B ∈ R_q^{1×2}, pk

User:
  r ← D_σ0 ∈ R_q^2, resample if ‖r‖ > β_r
  c = B·r + H(G(r), µ)
  coins ← {0,1}^λ
  ct = PKE.Enc(r, µ; pk, coins)
  π1 = NIZK1.P( ∃ r,µ,coins : c = B·r + H(G(r),µ) ∧ ct = Enc(r,µ;pk,coins) ∧ ‖r‖ ≤ β_r )
  → sends (c, ct, π1) to signer

Signer:
  if NIZK1.V(π1) = 0: abort
  s ← A⁻¹_σ(c)   [FALCON-style Gaussian trapdoor preimage sample]
  resample if ‖s‖ > β_s
  → sends s back

User (finalize):
  ρ = G(r);  h = H(ρ,µ)
  π2 = NIZK2.P( ∃ r,s : A·s = B·r + h ∧ ‖s‖ ≤ β_s ∧ ‖r‖ ≤ β_r )
  signature = (ρ, π2)

Verify: h = H(ρ,µ); return NIZK2.V(π2)
```

Concrete parameters (paper's own Table 2/notation): ring `(q,d) = (7933,
512)`, proof-system modulus `q̂ ≈ 2^41`, total π2 proof size `21.5KB`
(matches the abstract's rounded "22KB"), target root Hermite factor
`~1.0042–1.0045` for 128-bit security. **This repo's implementation uses
FALCON-512's own stock `q=12289` instead — see "What's NOT resolved:
parameter fidelity" below, the single biggest open question this code has.**

## The library find: LaZer / LaBRADOR

[LaZer](https://github.com/lazer-crypto/lazer) — MIT-licensed, built partly
by **Lyubashevsky and Seiler**, two of this paper's own four authors. It's a
general toolkit: describe a lattice relation, it builds a working ZK proof
system for it, using **LaBRADOR** (also Beullens/Seiler-authored) or a
linear-size ("LNP22") proof system.

**Important correction made mid-research:** LaZer's `demos/blindsig` is
*not* a reference implementation of our paper. It implements a different,
related paper (Bootle/Lyubashevsky/Nguyen/Sorniotti, "A Framework for
Practical Anonymous Credentials from Lattices," CRYPTO 2023 — coincidentally
also cited under the acronym `BLNS23`). Checked the whole bibliography;
Beullens/Lyubashevsky/Nguyen/Seiler's paper isn't cited in that repo at all.

**Why LaZer still matters directly:** the target paper's own parameter
section explicitly states π2 is built using **[LNP22]**, and names
**LaBRADOR [BS22]** as a candidate technique for π1 — both of which are
exactly what LaZer implements. This is about as direct a library-to-paper
match as this kind of search turns up. (Not vendored into this repo — see
[the LaZer GitHub repo](https://github.com/lazer-crypto/lazer) directly if
useful for cross-reference.)

## What's tractable: π2

Maps cleanly onto LaZer's existing parameter-spec DSL — a genuine
parameter-translation task for someone who understands both papers' math,
not a from-scratch build, if a native-LaBRADOR path is ever pursued instead
of the zkVM path this repo actually took (see below).

## What was NOT solved anywhere we could find: π1

Read directly from the paper's own introduction (not inferred):

> "We leave the implementation of [LNP22, BS22] and their adaptations to
> our blind signature scheme as **important future work**."

π1 has to prove a **SHA-style hash function evaluation was computed
correctly, inside zero knowledge** (the paper quantifies it: an output of
`832 bytes ≈ 26 SHA outputs`). That's a fundamentally different, harder kind
of proof than the algebraic lattice relations LaBRADOR/LNP22 are built for.
The paper's own authors — including two of LaZer's own creators — say
plainly that nobody, including them, had actually built this integration as
of this paper's writing.

**The insight that made a concrete π1 tractable**: no cross-proof-system
composition is actually needed. π1 is checked once by the signer before it
signs; π2 is checked later by anyone; neither party ever needs to verify a
relationship *between* the two proofs — only the user needs `r` to be
consistent across them, and they trivially know it, since they generated it.
That means a general-purpose zkVM proving the *whole* computation (lattice
arithmetic, hash, encryption, norm check) as an ordinary program trace —
no specialized relation needed — is a legitimate way to instantiate π1,
not a shortcut past the hard part. This doesn't touch the paper's security
proof either: a zkVM only proves "this program ran correctly on hidden
inputs," so `H`/`G` stay the same SHA-based random oracles the proof relies
on. This repo's `blindsig-prover/` is exactly that: NIZK1 and NIZK2 as two
RISC0 zkVM guest programs, see below.

A shortcut considered and explicitly **not** pursued: swapping `H`/`G` for a
lattice-native SIS-based hash, which would make the entire π1 relation
directly expressible in LaBRADOR/LNP22 with no second proof system needed.
Rejected because the paper's security proof treats `H`/`G` as ideal random
oracles, and an SIS-based hash doesn't have that property in the same sense
— making that swap would need a **new security argument**, not already
established anywhere found. That crosses from "engineering" into "original,
unreviewed cryptographic research."

## What's built: the algebraic core, real FALCON trapdoor sampling

`BLIND/prototype-demo/blind_falcon_demo.cpp` — a resource-naive C++
prototype using the **real, vendored, unmodified official FALCON reference
implementation** (`falcon-sign.info`, vendored at
`third_party/falcon-impl-20211101/` in this repo) for trapdoor generation
and Gaussian preimage sampling, with the paper's additive-blinding idea
(`c = B·r + H(G(r),µ)`) layered on top. **Verified: `A·s = B·r + H(G(r),µ)`
round-trips correctly through real FALCON trapdoor sampling, 5/5 runs with
freshly random keys each time.** No zero-knowledge layer at all in this one
file — it reveals `(ρ, r, s)` in the clear, zero blindness, by design: it
only tests that the underlying algebra works with a real trapdoor sampler.
The actual zero-knowledge layer lives in `blindsig-prover/`.

## NIZK1 and NIZK2: real zero-knowledge, via a RISC0 zkVM

`blindsig-prover/` (this repo's canonical, current version — a refactor of
what was originally built and verified in the standalone research
directory as `nizk2_zkvm/`) has both proofs:

- **NIZK2** proves knowledge of `(r, s)` satisfying `A·s = B·r + H(ρ,µ)`
  (FALCON's own `verify_raw()`/`is_short()` check, reimplemented faithfully
  in Rust) without revealing them. Measured: ~98-100s proof generation
  (CPU, NTT-optimized guest), independently verified receipt, empirically
  confirmed zero private-witness bytes in the serialized proof.
- **NIZK1** proves the blinding relation `c = B·r + H(G(r),µ)` **and** the
  "encryption to the sky" extractability property (see below), together, in
  one proof, without revealing `r`, `µ`, or the encryption `coins`.
  Measured (current `blindsig-prover` build): **212.1s, 1,730,169-byte
  (~1.65MB) receipt** — this repo's own re-measurement; the original
  research prototype measured 207.2s for the same relation.

Both use a faithful port of FALCON's own NTT (ported function-for-function
from `vrfy.c`, not re-derived) for the guest's polynomial arithmetic —
verified against a schoolbook reference on 200 random trials
(`prover-core`'s own test suite) before ever being trusted in the guest.

**Encryption to the sky, what it actually is**: the paper's own footnote 6
says this PKE "public key" need never be validly generated, since it's
never decrypted in the live protocol — its only role is enabling the
security proof's extraction argument. Built as a standard LPR-style
(Lyubashevsky-Peikert-Regev) Ring-LWE dual encryption,
`(a·u+e1, pk·u+e2+message)`, with `a`/`pk` fresh random ring elements (no
real keypair) and `u,e1,e2` short polynomials derived deterministically
from `coins`. Two independent ciphertexts — one for `r` directly, one for
`SHA-256(µ)`'s bits — rather than one dense packed ciphertext, to avoid
inventing a custom multi-bit encoding on top of everything else that's
already novel here. Cross-checked natively against real generated
ciphertexts before ever being trusted inside the slow zkVM guest, including
a negative control that corrupts `r` and confirms the check correctly
rejects it (`prover-core`'s `enc` module tests).

**Honest scope, stated plainly**: this construction (the specific
encryption scheme, the message-encoding choice, the split into two
ciphertexts) was designed for this project, not ported from the paper or
from LaZer/LaBRADOR — the paper deliberately leaves the PKE choice open
("we need an IND-CPA encryption scheme") and never concretely instantiates
one. It has been verified to be self-consistent (round-trips, discriminates
correctly against a corrupted witness) but **not independently reviewed for
whether it actually provides the extraction property the paper's security
proof needs from it**. This is the single thing under review with the
highest priority — see `REVIEW_REQUEST.md`.

## What's NOT resolved: parameter fidelity (q=12289 vs q=7933)

This is the biggest open question in this codebase's blind-sig work, and
it is *not* something that gets resolved by running the code — the
implementation will produce correct-looking output regardless of whether
the chosen modulus gives adequate security margin, since correctness of
the arithmetic and security of the parameters are different questions.

FALCON-512's own modulus (`q=12289`) was chosen and analyzed for *plain*
FALCON signatures. The paper's blind-signature construction uses a
different modulus (`q=7933`) — chosen, per the paper's own parameter
analysis, to hit their target root Hermite factor (`~1.0042-1.0045`) for
128-bit security *for the blind construction specifically*, which may need
a different margin than plain FALCON needs (e.g. depending on how the
blinding relation's own lattice geometry, the NIZK soundness slack, or the
encryption-to-the-sky noise growth factor into the reduction). Reusing
FALCON-512's stock modulus was a deliberate choice to stay on already-vetted
arithmetic rather than hand-derive new NTT tables for an arbitrary modulus
— but it means this implementation does **not** automatically inherit the
paper's own security analysis.

**Update — we actually ran this check, here's what it found and didn't
find.** Using `lattice-estimator` (Martin Albrecht et al., the standard
tool behind NIST PQC parameter selection - SageMath 10.9, real run, not a
hand-derived estimate):

- *Sanity check first*: the tool's own built-in `Falcon512_Unf` parameters
  (FALCON-512's actual unforgeability problem, `n=512, q=12289`) estimate
  at **≈2^121-146 bits** depending on cost model (`rough` vs full
  `estimate`), root Hermite factor `δ≈1.003882`. This matches FALCON-512's
  publicly documented NIST Level 1 security - confirms the tool and
  methodology are being used correctly before trusting anything novel from
  it.
- *Then we tried the obvious framing for our own blinding relation*: model
  "given public `B` and target `t`, find short `r` (worst-case `‖r‖≈45.25`
  for coefficients bounded in `[-2,2]`, `n=512`)" as a SIS instance, at both
  `q=12289` and `q=7933`, same `(n,m)` shape as `Falcon512_Unf`. Both
  moduli returned **identical results**: `rop: ≈2^inf, δ: 1.002007` - the
  required root Hermite factor for a target this short, relative to this
  lattice's Gaussian-heuristic scale, is beyond what BKZ can reach at any
  practical block size. Same result at both `q`, meaning this framing
  doesn't discriminate between the two moduli **at all**.
- *What that actually means*: not "we're unconditionally safe" - it means
  this specific framing is the wrong question. `r` isn't something an
  attacker searches for against an arbitrary target; the honest user picks
  `r` first, then computes `c = B·r + H(...)` from it. There is no
  "find `r` from `B` and a random target" attack in the real protocol,
  which is presumably *why* a generic SIS reformulation returns
  "infeasible" regardless of `q` - it's not modeling a real adversary
  strategy. The real hardness questions - the paper's own "one-more
  unforgeability" / ROS-resistance bound, and how the NIZK's soundness
  slack and the encryption-to-the-sky noise growth factor into their
  reduction - are reduction-specific properties tied to the paper's own
  proof, not raw SIS/LWE/NTRU instances a generic estimator can evaluate
  by itself.

**Where this leaves us**: real, tool-verified confirmation that `q=12289`
is not some obviously-broken modulus for a ring/dimension this size (the
FALCON-512 sanity check backs that), but no verified answer - because
there isn't a simple lattice-hardness number to compute - to whether it
carries the *specific* extra margin the paper's own reduction needs for
the blind construction. That answer requires reading the paper's actual
theorem/proof and substituting `q=12289` into their own bound, which is
exactly the kind of thing that needs a cryptographer's judgment, not a
tool call. Still `REVIEW_REQUEST.md` priority #3.

## Roadmap: what has to be true before this is a responsible production integration

Written down explicitly so "we prototyped it" is never confused with "it's
ready." Roughly dependency-ordered.

1. **NIZK1 has to exist.** ✅ Done — both halves (blinding relation +
   encryption-to-the-sky), verified. Still needs independent review (#3)
   before that changes what it means for production readiness.
2. **Real parameters, not FALCON-512's borrowed ones** — or a real analysis
   of why the borrowed ones are still safe for this construction. See
   "What's NOT resolved" above. **Still open.**
3. **Independent cryptographic review**, by someone who is neither of us —
   in progress, package sent to a cryptographer contact (QRL2). Some
   real-world cryptanalysis exposure time matters too — Parallel ROS broke
   three schemes that had looked sound for a year.
4. **Proving time** (~100-212s per proof) — acceptable for an experimental,
   clearly-labeled feature where proving is entirely client-side and the
   signer's own per-request cost stays fast (see `specs.txt` §9.3a); still
   too slow for anything presented as a snappy interactive feature.
5. **Language boundary** — resolved for the experimental integration: a
   separate Rust sidecar process (`blindsig-prover/`), invoked over a
   subprocess boundary, not linked into the C++ binary. See `specs.txt`
   §9.3a.
6. **Key custody** for the signer's FALCON trapdoor — resolved for the
   experimental integration via an AEAD-encrypted keystore, stricter than
   this codebase's usual operational-key custody given the stakes. See
   `specs.txt` §9.3a.
7. **A real test suite.** No official test vectors exist anywhere for this
   scheme. `prover-core` has regression tests (NTT correctness, encryption
   negative control); the wire protocol and keystore have their own C++
   unit tests. Property-based / differential testing against LaZer-adjacent
   tooling is still open.
8. **Honest `specs.txt` documentation** — done, see §9.3a and the §11
   rewrite explaining why this was built ahead of independent review.
9. **Explicit, separate authorization to wire it into `tradep2p2` itself.**
   ✅ Given explicitly by the project lead — see `specs.txt` §11.

## Files

- `README.md` (this folder) — current integration status, entry point.
- `REVIEW_REQUEST.md` — the reviewer-facing document.
- This file — research history.
- `prototype-demo/` — the original no-ZK algebraic-core demo
  (`blind_falcon_demo.cpp` + `Makefile` + a sample instance JSON). Builds
  against `../../third_party/falcon-impl-20211101/`.
- `../blindsig-prover/` — the actual NIZK1/NIZK2 Rust implementation (not
  duplicated here — this folder is documentation/reference, not a second
  copy of the code).
- `../third_party/falcon-impl-20211101/` — the vendored FALCON C reference.
