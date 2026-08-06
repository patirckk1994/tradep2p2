# Prompt: Phase 1 — cryptographic identity primitives

Prerequisite: `docs/identity-architecture-report.md` must exist. Paste this
file plus that report into a fresh session. This phase adds no user-visible
behavior — it's primitives and tests only.

---

## Context

This is phase 1 of 9 in an optional decentralized identity system for this
peer-to-peer trading project (see `docs/IDENTITY-PLAN.md` for the full phase
order if you want it, but you only need this file for this session). Full
plan lives across `docs/identity-0*.md`; do not read those other phase files,
they're out of scope for this session.

## Key separation

Use separate keys for separate purposes. Never transmit the master secret.
Never reuse the login key as the trade identity. Never reuse one long-term
key across unrelated mediators unless the user explicitly configures that.

```text
master identity secret
├── service-scoped login key      (phase 7)
├── local-history authentication key (phase 3)
├── per-mediator pseudonym key    (phase 6/8)
└── per-trade ephemeral key       (phase 5, freshly random, not derived)
```

Prefer deterministic derivation for the scoped long-term keys and
cryptographically random generation for per-trade ephemeral keys.

### KDF domain separation — do this correctly, not like the naive version

The naive derivation people reach for is:

```text
login_key = KDF(master_secret, "login" || service_identifier)
```

Don't implement it this way. Concatenating variable-length strings without a
length prefix or fixed-width field is exactly the ambiguity this whole spec
elsewhere warns against for signed objects (`"login" || "x"` and
`"logi" || "nx"` produce the same bytes) — it must not reappear in the KDF
info parameter. Build the derivation info as either:

- fixed-length domain labels (pad/truncate to a constant width), or
- length-prefixed fields (e.g. `u8 label_len || label || u16 id_len || id`),

and use it as the `info`/context parameter of the KDF, not naive
concatenation. Apply the same rule to every derivation:

```text
login_key        = KDF(master_secret, info("login", service_identifier))
mediator_key      = KDF(master_secret, info("mediator", mediator_identifier))
local_history_key = KDF(master_secret, info("local-history", ""))
```

`trade_key` is always freshly generated random, never derived — it must be
unlinkable to the master secret and to other trade keys.

## Signatures — Ed25519

Use OpenSSL 3.x EVP interface, `EVP_PKEY_ED25519`. Sizes: 32-byte public key,
32-byte private seed (or OpenSSL's managed representation), 64-byte
signature.

**Use the one-shot API.** Ed25519 in OpenSSL does not support the
`EVP_DigestSignUpdate`/`Final` streaming path — you must call
`EVP_DigestSign()` / `EVP_DigestVerify()` directly with the full message in
one call. Confirm this against the actually-linked OpenSSL version in the
architecture report and don't spend a cycle discovering it by trial and
error.

Use the EVP interface throughout, not deprecated low-level APIs
(`RSA_*`, direct `ed25519_*` calls, etc.).

## KDF for anything that isn't scoped-key derivation

If this phase also needs a general-purpose KDF for other primitive work
(this phase, not the keystore — that's phase 2's concern), use `EVP_KDF`
from OpenSSL 3.x rather than inventing anything custom.

## What this phase actually delivers

- A small library of primitives: key generation, scoped key derivation (with
  correct domain separation as above), Ed25519 sign/verify via the one-shot
  API, RAII wrappers for `EVP_PKEY*`/`EVP_MD_CTX*` so nothing leaks on an
  exception path.
- Constant-time comparison for anything that compares secret material or
  MACs/signatures.
- Zeroing of sensitive temporary buffers where practical (derived keys,
  intermediate KDF material) — best-effort in C++, not a hard guarantee, but
  don't skip it because it's imperfect.
- No persistence, no network messages, no keystore file format yet — that's
  phase 2. This phase is a library plus tests.

## Tests to add

- KDF domain separation: prove `KDF(secret, info("login","x"))` !=
  `KDF(secret, info("logi","nx"))` and similar adjacent-boundary cases for
  every label used.
- Ed25519 sign/verify round trip, including a negative test with a flipped
  bit in the signature and in the message.
- Malformed/invalid public key rejection (wrong length, all-zero, not a
  valid point where checkable).
- Determinism: same master secret + same scoped label always yields the same
  derived key; different label or different identifier always yields a
  different one.
- Constant-time comparison: at minimum a functional test that it produces
  correct results; don't try to assert timing in a unit test.

## Deliverable checklist for this phase

- List files changed/added.
- Explain the new data structures (key types, derivation info encoding).
- Explain the security invariants (master secret never serialized/logged,
  derivation info is unambiguous, ephemeral keys never derived).
- Explain compatibility impact (should be none — nothing calls this yet).
- Add unit tests, negative tests, and any serialization test vectors for the
  derivation-info encoding itself.
- Compile the project and run the new tests.
- Report any unresolved limitations honestly (e.g. if zeroization can't be
  guaranteed against compiler optimization in some path, say so instead of
  claiming it's solved).
