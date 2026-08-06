# Prompt: Phase 2 — encrypted local keystore

Prerequisite: `docs/identity-architecture-report.md` and phase 1 (crypto
primitives) must already be merged. Paste this file plus the architecture
report into a fresh session.

---

## Context

Phase 2 of the identity plan (see `docs/IDENTITY-PLAN.md` for the overall
order — you don't need the other phase files in this session). This phase
implements local, at-rest storage for the keys phase 1 defined. No network
protocol changes in this phase.

## Format

A local identity keystore file containing:

```text
format version
identity identifier
encrypted master secret or encrypted scoped private keys
public keys
KDF parameters
AEAD nonce
AEAD authentication tag
creation time
optional human-readable alias
```

## Encryption

Authenticated encryption via OpenSSL EVP: AES-256-GCM or
ChaCha20-Poly1305.

**Key derivation from the user's passphrase — do not take the PBKDF2
fallback by default.** The obvious reading of "use a memory-hard KDF if
already available in the repository, otherwise fall back to PBKDF2" is wrong
for this codebase: check what's actually linked before concluding nothing is
available. This project links OpenSSL 3.x, which ships:

- scrypt via `EVP_KDF` (OpenSSL 3.0+)
- Argon2id via `EVP_KDF` (OpenSSL 3.2+)

Confirm the linked OpenSSL version (the architecture report should already
have it; if not, check now) and use scrypt or Argon2id through `EVP_KDF`.
Only fall back to PBKDF2, with the limitation clearly documented in the code
and in this phase's report, if the linked OpenSSL genuinely lacks both —
don't reach for PBKDF2 just because it's the only one already used elsewhere
in the repo for something else.

Never write plaintext private key material to logs, debug output,
exceptions, crash reports, JSON diagnostics, or terminal output. Audit
existing logging call sites (`append_log` or equivalent — check the actual
name in the architecture report) to make sure a caught exception from this
module can't carry key bytes into a log line.

## Operations

```text
create
unlock
lock
change passphrase
export encrypted backup
import encrypted backup
display public identity
rotate service-scoped key
destroy local identity
```

- Default export stays encrypted. Plaintext export must either not exist, or
  require an explicit separate dangerous operation with confirmation — not a
  flag on the normal export path.
- Do not silently overwrite an existing identity file. `create` on an
  existing path is an error, not an implicit overwrite.

## Atomic file replacement

```text
write temporary file
fsync if supported
rename atomically
set restrictive permissions
```

On Unix-like systems, owner-only permissions (0600/0700 as appropriate) both
on the temp file *before* it's populated and on the final path.

## Tests to add

- Round trip: create → lock → unlock → verify keys match.
- Wrong passphrase is rejected without leaking timing/error detail that
  narrows the search space.
- Corrupted AEAD tag/nonce/ciphertext is rejected, not silently accepted or
  silently regenerated — a keystore that fails to authenticate must produce a
  clear error, not a fresh identity.
- Change-passphrase re-encrypts without ever writing an intermediate
  plaintext-adjacent file.
- Import/export round trip, including rejecting a tampered encrypted backup.
- Atomicity: simulate a crash between temp-file write and rename (e.g. kill
  the process or mock the rename call) and verify the original file is
  untouched.
- Permission check: verify the file is created with owner-only permissions
  on Unix.
- Malformed keystore file (truncated, wrong format version, garbage) is
  rejected with a structured error, not a crash or silent fallback.

## Deliverable checklist for this phase

- List files changed/added (e.g. `IdentityKeyStore` or whatever name fits
  existing naming conventions from the architecture report).
- Explain the keystore file format fields and why each is there.
- Explain security invariants: AEAD used correctly (unique nonce per
  encryption, tag verified before any use of decrypted material), KDF choice
  and parameters, atomic-write guarantee, permission model.
- Explain compatibility impact (new opt-in file, no existing behavior
  changes).
- Add the tests above, including malformed-input and negative tests.
- Compile and run tests.
- Report unresolved limitations honestly (e.g. if `fsync` isn't available on
  some target, say so rather than asserting durability everywhere).
