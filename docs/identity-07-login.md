# Prompt: Phase 7 — service-scoped challenge-response login

Prerequisite: `docs/identity-architecture-report.md` and phases 1-2 (crypto
primitives, keystore) must already be merged. Paste this file plus the
architecture report into a fresh session.

---

## Context

Phase 7 of the identity plan — deliberately scheduled near the end, not
phase 3 as in the original conceptual write-up. This is the lowest-value
item of the nine: it only affects the hosted web client's password
replacement (`webclient-accounts.tsv` or equivalent per the architecture
report), and the existing PBKDF2-based path there is already careful. It
also only matters for the client where, per phase 9, the operator controls
the served JavaScript anyway — so a stronger login mechanism there has a
real but bounded ceiling on what it can protect against.

## Which login this phase actually changes — resolve before writing code

The architecture report (`docs/identity-architecture-report.md`, §2) found
that the *only* existing login flow — `AccountStore`/`SessionManager` in
`src/http_webclient.cpp` — authenticates a browser session to that one
web-client instance. It never reaches the mediator protocol at all;
`LobbyServer::Impl::dispatch()` (`src/lobby.cpp:489-515`) has no login
message case of any kind today. So "service-scoped login" is not a drop-in
replacement of one existing thing — it's a design fork this phase must
resolve explicitly and state in its report:

1. Extend the existing web-client `AccountStore` to also bind a phase-2
   keystore identity per account (keeps the scope limited to the hosted web
   client, matches this phase's original motivation of replacing password
   storage), or
2. Introduce a new, separate mediator-facing login message
   (`IDENTITY_CHALLENGE`/`IDENTITY_RESPONSE`, dispatched through
   `LobbyServer::Impl::dispatch()`) that authenticates a connection to the
   mediator itself, independent of the web client, or
3. Both, explicitly scoped as two separate features sharing the same
   keystore/challenge primitives from phase 1.

Pick one and say why in the phase report — don't let the implementation
silently default to whichever was easier to bolt on.

## Accept-loop concurrency — already handled, no prerequisite blocker

An earlier version of this plan assumed the TLS accept loop was unbounded
thread-per-connection and required a pooling fix before this phase could
safely add a challenge round trip. The architecture report checked this
directly (verification item 2) and found it's already bounded: both
`LobbyServer` and `RegistryServer` cap in-flight handshakes at
`kMaxPendingHandshakes = 64` before a thread is even spawned, the lobby
separately caps established clients at `kMaxClients = 128`, and each
handshake is bounded to 10s. There's no separate prerequisite to land here.
The one thing worth being deliberate about: this phase's challenge/response
adds a round trip *before* `Welcome`, which extends how long a connection
occupies those already-capped windows — pick a challenge expiry that's
comfortably inside the existing 10s handshake bound, and note the choice in
the phase report, but don't block the phase on infrastructure work that
turned out to already exist.

## Design

Replace or supplement password-based login with challenge-response
authentication. The server stores only the public login key or its
identifier — not a shared secret.

A login challenge must bind at least:

```text
protocol version
service identifier
server identity or domain
session identifier
random nonce
challenge creation time
challenge expiry
TLS channel binding or TLS exporter value where available
```

Use the domain-separated canonical serialization from phase 1
(`TRADEP2P_LOGIN_CHALLENGE_V1` or whatever label fits). Do not sign ambiguous
string concatenations — same discipline as phase 1's KDF fix, applied here to
the signed challenge object.

The server must:

- generate a cryptographically random nonce,
- enforce challenge expiry,
- make each challenge single-use,
- reject replayed signatures,
- bind the signature to the intended service,
- bind it to the current session where possible,
- rate-limit authentication attempts,
- avoid account enumeration (a failed lookup and a failed signature check
  should not be distinguishable from the response).

The public key may act as the account identifier itself, or a separate
local alias may map to it. Do not expose the same public login key to
unrelated services by default (ties back to the per-service key derivation
from phase 1 — confirm the login key is actually service-scoped here, not
reused).

New message types: `IDENTITY_CHALLENGE`, `IDENTITY_RESPONSE`.

## Migration

The architecture report should have identified the existing
password/account storage. This phase must include explicit migration
handling for it — existing accounts don't just get ignored or silently
orphaned. At minimum: document how an existing password-based account
either continues to work unmodified, or how a user opts an existing account
into key-based login without losing access. Don't leave this as an implicit
gap; the original spec asked for migration handling generally and this is
the concrete place it was missing.

## Cost of running both paths

Supporting both password-based and key-based login means two auth paths in
the hosted web client's server-side handler. Check the actual file size and
complexity in the architecture report before assuming this is free — if the
existing password path is already large, adding a second full path is a real
maintenance cost, not a footnote. State this cost plainly in the phase
report; it's a legitimate reason to consider a cleaner migration instead of
permanent dual-path support, but that trade-off is the repo owner's call,
not something to decide silently in this session.

## Tests to add

- Full challenge-response round trip, valid signature accepted.
- Expired challenge rejected.
- Replayed (already-used) challenge/signature rejected.
- Challenge bound to wrong service/session rejected (signature valid, wrong
  context).
- Malformed/invalid public key rejected.
- Rate limiting: repeated failed attempts throttled.
- Account enumeration: response for "unknown account" and "known account,
  wrong signature" are indistinguishable (same shape, same timing profile as
  far as practical).
- Migration path: existing password-based account still authenticates after
  this phase lands, and/or the explicit opt-in path to key-based login for
  an existing account works as designed.

## Deliverable checklist for this phase

- List files changed (`LoginChallengeManager` or fitting name, plus wiring
  into the existing web-client auth handler).
- Explain new data structures (challenge object, response object).
- Explain security invariants: single-use/expiring nonces, service binding,
  rate limiting, no enumeration.
- Explain compatibility impact in detail, including the migration story and
  the dual-path maintenance cost noted above.
- Add all tests above.
- Compile and run tests.
- Report unresolved limitations honestly, including whether the accept-loop
  prerequisite was actually resolved before this landed.
