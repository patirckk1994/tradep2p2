# Prompt: Phase 4 — personal local counterparty history and blocklist

Prerequisite: `docs/identity-architecture-report.md` and phases 1-3 (crypto
primitives, keystore, journal) must already be merged. Paste this file plus
the architecture report into a fresh session.

---

## Context

Phase 4 of the identity plan. Scheduled early because it's nearly free once
the keystore and journal exist (it's largely a read model over journal data
plus a small local store) and has immediate user value, independent of
login, ephemeral trade identities, or receipts landing first.

## What this is not

Not a global score, not gossiped between clients, not auto-uploaded to
mediators. This is a private, local-only record the user builds from their
own trade history. If you find yourself designing a sync/share mechanism,
stop — that's out of scope for this phase and contradicts the point of it.

## Fields

```text
counterparty fingerprint
scope of fingerprint
mediator identifier
first seen
last seen
number of local encounters
local outcome labels
locally blocked flag
local notes
evidence hashes
confidence level
```

"Scope of fingerprint" matters: be explicit in the data model about whether
a fingerprint is scoped to one mediator or is meant to be stable across
mediators, since that determines how much correlation this record enables
even locally. Prefer per-mediator scoping unless there's a clear reason not
to, consistent with the "per-mediator pseudonym key" design from phase 1.

## Behavior

Local client may use this to display: previously encountered, previous
successful interaction, previous incomplete interaction, locally blocked,
unknown identity. That's the full extent of it — do not convert this into a
score, do not synchronize it between the user's own devices automatically
(a manual encrypted export/import via the phase-2 keystore backup mechanism
is fine; automatic background sync is not this phase's job), do not upload
it anywhere.

## CLI and dashboard wiring (required this phase, not optional)

Phases 1-3 landed as libraries only — there is currently no way for a user
to actually create/unlock a keystore, inspect a journal entry, or trigger a
recovery request from either `tradep2p_cli` or `tradep2p-dashboard`. Phase 4
depends on a keystore being unlockable and a journal being readable to be
useful at all, so this phase includes closing that gap rather than adding
yet another headless module on top of two other headless modules. Concretely:

- **`tradep2p_cli` (interactive client, `src/main.cpp`'s `run_client`):** add
  commands for `keystore create/unlock/lock/rotate/destroy/show-identity`
  (phase 2's `IdentityKeystore`, catch-up), `journal status` (last few
  entries, chain-verification result, phase 3's journal, catch-up),
  `recovery request <room-id>` (sends `RecoveryStateRequest` and prints the
  response, phase 3, catch-up), and this phase's own `history list`,
  `history show <fingerprint>`, `block <fingerprint>`, `unblock
  <fingerprint>`, `note <fingerprint> <text>`.
- **`tradep2p-dashboard` (loopback HTTP UI, `src/http_dashboard.cpp`):** add
  a keystore-status/unlock panel and a counterparty-history panel (list with
  blocked/notes/first-last-seen, matching this phase's "what it may display"
  list above). This is the single-operator surface where showing "locally
  blocked" inline next to a counterparty makes the feature actually useful
  day-to-day, not just queryable via CLI.
- **`tradep2p-mediator-dashboard`:** add a small operational panel for phase
  3's room persistence — whether `TRADEP2P_ROOM_STATE_FILE` is configured,
  and how many rooms were restored on last startup (the mediator process
  already logs this once at startup per `lobby.cpp`'s
  `load_persisted_rooms_at_startup()`; surface the same fact in the
  dashboard's JSON/HTML rather than only in a log line an operator has to go
  find). Do not add any end-user identity/history data here — this
  dashboard has no protocol connection and no business seeing it.
- Do not touch `tradep2p-registry-dashboard` or `tradep2p-webclient` this
  phase — the former has nothing relevant yet, the latter is phase 9's job
  specifically.

## Tests to add

- Recording an encounter updates first/last seen and encounter count
  correctly.
- Blocked flag suppresses/warns appropriately in whatever UI surface
  consumes this (CLI/dashboard — check the architecture report for what
  exists).
- Fingerprint scoping: two encounters with the same counterparty on
  different mediators are recorded as distinct entries if scoping is
  per-mediator (confirm this is the intended design, don't silently merge
  them).
- Local notes and evidence hashes persist through the keystore's
  encrypted-export/import path without leaking in plaintext.
- Nothing in this module makes a network call — assert this isn't
  accidentally wired to send data out (e.g. a grep-style test or explicit
  code review note, since a unit test can't easily prove a negative about
  network calls).

## Deliverable checklist for this phase

- List files changed/added (e.g. `LocalCounterpartyHistory` or a name
  fitting existing conventions).
- Explain the data structure and the fingerprint-scoping decision
  specifically.
- Explain security invariants: local-only, no automatic disclosure, storage
  encrypted at rest consistent with the keystore's approach.
- Explain compatibility impact (new opt-in local data, no protocol changes).
- Add the tests above.
- Compile and run tests.
- Actually run `tradep2p-dashboard` and exercise the new keystore/history
  panels through a browser (not just unit tests) before calling the
  dashboard portion done — click through create/unlock, blocking a
  fingerprint, adding a note, and confirm it renders and round-trips
  correctly. Do the same for `tradep2p_cli`'s new commands from an actual
  terminal session.
- Report unresolved limitations honestly.
