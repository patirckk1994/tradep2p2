# Prompt: Phase 3 — signed local journal, crash recovery, and mediator room persistence

Prerequisite: `docs/identity-architecture-report.md` and phases 1-2 (crypto
primitives, keystore) must already be merged. Paste this file plus the
architecture report into a fresh session.

---

## Context

Phase 3 of the identity plan. This phase is scheduled early (right after the
keystore, ahead of login and most everything else) because it fixes a real
state-loss/fund-loss risk today — it does not need the rest of the identity
system to be valuable, it only needs the keystore's local-history key from
phase 2.

**Read the "why this phase has two halves" section before writing any code.**

## Why this phase has two halves

The original design for this feature was client-side only: a signed local
journal plus `RECOVERY_STATE_REQUEST`/`RECOVERY_STATE_RESPONSE` messages to
ask the mediator what it remembers. That assumes the mediator can answer.

Check this against the actual code before assuming it works: does anything
in the mediator ever reconstruct in-memory room state
(`RoomEntry`/`rooms_` or whatever the architecture report found) from disk
after a restart, or is the existing snapshot file (`lobby-state.json` or
equivalent) write-only — a display feed for a dashboard, not a restore path?
If it's write-only, then after a mediator restart the room is gone from the
mediator's memory and both clients are talking to a server with no memory of
the trade, no matter how good the client's own journal is.

A client-side journal alone gives you:

- local reconciliation ("what did I last do/see"),
- duplicate-action prevention,
- corruption/rollback detection.

It **cannot** resurrect a half-settled room by itself, because the
authoritative multi-party state (whose turn it is, what's been
acknowledged by both sides) lives on the mediator, not on either client.

So this phase must add **mediator-side room persistence** — the mediator
writing enough state to disk, durably and before acknowledging critical
transitions, to reconstruct `rooms_` (or equivalent) after a restart — either
before or alongside the client journal. Do not ship
`RECOVERY_STATE_REQUEST`/`RESPONSE` against a mediator that can't actually
answer them; that ships a feature that documents its own limitation in the
README instead of fixing it.

If, after inspecting the mediator code, persistence turns out to be a larger
lift than fits in one reviewable phase, split it explicitly (e.g. "3a:
mediator room persistence", "3b: client journal + recovery protocol") rather
than quietly shipping half of it under one phase label.

## Client-side signed journal

Client-side encrypted and authenticated trade journal. Purpose: crash
recovery, reconnect recovery, detecting local state corruption,
reconstructing the last known round, preventing accidental duplicate
actions, recording personal counterparty history (feeds phase 4).

Per-entry fields:

```text
journal version
room identifier
trade identifier
mediator identifier
counterparty pseudonym fingerprint
terms commitment
current round
message direction
message type
message hash
acknowledgement state
local settlement state
timestamp
previous entry hash
```

Hash chain:

```text
entry_hash[n] = Hash(canonical_entry[n] || entry_hash[n - 1])
```

Authenticate checkpoints/entries with the local-history key from phase 2.

The journal must detect: modified entries, removed middle entries where
detectable, reordered entries, rollback to an older checkpoint where
practical, malformed state transitions. It does not, and must not claim to,
prove what happened externally — only what the local client recorded. It
must never automatically publish anything.

## Mediator-side room persistence

Inspect the existing room/round state machine and the existing snapshot
mechanism (`snapshot_loop()` or equivalent) before designing this — don't
assume its current write path is reusable as-is for restore; it may need a
different format (e.g. a append-only log of state transitions vs. a
periodic full snapshot) to be safe to replay.

At minimum, on restart the mediator must be able to reconstruct, for each
room that was still open: which parties are in it, agreed terms, last
confirmed round, and outstanding acknowledgements — enough to answer a
recovery request truthfully rather than silently pretending the room never
existed.

### The privacy cost this introduces — decide explicitly, don't default silently

Today, `RoomEntry` (or equivalent) lives only in memory: a mediator that's
seized, subpoenaed, or simply compromised has nothing on disk about past
rooms. That's presently an *accidental* privacy property, not a designed
one — but making room state durable for recovery removes it, because durable
room state means durably storing the pair of receive addresses that links
two counterparties, which is exactly the linkage this whole identity
architecture otherwise goes out of its way to avoid creating. See
`specs.txt` §7.2 ("The mediator persistence trade-off") for the full
reasoning — this file gives you the concrete implementation choice to make
from it.

Ranked options, most to least preferred:

1. **Persist the room's state machine (party identifiers, terms, round/ack
   progress) but not the receive addresses; re-solicit addresses from both
   clients on recovery** before resuming settlement. This is the default to
   implement unless the architecture report or your own inspection turns up
   a concrete reason it doesn't fit this mediator's actual round flow — it
   gets recovery without adding a new durable deanonymization artifact.
2. Encrypt full room state (including addresses) at rest under an
   operator-held key, if re-soliciting addresses turns out to be impractical
   given how the round state machine is structured.
3. Delete room state aggressively on completion/abort (bounds the exposure
   window but doesn't eliminate it for rooms that crash mid-flight, which is
   the exact case this phase is for).

Whichever you implement, say so explicitly in the phase report — restating
the trade-off, not just the mechanism — since silently picking the
convenient option (durably storing everything, addresses included, because
it's the least code) is the one outcome `specs.txt` says is not acceptable.

## Recovery protocol (client ↔ mediator)

New message types (bounded, not appended to existing frames — see the
network-framing note in `docs/IDENTITY-PLAN.md`'s ground rules and the
existing frame size cap from the architecture report):

```text
RECOVERY_STATE_REQUEST
RECOVERY_STATE_RESPONSE
```

On restart, the client should be able to determine: which room was active,
which terms were accepted, which round was last confirmed, which outbound
messages were sent, which acknowledgements were received, which action may
safely be retried, which action must not be duplicated.

Recovery must not blindly resend value-bearing or settlement-critical
actions. Separate:

```text
safe idempotent retries
unsafe actions requiring explicit user confirmation
already committed actions
unknown state requiring reconciliation
```

## Tests to add

Crash-injection tests, at minimum:

- before sending a message,
- after sending but before journaling,
- after journaling but before receiving an acknowledgement,
- after receiving an acknowledgement,
- during atomic file replacement (reuse the keystore's atomic-write test
  pattern from phase 2),
- between trade rounds,
- immediately before final settlement,
- **mediator restart mid-room**, at each of: before either party
  acknowledged a round, after one party acknowledged, after both
  acknowledged but before the next round started, immediately before final
  settlement. This set doesn't exist in the original client-only version and
  is the one that actually exercises the new mediator persistence.

Also: hash-chain tamper tests (modify/remove/reorder an entry and confirm
detection), rollback-to-old-checkpoint detection.

## Deliverable checklist for this phase

- List files changed (client journal module, mediator persistence, new
  message types + encode/decode).
- Explain new data structures (journal entry format, mediator persisted room
  format) and why each field is there.
- Explain security invariants (hash chain authenticity, local-history-key
  authentication of checkpoints, no external-proof claims documented as such
  in code comments/docs).
- Explain compatibility impact — old clients talking to a new mediator, new
  clients talking to an old mediator; recovery messages must be safely
  rejected by parties that don't support them (capability negotiation) rather
  than misinterpreted.
- Add all tests above.
- Add migration handling if the on-disk snapshot format changes shape.
- Compile and run tests.
- Report unresolved limitations honestly — in particular, be explicit in the
  final report about exactly which crash windows are now recoverable and
  which (if any) still require manual reconciliation. Don't claim full crash
  recovery if a gap remains; name the gap.
