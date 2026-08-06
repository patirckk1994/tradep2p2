# Prompt: Phase 5 — per-trade ephemeral identities

Prerequisite: `docs/identity-architecture-report.md` and phases 1-2 (crypto
primitives, keystore) must already be merged. Phase 3/4 are not hard
dependencies but should already be in the codebase per the plan order in
`docs/IDENTITY-PLAN.md`. Paste this file plus the architecture report into a
fresh session.

---

## Context

Phase 5 of the identity plan. This is what receipts (phase 6) bind to
instead of a long-term key, so it lands before receipts.

## What this buys you, and what it doesn't

State this honestly in the phase report, not just in a threat-model
appendix: **ephemeral trade keys do not hide anything from the mediator.**
The mediator sees which connection joined which room in real time,
regardless of what key signs messages inside it. What ephemeral keys protect
against is correlation by other clients or anyone reading the public offer
book/room contents across trades — not the mediator's own view. If the
implementation or its docs imply this hides trade activity from the
mediator, that's overselling it — fix the wording, not just the code.

## Design

Each trade/room uses a fresh ephemeral signing key unless the protocol
already provides an equivalent unlinkable identity (check — don't assume).
Freshly generated random per phase 1's derivation table (never derived from
the master secret). The ephemeral trade key binds room messages and state
transitions without revealing the user's long-term login identity.

A trade message signature binds at least:

```text
protocol version
room identifier
trade identifier
round number
message type
payload hash
sender ephemeral public key
recipient or room context
timestamp or sequence number
```

Use the domain-separated, canonically-serialized signing approach from
phase 1 (`TRADEP2P_TRADE_MESSAGE_V1` or whatever label fits existing
naming) — no raw struct signing, no ambiguous concatenation.

New message type: `TRADE_EPHEMERAL_KEY` (announce/exchange the ephemeral
public key for a room — check the existing room-join flow in the
architecture report for the natural place to carry this).

## Replay prevention

Prevent replay across: rooms, rounds, mediators, protocol message types,
protocol versions. This means the signed context above (room id, trade id,
round number, message type, protocol version) must actually be checked on
the receiving side, not just included on the sending side — write the
verification test that proves a valid signature from room A is rejected when
replayed into room B, etc.

## Do not

Do not attach the service login public key (phase 7) to offers or trade
messages by default — that's exactly the linkability this phase exists to
avoid. If some future explicit user action wants to attach a persistent
identity to a trade, that's a distinct, explicit opt-in action, not a
default wiring between phase 7 and phase 5.

## Tests to add

- Cross-room replay rejected (same signature/message replayed into a
  different room id).
- Cross-round replay rejected.
- Cross-mediator replay rejected (if mediator identifier is part of the
  signed context).
- Cross-message-type substitution rejected (a validly-signed `Turn` message
  replayed as if it were a different message type).
- Cross-protocol-version replay rejected once versioning is meaningful.
- Fresh ephemeral key per room: confirm two rooms from the same identity
  produce unlinkable public keys (no shared derivation path back to a
  long-term key — this should be a structural property, not just "we
  generated randomly," so test that nothing in the code path derives it from
  anything stable).
- Malformed/truncated `TRADE_EPHEMERAL_KEY` message rejected cleanly.

## Deliverable checklist for this phase

- List files changed (ephemeral identity module, new message type + wiring
  into the existing room-join/trade-round flow).
- Explain new data structures (signed trade-message envelope, ephemeral key
  announcement).
- Explain security invariants: freshness/randomness of ephemeral keys,
  replay-bound signed context, no default linkage to the login key.
- Explain compatibility impact: capability negotiation so older clients
  reject the new message type safely instead of misinterpreting it.
- Add the replay/substitution tests above plus malformed-input tests.
- Compile and run tests.
- Report unresolved limitations honestly, and explicitly restate the
  mediator-visibility caveat from above in the phase report so it doesn't
  get lost by the time phase 6/8 build on this.
