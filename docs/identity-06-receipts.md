# Prompt: Phase 6 — mediator-signed staged receipts

Prerequisite: `docs/identity-architecture-report.md` and phases 1-5 (crypto
primitives, keystore, journal/recovery, local history, ephemeral trade
identities) must already be merged. Paste this file plus the architecture
report into a fresh session.

---

## Context

Phase 6 of the identity plan. Depends on phase 5 directly — receipts bind to
the per-trade ephemeral key, not a long-term identity. This is also the
phase where the unauthenticated-registry risk noted in
`docs/IDENTITY-PLAN.md` matters most: a receipt is the first thing a
hostile mediator profits from forging, so confirm that risk has been
addressed (or is being addressed alongside this phase) before shipping
receipts that clients might trust.

## What a receipt is, and isn't

A receipt is evidence signed by a mediator or counterparty. It is not the
client's own local journal (phase 3) and must not be confused with it in
code, docs, or UI — the journal proves what the local client recorded; a
receipt proves what a third party attested to.

Do not use a bare statement like `public_key X traded successfully`.
Receipts must be context-bound and non-replayable, same discipline as phase
5's trade messages.

## Fields

```text
receipt version
room identifier or privacy-preserving room commitment
terms commitment
party ephemeral public keys or scoped pseudonyms
mediator public key
receipt stage
completion state
timestamp
unique nonce
previous-stage receipt hash if staged
```

## Staged receipts, and the withholding fix

Stages:

```text
terms accepted
round N acknowledged
all obligations except final settlement completed
settlement completed
```

A final completion receipt only asserts completion after the protocol's
actual completion condition is satisfied — don't let it be issued
optimistically.

**Timing fix, not just staging:** if receipts (even staged ones) are only
issued *after* a round completes, a defector can simply refuse to request/
sign the final one and walk away with nothing recorded for what was
otherwise an honest trade — withholding as griefing, with no cost to the
withholder. Make the penultimate-stage receipt (the "all obligations except
final settlement completed" stage) a required settlement step that happens
*before* the final tranche is sent, using the existing round machinery from
the architecture report. That way withholding the receipt also means
withholding your own last leg of the trade — it stops being free. Design the
final "settlement completed" receipt the same way relative to whatever the
last value-bearing action is.

Where appropriate, use two-party acknowledgements plus mediator
countersignature rather than a mediator-only assertion, so the mediator
can't unilaterally fabricate a receipt neither party actually agreed to.

Analyze withholding attacks explicitly in the phase report, not just in
code comments — this is one of the harder invariants to get right and it's
the one most likely to regress silently later.

## Reputation constraints (apply now, not deferred to phase 8)

Keys are free — key continuity proves continuity, not unique personhood, and
does not solve Sybil attacks by itself. Do not implement or imply otherwise.
Do not implement a system where two self-created identities can generate
arbitrary positive reputation by trading with each other (check this isn't
possible before considering the phase done — e.g. does anything prevent or
at least flag a room where both ephemeral keys were requested by the same
keystore/session?).

Keep receipts private by default in this phase — no public aggregation, no
score. Any future public reputation mechanism (phase 8) must distinguish
key age, receipt count, distinct mediator count, economic cost/bond
age/value band, prior interaction with this specific client, and locally
blocked status, rather than collapsing to one scalar. This phase just needs
to store receipts in a form that supports that later — see phase 8's file
for the concrete mechanism (blind-signed completion tokens + bond
anchoring).

## Network framing

New message types, bounded and paginated (do not append receipt bundles to
ordinary offer/room messages, given the existing frame size cap from the
architecture report):

```text
RECEIPT_REQUEST
RECEIPT_RESPONSE
RECEIPT_PAGE
RECEIPT_ACK
```

Every paginated message binds: bundle identifier, page number, total pages,
content hash, sender, recipient or room, expiry. Apply strict limits: total
receipt count, total byte size, page count, per-message size, nesting depth,
string lengths, decoded binary lengths. Reject malformed, oversized,
duplicate, reordered, or inconsistent pages — don't accept a partial bundle
and proceed as if it were complete.

## Tests to add

- Staged-receipt ordering: a later-stage receipt without a valid
  previous-stage hash is rejected.
- Withholding scenario: simulate a counterparty refusing to sign the
  penultimate receipt and confirm the protocol-level consequence is that
  they also don't get their last tranche — write this as an explicit test,
  not just a design note.
- False-completion rejection: a "settlement completed" receipt issued before
  the actual completion condition is detected/rejected.
- Two-party-ack + mediator-countersignature path: mediator alone cannot
  produce a valid receipt without both parties' acknowledgements where that
  model is used.
- Receipt replay across rooms/mediators rejected (same discipline as phase
  5).
- Malformed/oversized/duplicate/reordered receipt page rejected; partial
  bundle not silently accepted.
- Self-trade detection (or at least flagging) for two ephemeral keys from
  the same local keystore.

## Deliverable checklist for this phase

- List files changed (`Receipt`, `ReceiptVerifier`, `ReceiptStore`,
  `ReceiptPaginator` or names fitting existing conventions).
- Explain new data structures and the staged-receipt state machine.
- Explain security invariants: context-binding, non-replayability, the
  withholding-resistant timing, private-by-default storage.
- Explain compatibility impact: capability negotiation for the new message
  types.
- Add all tests above.
- Compile and run tests.
- Report unresolved limitations honestly — especially note explicitly
  whether the unauthenticated-registry risk from `docs/IDENTITY-PLAN.md` has
  been addressed; if not, say so plainly rather than letting receipts ship
  as if mediator identity were trustworthy by default.
