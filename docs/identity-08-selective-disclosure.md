# Prompt: Phase 8 — selective private receipt disclosure

Prerequisite: `docs/identity-architecture-report.md` and phase 6 (receipts)
must already be merged. Paste this file plus the architecture report into a
fresh session.

---

## Context

Phase 8 of the identity plan — the future-compatible reputation layer. This
phase is explicitly scoped: it may implement explicit private disclosure of
selected receipts now, but must not implement advanced anonymous credentials
unless the repository already contains the required primitives (check
before assuming — pairing-friendly curve support, blind-signature libraries,
etc. are very unlikely to already be in this repo's dependency set per the
architecture report, so the realistic scope of this phase is the
serialization/versioning groundwork plus the simplest disclosure primitive
that's actually implementable with what's linked, not a full BBS+
implementation).

## Two separate problems, two separate fixes

Don't conflate these — they solve different things and a scheme addressing
one does nothing for the other.

**Linkability** (a stable key/receipt chain lets anyone correlate every
trade back to one identity): the fix is blind-signed completion tokens.
Mediator blindly signs a token per completed room; the holder later proves
"I hold N completion tokens" (or discloses specific attributes like a volume
band or age band) without revealing which trades produced them.

- Chaumian blind signatures are sufficient if the only thing that needs
  proving is a count.
- BBS+ if attributes beyond a count need selective disclosure (volume band,
  age band, distinct-mediator count).
- This gets you unlinkable reputation, consistent with the anonymity
  properties this codebase already protects elsewhere (TLS ticket disabling
  etc., per `docs/IDENTITY-PLAN.md`). It does **nothing** for Sybil
  resistance — don't present it as solving both problems.

**Sybil resistance** (keys are free; two self-created identities can farm
each other's reputation with zero real trades): the fix that fits this
codebase's non-custodial stance is cost anchoring, not a social graph
(social vouching imports a deanonymization surface) and not proof-of-work
(a one-time amortizable tax that stops mattering after it's paid once).
Concretely: a reputation key publishes a bond address; reputation weight is
a function of value visibly at risk in that address × the age of the bond.
Clients verify by checking an on-chain balance, not by verifying trade
history, which keeps the mediator out of the trust computation and keeps
the design chain-agnostic (matches the existing multi-asset trade model per
the architecture report). There's no slashing without a smart contract, but
sunk cost plus age is a real, ongoing tax that a fresh keypair can't fake.

If this phase only has budget for one of the two, do the serialization
groundwork for both (see below) but implement blind-signed completion
tokens first — it's the one that doesn't require designing a bond/slashing
model, and it's the one that directly protects the thing this codebase's
existing design already cares about (unlinkability), whereas Sybil
resistance can remain a documented open problem for a later phase without
making anything already shipped unsafe.

## Reputation constraints (carried forward from phase 6, still apply)

No naive public reputation score. Prefer structured evidence over one
scalar: key age, receipt count, distinct mediator count, economic
cost/bond age/value band, prior interaction with this specific client,
locally blocked status — kept separate, not collapsed. Receipts stay private
by default; this phase adds the ability to *choose* to disclose, not a
default publication path.

## Serialization requirement

Design receipt formats (from phase 6) so they can later support: selective
disclosure to one counterparty, blind-signed credentials, anonymous
completion-count proofs, BBS+ credentials, zero-knowledge proofs, proof of
receipt age/volume band, proof of distinct mediator count — without this
phase necessarily implementing all of them. Keep serialization versioned
(the `TRADEP2P_RECEIPT_V1` domain label from phase 6 already gives you this
lever) so a later anonymous-credential layer is an additive version, not a
replacement of the phase 6 format.

The first implementation may support explicit private disclosure of
selected receipts to a chosen counterparty (i.e., "show this specific
receipt to this specific party") as the concrete deliverable, with the
blind-token count-proof as a stretch goal if the primitives are actually
available, and the bond-anchoring Sybil mechanism explicitly documented as
future work with its design constraints (chain-agnostic balance check, no
mediator involvement, age-weighted) rather than implemented in this phase
unless it's small enough to fit reviewably.

## The "optional" trap

Note for the phase report, not just code: once *some* offers carry
reputation signals, unkeyed offers tend to get deprioritized/ignored in
practice, collapsing the anonymity set to "people with something to hide."
The blind-credential route is the one where opting in doesn't cost
unlinkability — that's the only way keyed and unkeyed populations stay
mixed. If the implementation ends up requiring a persistent, always-visible
identifier to participate in reputation at all, that's a regression against
this framing and should be flagged, not shipped quietly.

## Tests to add

- Serialization round trip and version negotiation for the extended receipt
  format (old-format receipt still parses; new fields are additive).
- If blind-signed tokens are implemented: unforgeability (can't produce a
  valid token without a real completed-room signature from the mediator),
  unlinkability (two disclosures of "I hold N tokens" from the same holder
  don't reveal which underlying receipts they came from), and a negative
  test that a forged/tampered token is rejected.
- Explicit disclosure path: a receipt disclosed to counterparty X is
  verifiable by X and does not leak to anyone else who might intercept it
  (bound to the intended recipient, not broadcastable).
- Malformed/downgrade-attack tests: an old client can't be tricked into
  accepting an unsigned or improperly-scoped "reputation" claim as if it
  were a real disclosure.

## Deliverable checklist for this phase

- List files changed.
- Explain new data structures for whichever disclosure mechanism is
  actually implemented, and explicitly document what's deferred vs. done.
- Explain security invariants for each of the two problems (linkability,
  Sybil) separately — do not present one fix as solving both.
- Explain compatibility impact and version negotiation.
- Add the tests above.
- Compile and run tests.
- Report unresolved limitations honestly — this phase has the most
  legitimate reason of any of the nine to have a real "not yet implemented"
  list; write it down plainly rather than implying more coverage than
  exists.
