# Bounding Counterparty Risk in Peer-to-Peer Transactions: A Protocol for Fractional Settlement and Privacy-Preserving Reputation

**Draft design document — not an official standards submission**

---

## Status of this document

This is an implementation-informed design document, not a submission to any
standards body. It describes a protocol architecture in transaction-agnostic
terms, generalized from a working reference implementation built and tested
for digital-asset settlement. Every mechanism described here — fractional
settlement, the facilitator-countersigned receipt scheme, the withholding
fix, live counterparty recognition, selective disclosure — has a tested
implementation behind it; this document is the generalization of that design
to arbitrary peer-to-peer transactions, written so it can be evaluated,
critiqued, or adapted independently of any one asset class, chain, or
vendor. It is written in a standards-track register (terminology section,
numbered requirements, explicit security considerations) so that a reader
evaluating it for actual standardization has the pieces they'd need, without
this document itself asserting that status.

## Abstract

Two parties who do not know or trust each other want to exchange value —
money for goods, a deliverable for payment, one asset for another — without
a third party holding custody of either side, and without either party
being able to walk away mid-exchange with more than a bounded fraction of
what was at stake. Separately, both parties would benefit from some notion
of reputation — *have I dealt with this counterparty before, and how did it
go* — without that reputation becoming a permanent, public, cross-context
identity that erodes the privacy the rest of the protocol protects.

This document specifies a protocol architecture with two layers addressing
these two problems independently, plus the constraints that keep the second
layer from quietly undermining the first:

1. **Fractional settlement** — a value exchange is split into rounds, each
   independently acknowledged, so a party who defects at the worst possible
   moment steals at most one round's worth, not the whole transaction.
2. **Scoped-continuity reputation** — an optional, additive layer providing
   live proof of counterparty key control, a locally verified encounter
   count, facilitator-countersigned settlement receipts, and selective
   disclosure of those receipts to a chosen party — without a public
   identifier, a numeric trust score, or a claim of Sybil resistance the
   mechanism cannot actually back.

The guiding principle, and the reason this design looks different from most
systems carrying the word "reputation": **continuity must be scoped to the
smallest context that actually requires it.** A counterparty is recognizable
within one facilitator's domain because you've dealt with them there before
— not globally, not permanently, and not in a way a third party can read
off a public ledger.

---

## 1. Introduction and motivation

Peer-to-peer transaction protocols that avoid custodial intermediaries face
a structural problem: without an escrow holder, either party can defect —
receive value and refuse to reciprocate — and the counterparty has no
recourse. Two families of mitigation exist in practice, and both are
usually deployed alone rather than together:

- **Damage-bounding mechanisms** (staged/fractional settlement, milestone
  payments, partial shipments) reduce the size of any single defection but
  do nothing to deter a determined attacker who can simply re-identify and
  repeat the pattern against new counterparties indefinitely.
- **Reputation mechanisms** (star ratings, review systems, KYC-linked trust
  scores) deter repeat abuse but typically do so by building a permanent,
  often public, cross-context identity — which is itself a privacy cost and,
  in adversarial settings, a correlation and deanonymization surface.

This document specifies both layers together, deliberately engineered so
that the second does not erode the anonymity properties the first is built
on. It does not claim to solve fraud. It bounds the damage from any single
transaction and raises the cost of repeated abuse against the same
counterparty, while stating plainly, in a dedicated section, exactly what it
does not achieve (§16).

The design originates from and has been validated against a reference
implementation for peer-to-peer digital-asset settlement. Nothing in the
mechanism is specific to that domain; §20 works through several others in
concrete terms.

---

## 2. Terminology

| Term | Meaning |
|---|---|
| **Party** | A participant in a transaction. Two parties per transaction session in this specification; the model does not preclude multi-party extensions, which are out of scope here. |
| **Facilitator** | The untrusted coordination process. Pairs parties, relays round-by-round settlement signals, and (optionally) countersigns receipts. Never holds, inspects, or verifies the value being exchanged, and is assumed adversarial throughout this document. |
| **Directory Service** | An optional, unauthenticated-by-default registry of facilitator endpoints, so a party can discover a facilitator without a hardcoded address. |
| **Transaction Session** | One in-progress exchange between two parties, coordinated by one facilitator, identified by an opaque session identifier. |
| **Settlement Round** | One fractional increment of a transaction session. A session with *N* rounds bounds any single party's maximum uncompensated loss to `total / N`. |
| **Unit of Value** | Whatever is being exchanged — currency, a digital asset, a staged deliverable, a service credit, a licensing entitlement. The protocol does not inspect, move, or verify it; parties exchange it through whatever external channel is appropriate to what it is (see §19 for the divisibility assumption this requires). |
| **Delivery Reference** | An opaque endpoint identifier a party supplies to receive its side of a round — a payment address, an account reference, a delivery confirmation channel. Treated as an opaque string by the protocol. |
| **Master Secret** | A single, locally held secret from which every scoped key below is derived (or, for ephemeral keys, from which nothing is derived — see §9). |
| **Facilitator-Scoped Pseudonym Key** | A key derived per facilitator, presented consistently to that facilitator across transactions, unrelated to the key presented to any other facilitator. |
| **Transaction-Ephemeral Key** | A freshly generated (never derived) key used for exactly one transaction session. |
| **Local Transaction Log** | A party's own hash-chained record of its transaction activity. Proves what that party recorded, nothing more — never evidence to anyone else. |
| **Local Counterparty Record** | A party's own, never-transmitted record of prior encounters with a given counterparty key, scoped per facilitator. |
| **Settlement Receipt** | A facilitator-countersigned attestation that a specific transaction session reached a specific stage, bound to both parties' transaction-ephemeral keys. |

---

## 3. System model and roles

Three logical roles, independent of how many physical processes implement
them:

1. **The facilitator** accepts transaction proposals, pairs parties,
   relays round-by-round settlement signals, and optionally countersigns
   receipts. It never authenticates a party's real-world identity and never
   verifies that value actually changed hands externally — it coordinates
   claims, not proofs.
2. **The directory service** is a discovery mechanism only. In the
   reference design it is *not* authenticated by default: an entry is
   accepted as long as it doesn't silently overwrite a different pin for an
   already-registered endpoint, but nothing stops an unclaimed endpoint from
   being squatted. Any deployment of this protocol that adds a reputation or
   receipt layer (§10–13) should treat closing this gap as higher priority
   than it would otherwise be, since a forged facilitator identity is the
   first thing an attacker profits from once receipts exist (§13).
3. **Parties** are pairwise anonymous to each other and to the facilitator
   beyond whatever they voluntarily disclose (§14). A party's connection
   identifier is not required to be stable across sessions, and the
   reference design deliberately makes it unstable by default.

A transaction session's state lives with the facilitator for the session's
duration. Facilitator-side persistence across a restart is optional and, if
implemented, should exclude delivery references from durable storage —
persisting the state machine (parties, terms, round progress) without the
data that links the two parties' real-world endpoints is a materially
smaller privacy exposure than persisting everything, at the cost of needing
those references re-supplied after a recovery.

---

## 4. Transport and session security

Independent of the settlement logic, the transport layer should provide:

- **Modern, forward-secure channel encryption** (TLS 1.3 or equivalent),
  with post-quantum hybrid key exchange preferred where available — harvest-
  now-decrypt-later applies to key exchange specifically, since traffic
  recorded today is retroactively exposed once a cryptographically relevant
  quantum computer exists.
- **Endpoint pinning over CA-chain trust** for the facilitator: an exact
  fingerprint pin, established out of band, rather than delegated
  certificate authority trust — appropriate when the facilitator's identity
  is something a party already learned from a directory service or a peer,
  not something a public CA hierarchy needs to vouch for.
- **No party-side transport authentication.** Parties should not present
  client certificates or other transport-level identifiers; whatever
  identity layer exists (§8 onward) operates at the application layer, on
  the party's own terms, not as a transport requirement.
- **Session-resumption disabled**, or otherwise engineered so that
  transport-layer session continuity cannot become a correlation channel
  across otherwise-unrelated sessions.
- **Bounded framing**: fixed-size headers, hard payload caps, strict binary
  decoding, and rejection (not silent truncation) of malformed or oversized
  messages.
- **Bounded connection admission**: caps on in-flight handshakes and
  established connections, independent of any per-session logic, so that
  transport-layer resource exhaustion is a solved problem before the
  settlement or identity logic is ever reached.

None of this is novel; it is stated here because the layers above depend on
these properties holding, particularly the anti-correlation posture that
motivates disabling session resumption and pinning rather than trusting a CA
chain.

---

## 5. Fractional settlement

A transaction session's terms specify: two parties, the units of value each
side contributes, an integer round count *N*, and which party's leg leads
each round. Settlement proceeds round by round; each round has two legs
(one party's contribution, then the other's), with the leading party
alternating round to round. The facilitator's state machine per session is:

```
awaiting_peer
  -> awaiting_leg_sent -> awaiting_leg_received      (repeat per leg, per round)
  -> awaiting_facilitator_fee_sent                    (only if a facilitator fee is configured)
  -> complete
```

with an aborted state reachable from any non-terminal state. The
facilitator computes each leg's expected quantity for display purposes
only — it never verifies that value actually moved externally.

**Acknowledgements are claims, not proofs.** When a party signals that it
sent its leg, the facilitator learns that a message arrived, nothing about
whether value actually moved. A session that reaches `complete` means both
parties clicked through a state machine together, not that value changed
hands. This is the central, honestly-stated limitation of coordinating
value the facilitator cannot itself inspect (§16).

**Splitting into *N* rounds bounds damage; it does not deter.** A party who
abandons at the final leg steals at most `total / N`. This is real
protection against catastrophic loss in a single transaction. It is not
deterrence on its own, because acquiring a fresh identity and finding
another counterparty costs approximately nothing in an identity-free
system — an attacker can farm `total / N` from many victims indefinitely.
This is precisely the gap the reputation layer (§8 onward) exists to
narrow, and precisely the gap it cannot fully close (§16).

An optional facilitator fee, if the deployment charges one, settles as an
ordinary additional final leg, acknowledged the same honor-system way as
every other round — the facilitator is never trusted with the fee any
differently than with the rest of the transaction.

---

## 6. Threat model

**The facilitator is not trusted.** It may be adversarial, may be run by a
counterparty, may collude, may forge attestations, and — if directory-service
registration is unauthenticated in a given deployment — may be cheap to
stand up at scale. Every claim a facilitator makes must be independently
checkable by a party, or explicitly marked as facilitator-asserted and
weighted accordingly.

**Counterparties are not trusted.** They may defect at the final leg,
withhold cooperation on a receipt to deny an honest counterparty evidence
of an otherwise-good transaction, attempt to farm reputation against
themselves through self-dealing, or attempt to correlate a party's activity
across sessions.

**Observers of any public listing (offers, open transaction requests) are
not trusted.** Anything published to a discovery surface is published to an
adversary building a correlation graph.

**A party's own device is trusted, conditionally.** Local storage is
assumed private but not durable — loss, corruption, and rollback are
expected and must fail loudly, never silently.

**Explicitly outside this model:** external-channel analysis of how value
actually moved (e.g. blockchain analytics, bank transaction correlation),
network-level traffic-timing correlation by a facilitator observing both
connections, and endpoint compromise.

---

## 7. Reputation layer: design constraints

The reputation layer is optional, additive, and must not weaken anything
§4–6 already established. Six constraints govern every mechanism from here
on:

1. **No public lifelong identifier.** Nothing introduced may become a
   stable handle visible across transactions to a public listing, other
   parties, or a facilitator a party did not choose to reveal it to.
2. **No scalar score.** A single trust number collapses information a
   reader could otherwise judge for themselves; structured evidence
   (§10–13) preserves that judgment instead of pre-deciding it.
3. **No claim of Sybil resistance.** Key continuity proves *continuity*, not
   unique personhood — this must never be implied otherwise in
   implementation, documentation, or interface copy (§16 states this at
   length precisely because it is the easiest constraint to violate by
   accident).
4. **No gossip.** A party's private judgements about a counterparty never
   leave that party's own device unless the party explicitly exports them.
5. **Optional in practice, not just in principle.** A design where opting
   in costs unlinkability is not optional; it is compulsory with extra
   steps (§16.3 discusses why this is harder to maintain than it sounds).
6. **Honest layering.** Evidence a party generated about itself, evidence
   it verified live from a counterparty, and evidence a third party
   (the facilitator) attested to are three different objects with three
   different evidentiary weights, and must never be represented as
   interchangeable.

**Explicit non-goals:** real-world identity verification, dispute
arbitration, custody or escrow of any kind, verification of the underlying
transaction's external settlement, global blocklists, and any mechanism
that would require the facilitator to be trusted with the value itself or
with the truth about whether it moved.

---

## 8. Key architecture

A single master secret, held only in an encrypted local store and never
transmitted, from which scoped keys are derived deterministically — except
one, which is generated fresh instead:

```
master secret
├── service-scoped login key        one per hosted service a party uses
├── local-record authentication key  one, never leaves the device
├── facilitator-scoped pseudonym key one per facilitator
└── transaction-ephemeral key        one per transaction session, random — never derived
```

Long-term scoped keys are derived via a standard KDF (e.g. HKDF) with the
master secret as input keying material and a **length-prefixed,
domain-labelled context structure** as the derivation context — naive
concatenation of a label and an identifier is unsafe, since two distinct
(label, identifier) pairs can produce identical concatenated bytes; an
ambiguity in key derivation is as dangerous as an ambiguity in a signed
message.

The transaction-ephemeral key is the deliberate exception: freshly
generated at random, never derived. Deriving it from the master secret
would make transaction keys mutually linkable to anyone who later learned
the derivation path, defeating the purpose of using a fresh key at all. The
operational consequence is real and should be stated plainly in any
implementation: a randomly generated key cannot be regenerated after a
crash, so an in-flight transaction's ephemeral key needs its own durability
story if crash recovery mid-transaction is a requirement.

**Why per-facilitator pseudonyms, specifically.** A party who returns to
the same facilitator repeatedly presents the same pseudonym there and can
accumulate standing with it. That facilitator learns nothing about the
party's activity elsewhere, because a different facilitator sees an
unrelated key. An adversary running many facilitators to correlate a party
gains many unlinkable pseudonyms, not one linkable identity — the
correlation attack does not scale with the number of facilitators an
attacker controls.

---

## 9. Local state: transaction log and counterparty records

**The local transaction log** is an encrypted, hash-chained, append-only
record of a party's own activity, authenticated under its local-record key.
It exists for crash recovery, duplicate-action prevention, corruption
detection, and as the *sole* source of truth for the counterparty record
below. It is never evidence to anyone else: a party can write anything into
its own log, and any implementation must resist the temptation to present
it as though a counterparty could rely on it.

**The local counterparty record** answers one question per counterparty
key, per facilitator: *how many times have I completed a transaction with
this specific key, and how many times did an encounter with it go
unfinished?* Two counters, not one collapsed figure, and populated only
from the party's own transaction log — never from a counterparty's
self-reported claim.

**The counting rule that matters most:** only a transaction that actually
reached completion increments the settlement counter. A session that was
entered and abandoned is not a prior transaction — counting it would let a
counterparty inflate its standing with a party by repeatedly starting and
abandoning sessions at zero cost, reintroducing a Sybil-flavored problem
*locally*, exactly where it is easiest to miss. Abandoned encounters are
recorded in a separate counter and surfaced alongside the completion count,
since an abandonment history is as informative as a completion one.

Presentation should show only what is known, without aggregation:

```
previously settled with this key   (n times, on this facilitator)
previously encountered, never completed  (n times)
locally blocked
unknown key
no key presented
```

"Unknown key" and "no key presented" are the *normal* case for a stranger —
most counterparties will be strangers, permanently, since this mechanism
provides no bootstrap. Styling either as a warning manufactures exactly the
ranking system constraint 2 (§7) forbids, by accident.

---

## 10. Live counterparty recognition

Local records are worthless without proof that the counterparty in the
*current* session actually controls the key the record is keyed on. This
section specifies that proof.

Recognizing a key requires proving control of it **now**, via a live,
facilitator-relayed challenge–response: a fresh, verifier-chosen,
single-use, expiring nonce, with the signed response binding a domain
separation label, a protocol/suite version, the facilitator identifier, the
current transaction-session identifier, the nonce, and creation/expiry
times. A stored signature from a prior session is replayable and therefore
worthless as proof; only a freshly produced one counts. Recognition is
mutual — either party may challenge the other — and declining to answer is
not evidence of anything and must never be displayed as though it were.

The recognition key is the **facilitator-scoped pseudonym key** (§8), not
the transaction-ephemeral key, which is fresh per session by design and
recognizes nothing. This keeps recognition scoped per facilitator by
default, matching the linkability reasoning in §8: a global,
cross-facilitator recognition key is deliberately not offered, since it
would reintroduce a permanent cross-facilitator identifier — precisely the
outcome this architecture exists to avoid.

An attacker minting many identities produces many keys a given party has
never seen, so every counter reads zero against them. There is nothing to
forge, because a party verifies against its own log rather than accepting a
claim — which is also why this mechanism, on its own, says nothing about
whether *anyone else* has dealt with a given key. That is a different,
heavier question, addressed by §13.

---

## 11. Per-transaction ephemeral identities

Every transaction session uses a fresh, transaction-ephemeral signing key
(§8), announced to the counterparty at session start. Messages inside the
session — and, notably, the settlement receipts in §13 — bind to this key
rather than to a party's long-term identity, so activity inside one session
shares nothing linkable with any other session, even to an observer who is
also a facilitator.

**This does not hide anything from the facilitator.** The facilitator sees
which live connection joined which session in real time, regardless of what
key signs messages inside it. What ephemeral session keys protect against
is correlation by *other* parties or observers of any public listing across
sessions — not the facilitator's own, necessarily complete, view of session
membership and timing. Any implementation or its documentation implying
otherwise is overselling the guarantee, and the wording is the defect, not
just the code.

---

## 12. Facilitator-countersigned staged receipts, and the withholding fix

A **settlement receipt** is an attestation signed by a party other than its
holder — unlike the local transaction log (§9), it carries weight to a
third party who was not present for the transaction. A bare assertion of
the form *"key X transacted successfully"* is insufficient: it is
replayable into any context and attests to nothing checkable. A receipt
must instead bind: a version and suite identifier, the transaction-session
identifier (or a privacy-preserving commitment to it), a commitment to the
transaction's terms, both parties' transaction-ephemeral public keys, the
facilitator's public key, a stage identifier, a completion flag, a
timestamp, a unique nonce, and the hash of the previous stage's receipt —
chaining stages together the way a hash-chained log chains entries.

**Staging.** Four stages: *terms accepted*, *round N acknowledged*, *all
obligations except final settlement completed*, and *settlement completed*.
Each stage commits to the hash of the one before it, so a later-stage
receipt without a valid predecessor is rejected outright. Where practical,
a receipt should be produced from **both parties' acknowledgement plus
facilitator countersignature**, rather than a facilitator-only assertion —
so a hostile facilitator cannot unilaterally fabricate an attestation
neither party actually made.

**The withholding problem, and the fix that actually closes it.** If
receipts are issued only *after* a round completes, a party who has already
received everything they wanted can simply decline to participate in
producing the final receipt — the honest counterparty is left with nothing
recorded for a transaction they completed in good faith, and the
withholding costs the withholder nothing. Staging alone does not fix this;
**timing** does: make the penultimate-stage receipt (*"all obligations
except final settlement completed"*) a **required step in the settlement
sequence itself, occurring before the transaction's final leg is
deliverable at all.** Concretely, the coordination state machine (§5) gates
entry into the transaction's actual final leg behind both parties'
acknowledgement of that receipt stage. Withholding the acknowledgement
therefore also withholds the withholder's own final leg — the cost of
denying a counterparty their evidence becomes exactly the cost of an
ordinary defection, no longer free. This is the single most important, and
most easily lost, invariant in this design: it is subtle enough that it
will regress silently in any reimplementation without an explicit test that
simulates a refusal and asserts the protocol-level consequence, not merely
the receipt's shape.

The final ("settlement completed") stage should be issued only once the
coordinator has independently observed the actual completion condition —
never optimistically, and never before the state machine itself reflects
completion.

---

## 13. Selective disclosure

Receipts are private by default: no publication path, no aggregation, no
directory. A holder may disclose a specific receipt, or chain of receipts,
to a specific counterparty during a specific, current negotiation — bound
to that intended recipient and not broadcastable. A receipt shown to one
party cannot be replayed by that party to someone else, and cannot be
replayed by an interceptor as their own.

The binding that makes this work: the disclosure is signed with the
**original** transaction-ephemeral key that appears inside the receipts
being shown (proving the discloser genuinely was a party to that earlier
transaction), while the disclosure envelope itself binds the **current**
negotiation's session identifier and the **current** recipient's
transaction-ephemeral key. The signing key is old; the binding fields are
fresh to the exact exchange taking place, which is what prevents replay
into a different session or to a different recipient even though the
underlying signature reuses a historical key.

If the disclosed receipts were issued by a different facilitator than the
one relaying the disclosure, the recipient has no independent way to
confirm that other facilitator's public key is genuine rather than
self-asserted — this is the same directory-authentication gap named in §3,
surfacing again at the point where it becomes concrete, not a new
weakness introduced by disclosure itself.

A residual leak remains even with this mechanism: the receipts a holder
discloses are individually identifiable, so a counterparty who is also a
facilitator (or who compares notes with one) can correlate disclosures made
to it against the sessions that produced them. Closing that leak requires
blind-signature or similar anonymous-credential techniques — a holder
proving possession of *N* valid completion tokens without revealing which
sessions produced them — which is a substantially heavier cryptographic
mechanism than anything else in this document and is named here as
future work, not specified (§17).

---

## 14. Service-scoped login

Separate from the transaction protocol itself: a party's use of any *hosted
service* built on this protocol (a web-based client, a mobile app backend)
benefits from the same key-based approach applied to logging into that
service, using the service-scoped login key from §8 — one per service, so
a login credential for one hosted service is never presented to, or
correlatable with, another.

A login challenge should bind at minimum: a protocol/suite version, a
service identifier, the server's own identity or domain, a session
identifier, a random verifier-chosen nonce, and creation/expiry times, with
the server enforcing single-use, expiry, and rate-limited attempts, and
responding identically to an unknown account and a known account with a
failed signature check (indistinguishable failure, to resist account
enumeration).

**The honest ceiling on this mechanism, stated plainly:** a hosted page
cannot protect a private key from an operator who controls the code
delivered to the client. Key-based login of this kind protects against
*stored-credential compromise* — a leaked account database, credential
stuffing from password reuse elsewhere — and against nothing else. Where a
browser or similarly operator-controlled runtime is involved, prefer, in
roughly this order: a hardware-backed platform authenticator, an external
signer, a dedicated native client, over holding the raw key inside the
operator-controlled page itself.

---

## 15. Directory-service authentication (a named, open dependency)

The reputation layer's soundness rests partly on facilitator identity
meaning something. If directory registration is unauthenticated — as it is
by default in the reference design — then an adversary can stand up a
facilitator cheaply and use it to collect or fabricate receipts. This
becomes a materially more attractive attack once §12–13 are deployed than
it was for §5 alone, since receipts are the first artifact a hostile
facilitator directly profits from forging. Any deployment layering the
reputation mechanisms onto a discovery/directory system should treat
closing this gap as a priority that rises, not stays fixed, once receipts
exist — this document names it rather than silently assuming it away.

---

## 16. What this architecture does not do

### 16.1 It does not achieve Sybil resistance

Identities are free to create. Two identities created in a second can
complete a hundred transaction sessions with each other, moving no real
value, and mint a spotless mutual history, because acknowledgements are
unverified claims (§5) — a reputation built on completed sessions is a
reputation about *claim-making*, not behavior, and claim-making costs
nothing. No cryptographic mechanism in this document fixes that:
unforgeable, unlinkable, perfectly staged receipts attesting to a hundred
fabricated transactions are unforgeable, unlinkable, perfectly staged
garbage. The signature is sound; the referent is fiction.

Approaches considered and rejected as the *default* mechanism: proof of
work (a one-time tax an attacker amortizes and then farms indefinitely),
social vouching (imports a social graph, itself a deanonymization surface),
and facilitator attestation of external value movement (the facilitator
cannot see the external settlement channel — the founding constraint of
this whole design, not an implementation gap).

**Economic stake anchoring** is offered as a bounded, honest partial
measure, not a solution: a reputation key may publish a claim to
economically verifiable stake (a bonded deposit, a balance in a
chain-agnostic or channel-appropriate verification mechanism), with
reputation weight a function of value visibly at risk multiplied by the
age of that stake, verified by each party independently rather than by the
facilitator. This raises the cost of Sybil attacks linearly with the number
of identities funded; it does not prevent them, offers no slashing without
an external enforcement mechanism, and introduces its own linkability cost
that must be weighed against the benefit. It is documented here as an
option with its costs stated, not shipped as a default.

### 16.2 It does not make a transaction anonymous

The guarantees in this document cover the *protocol's* reputation and
recognition mechanisms — they do not extend to whatever external channel
actually moves the value. If that channel is itself an observable public
record (a public ledger, a bank's own records, a shipping carrier's
tracking system), correlation is possible there regardless of how carefully
identity was handled inside this protocol. The accurate claim is narrow:
*this removes identity from the protocol's own reputation mechanism.* It
does not remove identity from the act of transacting.

### 16.3 "Optional" is unstable in practice

Once some transaction offers carry reputation signals, unkeyed offers tend
to be deprioritized in practice by counterparties choosing between
listings, and the anonymity set collapses toward "participants with
something to hide." An implementation should treat any design that ends up
*requiring* a persistent, always-visible identifier to participate in
reputation at all as a regression against this framing, worth flagging as
a defect rather than shipping quietly. The disclosure route in §13,
extended with the anonymous-credential mechanism named as future work
there, is the one variant where opting in does not itself cost
unlinkability — and therefore the only one where keyed and unkeyed
populations plausibly stay mixed.

### 16.4 Key loss is total

There is no recovery authority, by construction. A lost local key store is
a lost identity and a reset to zero standing. This is not a flaw to be
engineered around — it is the Sybil cost (§16.1) surfacing honestly, since
a recovery service would be a trusted party this design otherwise goes out
of its way not to require. Encrypted backup and export of a party's own key
material should be supported; a third-party recovery service should not
be, since it reintroduces exactly the trust dependency avoided everywhere
else.

---

## 17. Post-quantum considerations

Migration splits into groups with different urgency:

**Harvest-now-decrypt-later applies to key exchange specifically** (§4).
Traffic recorded today is decrypted retroactively once a cryptographically
relevant quantum computer exists — this is the one urgent item, and the
fix (a post-quantum hybrid key-exchange group, classical groups retained as
fallback for a peer that doesn't offer the hybrid one) is available today
using standardized primitives.

**Signatures do not have that property in general** — forging a signature
after the fact is worthless against a session that already completed —
**except for the settlement receipts in §12**, which are designed to stay
independently verifiable for years after the transaction. A classical-only
receipt corpus becomes forgeable wholesale, retroactively, once quantum
attacks on the underlying signature scheme are practical. Facilitator
receipt-signing keys should be migrated to a hybrid classical+post-quantum
signature scheme; other, shorter-lived keys in this design (login,
recognition, ephemeral) carry comparatively low urgency, since forging them
after a session concludes yields nothing.

**Symmetric and hash primitives need no urgent change** under this design —
they face only a quadratic (Grover) speedup, not the exponential break that
motivates the key-exchange and long-lived-signature items above.

**The anonymous-credential mechanism named in §13 has no standardized
post-quantum answer today**, and this is structural: the algebraic
properties that make a signature scheme "blindable" tend to be exactly the
properties post-quantum signature schemes' security proofs remove. This is
a research gap, not an oversight in this document, and it should be
tracked as such rather than assumed solvable by swapping a primitive.

**One cheap step to take from the first shipped version of any
implementation:** include a suite identifier inside every signed object
this document defines (receipts, recognition challenges, login challenges,
disclosure envelopes), with verifiers rejecting an unrecognized suite
identifier rather than ignoring the field. Two bytes now is the difference
between a future post-quantum migration being an additive version bump
versus a wholesale reissue of every artifact already in existence.

---

## 18. Security and privacy summary

Provided:

- Bounded loss per transaction session, independent of round count chosen.
- Live, unforgeable proof of counterparty key control, scoped per
  facilitator.
- A locally verified, non-gameable "have I completed a transaction with
  this key before, and how many times" count.
- Facilitator-countersigned, non-repudiable settlement receipts, with a
  structural fix for the receipt-withholding griefing attack.
- Selective, non-broadcastable disclosure of those receipts to a chosen
  party for a chosen negotiation.
- No public, cross-transaction identifier; no numeric trust score.

Not provided, stated plainly rather than implied away:

- Proof that value external to the protocol actually moved.
- Sybil resistance of any kind, by default.
- Protection against a hostile operator of a hosted client the party did
  not run themselves.
- Unlinkable aggregate reputation proofs (documented future work, §13, §17).
- Anonymity of the external settlement channel itself.

---

## 19. Applicability and the divisibility assumption

Fractional settlement requires that the unit of value being exchanged can
be split into sequential, independently verifiable increments without
losing most of its value in the process. This is a natural fit for
currency, digital assets, metered services, and staged deliverables (design
documents, code modules, licensed content chunks). It is a poor fit for
genuinely atomic exchanges — a single physical handoff, a one-time,
non-decomposable service — where there is nothing to fraction and the
damage-bounding property (§5) simply does not apply. Deployments outside
currency-like value should evaluate this before adopting the fractional
layer; the reputation layer (§7 onward) does not depend on fractional
settlement and can be deployed on its own for exchanges that are inherently
atomic.

---

## 20. Candidate use cases

The following are illustrative, not exhaustive. Each notes the divisibility
fit from §19.

**Freelance and contract milestone payments.** A client and a contractor
split a project into deliverable-linked payment rounds, coordinated without
a platform escrowing funds or taking a custody-based cut. Strong
divisibility fit; the withholding fix (§12) directly addresses a common
real complaint in this space — a client accepting final work then delaying
or disputing the final payment once they have what they wanted.

**Over-the-counter trading of any asset class.** Two parties trade
securities, commodities, collectibles, or any asset outside a listed
exchange, without a broker-dealer intermediary holding either side. Strong
fit for currency-like or fungible assets; weaker for one-of-a-kind physical
items unless paired with a staged-delivery-and-inspection process external
to the protocol.

**Supply-chain partial shipment and partial payment.** A buyer and supplier
coordinate staged delivery against staged payment across multiple
shipments, with counterparty recognition (§10) letting either side confirm
they are dealing with the same organization as a prior order without a
shared platform account. Strong fit; the "unit of value" here is the
payment side, with delivery confirmation as the round-completion signal.

**Metered API, data, or compute access.** A consumer pays incrementally for
usage against a provider who grants access incrementally, with neither side
needing to trust the other with a large upfront payment or an unbounded
credit line. Strong fit — this is close to the reference implementation's
own domain in structure, if not in the specific asset type.

**Peer-to-peer marketplaces wanting private repeat-dealer reputation.**
Local goods and services marketplaces where a buyer and seller who have
dealt well before want to recognize each other on a future encounter,
without a public review profile that doubles as a permanent, searchable
identity. Divisibility is irrelevant here — this is a pure application of
§7–§10 without the fractional-settlement layer at all.

**Cross-border remittance coordination.** Two parties (or a chain of
intermediaries) coordinate a value transfer across currency or payment-rail
boundaries without a single custodial remittance operator holding funds
mid-transfer. Fit depends on whether the underlying rails support staged,
independently confirmable legs; where they do, this is a strong match.

**Crowdfunding or grant disbursement with milestone release.** A funder and
a recipient use staged settlement rounds gated on deliverable milestones
instead of a platform holding the full amount in escrow until a single
release event. Strong fit, and the receipt mechanism (§12) gives the funder
durable, disclosable evidence of what was actually acknowledged at each
stage.

**Licensing and royalty settlement.** A licensor and licensee settle
usage-based royalties in periodic rounds, with selective disclosure (§13)
letting the licensee prove a clean payment history to a new licensor
without publishing its full royalty history.

---

## 21. Relationship to prior art

This design sits adjacent to, but is not a replacement for, several
existing mechanisms, each solving a related but distinct problem:

- **Custodial escrow services** solve the same defection problem this
  document addresses, but by introducing a trusted custodian holding the
  value itself — the opposite tradeoff from a facilitator that never takes
  custody.
- **Verifiable credentials / decentralized identifiers** address portable,
  cryptographically verifiable identity claims, generally with more
  emphasis on issuer-backed attribute assertions than on the specific
  live-recognition and withholding-resistant receipt mechanisms here; the
  two are compatible in principle, with this document's receipts being one
  possible credential type in a broader credential ecosystem.
- **State/payment channels** in ledger-based systems solve incremental
  settlement with on-chain finality guarantees this document does not
  attempt to provide, at the cost of being specific to systems that support
  channel constructions at all; this document's fractional settlement is
  deliberately chain- and rail-agnostic, trading a finality guarantee for
  broader applicability.
- **Star-rating and review platforms** solve discoverable reputation at the
  cost of exactly the public, aggregable, permanent identifier this
  document's constraints (§7) rule out by design.

---

## 22. Open problems and future work

- **Anonymous aggregate disclosure** (§13): proving possession of *N* valid
  receipts without revealing which sessions produced them. Blocked on
  either a classical blind-signature scheme accepted as sound under
  concurrent use, or a post-quantum equivalent that does not yet exist
  (§17).
- **Directory-service authentication** (§15): proving control of a
  facilitator endpoint at registration time without reintroducing a
  centralized certificate authority.
- **Multi-party transaction sessions**: this document specifies two-party
  sessions throughout; extending fractional settlement and the withholding
  fix to three or more parties raises coordination questions (who gates
  whom) not addressed here.
- **Dispute signaling without arbitration**: a structured way for a party
  to flag a specific receipt or session as disputed, visible only to
  parties the discloser chooses, without the protocol taking on the
  arbitration role itself (a non-goal per §7).
- **Formal verification of the withholding-fix invariant** (§12): the
  property that withholding a receipt acknowledgement costs the withholder
  their own final leg is exactly the kind of state-machine property well
  suited to formal methods, and is also exactly the kind of property that
  regresses silently under an ad hoc reimplementation.

---

## 23. Conclusion

Bounding the damage from a single defection and building reputation without
a permanent public identity are usually treated as separate problems,
solved by separate systems, with the reputation system frequently
undermining the anonymity the rest of the design worked to establish. This
document specifies them together, with the constraints (§7) that keep the
second from quietly compromising the first, and states without
qualification what the combination does not achieve: it does not verify
that value actually moved, and it does not resist an attacker willing to
mint fresh identities indefinitely. What it does provide — a locally
verified, non-transferable notion of "I have dealt honestly with this
specific counterparty before," backed by facilitator-countersigned evidence
that survives a griefing attempt, disclosable only to whoever a party
chooses to show it to — is a narrower claim than "trustworthy," and a more
defensible one.
