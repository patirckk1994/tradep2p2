# Prompt: Phase 4b — personal counterparty recognition

Prerequisite: `docs/identity-architecture-report.md`, plus phases 1 (crypto
primitives), 3 (journal), and 4 (local history/blocklist) must already be
merged. Paste this file plus the architecture report into a fresh session.
Do not read the other phase files — this one is self-contained.

Slotted as "4b" (between phase 4 and phase 5) rather than renumbering the
whole sequence: it extends phase 4's local record and does **not** depend on
phase 5 (see "Why this doesn't need phase 5" below) — a prior draft of this
plan assumed it did, that was wrong.

---

## This phase replaces nothing and depends on no third party

It answers one question — *have I traded with this counterparty before?* —
using only data the local client already holds. It does not attempt to
answer whether anyone else has, which is the attestation layer's job
(phase 6, receipts) and is deliberately deferred.

## Why this exists

Sybil attacks target the general question. An attacker minting a thousand
identities produces a thousand keys the local client **has never seen**, so
every counter reads zero. There is nothing to forge, because the client is
reading its own journal rather than accepting a claim.

This is why the guarantee is small and true rather than large and false:

> We cannot tell you this counterparty is reliable. We can tell you, with
> certainty, that you have settled with this same key *n* times before.

Do not extend the claim beyond that anywhere in code, logs, or interface.

## Why this doesn't need phase 5, and why it's not "purely local" either

Two corrections to how this was originally scoped, both worth stating
explicitly so the next session doesn't redo this reasoning:

**Not gated on phase 5.** The recognition key is the **per-mediator
pseudonym key** from phase 1 (`key_scope::kMediatorPseudonym`,
`include/tradep2p/identity.hpp`) — not the per-trade ephemeral key phase 5
adds. The ephemeral key is fresh per room by design and recognizes nothing;
using it for recognition would defeat its own purpose. Since the pseudonym
key already exists (phase 1) and the completion counter reads from the
journal (phase 3) into the local record (phase 4), this phase's real
dependencies are 1, 3, and 4 — all already built or in progress. It does not
need to wait for phase 5.

**Not purely local, either.** The live challenge-response handshake between
two counterparties has to actually reach the other party, and clients in
this codebase never connect to each other directly — only to the mediator.
Check `src/lobby.cpp` before assuming a relay mechanism needs to be invented:
it doesn't. `TradeReady`, `Sent`, and `Received` already establish the exact
pattern needed — one party triggers something, the mediator relays a
corresponding message to the *other* party via `Client::enqueue()` (e.g.
`receiver->enqueue(MessageType::Sent, ...)`,
`sender->enqueue(MessageType::Received, ...)`). A `RecognitionChallenge` /
`RecognitionResponse` pair follows this same shape and the same mechanical
registration process phase 3 already used cleanly for
`RecoveryStateRequest`/`Response`: new contiguous `MessageType` values,
widen `validate_message_type()`'s upper bound, `encode_*`/`decode_*`
following the existing `Writer`/`Reader` pattern, a `dispatch()` case, and an
`enqueue()` relay call site. This is proven, low-risk work in this codebase
now, not a new category of complexity — just don't call it "local," since it
does put two new message types on the wire and route through the mediator
(which sees that a challenge/response happened, though not its content's
meaning beyond the signed structure — same visibility the mediator already
has into every other room message).

## Scope decision — already resolved, restated here

Per-mediator scoped (`key_scope::kMediatorPseudonym`, keyed by mediator
identifier): a counterparty is recognizable on the mediator where you met
them, and presents an unrelated key elsewhere. Recognition does not follow
anyone across mediators. Cost: standing does not transfer, so the same
counterparty is a stranger on a different mediator. This is the only option
to implement by default.

Do **not** offer a global cross-mediator recognition key. That reintroduces
a permanent cross-mediator identifier visible to every counterparty and
every mediator — exactly the linkability outcome this whole architecture
exists to avoid. If ever offered at all, it must be explicit opt-in with the
consequence stated plainly — not a decision to make in this phase.

## Proof of control — challenge-response, not a stored credential

Recognition requires proving control of the key **now**. A stored
signature, or any artifact presented rather than freshly produced, is
replayable by anyone who observed a prior session — this is a hard
requirement, not something to simplify away because the payoff (a counter)
is simple. Without it, the one property this mechanism has going for it
("nothing to forge, because the client reads its own journal") breaks: a
captured signature could be replayed to impersonate a previously-seen key.

The challenge must be a fresh CSPRNG nonce, single-use, expiring, and the
signed object must bind at least:

```text
domain separation label (TRADEP2P_RECOGNITION_CHALLENGE_V1, matching this
  codebase's existing domain-separation convention)
protocol version
suite identifier (suite_id — see the note below)
mediator identifier
room or negotiation identifier
challenge nonce
challenge creation time
challenge expiry
TLS channel binding or exporter value where available
```

Requirements:

- Canonical, versioned, length-prefixed serialization — reuse
  `identity.hpp`'s `encode_derivation_info`-style length-prefixing
  discipline, or an equivalent explicit scheme. Never sign concatenated
  strings.
- The verifier generates the nonce; the prover never chooses it.
- Single-use, tracked, and expired. Reject replays explicitly rather than
  relying on expiry alone.
- Bind to the current session where the transport exposes an exporter
  value (check what `SecureChannel`/OpenSSL 3.5.5 actually expose here
  before assuming), so a signature captured on one connection cannot be
  presented on another.
- Include a `suite_id` field inside the signed payload (start at `0x0001`
  for plain Ed25519, per the domain-separation/versioning convention
  already established) — cheap now, and the post-quantum migration
  discussion elsewhere in this project's docs depends on every new signed
  object type having this from day one rather than needing a reissue later.

Both parties may challenge each other. Recognition is mutual and neither
side is obliged to answer — declining is not evidence of anything and must
not be displayed as though it were.

## Local record

Extend phase 4's `LocalCounterpartyHistory` record. Fields beyond what
phase 4 already has:

```text
counterparty public key fingerprint
scope of that fingerprint (mediator identifier — per the scope decision above)
first seen
last seen
settlement count — rooms that reached actual completion
incomplete count — rooms entered that did not complete
last outcome
locally blocked flag
local notes
```

Rules:

- **Count only completed settlements.** A room that was entered and
  abandoned is not a prior trade, and counting it would let a counterparty
  inflate their standing with you by repeatedly starting and abandoning
  rooms at zero cost — the Sybil problem reappearing locally, where you'd
  least expect it. Record incompletes separately and surface them; an
  abandonment history is as informative as a completion history. If phase 4
  shipped a single undifferentiated "encounter count" instead of this
  split, that's a defect to fix as part of this phase, not a precedent to
  preserve.
- Increment on the local client's own record of completion, read from the
  journal (phase 3) — never on a counterparty's claim.
- The record is local, encrypted at rest (consistent with the keystore's
  approach), and **never transmitted**. Not gossiped, not uploaded, not
  aggregated, not exported without an explicit user action.
- A fingerprint under one scope must never be silently matched against a
  different scope.

## Presentation

Display only what is known:

```text
previously settled with this key  (n times, on this mediator)
previously encountered, never completed  (n times)
locally blocked
unknown key
no key presented
```

Constraints:

- No score, no rating, no aggregation into a single figure.
- **"Unknown key" and "no key presented" are not negative signals** and must
  not be styled as warnings. Most counterparties will be strangers; that's
  the normal case, not a risk indicator. If the UI styles zero-count as a
  caution, that's the ranking system `specs.txt` §14 forbids, built by
  accident.
- A key badge must not imply trust, verification, personhood, or safety. If
  the interface shows anything, it shows the count and the scope.
- Do not rank keyed counterparties above unkeyed ones by default.
- Wire this into `tradep2p_cli` and `tradep2p-dashboard`, same as phase 4's
  own CLI/dashboard requirement — this is exactly the kind of state that
  must not land headless. Actually run the dashboard and exercise it in a
  browser before calling that part done.

## What this phase must not do

- Must not have the mediator itself interpret, log the meaning of, or act on
  challenge/response contents beyond relaying them — it sees that an
  exchange happened (same as any other room message) but the recognition
  record itself lives only on each client.
- Must not aggregate counts across counterparties into any reputation
  figure.
- Must not share, gossip, or publish the local record.
- Must not treat a counterparty's own signed claim about their history as
  evidence.
- Must not block or auto-reject based on unknown status. Blocking is a user
  action on a specific key (phase 4's existing blocklist).

## Tests

- Replay: a signature captured from a prior session is rejected against a
  new challenge.
- Cross-context replay: a valid signature from one room, mediator, or
  negotiation is rejected in another.
- Expiry: a response to an expired challenge is rejected.
- Single-use: a second response to the same challenge is rejected.
- Nonce origin: a prover-supplied nonce is not accepted.
- Scope isolation: the same underlying identity presenting on two mediators
  produces two unrelated fingerprints that do not match.
- Count integrity: an abandoned room does not increment the settlement
  count; a completed one does; a counterparty's assertion of prior trades
  changes nothing.
- Malformed input: invalid public keys, wrong-length signatures,
  wrong-suite objects, truncated challenges — all rejected without crashing
  or leaking which check failed first.
- Absent key: negotiation with a counterparty presenting no key proceeds
  normally.
- No egress: the local record is not transmitted on any code path outside
  the challenge/response relay itself — assert this rather than assuming it.
- Relay mechanics: mediator correctly relays `RecognitionChallenge`/
  `RecognitionResponse` between the two room parties following the existing
  `Sent`/`Received` pattern; malformed/oversized relay payloads rejected
  the same way other message types are.

## Deliverable checklist for this phase

- List files changed. State the scope decision (already made above — just
  confirm nothing in the actual codebase makes it wrong) and reconfirm it in
  the phase report.
- Document the signed-challenge structure and where `suite_id` sits within
  it.
- State the security invariants: freshness, single-use, context binding,
  local-only storage, completion-only counting.
- Explain compatibility impact (new message types, capability negotiation
  for older clients/mediators).
- Add all tests above.
- Add the CLI/dashboard wiring and actually run it (see "Presentation"
  above).
- Compile and run tests.
- Report unresolved limitations honestly. In particular: this provides no
  bootstrap — every counterparty is a stranger at count zero until traded
  with, which is most counterparties — and it says nothing about whether
  anyone else has dealt with them. Do not describe this as a reputation
  system. Blind signatures / unlinkable aggregate disclosure remain phase
  8's job for a different problem (proving a count to a party who wasn't
  there) — do not pull that forward into this phase.
