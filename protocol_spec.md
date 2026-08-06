# Fractional Settlement and Scoped Reputation Protocol — Protocol Specification

**Version 1 — companion to [`WHITEPAPER.md`](WHITEPAPER.md)**

This document specifies the wire formats, state machines, cryptographic
constructions, and conformance requirements needed to build an
interoperable implementation. `WHITEPAPER.md` covers motivation, threat
model, and design rationale and is not repeated here except where a
decision needs justifying inline. Where the two disagree, this document
governs implementation behavior.

Every wire format and cryptographic construction below is transcribed from
a working reference implementation, with real, machine-generated test
vectors (§14) — not hand-derived or illustrative pseudocode.

## Conformance language

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and
**MAY** are used as defined in RFC 2119.

---

## 1. Notational conventions

- All multi-byte integers are **big-endian (network byte order)** unless
  stated otherwise.
- `uN` denotes an unsigned integer of `N` bits (`u8`, `u16`, `u32`, `u64`).
- `byte[N]` denotes a fixed-length field of exactly `N` bytes.
- Two distinct length-prefix conventions are used in this protocol, and
  implementations **MUST** use the correct one per field — they are not
  interchangeable:
  - **Convention A (u16-length-prefixed strings/bytes):** a `u16` length
    `L` followed by exactly `L` raw bytes. Used for all variable-length
    fields inside signed objects (§9) and most session/settlement message
    fields (§8).
  - **Convention B (key-derivation context):** used only inside
    `encode_derivation_info` (§10) — a `u8` label length followed by the
    label bytes, then a `u16` identifier length followed by the identifier
    bytes. This convention exists specifically to keep a short, fixed set
    of label constants (§10.1) unambiguous from arbitrary-length
    identifiers, and **MUST NOT** be used for any other purpose.
- A field described as "opaque" is transported as raw bytes with no
  semantic interpretation by any protocol-conformant implementation.
- Hex values in this document are lowercase, no `0x` prefix, no separators,
  matching the output of the test-vector generator in §14.

---

## 2. Cryptographic suite (Suite ID `0x0001`)

Conformant implementations of Suite `0x0001` **MUST** implement:

| Purpose | Algorithm |
|---|---|
| Transport channel | TLS 1.3, no session resumption (session tickets disabled) |
| Transport key exchange | `X25519MLKEM768` **MUST** be offered and preferred; classical `X25519` and `P-256` **MUST** be retained as fallback for a peer that does not offer the hybrid group |
| Transport symmetric cipher | `TLS_CHACHA20_POLY1305_SHA256` and/or `TLS_AES_256_GCM_SHA384` |
| Local-storage AEAD | ChaCha20-Poly1305, IETF construction (96-bit nonce, 128-bit tag) |
| Signatures | Ed25519 (32-byte public key, 64-byte signature, one-shot sign/verify — no streaming API assumed) |
| Key derivation | HKDF-SHA256 |
| Passphrase-based key derivation | Argon2id, RFC 9106 §4 "second recommended option" (64 MiB memory, 3 iterations, 4 lanes); PBKDF2-HMAC-SHA256 at ≥600,000 iterations **MAY** be used only as a runtime fallback when Argon2id is unavailable, and the choice actually used **MUST** be recorded alongside the derived material so a verifier never has to guess which was used |
| Content hashing | SHA-256 |

A `suite_id` field (`u16`) **MUST** be carried inside every signed object
type defined in §9, populated with `0x0001` for this suite. A verifier
**MUST** reject a signed object carrying a `suite_id` it does not
recognize rather than attempting to interpret its fields under the
assumptions of a different suite. This is what allows a future suite
(e.g. a post-quantum-signature suite) to be introduced as an additive
`suite_id` value rather than a breaking change to every message type at
once (see §13 of `WHITEPAPER.md`).

Symmetric and hashing primitives above are not expected to need near-term
post-quantum migration (Grover's algorithm only halves their effective
security). Key exchange and long-lived signatures (specifically §9.4,
Settlement Receipts) are the items with real urgency — see `WHITEPAPER.md`
§17 for the reasoning.

---

## 3. Transport framing

Every message is carried inside a fixed 20-byte header followed by up to
4096 bytes of payload:

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | Magic | ASCII `"TP2P"` (`0x54 0x50 0x32 0x50`) |
| 4 | 2 | Protocol version | `u16`, currently `5` |
| 6 | 2 | Message type | `u16`, see §8 registry |
| 8 | 8 | Sequence number | `u64`, starts at 1, increments by 1 per frame sent in each direction independently, **MUST** reset to 1 on every new transport connection |
| 16 | 4 | Payload length | `u32`, **MUST** be ≤ 4096 |
| 20 | 0–4096 | Payload | Message-type-specific encoding, see §8 |

Conformance requirements:

- A receiver **MUST** reject a frame whose magic does not match exactly.
- A receiver **MUST** reject a frame whose protocol version does not match
  its own.
- A receiver **MUST** reject a frame whose message type is outside the
  contiguous, currently-assigned range (§8.1) — unrecognized future types
  **MUST** cause a hard rejection, never a best-effort skip, so that a
  version mismatch fails loudly rather than silently misinterpreting bytes.
- A receiver **MUST** reject a frame whose sequence number does not equal
  the next expected value for that connection (strictly monotonic, no
  gaps, no reordering tolerance at the framing layer).
- A receiver **MUST** reject a frame whose declared payload length exceeds
  4096, before attempting to read that many bytes.
- The sequence number **MUST NOT** be relied upon as a nonce or anti-replay
  token for anything outside the single transport connection it belongs
  to — it resets on reconnect, and every signed object in §9 carries its
  own, connection-independent freshness fields for exactly this reason.

Connection admission **SHOULD** be bounded independently of any
session/settlement logic: implementations **SHOULD** cap in-flight TLS
handshakes and established connections, and bound handshake duration, so
that transport-level resource exhaustion cannot be used to starve
legitimate connections regardless of what happens at the message layer.

---

## 4. Common data types

| Type | Size | Notes |
|---|---|---|
| `SessionId` | `byte[32]` | Random, chosen by whichever party proposes a transaction session (or by the facilitator on the proposer's behalf); **MUST NOT** be the all-zero value, which is reserved as "no session." |
| `PartyConnectionId` | `byte[16]` | Assigned by the facilitator per connection; **MUST** be freshly random per connection and **MUST NOT** be reused across a reconnect. |
| `ProposalId` | `byte[16]` | Identifies a pending, not-yet-accepted transaction proposal (an "invite"). |
| `Ed25519PublicKey` | `byte[32]` | Raw public key encoding. |
| `Ed25519Signature` | `byte[64]` | Raw signature encoding. |
| `Timestamp` | `u64` | Unix seconds. |
| `UnitTypeCode` | Convention-A string, max 16 bytes | e.g. a currency or asset symbol; opaque to the protocol. |
| `DeliveryReference` | Convention-A string, max 256 bytes | Opaque; printable-ASCII-only is **RECOMMENDED** but not required by this layer — see §12 for the validation profile the reference implementation applies. |

`Party` (`u8`): `0x00` = Party A (the session's proposer), `0x01` = Party
B (the accepting party). Any other value **MUST** be rejected.

---

## 5. Session lifecycle state machine

One state machine instance per transaction session, held by the
facilitator. States:

```
AWAITING_PEER
AWAITING_LEG_SENT
AWAITING_LEG_RECEIVED
AWAITING_FINAL_RECEIPT_ACK      (see §9.4 — gates the session's true final leg)
AWAITING_FACILITATOR_FEE_SENT   (only reachable if a facilitator fee is configured)
COMPLETE                        (terminal)
ABORTED                         (terminal)
```

### 5.1 Transition table

| From | Event | To | Condition |
|---|---|---|---|
| `AWAITING_PEER` | second party joins | `AWAITING_LEG_SENT` | — |
| `AWAITING_PEER` | abort | `ABORTED` | — |
| `AWAITING_LEG_SENT` | current sender signals sent | `AWAITING_LEG_RECEIVED` | — |
| `AWAITING_LEG_SENT` | abort | `ABORTED` | — |
| `AWAITING_LEG_RECEIVED` | current receiver signals received, more legs remain and this is not the session's final leg | `AWAITING_LEG_SENT` | leg/round counters advance (§5.2) |
| `AWAITING_LEG_RECEIVED` | current receiver signals received, **and the next leg would be the session's true final leg** | `AWAITING_FINAL_RECEIPT_ACK` | see §9.4 — this transition **MUST** occur instead of going directly to `AWAITING_LEG_SENT` |
| `AWAITING_LEG_RECEIVED` | current receiver signals received, no facilitator fee configured, and this WAS the gated final leg | `COMPLETE` | only reachable after `AWAITING_FINAL_RECEIPT_ACK` has already resolved for this leg |
| `AWAITING_LEG_RECEIVED` | abort | `ABORTED` | — |
| `AWAITING_FINAL_RECEIPT_ACK` | both parties acknowledge (§9.4) | `AWAITING_LEG_SENT` | when the gated leg is an ordinary leg (no fee configured) |
| `AWAITING_FINAL_RECEIPT_ACK` | both parties acknowledge (§9.4) | `AWAITING_FACILITATOR_FEE_SENT` | when a facilitator fee is configured — the fee leg is the true final leg in that case |
| `AWAITING_FINAL_RECEIPT_ACK` | abort | `ABORTED` | — |
| `AWAITING_FACILITATOR_FEE_SENT` | fee sender signals sent | `COMPLETE` | facilitator is the recipient of this leg; no separate receive-acknowledgement step |
| `AWAITING_FACILITATOR_FEE_SENT` | abort | `ABORTED` | — |

`COMPLETE` and `ABORTED` are terminal; no further transitions are valid
from either. A conformant facilitator implementation **MUST** reject any
signal received for a session already in a terminal state.

### 5.2 Leg and round bookkeeping

A session has a configured round count *N* ≥ 1. Each round has exactly two
legs (Party A's contribution, then Party B's, or the reverse — the leading
party alternates round to round, starting from whichever party the
session's terms designate as first). The session's **true final leg** is:

- the fee leg, if a facilitator fee is configured for this deployment; else
- the second leg of round *N* (the last round).

Implementations **MUST** compute this correctly before the transition in
§5.1's fourth row — determining "is the leg about to be entered the true
final leg" is what decides whether `AWAITING_FINAL_RECEIPT_ACK` is entered.
Getting this wrong either gates a non-final leg unnecessarily or, more
seriously, fails to gate the true final leg at all, defeating §9.4
entirely.

### 5.3 Why the gate exists here, structurally

This state machine differs from the "obvious" design (round loop, then a
fee leg, then complete) by inserting `AWAITING_FINAL_RECEIPT_ACK`
unconditionally before the true final leg becomes reachable. This is the
withholding fix from `WHITEPAPER.md` §12, implemented as a structural
property of the state machine rather than a policy layered on top:
withholding cooperation with §9.4's receipt exchange makes it
*structurally impossible* for the true final leg to ever be entered, for
either party — the mechanism does not rely on any party choosing to
enforce this at the application layer.

---

## 6. Session establishment messages

These messages precede and follow the settlement state machine (§5); they
are summarized here at a lower level of detail than §8–9 since they carry
no cryptographic novelty — see §8 for exact field encodings.

1. A party submits a transaction **proposal** (either as an open listing
   another party can accept by `SessionId`, or as a direct, targeted
   invitation to a specific `PartyConnectionId`).
2. The facilitator relays acceptance and assigns both parties their
   `Party` role and each other's `PartyConnectionId`.
3. Both parties receive a **session-ready** notification carrying the
   agreed terms and both delivery references.
4. The settlement state machine (§5) begins at `AWAITING_LEG_SENT`.

---

## 7. Identity-layer overview

Four independent, additive mechanisms sit on top of §5–6, corresponding to
`WHITEPAPER.md` §10–13:

| Mechanism | Purpose | Wire messages |
|---|---|---|
| Counterparty recognition | Live proof of key control | `RECOGNITION_CHALLENGE`, `RECOGNITION_RESPONSE` |
| Ephemeral transaction identity | Per-session unlinkable signing key | `EPHEMERAL_KEY_ANNOUNCE` |
| Settlement receipts | Facilitator-countersigned, staged, non-repudiable evidence | `RECEIPT_ACK_REQUIRED`, `RECEIPT_ACK`, `RECEIPT_ISSUED` |
| Selective disclosure | Show a receipt chain to a chosen party in a chosen session | `RECEIPT_DISCLOSURE` |

All four route through the facilitator using the **same relay
discipline**: a party sends the message addressed to its own session; the
facilitator, having confirmed the sender is a genuine member of that
session, forwards the payload verbatim to the other party. The facilitator
**MUST NOT** inspect, interpret, or act on the contents of a relayed
identity-layer message beyond this membership check — every cryptographic
verification happens only on the receiving party's own client. The one
exception is `RECEIPT_ACK`/`RECEIPT_ISSUED`, where the facilitator is
itself a required cryptographic participant (§9.4), not merely a relay.

---

## 8. Message catalog

### 8.1 Message type registry

| ID | Name | Direction | §
|---|---|---|---|
| 1 | `WELCOME` | facilitator → party | 8.2 |
| 2–9 | Session establishment (list/create/join/cancel/invite/accept/decline) | both | 6 |
| 10 | `SESSION_READY` | facilitator → both parties | 6 |
| 11 | `TURN` | facilitator → both parties | 8.3 |
| 12 | `LEG_SENT` | party → facilitator → other party | 8.3 |
| 13 | `LEG_RECEIVED` | party → facilitator → other party | 8.3 |
| 14 | `COMPLETE` | facilitator → both parties | 8.3 |
| 15 | `ABORT` | either direction | 8.3 |
| 16 | `ERROR` | facilitator → party | — |
| 17 | `DISCONNECT` | party → facilitator | — |
| 18–21 | Directory service (register/registered/list/list-response) | both | — |
| 22–28 | Open-listing management (create/created/list/list-response/join/cancel/cancelled) | both | 6 |
| 29–30 | Recovery state query/response (facilitator-side session persistence, optional) | both | — |
| 31 | `RECOGNITION_CHALLENGE` | party → facilitator → other party | 9.1 |
| 32 | `RECOGNITION_RESPONSE` | party → facilitator → other party | 9.1 |
| 33 | `EPHEMERAL_KEY_ANNOUNCE` | party → facilitator → other party | 9.2 |
| 34 | `RECEIPT_ACK` | party → facilitator | 9.4 |
| 35 | `RECEIPT_ISSUED` | facilitator → both parties | 9.4 |
| 36 | `RECEIPT_ACK_REQUIRED` | facilitator → both parties | 9.4 |
| 37 | `RECEIPT_DISCLOSURE` | party → facilitator → other party | 9.5 |

IDs 2–9, 18–30 are session-establishment, discovery, and recovery messages
whose fields are straightforward reflections of §6 and carry no
cryptographic novelty; a full field-by-field table for each is omitted
here for space and is available in the reference implementation's own
protocol definition. An implementation claiming conformance with this
specification **MUST** still implement them — §8.1's registry is
authoritative for which numeric ID is assigned to which message, since
that assignment is what makes two independent implementations
interoperate, even where this document doesn't re-derive every field.

A receiver **MUST** reject any message type numerically outside
`[1, 37]` for this version of the specification (see §3's framing
requirements). Extending the registry is an additive operation for a
future version; **MUST NOT** be done by reusing an already-assigned ID.

### 8.2 `WELCOME` (facilitator → party, on connect)

| Field | Type |
|---|---|
| `party_connection_id` | `PartyConnectionId` |
| `facilitator_fee_unit` | Convention-A string, max 16 |
| `facilitator_fee_quantity` | `u64` |
| `facilitator_fee_delivery_reference` | Convention-A string, max 256 |

A zero-length `facilitator_fee_unit` and zero `facilitator_fee_quantity`
signal "no fee configured" for this deployment.

### 8.3 Settlement messages

`TURN` (facilitator → both parties, whenever the current leg changes):

| Field | Type |
|---|---|
| `session_id` | `SessionId` |
| `round_index` | `u32`, zero-based |
| `sender` | `Party` |
| `unit_type` | `UnitTypeCode` |
| `quantity` | `u64` |
| `delivery_reference` | `DeliveryReference` |

`LEG_SENT` / `LEG_RECEIVED` (identical shape, distinguished by message
type):

| Field | Type |
|---|---|
| `session_id` | `SessionId` |
| `round_index` | `u32` |
| `sender` | `Party` |

`COMPLETE`:

| Field | Type |
|---|---|
| `session_id` | `SessionId` |

`ABORT`:

| Field | Type |
|---|---|
| `session_id` | `SessionId` |
| `reason` | Convention-A string, max 128, printable-ASCII **RECOMMENDED** |

---

## 9. Signed objects

Every signed object in this section shares a construction discipline:

1. A **domain separation label** (a fixed ASCII string, unique per object
   type) is the first field of the canonical encoding, itself
   Convention-A-length-prefixed. This is what prevents a signature over one
   object type from ever being misinterpreted as valid for another, even if
   two object types happened to share a field shape.
2. `protocol_version` (`u16`) and `suite_id` (`u16`) follow immediately.
3. Every subsequent field is encoded in a **fixed, specified order** — an
   implementation **MUST NOT** reorder fields, and **MUST NOT** fall back to
   any self-describing format (e.g. JSON, or naive string concatenation)
   for the signed bytes themselves. Concatenating a label and an identifier
   without length-prefixing is explicitly unsafe: `label="ab", id="c"` and
   `label="a", id="bc"` would otherwise produce identical bytes.
4. The resulting byte string is signed directly with Ed25519 (one-shot;
   Ed25519 has no streaming digest API in most implementations, so the
   full canonical encoding **MUST** be assembled before signing, not
   streamed incrementally).

### 9.1 Counterparty recognition

**Domain label:** `TRADEP2P_RECOGNITION_CHALLENGE_V1`

| Field | Type |
|---|---|
| domain label | Convention-A string |
| `protocol_version` | `u16` |
| `suite_id` | `u16` |
| `facilitator_id` | Convention-A string, max 256 — an opaque label both parties independently already know from having connected to the same facilitator; **MUST NOT** be transmitted on the wire as part of the challenge/response messages themselves (see §9.1.1) |
| `session_id` | `SessionId` |
| `nonce` | `byte[32]` |
| `created_at` | `Timestamp` |
| `expires_at` | `Timestamp` |

Signed with the **facilitator-scoped pseudonym key** (`WHITEPAPER.md` §8),
never the per-session ephemeral key.

**Requirements:**

- The verifier **MUST** generate `nonce` using a CSPRNG; the prover **MUST
  NOT** be permitted to supply or influence it.
- The verifier **MUST** track outstanding challenges it issued (keyed by
  `session_id` + `nonce`) and **MUST** enforce: single use (a challenge is
  consumed, successfully or not, on its first matching response), and
  expiry (`now > expires_at` **MUST** be rejected even given an otherwise-
  valid signature).
- On any failure (unknown nonce, expired, wrong session, bad signature,
  malformed public key), the verifier **MUST** respond/behave identically
  regardless of which specific check failed, so a failure carries no
  information about which check tripped.
- A default challenge lifetime of 120 seconds is **RECOMMENDED**.

#### 9.1.1 Wire messages

`RECOGNITION_CHALLENGE`:

| Field | Type |
|---|---|
| `session_id` | `SessionId` |
| `suite_id` | `u16` |
| `nonce` | `byte[32]` |
| `created_at` | `Timestamp` |
| `expires_at` | `Timestamp` |

`RECOGNITION_RESPONSE`:

| Field | Type |
|---|---|
| `session_id` | `SessionId` |
| `nonce` | `byte[32]` (echoes the challenge being answered) |
| `prover_public_key` | `Ed25519PublicKey` |
| `signature` | `Ed25519Signature` |

`facilitator_id` is deliberately absent from both wire messages — each
party supplies it locally, from its own knowledge of which facilitator it
is connected to, when constructing or verifying the signed payload above.
Carrying it on the wire would add nothing a facilitator relaying the
message couldn't already fabricate, since the facilitator sees both
connections regardless.

### 9.2 Ephemeral transaction identity

No signed object of its own — this mechanism is a bare key announcement.
A conformant implementation **MUST** generate this key using a CSPRNG,
**MUST NOT** derive it from any other key material, and **MUST** generate
a fresh one per transaction session.

`EPHEMERAL_KEY_ANNOUNCE`:

| Field | Type |
|---|---|
| `session_id` | `SessionId` |
| `ephemeral_public_key` | `Ed25519PublicKey` |

### 9.3 Signed transaction messages (optional layer)

Implementations **MAY** additionally have each party locally sign a
statement about its own settlement actions (§8.3's `LEG_SENT`/
`LEG_RECEIVED`), using the ephemeral key from §9.2, for the party's own
evidentiary purposes (this does not change the wire shape of §8.3's
messages themselves — it is a parallel, locally-held signature, not a
wire requirement).

**Domain label:** `TRADEP2P_TRADE_MESSAGE_V1`

| Field | Type |
|---|---|
| domain label | Convention-A string |
| `protocol_version` | `u16` |
| `suite_id` | `u16` |
| `facilitator_id` | Convention-A string, max 256 |
| `session_id` | `SessionId` |
| `round_index` | `u32` |
| `message_type` | `u16` (the §8.1 message type ID the signature is about) |
| `payload_hash` | `byte[32]`, SHA-256 of the corresponding §8.3 message's canonical encoding |
| `sender_ephemeral_public_key` | `Ed25519PublicKey` |
| `recipient` | `PartyConnectionId` |
| `timestamp` | `Timestamp` |

### 9.4 Settlement receipts, and the withholding fix

Four stages, `u8`-encoded:

| Value | Stage |
|---|---|
| 1 | Terms accepted |
| 2 | Round *N* acknowledged |
| 3 | All obligations except final settlement completed |
| 4 | Settlement completed |

A conformant implementation **MUST** implement stages 3 and 4 live (they
are what the withholding fix and completion evidence require). Stages 1
and 2 **MAY** be implemented as receipt-chain-verifiable stages without
being triggered by the live protocol in every deployment; if a
deployment does not issue them, its receipt chains simply begin at stage
3.

**9.4.1 Receipt acknowledgement (party-signed half)**

**Domain label:** `TRADEP2P_RECEIPT_ACK_V1`

| Field | Type |
|---|---|
| domain label | Convention-A string |
| `protocol_version` | `u16` |
| `suite_id` | `u16` |
| `facilitator_id` | Convention-A string, max 256 |
| `session_id` | `SessionId` |
| `stage` | `u8` |
| `terms_commitment` | `byte[32]`, SHA-256 of the session's canonically-encoded terms |
| `timestamp` | `Timestamp` |

Signed with the party's **ephemeral transaction key** for this session
(§9.2) — never the facilitator-scoped pseudonym key, and never a key
embedded in the acknowledgement message itself (the facilitator **MUST**
verify against the key it independently observed via §9.2's announcement,
never a key a party claims in the acknowledgement).

`RECEIPT_ACK` (party → facilitator):

| Field | Type |
|---|---|
| `session_id` | `SessionId` |
| `stage` | `u8` |
| `timestamp` | `Timestamp` |
| `signature` | `Ed25519Signature` |

**9.4.2 The receipt itself (facilitator-signed)**

**Domain label:** `TRADEP2P_RECEIPT_V1`

| Field | Type |
|---|---|
| domain label | Convention-A string |
| `protocol_version` | `u16` |
| `suite_id` | `u16` |
| `facilitator_id` | Convention-A string, max 256 |
| `session_id` | `SessionId` |
| `terms_commitment` | `byte[32]` |
| `party_a_ephemeral_key` | `Ed25519PublicKey` |
| `party_b_ephemeral_key` | `Ed25519PublicKey` |
| `facilitator_public_key` | `Ed25519PublicKey` |
| `stage` | `u8` |
| `completed` | `u8`, `0` or `1` |
| `timestamp` | `Timestamp` |
| `nonce` | `byte[16]` |
| `previous_stage_hash` | `byte[32]`, see §9.4.3; all-zero for the first receipt in a chain |

Signed with the facilitator's own receipt-signing key. Implementations
**SHOULD** keep this key stable across restarts (it is meant to remain
verifiable for years — see `WHITEPAPER.md` §17) rather than regenerating
it on every process start.

**9.4.3 Chain linkage**

```
chain_link_hash(fields, signature) = SHA-256( encode(fields) || signature )
```

A receipt's `previous_stage_hash` **MUST** equal `chain_link_hash` of the
immediately preceding stage's receipt (fields and signature together — not
fields alone, so a later stage cannot be re-parented onto a same-fields,
different-signature forgery). A verifier reconstructing a chain **MUST**
reject it if: any signature fails to verify against the facilitator public
key, stages do not strictly increase from entry to entry, `session_id` /
`terms_commitment` / both ephemeral keys are not identical across every
entry in the chain, or any `previous_stage_hash` does not match.

**9.4.4 The withholding fix — timing requirement**

A conformant facilitator implementation **MUST**:

1. Enter `AWAITING_FINAL_RECEIPT_ACK` (§5) before the session's true final
   leg becomes reachable — not after.
2. Require a valid stage-3 `RECEIPT_ACK` from **both** parties before
   transitioning out of that state.
3. Issue the stage-3 `RECEIPT_ISSUED` to both parties only once both
   acknowledgements have been independently verified.
4. Issue the stage-4 `RECEIPT_ISSUED` **only** once the state machine has
   independently reached `COMPLETE` through the ordinary settlement flow
   (§5) — never optimistically, and never as a side effect of the
   stage-3 exchange alone.

This ordering is the entire mechanism. A conformance test suite for this
specification **MUST** include a test that: brings a session to the point
where only one party has submitted a stage-3 acknowledgement, confirms no
`TURN` for the final leg is issuable, confirms the *other* party's own
final-leg obligation is also blocked, and confirms this state is
observably distinct from — and does not silently resolve into —
`COMPLETE`.

`RECEIPT_ACK_REQUIRED` (facilitator → both parties, sent exactly once per
session, when `AWAITING_FINAL_RECEIPT_ACK` is entered):

| Field | Type |
|---|---|
| `session_id` | `SessionId` |

This message exists so a receiving implementation has an explicit signal
that no further `TURN` is coming until both parties acknowledge — silence
alone is not a valid signal to build a client against.

`RECEIPT_ISSUED` (facilitator → both parties):

| Field | Type |
|---|---|
| `session_id` | `SessionId` |
| `facilitator_id` | Convention-A string, max 256 — **MUST** be carried on this message specifically (unlike §9.1/§9.2, which omit it), because a receipt legitimately outlives the connection it was issued on and may be verified by a party who was never connected to the issuing facilitator at all (§9.5) |
| `stage` | `u8` |
| `completed` | `u8` |
| `terms_commitment` | `byte[32]` |
| `party_a_ephemeral_key` | `Ed25519PublicKey` |
| `party_b_ephemeral_key` | `Ed25519PublicKey` |
| `facilitator_public_key` | `Ed25519PublicKey` |
| `timestamp` | `Timestamp` |
| `nonce` | `byte[16]` |
| `previous_stage_hash` | `byte[32]` |
| `facilitator_signature` | `Ed25519Signature` |

**9.4.5 Trust-on-first-use, named explicitly**

A party receiving its first `RECEIPT_ISSUED` from a given facilitator has
no external anchor for that facilitator's `facilitator_public_key` beyond
whatever pinning already applies to the transport connection (§2). A
conformant client **SHOULD** pin the first receipt-signing key it observes
for a given `facilitator_id` for the remainder of its session and **MUST**
treat any later receipt claiming a different key for the same
`facilitator_id` as untrusted rather than silently accepting it. This is
the same trust-on-first-use posture the directory service (`WHITEPAPER.md`
§15) already has, surfacing here rather than being a new gap.

### 9.5 Selective disclosure

**Domain label:** `TRADEP2P_RECEIPT_DISCLOSURE_V1`

| Field | Type |
|---|---|
| domain label | Convention-A string |
| `protocol_version` | `u16` |
| `suite_id` | `u16` |
| `facilitator_id` | Convention-A string, max 256 — the **current** negotiation's facilitator |
| `session_id` | `SessionId` — the **current** negotiation, not the disclosed chain's original session |
| `recipient_ephemeral_key` | `Ed25519PublicKey` — the recipient's **current**-session ephemeral key |
| `disclosed_chain_hash` | `byte[32]`, see below |
| `timestamp` | `Timestamp` |
| `nonce` | `byte[16]` |

```
disclosed_chain_hash = SHA-256( chain_link_hash(r1) || chain_link_hash(r2) || ... )
```
over every receipt in the disclosed chain, in stage order.

Signed with the **original** session's ephemeral key (the one that appears
as `party_a_ephemeral_key` or `party_b_ephemeral_key` inside the disclosed
receipts) — not the current session's ephemeral key. This is the field
that proves the discloser genuinely held that receipt chain; the fields
above bind the disclosure to the current, live exchange even though the
signing key itself is historical.

`RECEIPT_DISCLOSURE` (party → facilitator → other party):

| Field | Type |
|---|---|
| `session_id` | `SessionId` (current negotiation) |
| `recipient_ephemeral_key` | `Ed25519PublicKey` |
| `disclosed_chain_hash` | `byte[32]` |
| `timestamp` | `Timestamp` |
| `nonce` | `byte[16]` |
| `signature` | `Ed25519Signature` |
| `chain_length` | `u8`, **MUST** be ≤ 8 |
| `chain` | `chain_length` repetitions of a Convention-A-length-prefixed, fully-encoded `RECEIPT_ISSUED` payload |

**Verification (recipient side) — a conformant client MUST check all of:**

1. The attached chain independently verifies per §9.4.3.
2. `disclosed_chain_hash` matches the attached chain.
3. `session_id` matches the recipient's own current session.
4. `recipient_ephemeral_key` matches the recipient's own current-session
   ephemeral key (never a broadcast disclosure — this is what makes it
   *selective*).
5. `signature` verifies under **either** `party_a_ephemeral_key` or
   `party_b_ephemeral_key` from the attached chain (whichever party
   actually disclosed it).

Failure of any single check **MUST** cause the whole disclosure to be
rejected; a client **MUST NOT** partially trust a disclosure that fails
one check while accepting the rest.

### 9.6 Service-scoped login (out-of-band from the facilitator protocol)

Where a deployment includes a hosted service (a web client, a mobile
backend) with its own account system, the following applies at that
service's own transport (typically HTTPS, not the facilitator wire
protocol of §3).

**Domain label:** `TRADEP2P_LOGIN_CHALLENGE_V1`

| Field | Type |
|---|---|
| domain label | Convention-A string |
| `protocol_version` | `u16` |
| `suite_id` | `u16` |
| `service_id` | Convention-A string, max 256 |
| `server_identity` | Convention-A string, max 256 — **MUST** be the service's actual public-facing identity (its domain, if reverse-proxied) not merely its bind address, or the binding is meaningless |
| `username` | Convention-A string, max 256 |
| `session_id` | `byte[16]` |
| `nonce` | `byte[32]` |
| `created_at` | `Timestamp` |
| `expires_at` | `Timestamp` |

Server requirements: single-use and expiring challenges (server-tracked,
not merely client-trusted expiry); constant-shape, constant-effort
responses to an unknown username and a known username with a failing
signature (account-enumeration resistance); per-account rate limiting on
authentication attempts, applied identically whether or not the account
exists.

**Honest ceiling (normative, not merely descriptive):** an implementation
**MUST NOT** represent this mechanism, in documentation or interface copy,
as protecting a party against a hosted service's own operator. It protects
only against compromise of stored credentials (a leaked account database,
credential stuffing). Where the client runtime is operator-controlled (a
browser page the operator serves), a hardware-backed authenticator, an
external signer, or a native client **SHOULD** be preferred over holding
the raw private key inside that runtime.

---

## 10. Key derivation

### 10.1 `encode_derivation_info` (Convention B)

```
u8   label_length
     label bytes (label_length bytes)
u16  identifier_length
     identifier bytes (identifier_length bytes)
```

`label` **MUST** be one of the fixed registry values below (§10.2) — never
an ad hoc string — so the total set of derivation contexts in use stays
closed and auditable. `identifier` is deployment/context-specific (e.g. a
facilitator identifier, a service identifier, or empty).

Scoped key derivation:

```
scoped_key = HKDF-SHA256( ikm = master_secret,
                           salt = empty,
                           info = encode_derivation_info(label, identifier),
                           length = 32 )
```

An empty HKDF salt is well-defined (treated as a zero-filled string of the
hash output length) and is used deliberately here so that the master
secret and the domain-separated `info` parameter alone determine every
derived key.

The transaction-ephemeral key (§9.2) is the **sole exception**: it **MUST**
be generated with a CSPRNG and **MUST NOT** be produced via this
derivation, for the linkability reasons in `WHITEPAPER.md` §8.

### 10.2 Key-scope label registry

| Label (ASCII) | Purpose |
|---|---|
| `login` | Service-scoped login key (§9.6), one per `service_id` |
| `local-history` | Local transaction log / counterparty record authentication key, one per party, never leaves the device |
| `mediator` | Facilitator-scoped pseudonym key (§9.1), one per `facilitator_id` |

New labels **MUST** be added to this registry before use, in a future
version of this specification — an implementation **MUST NOT** invent a
private label, since doing so reintroduces exactly the kind of
undocumented, unauditable derivation context §10.1 exists to prevent.

---

## 11. Local storage (informative requirements)

Full on-disk formats are implementation-specific, but a conformant
implementation's local storage **MUST** satisfy:

- **Key material at rest** **MUST** be authenticated-encrypted (§2's AEAD)
  under a passphrase-derived key (§2's Argon2id/PBKDF2), never stored in
  plaintext.
- **The local transaction log MUST** be a hash-chained, append-only
  structure such that modification, deletion, or reordering of any entry
  is detectable, and **MUST** be signed (checkpointed) under the
  local-history key (§10.2) at a implementation-chosen cadence.
- **The local counterparty record MUST** be keyed by (counterparty public
  key, `facilitator_id`) pairs, **MUST NOT** merge records across different
  `facilitator_id` values for the same key bytes, and **MUST** increment
  its "completed" counter only from the party's own transaction log —
  never from any counterparty-supplied claim.
- Every local store **MUST** fail closed (a typed, distinguishable error)
  on a corrupted or tampered file, never silently regenerate or fall back
  to an empty store.

---

## 12. Delivery reference validation profile

Implementations **SHOULD** apply the following validation to
`DeliveryReference` fields before accepting them into a session:

- 1 to 256 bytes.
- Printable ASCII only (bytes `0x20`–`0x7E`); reject or reject-and-report
  control characters and non-ASCII bytes rather than silently stripping
  them.
- No implicit truncation — a reference exceeding the maximum length
  **MUST** be rejected, never silently cut short.

This profile is a **SHOULD**, not a **MUST**, because some deployments'
delivery references may legitimately need a different alphabet; the
length bound and truncation behavior remain strong recommendations
regardless.

---

## 13. Error handling and version negotiation

- A message that fails to decode (truncated, oversized declared length,
  malformed enum value) **MUST** be rejected with a typed error, never
  partially applied.
- A `suite_id` an implementation does not recognize **MUST** cause
  rejection of that specific signed object, not a fallback to treating it
  as suite `0x0001`.
- A `protocol_version` mismatch at the transport layer (§3) **MUST**
  terminate the connection rather than attempting best-effort
  interpretation.
- Implementations extending this specification with new message types or
  signed-object fields **MUST** do so additively (new message type IDs,
  new `suite_id` values) — never by silently repurposing an existing ID or
  changing an existing signed object's field order or count under the same
  `suite_id`.

---

## 14. Test vectors

Generated directly from the reference implementation's encoders (not
hand-computed). Reproducing these exactly is a strong signal an
implementation's canonical encoding is correct.

### 14.1 Recognition challenge signed payload

Input:
```
suite_id      = 0x0001
protocol_version = 5
facilitator_id = "facilitator.example:7443"
session_id    = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
                10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
nonce         = ab (repeated 32 times)
created_at    = 1700000000
expires_at    = 1700000120
```

Output (145 bytes):
```
002154524144455032505f5245434f474e4954494f4e5f4348414c4c454e47455f5631
000500010018666163696c697461746f722e6578616d706c653a37343433
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
abababababababababababababababababababababababababababababababab
000000006553f100000000006553f178
```
(concatenated; line breaks added for readability only)

### 14.2 Receipt signed payload (stage 3, genesis previous-hash)

Input:
```
suite_id       = 0x0001
protocol_version = 5
facilitator_id = "facilitator.example:7443"
session_id     = 00..1f (as above)
terms_commitment = cd (repeated 32 times)
party_a_ephemeral_key = 11 (repeated 32 times)
party_b_ephemeral_key = 22 (repeated 32 times)
facilitator_public_key = 33 (repeated 32 times)
stage          = 3
completed      = 0
timestamp      = 1700000200
nonce          = ef (repeated 16 times)
previous_stage_hash = 00 (repeated 32 times)
```

Output (269 bytes):
```
001354524144455032505f524543454950545f5631
000500010018666163696c697461746f722e6578616d706c653a37343433
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
1111111111111111111111111111111111111111111111111111111111111111
2222222222222222222222222222222222222222222222222222222222222222
3333333333333333333333333333333333333333333333333333333333333333
03
00
00000000 6553f1c8
efefefefefefefefefefefefefefef
0000000000000000000000000000000000000000000000000000000000000000
```
(concatenated; line breaks and the split of the 8-byte timestamp added for
readability only)

### 14.3 Key-derivation context encoding

Input: `label = "login"`, `identifier = "facilitator.example:7443"`

Output (32 bytes):
```
056c6f67696e0018666163696c697461746f722e6578616d706c653a37343433
```

Decoded: `05` (label length 5) `"login"` `0018` (identifier length 24,
big-endian) `"facilitator.example:7443"`.

---

## 15. Conformance checklist

An implementation claiming conformance with this specification:

- [ ] Implements the transport framing of §3 exactly, including all
      **MUST**-level rejection behavior.
- [ ] Implements Suite `0x0001` (§2) or declares which alternate suite it
      implements instead.
- [ ] Implements the full session lifecycle state machine of §5,
      including `AWAITING_FINAL_RECEIPT_ACK` gating the session's true
      final leg unconditionally.
- [ ] Implements the message catalog of §8 with the exact numeric IDs of
      §8.1.
- [ ] Implements canonical encoding for every signed object in §9 exactly
      as specified, field order included, and reproduces §14's test
      vectors byte-for-byte given the same inputs.
- [ ] Enforces every verifier-side requirement in §9.1, §9.4, and §9.5
      (freshness, single-use, expiry, uniform failure behavior).
- [ ] Never derives a transaction-ephemeral key (§9.2) — generates it
      fresh, every session.
- [ ] Applies §10's key-derivation scheme and does not introduce
      undocumented derivation labels.
- [ ] States plainly, in its own documentation, the non-claims in
      `WHITEPAPER.md` §16 (no Sybil resistance, no proof of external value
      movement) rather than allowing interface copy to imply otherwise.
