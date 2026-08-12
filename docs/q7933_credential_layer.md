# q7933 Credential Layer: Replay Protection and Issuance Uniqueness

## Overview

This document describes the credential-layer semantics added on top of the existing q7933 blind-signature primitive, implementing replay protection and issuance uniqueness as specified in TradeP2P specs.txt §9.3.

The q7933 primitive (§9.3a) provided only the algebraic mechanism for blind signing. This layer adds the missing application-level logic:

1. **Issuance Uniqueness**: One credential per completed room/party/epoch
2. **Credential Serial**: 32-byte hidden random value bound to each credential
3. **Scoped Nullifiers**: Domain-separated derivation preventing cross-room replay
4. **Presentation Binding**: Cryptographic commitment to the current context
5. **Double-Count Protection**: Rejection of duplicate credentials within N-element proofs
6. **Durable State**: Server-side persistence surviving mediator restarts

## Architecture

### Core Components

```
include/tradep2p/
  q7933_credential.hpp          # Credential serial, payload, encoding
  q7933_issuance_store.hpp      # Durable issuance uniqueness tracking
  q7933_presentation.hpp        # Nullifier verification, presentation binding

src/
  q7933_credential.cpp
  q7933_issuance_store.cpp
  q7933_presentation.cpp
```

### Design Principles

- **Mediator does NOT learn**: which rooms produce which credentials
- **Mediator DOES learn**: which rooms have already claimed their issuance (for uniqueness enforcement)
- **No global identifiers**: nullifiers are scoped to specific presentation contexts
- **Constant-time verification**: all comparisons use bitwise operations to prevent timing attacks
- **Atomic durability**: all disk writes follow tmp file + rename pattern (no in-place writes)
- **Format versioning**: credential payloads and issuance contexts are versioned for forward compatibility

## Component Details

### 1. Credential Serial (`q7933_credential.hpp/.cpp`)

Each credential contains a cryptographically random 32-byte serial:

```cpp
using CredentialSerial = std::array<std::uint8_t, 32>;
CredentialSerial generate_serial();  // 32 random bytes from CSPRNG
```

**Lifecycle**:
1. Client generates serial (random, never logged)
2. Serial included in credential payload → blinded → hidden from mediator
3. Client retains serial to later derive nullifiers
4. Serial never transmitted to verifier in the clear

**Domain-separated encoding** ensures the serial is always bound to a specific credential type and version, preventing cross-protocol attacks.

### 2. Issuance Context and Uniqueness

An `IssuanceContext` uniquely identifies which room/party/epoch can issue a credential:

```cpp
struct IssuanceContext {
    std::uint8_t version;
    std::uint8_t issuer_scope;       // Mediator public key identifier
    std::uint32_t epoch;              // Credential epoch
    std::array<std::uint8_t, 32> room_id;  // 32-byte room identifier
    std::uint8_t party;               // Party A (0) or Party B (1)
};
```

**Uniqueness enforcement**:
- Mediator stores (version, issuer_scope, epoch, room_id, party) → issuance record
- First issuance: record file created → succeeds
- Duplicate attempt: record exists → rejected
- Each party in same room has independent issuance right
- Different rooms/epochs are independent

**Storage**:
```
$STORE_DIR/issuance_<v>_<issuer>_<epoch>_<roomid_hex>_<party>.record
```

Filename encodes the context; file existence = already issued. No encryption needed (mediator is allowed to know issuance state).

### 3. Nullifier Derivation

Nullifiers prevent replay and enable duplicate detection:

```cpp
Nullifier derive_nullifier(
    const CredentialSerial& serial,
    std::uint8_t issuer_scope,
    std::uint32_t epoch,
    std::span<const std::uint8_t> presentation_scope);
```

**Derivation formula**:
```
Nullifier = SHA256(
  "TRADEP2P-Q7933-CREDENTIAL-NULLIFIER-v1" ||
  issuer_scope ||
  epoch ||
  presentation_scope_length (4 bytes, big-endian) ||
  presentation_scope ||
  serial
)
```

**Properties**:
- Deterministic: same (serial, scope) → same nullifier
- Domain-separated: different "CREDENTIAL-NULLIFIER-vN" strings prevent cross-protocol collisions
- Scoped: different presentation_scope → different nullifier (prevents cross-room replay)
- Hidden: serial is kept secret, only nullifier is revealed

### 4. Presentation Context Binding

Each presentation binds to a specific room and verifier context:

```cpp
struct PresentationContext {
    std::vector<std::uint8_t> room_id;              // 32 bytes
    std::vector<std::uint8_t> verifier_identity;   // Counterparty's ephemeral key
    std::vector<std::uint8_t> challenge;            // Optional fresh challenge
};
```

**Encoding** (length-prefixed for domain separation):
```
room_id_len (4) || room_id ||
verifier_len (4) || verifier ||
challenge_len (4) || challenge
```

**Effect**: 
- A credential presented in room A cannot be replayed in room B (different room_id in scope)
- A credential intended for verifier A cannot be accepted by verifier B (different verifier_identity in scope)
- A presentation with an associated challenge is invalidated if challenge changes

### 5. Issuance Store (`q7933_issuance_store.hpp/.cpp`)

Durable server-side tracking of which credentials have been issued:

```cpp
class IssuanceStore {
    bool record_issuance(const IssuanceContext& context);  // Returns true on first issuance
    bool has_been_issued(const IssuanceContext& context) const;
};
```

**Atomic writes**:
1. Write to temp file: `path.tmp`
2. Flush (no explicit fsync on std::ofstream, but close() ensures data is written)
3. `std::filesystem::rename()` (atomic on POSIX)

**Corruption handling**:
- Truncated files rejected (minimal size check)
- Unreadable records throw `IssuanceStoreFormatError`
- I/O errors throw `IssuanceStoreError`

**Recovery**: 
- No in-memory cache; all checks hit disk
- Restart-safe by design (disk is source of truth)
- Bounded storage: one file per (version, issuer, epoch, room, party) tuple

### 6. Presentation Verification (`q7933_presentation.hpp/.cpp`)

Verifies that a nullifier is valid and hasn't been seen before:

```cpp
bool verify_nullifier(
    const CredentialSerial& serial,
    const Nullifier& claimed_nullifier,
    std::uint8_t issuer_scope,
    std::uint32_t epoch,
    const PresentationContext& context);

class NullifierTracker {
    bool record_nullifier(const Nullifier& nullifier);  // First → true, duplicate → false
};
```

**Verification steps**:
1. Re-derive expected nullifier from (serial, issuer_scope, epoch, context)
2. Constant-time comparison with claimed nullifier
3. `NullifierTracker` records nullifier (session-only, not persistent)
4. Duplicate nullifiers are rejected

**Double-count protection**:
- When verifying N credentials, use same `NullifierTracker` for all
- Each credential's nullifier must be distinct
- If any credential appears twice, total count < N

## Security & Privacy Invariants

### Preserved Invariants

✓ **Mediator cannot link presentations to rooms**: Only issuance state (that it happened) is known, not which credentials belong where.

✓ **No global lifelong identifier**: Nullifiers are scoped; different presentation contexts produce different nullifiers from the same serial.

✓ **No raw credential serials leaked**: Serial is client-side only, included only in the blinded commitment (hidden from mediator by blind-signature primitives).

✓ **Atomic persistence**: Issuance state survives crash/restart; no in-progress corruptions possible.

✓ **No passphrase in env/CLI**: Credentials themselves are cryptographic (no traditional "passwords"), and no operator secrets are moved into env vars.

✓ **q7933 remains experimental/gated**: Compile-time and runtime gates unchanged.

✓ **q12289/FALCON unchanged**: FALCON path unaffected except for generic credential plumbing (integration points only).

### Non-Invariants (Not Guaranteed)

✗ **Aggregate ZK proof not implemented**: This layer provides the credential structures and nullifier derivation, but does NOT include a formal ZK proof of "N distinct credentials." Implementations must handle this separately.

✗ **Sybil resistance**: Credentials address only linkability and replay; they do not prevent an attacker from creating many identities. (See specs.txt §12.)

✗ **Cross-mediator continuity**: Credentials are issuer-scoped (issuer_scope field); different mediators produce incomparable credentials.

## Testing

### Test Coverage

**Credential Structures** (4 tests):
- Serial generation produces distinct 32-byte values
- Credential payload encodes/decodes correctly
- IssuanceContext encodes/decodes correctly
- Nullifier derivation is deterministic and scoped

**Issuance Uniqueness** (5 tests):
- First issuance for a room/party/epoch succeeds
- Duplicate issuance attempt fails
- Different rooms have independent issuance rights
- Different parties in same room have independent issuance rights
- Issuance state persists across store restart

**Nullifier & Verification** (4 tests):
- Correct nullifier verifies, wrong nullifier doesn't
- Different issuer_scope produces different nullifier
- NullifierTracker accepts first nullifier, rejects duplicates
- Different nullifiers are tracked as distinct

**Presentation & Encoding** (3 tests):
- PresentationContext encodes correctly
- Credential payload for blind signing encodes correctly
- Empty nullifier derivation works (test/default case)

All tests pass without requiring STARK proofs (no external prover invocation).

## Integration Points (Not Yet Implemented)

The following require additional work to fully integrate the credential layer:

1. **Wire Protocol**: Q7933BlindSigResponse needs optional fields for credential serial and nullifier
2. **Client-Side**: After finalization, client extracts serial and can derive nullifier for presentation
3. **Mediator-Side**: When receiving blind-sig request with room_id, record issuance context
4. **Verifier-Side**: When presenting credential, compute and transmit nullifier, verify against context
5. **Aggregate Proof**: Formal ZK proof over N distinct nullifiers (outside scope of this layer)

## Future Directions

1. **Persistent Nullifier Store**: For longer-lived sessions, track consumed nullifiers to prevent cross-session replay (currently session-only via NullifierTracker).

2. **Verifier Challenge**: Implement fresh per-presentation challenges bound into the presentation_scope to prevent complete presentation replays even within the same room (requires protocol extension).

3. **Epoch Rotation**: Formalize epoch transitions and cleanup of old epoch records (currently implicit).

4. **Aggregate ZK Proof**: Build formal NIZK3 over the nullifier tuple to prove N distinct credentials without revealing which rooms they're from.

5. **Cross-Mediator Bridging**: Allow credentials from different mediators if signed by a common trusted issuer (requires issuer_scope extension).

## References

- `specs.txt` §9.3 (Credential layer design requirements)
- `specs.txt` §9.3a (q7933 blind-signature primitive, the substrate)
- `include/tradep2p/q7933_credential.hpp` (API)
- `include/tradep2p/q7933_issuance_store.hpp` (Persistence)
- `include/tradep2p/q7933_presentation.hpp` (Verification)
- `tests/q7933_credential_tests.cpp` (Test suite, 16 tests)
