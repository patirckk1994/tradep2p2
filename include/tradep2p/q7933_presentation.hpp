#pragma once

// Presentation proof and nullifier verification for q7933 blind-signed
// credentials.
//
// This module provides:
// 1. Nullifier derivation and validation
// 2. Presentation context binding (room + verifier)
// 3. Duplicate/replay detection logic
// 4. Domain-separated encoding for presentation proofs
//
// The credential holder derives a nullifier from their hidden serial and
// the presentation scope (room_id + verifier identity + challenge), and
// presents both the credential and nullifier. The verifier checks:
// - The nullifier matches what's derivable from the presented credential
// - The nullifier hasn't been seen before in this presentation scope
// - All N presented credentials have distinct nullifiers

#include "tradep2p/q7933_credential.hpp"

#include <map>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace tradep2p::q7933_credential {

// Presentation context: the scope in which a nullifier is valid and
// duplicate detection is enforced. Typically:
// - room_id (32 bytes)
// - verifier/counterparty identity or ephemeral key (variable)
// - fresh challenge (optional, variable)
//
// Serialized as a length-prefixed blob for domain separation.
struct PresentationContext {
    std::vector<std::uint8_t> room_id;        // 32 bytes
    std::vector<std::uint8_t> verifier_identity; // e.g., ephemeral key
    std::vector<std::uint8_t> challenge;       // optional challenge

    [[nodiscard]] std::vector<std::uint8_t> encode() const;
};

// Verifies that a nullifier is valid for this credential serial and
// presentation context. Returns true if valid, false if invalid.
[[nodiscard]] bool verify_nullifier(
    const CredentialSerial& serial,
    const Nullifier& claimed_nullifier,
    std::uint8_t issuer_scope,
    std::uint32_t epoch,
    const PresentationContext& context);

// In-memory tracker for nullifiers already seen in a specific presentation
// scope. Used during a single verification session to detect duplicates
// within an N-credential presentation.
//
// NOT persistent (session-only); for cross-session replay detection,
// use a persistent store if needed.
class NullifierTracker {
public:
    NullifierTracker() = default;

    // Record a nullifier as seen. Returns true if this is the FIRST time
    // seeing it (allowed), false if already seen (duplicate).
    [[nodiscard]] bool record_nullifier(const Nullifier& nullifier) {
        return seen_.insert(nullifier).second;
    }

    // Check if a nullifier has been seen without recording.
    [[nodiscard]] bool has_been_seen(const Nullifier& nullifier) const {
        return seen_.count(nullifier) > 0;
    }

    // Clear all recorded nullifiers (start a new verification session).
    void reset() { seen_.clear(); }

    [[nodiscard]] std::size_t count() const { return seen_.size(); }

private:
    std::set<Nullifier> seen_;
};

// Encode presentation context for hashing during nullifier derivation.
[[nodiscard]] std::vector<std::uint8_t> encode_presentation_context(
    const PresentationContext& context);

} // namespace tradep2p::q7933_credential
