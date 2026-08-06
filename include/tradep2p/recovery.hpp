#pragma once

// Phase 3 of the optional identity system (client half, continued): turns a
// client's own journal entry plus the mediator's truthful
// RecoveryStateResponseMessage (protocol.hpp) into one of the four
// categories docs/identity-03-journal-recovery.md's "Recovery protocol"
// section requires recovery to distinguish:
//
//   safe idempotent retries
//   unsafe actions requiring explicit user confirmation
//   already committed actions
//   unknown state requiring reconciliation
//
// This module is intentionally conservative, not an exhaustive replay
// engine: whenever the available information does not clearly place an
// action in one of the first three categories, it defaults to
// UnknownRequiresReconciliation rather than guessing. It compares round
// numbers (the one piece of round progress the journal itself records per
// docs/identity-03-journal-recovery.md's field list) and acknowledgement
// state; it does NOT independently model leg index or replay
// MediatorSession's full state machine. See the phase report for this
// scoping decision stated plainly.
//
// The one bright line this module draws structurally: a Sent signal - the
// client's own claim to have moved real value off-protocol (specs.txt SS1,
// "Acknowledgements are claims, not proofs") - is the only message type
// classified as unsafe to blindly retry. Everything else this protocol
// carries is either read-only (ListOffers, RecoveryStateRequest itself) or
// is validated for turn/round/sender correctness by the mediator's own
// MediatorSession state machine, so a stale resend of those simply fails
// cleanly rather than duplicating a real-world transfer.

#include "tradep2p/journal.hpp"
#include "tradep2p/protocol.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace tradep2p {

enum class RecoveryActionCategory : std::uint8_t {
    SafeIdempotentRetry = 0,
    UnsafeRequiresConfirmation = 1,
    AlreadyCommitted = 2,
    UnknownRequiresReconciliation = 3,
};

struct RecoveryClassification {
    RecoveryActionCategory category{RecoveryActionCategory::UnknownRequiresReconciliation};
    std::string explanation;
};

// True only for MessageType::Sent - see the class-level comment above for
// why that is the one message type this module treats as unsafe to
// blindly resend.
[[nodiscard]] bool is_value_bearing_message_type(MessageType type);

// `last_local_entry` should be the caller's own Journal::latest_for_trade()
// result for the trade in question; `mediator_state` should be the
// RecoveryStateResponseMessage the mediator returned for the corresponding
// room id (or std::nullopt if the mediator could not be reached at all -
// a materially different situation from "reached, and it truthfully
// reported `found=false`").
[[nodiscard]] RecoveryClassification classify_recovery_action(
    const std::optional<JournalEntry>& last_local_entry,
    const std::optional<RecoveryStateResponseMessage>& mediator_state);

} // namespace tradep2p
