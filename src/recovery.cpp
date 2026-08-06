#include "tradep2p/recovery.hpp"

namespace tradep2p {

bool is_value_bearing_message_type(MessageType type) {
    return type == MessageType::Sent;
}

RecoveryClassification classify_recovery_action(
    const std::optional<JournalEntry>& last_local_entry,
    const std::optional<RecoveryStateResponseMessage>& mediator_state) {
    if (!last_local_entry.has_value()) {
        return {RecoveryActionCategory::UnknownRequiresReconciliation,
                "no local journal entry exists for this trade; there is nothing recorded "
                "locally to reconcile against"};
    }
    const JournalEntryFields& local = last_local_entry->fields;

    if (!mediator_state.has_value()) {
        return {RecoveryActionCategory::UnknownRequiresReconciliation,
                "the mediator could not be reached to confirm its side of this room; "
                "only the local journal entry is available"};
    }
    const RecoveryStateResponseMessage& remote = *mediator_state;

    if (!remote.found) {
        if (local.local_state == SessionState::Complete ||
            local.local_state == SessionState::Aborted) {
            return {RecoveryActionCategory::AlreadyCommitted,
                    "the local journal already shows this trade as finished; the mediator "
                    "prunes finished rooms from its persisted state, so its absence here is "
                    "expected, not a loss"};
        }
        return {RecoveryActionCategory::UnknownRequiresReconciliation,
                "the mediator has no record of this room even though the local journal "
                "shows it as still in progress; the room may have been lost before the "
                "mediator's persistence recorded it, or this room id is stale - do not "
                "resend a value-bearing action based on local state alone"};
    }

    if (remote.round_index > local.round) {
        return {RecoveryActionCategory::AlreadyCommitted,
                "the mediator reports further round progress than the local journal does; "
                "the intervening round(s) are already committed on the mediator's side, so "
                "nothing for the earlier round should be resent"};
    }
    if (remote.round_index < local.round) {
        return {RecoveryActionCategory::UnknownRequiresReconciliation,
                "the local journal shows more round progress than the mediator currently "
                "reports; this can happen if the mediator crashed just before persisting an "
                "already-acknowledged round advance - reconcile manually before acting"};
    }

    // Same round on both sides - the acknowledgement state of the local
    // client's last recorded action against this round is what decides the
    // category.
    switch (local.ack_state) {
        case AcknowledgementState::Acknowledged:
            return {RecoveryActionCategory::AlreadyCommitted,
                    "the local journal already recorded this round's acknowledgement; there "
                    "is nothing to retry"};
        case AcknowledgementState::Pending:
            if (local.direction == MessageDirection::Outbound &&
                is_value_bearing_message_type(local.message_type)) {
                return {RecoveryActionCategory::UnsafeRequiresConfirmation,
                        "the last recorded local action was reporting this client's own "
                        "value transfer as sent, with no confirmation that the mediator ever "
                        "received it; resignaling would falsely claim the transfer happened "
                        "again if it already completed off-protocol - ask the user to "
                        "confirm the underlying transfer's status before retrying"};
            }
            return {RecoveryActionCategory::SafeIdempotentRetry,
                    "the last recorded local action does not itself move value and matches "
                    "the mediator's current round; it is safe to resend or re-request"};
        case AcknowledgementState::NotApplicable:
            break;
    }
    return {RecoveryActionCategory::UnknownRequiresReconciliation,
            "no acknowledgement tracking applies to the local journal's last entry for this "
            "round; manual review is needed before taking any action"};
}

} // namespace tradep2p
