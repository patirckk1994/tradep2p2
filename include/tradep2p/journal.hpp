#pragma once

// Phase 3 of the optional identity system (client half): a client-side,
// encrypted-at-rest*, hash-chained, append-only journal of a client's own
// trade activity. See docs/identity-03-journal-recovery.md ("Client-side
// signed journal") and specs.txt SS5 ("Layer one - the local journal") for
// the design this implements.
//
// (*"Encrypted-at-rest" here means: the journal's *authenticity* is
// protected by an Ed25519 signature over each checkpoint, using the
// local-history key phase 2's IdentityKeystore derives via
// key_scope::kLocalHistory. This module does NOT itself encrypt the journal
// file's contents - entries are readable plaintext on disk. Confidentiality
// of trade history at rest is a filesystem-permissions concern (this module
// opens its files at owner-only 0600, matching keystore.cpp's convention),
// not something this module's signatures provide. Signatures give
// integrity/authenticity - tamper *detection* - not secrecy.)
//
// What this journal is for: crash recovery, reconnect recovery, detecting
// local state corruption, reconstructing the last known round, preventing
// accidental duplicate actions, and (later, phase 4) feeding a private
// counterparty history.
//
// What this journal is NOT, and must never be treated as: evidence to a
// counterparty. It proves only what THIS client recorded about itself. A
// user can write anything into their own journal - there is no external
// check on its contents, by design (see specs.txt SS5: "It has no value to a
// counterparty and must never be presented as though it does."). Nothing in
// this module ever transmits a journal entry anywhere; publishing is a
// decision that belongs entirely to a caller this module has no path to.
//
// Data structures:
//   - JournalEntryFields: the caller-supplied content of one entry, exactly
//     the field list from docs/identity-03-journal-recovery.md ("Per-entry
//     fields"): journal version, room id, trade id, mediator id,
//     counterparty pseudonym fingerprint, terms commitment, round, message
//     direction, message type, message hash, acknowledgement state, local
//     settlement state, timestamp.
//   - JournalEntry: one committed entry - JournalEntryFields plus its index
//     and its position in the hash chain (previous_hash, entry_hash).
//
// Hash chain: entry_hash[n] = SHA256(index[n] || canonical(fields[n]) ||
// entry_hash[n-1]), with entry_hash[-1] defined as 32 zero bytes (a fixed,
// documented genesis constant - not a secret). Every field that was ever
// part of an entry, including its own index, is inside the hash, so
// reordering, renumbering, or editing any field of any entry changes that
// entry's hash and breaks the chain from that point forward.
//
// Checkpoints: periodically (caller-driven, e.g. after each acknowledged
// round - see checkpoint()), the CURRENT chain head (index, hash) is signed
// with the local-history private key and appended as a distinct record
// type, and the same (index, hash, signature) is also written to a small,
// separately-atomic "head pointer" file. Two independent things are
// checked on open(): every checkpoint's signature verifies against the
// caller-supplied local-history public key, AND the head-pointer file
// (if present) is not AHEAD of the newest checkpoint found by replaying the
// main log - the latter is what catches "restore an older copy of the main
// log, but leave the head-pointer file with the newer log's already-more-
// advanced checkpoint" rollback attacks. See the class comment on Journal
// for the honest limits of what this can and cannot detect.

#include "tradep2p/identity.hpp"
#include "tradep2p/mediator.hpp"   // SessionState
#include "tradep2p/protocol.hpp"   // RoomId, MessageType

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace tradep2p {

constexpr std::uint16_t kJournalFormatVersion = 1;
constexpr std::size_t kJournalHashLength = 32; // SHA-256
constexpr std::size_t kJournalTradeIdLength = 16;
constexpr std::size_t kJournalMaxMediatorIdLength = 256;

using JournalHash = std::array<std::uint8_t, kJournalHashLength>;
using TradeId = std::array<std::uint8_t, kJournalTradeIdLength>;

// SHA-256, exposed here because callers need it to build
// JournalEntryFields::terms_commitment / message_hash before calling
// Journal::append(). Not exported from identity.hpp (phase 1 never needed a
// bare digest primitive - its HKDF calls SHA-256 internally via OpenSSL's
// KDF API, but never exposes a standalone digest function), so this module
// adds its own small wrapper around EVP_Digest, reusing identity.hpp's
// EvpMdCtxPtr RAII type rather than introducing a second one.
[[nodiscard]] JournalHash sha256(std::span<const std::uint8_t> data);

// Convenience: sha256(encode_terms(terms)), the canonical "terms commitment"
// this journal's entries are meant to carry.
[[nodiscard]] JournalHash sha256_terms_commitment(const TradeTerms& terms);

enum class MessageDirection : std::uint8_t {
    Outbound = 0, // this client sent (or was about to send) the message
    Inbound = 1,  // this client received the message
};

enum class AcknowledgementState : std::uint8_t {
    NotApplicable = 0, // this entry does not itself await an acknowledgement
    Pending = 1,       // sent/expected, but not yet confirmed locally
    Acknowledged = 2,  // confirmed (e.g. the matching Sent/Received arrived)
};

// One entry's caller-supplied content - exactly the field list the phase
// spec enumerates (plus `version`, since the spec lists "journal version"
// as a per-entry field so that entries recorded by different software
// versions can still hash-chain together consistently).
struct JournalEntryFields {
    std::uint16_t version{kJournalFormatVersion};
    RoomId room_id{};      // all-zero if not yet assigned by the mediator
    TradeId trade_id{};    // client-local identifier, assigned before room_id is known
    std::string mediator_id;  // opaque caller label (e.g. host:port); not a
                               // cryptographic identity before phase 6/8
    std::array<std::uint8_t, 32> counterparty_fingerprint{}; // all-zero if unknown
    JournalHash terms_commitment{}; // sha256_terms_commitment(); all-zero if terms unknown yet
    std::uint32_t round{0};
    MessageDirection direction{MessageDirection::Outbound};
    MessageType message_type{MessageType::Welcome}; // reused wire enum; see class comment
    JournalHash message_hash{};
    AcknowledgementState ack_state{AcknowledgementState::NotApplicable};
    SessionState local_state{SessionState::WaitingForPeer}; // client's own local mirror
    std::uint64_t timestamp{0}; // unix seconds; 0 => append() fills in wall-clock time
};

// A committed entry: fields plus its place in the hash chain.
struct JournalEntry {
    std::uint64_t index{0};
    JournalEntryFields fields;
    JournalHash previous_hash{};
    JournalHash entry_hash{};
};

// ---------------------------------------------------------------------------
// Exceptions. Three distinct types, matching keystore.hpp's precedent of
// giving different failure classes different types so a caller (and a test)
// can tell them apart:
//   - JournalFormatError: the bytes on disk are not well-formed (bad magic,
//     unsupported version, truncated header/field). A torn trailing write
//     (the last record cut short by a crash mid-append) is NOT reported
//     this way - see the class comment on Journal::open() - only a
//     genuinely malformed EARLIER record is.
//   - JournalTamperError: the file is structurally well-formed but its
//     content fails an authenticity check - a broken hash-chain link, a
//     content hash that doesn't match its recomputation, an out-of-order
//     entry index, an invalid state transition, or a checkpoint signature
//     that doesn't verify.
//   - JournalRollbackError: both the main log and the head-pointer file are
//     individually well-formed and internally consistent, but the
//     head-pointer file references a checkpoint further along than
//     anything the main log's replay reaches - i.e. the main log looks like
//     an older copy of itself was substituted back in.
// ---------------------------------------------------------------------------

class JournalFormatError : public std::runtime_error {
public:
    explicit JournalFormatError(const std::string& message) : std::runtime_error(message) {}
};

class JournalTamperError : public std::runtime_error {
public:
    explicit JournalTamperError(const std::string& message) : std::runtime_error(message) {}
};

class JournalRollbackError : public std::runtime_error {
public:
    explicit JournalRollbackError(const std::string& message) : std::runtime_error(message) {}
};

// ---------------------------------------------------------------------------
// Journal
//
// One in-memory handle over (at most) one on-disk journal: a `log_path`
// (append-only, framed records - entries and checkpoints interleaved in
// the order they were written) and a `head_path` (a small file holding only
// the latest checkpoint, atomically tmp-then-rename replaced, mirroring
// keystore.cpp's write_replace_atomic() convention exactly - 0600, fsync,
// same-directory temp file, no cross-process locking).
//
// Honest limits (state these, don't just implement them):
//   - This detects tampering with the copy of the journal an attacker
//     controls. If an attacker can overwrite BOTH log_path and head_path
//     with an older, mutually-consistent pair (e.g. restoring both from the
//     same backup snapshot), this module has no external anchor to detect
//     that - rollback detection here is "the head pointer can't be made to
//     lag behind reality without noticing", not "an external, tamper proof
//     timestamp service". This is the documented "where practical" the
//     phase spec asks for, not a stronger claim.
//   - A torn write (process killed mid-append, so the log's last record is
//     physically incomplete) is tolerated: open() truncates the file back
//     to the last complete record and continues, rather than treating an
//     honest crash as tamper. This is deliberate: crash-safety is the whole
//     point of this module, so a crash mid-write must be a *recoverable*
//     event, not a *fatal* one.
//   - Malformed local-state-transition detection (see open()'s replay) is a
//     coarse, per-trade-id state-machine check mirroring
//     tradep2p::SessionState's legal transitions. It catches "recorded
//     WaitingForPeer then Complete with nothing in between" but is not a
//     full replay of MediatorSession's round/leg logic (this module does
//     not track leg index at all, matching the phase spec's per-entry
//     field list, which lists only "current round").
// ---------------------------------------------------------------------------
class Journal {
public:
    // Opens (creating if absent) the journal at `log_path`/`head_path`.
    // Fully replays and verifies the existing log (if any) against
    // `local_history_public_key` before returning - see the class comment
    // for exactly what is/isn't caught. Throws JournalFormatError /
    // JournalTamperError / JournalRollbackError as appropriate; a
    // successful return means the entire existing chain (if non-empty) is
    // internally consistent and its checkpoints are genuinely signed by the
    // holder of the matching private key.
    [[nodiscard]] static Journal open(const std::string& log_path,
                                      const std::string& head_path,
                                      const Ed25519PublicKey& local_history_public_key);

    // Appends one new entry: computes its hash-chain link, writes it to
    // `log_path` (single `write()` of the fully-framed record, then
    // `fsync()`), and returns the resulting JournalEntry. `fields.timestamp
    // == 0` is replaced with the current wall-clock time before the entry
    // is hashed - so a caller does not have to supply it, but the exact
    // value that was actually hashed is always the one returned.
    JournalEntry append(JournalEntryFields fields);

    // Signs (index, hash) of the CURRENT chain head with
    // `local_history_private_key` and durably records the checkpoint: first
    // appended to `log_path` as a checkpoint record, then written to
    // `head_path` via atomic tmp-then-rename replace. Throws
    // std::logic_error if the journal has no entries yet (nothing to
    // checkpoint).
    void checkpoint(const Ed25519PrivateSeed& local_history_private_key);

    [[nodiscard]] const std::vector<JournalEntry>& entries() const noexcept { return entries_; }

    // The most recently appended entry for `trade_id`, or nullopt if this
    // journal has no entry for it. Used by recovery.hpp's classification
    // logic and by callers reconstructing "what did I last do" for one
    // trade.
    [[nodiscard]] std::optional<JournalEntry> latest_for_trade(const TradeId& trade_id) const;

    Journal(const Journal&) = delete;
    Journal& operator=(const Journal&) = delete;
    // NOT defaulted: log_fd_ is a raw fd, and a defaulted move of a plain
    // int would copy the value into the moved-to object without resetting
    // the moved-from object's copy to -1, causing the moved-from object's
    // destructor to close a descriptor the moved-to object still owns (and
    // may still be using). Both are hand-written to null out the source.
    Journal(Journal&&) noexcept;
    Journal& operator=(Journal&&) noexcept;
    ~Journal();

private:
    Journal() = default;

    std::string log_path_;
    std::string head_path_;
    int log_fd_{-1};
    std::vector<JournalEntry> entries_;
    JournalHash chain_head_{};       // entry_hash of the last entry, or genesis if none
    std::uint64_t last_checkpoint_index_{0};
    bool has_checkpoint_{false};
    // Per-trade last-seen local_state, seeded from open()'s replay and kept
    // up to date by append() - lets a live append() reject an illegal
    // transition immediately, not just detect one already on disk (see the
    // "malformed state transitions" requirement in
    // docs/identity-03-journal-recovery.md).
    std::unordered_map<std::string, SessionState> last_state_by_trade_;
};

} // namespace tradep2p
