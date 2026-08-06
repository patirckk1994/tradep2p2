#pragma once

// Phase 4 of the optional identity system: a purely local, client-side
// record of previously encountered counterparties - a personal history and
// blocklist. See docs/identity-04-local-history-blocklist.md and
// specs.txt SS2 ("No public lifelong identifier", "No scalar score",
// "No gossip") for the design this implements.
//
// WHAT THIS IS NOT, per the phase spec (repeated here because it is the
// easiest boundary in this whole system to accidentally erode):
//   - not a global or shared reputation score - nothing in this module is
//     ever transmitted anywhere, to a mediator or to anyone else;
//   - not gossip - there is no sync mechanism, no upload path, no
//     aggregation across users. The only cross-machine path this module
//     offers is a manual, operator-initiated file copy of this store's own
//     encrypted file, exactly mirroring the keystore's own
//     export_encrypted_backup()/import_encrypted_backup() posture (copy
//     verbatim encrypted bytes, never decrypt-then-re-encrypt-elsewhere,
//     never automatic);
//   - not evidence to show a counterparty - this is the user's own private
//     judgement about their own past encounters, exactly as unverifiable to
//     a third party as the phase-3 journal entries that may feed it (see
//     journal.hpp's own "what this is not" comment - the same boundary
//     applies here one layer up).
//
// FINGERPRINT SCOPING DECISION (stated here, not just in the phase report,
// so it stays next to the code it governs): every entry in this store is
// keyed by the PAIR (fingerprint, mediator_id), never by fingerprint alone.
// Two encounters bearing the identical 32-byte fingerprint under two
// different mediator_id strings are recorded as two completely independent
// CounterpartyHistoryEntry values and are never merged or cross-referenced.
// This is "per-mediator" scoping, chosen deliberately over "global/stable
// across mediators", for the same reason identity.hpp's key_scope tree
// derives a distinct pseudonym key per mediator (see specs.txt SS4, "Why
// per-mediator pseudonyms"): nothing in this phase - or in phase 5/6, which
// will eventually populate real fingerprints from ephemeral/pseudonym
// public keys - guarantees that "the same fingerprint bytes at mediator X"
// and "the same fingerprint bytes at mediator Y" refer to the same real
// counterparty. Silently merging them into one record would manufacture a
// cross-mediator correlation handle this architecture otherwise goes out of
// its way to avoid (see identity-architecture-report.md's "stable
// identifiers becoming visible where none exist today" risk). FingerprintScope
// is still an explicit stored enum (not an implied constant) so a later
// phase that might deliberately add a second, cross-mediator scope must do
// so as a new, reviewed enumerator - never by silently repurposing this one.
//
// SECURITY INVARIANTS:
//   - Encrypted at rest, consistent with the keystore's approach: the same
//     AEAD primitive keystore.cpp uses (ChaCha20-Poly1305, IETF, 96-bit
//     nonce, 128-bit tag - matching this codebase's TLS 1.3 ciphersuite
//     preference order, per keystore.hpp's own rationale). The AEAD key is
//     NOT itself passphrase-derived here; it is derived via identity.hpp's
//     derive_scoped_key() from the CALLER-SUPPLIED, already-unlocked
//     IdentityKeystore's master secret, under key_scope::kLocalHistory
//     (the same top-level scope label the phase-3 journal's checkpoint
//     SIGNING key uses - HKDF's domain separation via a distinct identifier
//     string keeps the two derivations fully independent even though they
//     share a label; see identity.hpp's encode_derivation_info()). Net
//     effect: this store can only be decrypted by whoever can unlock the
//     matching keystore, and - because the key is deterministically
//     re-derivable from the master secret alone, with no extra salt to
//     manage - a keystore exported and re-imported via
//     IdentityKeystore::export_encrypted_backup()/import_encrypted_backup()
//     lets its owner decrypt this SAME history file again on another
//     machine (after manually copying it there too - see "not gossip"
//     above) without its notes or evidence hashes ever having existed in
//     plaintext during that transport.
//   - Unlike keystore.cpp (which derives a fresh AEAD key from a fresh
//     Argon2id salt on every single write, so nonce reuse under a fixed key
//     never arises by construction), this module's AEAD key is the SAME
//     value across every write of a given history file, because it is
//     re-derived from the same master secret and the same fixed identifier
//     every time. A fresh random 96-bit nonce is therefore generated on
//     every write specifically to avoid nonce reuse under that fixed key.
//     The birthday-bound collision probability at this file's realistic
//     write frequency (interactive, human-paced note/block/encounter edits,
//     bounded by kHistoryMaxEntries) is negligible, but - unlike the
//     keystore's fresh-key-every-time design - it is not structurally zero.
//     This trade-off is deliberate and stated honestly rather than left
//     implicit.
//   - No network calls anywhere in this module. Nothing here includes
//     secure_channel.hpp, dashboard_client.hpp, or any socket header, and
//     nothing here calls out to the mediator or anywhere else - see
//     history_tests.cpp's grep-style check, which is the practical way to
//     keep proving a negative like this true over time.
//   - No automatic disclosure. This module has no "export to mediator" or
//     "share with counterparty" path of any kind. The only way any byte
//     leaves this file is a caller reading an accessor and choosing, on
//     their own initiative, to show something to someone - a decision this
//     module has no path to make on a caller's behalf.
//
// WHAT THIS MODULE MAY BE USED TO DISPLAY (the full list from the phase
// spec, no more): previously encountered, previous successful interaction,
// previous incomplete interaction, locally blocked, unknown identity. See
// classify_for_display() below. This is explicitly NOT converted into a
// score anywhere in this module.

#include "tradep2p/identity.hpp"
#include "tradep2p/keystore.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace tradep2p {

constexpr std::uint16_t kHistoryFormatVersion = 1;
constexpr std::size_t kCounterpartyFingerprintLength = 32;
constexpr std::size_t kHistoryMaxMediatorIdLength = 256;
constexpr std::size_t kHistoryMaxNoteLength = 4096;
constexpr std::size_t kHistoryMaxNotesPerEntry = 256;
constexpr std::size_t kHistoryMaxOutcomesPerEntry = 4096;
constexpr std::size_t kHistoryMaxEvidenceHashesPerEntry = 256;
constexpr std::size_t kHistoryMaxEntries = 4096;

using CounterpartyFingerprint = std::array<std::uint8_t, kCounterpartyFingerprintLength>;
using EvidenceHash = std::array<std::uint8_t, 32>;

// See the file comment above: PerMediator is the only scope this phase
// implements or needs.
enum class FingerprintScope : std::uint8_t {
    PerMediator = 1,
};

enum class LocalOutcome : std::uint8_t {
    Unknown = 0,
    Successful = 1,
    Incomplete = 2,
};

// A coarse, purely local, non-shared descriptive tag about how well-backed
// a record is (e.g. by evidence hashes / repeated encounters) - NOT a trust
// or reputation score about the counterparty (specs.txt SS2/SS11: "No
// scalar score" / structured evidence "must not collapse into a single
// number"). This field describes the RECORD's own evidentiary basis, not a
// ranking of the counterparty against anyone else, and this module never
// aggregates it across entries or presents it as a leaderboard.
enum class ConfidenceLevel : std::uint8_t {
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3,
};

// What a local UI surface (CLI or dashboard) may show for a counterparty -
// exactly the list identity-04-local-history-blocklist.md enumerates, no
// more. See classify_for_display().
enum class DisplayCategory : std::uint8_t {
    UnknownIdentity = 0,
    PreviouslyEncountered = 1,
    PreviousSuccessfulInteraction = 2,
    PreviousIncompleteInteraction = 3,
    LocallyBlocked = 4,
};

// One free-form note the user recorded about a counterparty, timestamped so
// a history of judgement (not just the latest opinion) is preserved rather
// than overwritten.
struct HistoryNote {
    std::uint64_t recorded_at{0};
    std::string text;
};

// One counterparty's full local record, keyed by (fingerprint, mediator_id)
// - see the fingerprint-scoping decision above.
struct CounterpartyHistoryEntry {
    CounterpartyFingerprint fingerprint{};
    FingerprintScope scope{FingerprintScope::PerMediator};
    std::string mediator_id;
    std::uint64_t first_seen{0};
    std::uint64_t last_seen{0};
    std::uint64_t encounter_count{0};
    std::vector<LocalOutcome> outcome_labels;
    bool locally_blocked{false};
    std::vector<HistoryNote> notes;
    std::vector<EvidenceHash> evidence_hashes;
    ConfidenceLevel confidence{ConfidenceLevel::Unknown};
};

// Exceptions, matching keystore.hpp's precedent of distinct types per
// failure class:
//   - HistoryFormatError: the bytes on disk are not a well-formed history
//     store of a version this code understands.
//   - HistoryAuthenticationError: the file is structurally well-formed but
//     the AEAD tag did not verify - in practice this means the file was
//     encrypted under a DIFFERENT keystore's master secret (or has been
//     tampered with), since this module's own key derivation never changes
//     for a given keystore.
class HistoryFormatError : public std::runtime_error {
public:
    explicit HistoryFormatError(const std::string& message) : std::runtime_error(message) {}
};

class HistoryAuthenticationError : public std::runtime_error {
public:
    explicit HistoryAuthenticationError(const std::string& message) : std::runtime_error(message) {}
};

// Classifies an optional lookup result into exactly the display categories
// the phase spec enumerates. `entry` should be the result of find() for the
// counterparty currently being displayed (std::nullopt if never seen).
// Locally-blocked always wins regardless of past outcomes (a caller should
// warn on this before letting an operator proceed). Absent a block, ANY
// recorded Incomplete outcome outranks a Successful one - a defect is worth
// surfacing even if other encounters with the same counterparty went fine,
// which is a deliberately conservative (safety-first) tie-break, not an
// attempt to average outcomes into anything score-like.
[[nodiscard]] DisplayCategory classify_for_display(
    const std::optional<CounterpartyHistoryEntry>& entry);

// Phase 4b presentation helpers (docs/identity-04b-counterparty-
// recognition.md SS"Presentation"): "previously settled with this key (n
// times)" / "previously encountered, never completed (n times)" both need
// an actual count, not just the tie-broken DisplayCategory above. These
// count occurrences in outcome_labels rather than adding new stored
// fields - the split between successful and incomplete encounters already
// exists per-encounter in that vector; these are read-only views over it,
// not a format change. Never aggregated across entries/counterparties by
// any caller - see this file's "what this module may be used to display"
// comment.
[[nodiscard]] std::uint64_t settlement_count(const CounterpartyHistoryEntry& entry);
[[nodiscard]] std::uint64_t incomplete_count(const CounterpartyHistoryEntry& entry);

[[nodiscard]] std::string fingerprint_to_hex(const CounterpartyFingerprint& fingerprint);
[[nodiscard]] CounterpartyFingerprint fingerprint_from_hex(std::string_view text);
[[nodiscard]] std::string evidence_hash_to_hex(const EvidenceHash& hash);
[[nodiscard]] EvidenceHash evidence_hash_from_hex(std::string_view text);
[[nodiscard]] const char* local_outcome_name(LocalOutcome outcome);
[[nodiscard]] const char* confidence_level_name(ConfidenceLevel level);
[[nodiscard]] const char* display_category_name(DisplayCategory category);

// ---------------------------------------------------------------------------
// LocalCounterpartyHistory
//
// One in-memory handle over (at most) one on-disk, AEAD-encrypted history
// store. Every mutating call re-encrypts and atomically rewrites the entire
// file immediately (tmp-then-rename, 0600, fsync - the same discipline
// keystore.cpp/journal.cpp already use) - there is no separate "save()"
// step to forget to call, matching keystore.cpp's write-through-every-
// mutation posture rather than journal.cpp's append-only one, since a
// counterparty record is small, mutated rarely (interactive, human-paced),
// and has no meaningful "append-only" structure of its own to preserve.
// ---------------------------------------------------------------------------
class LocalCounterpartyHistory {
public:
    // Opens (creating an empty store in memory if `path` does not yet exist
    // - the file itself is only actually created on the first mutating
    // call) the history store at `path`, deriving its AEAD key from
    // `keystore`'s currently unlocked master secret. Throws
    // std::logic_error if `keystore` is locked. Throws HistoryFormatError
    // for a malformed file, or HistoryAuthenticationError if the derived
    // key does not open an existing file's AEAD tag (wrong keystore, or a
    // tampered file - the two are indistinguishable by design, mirroring
    // keystore.hpp's own stance on this).
    [[nodiscard]] static LocalCounterpartyHistory open(const std::string& path,
                                                        const IdentityKeystore& keystore);

    // Records one encounter with (fingerprint, mediator_id): creates a new
    // entry (first_seen = now) if this pair is not yet known, otherwise
    // updates last_seen and increments encounter_count. If `outcome` is not
    // LocalOutcome::Unknown, it is appended to outcome_labels and
    // confidence is recomputed (see recompute_confidence() in history.cpp
    // for the honest, non-score heuristic this uses). `now`, if zero, is
    // replaced with the current wall-clock time. Persists immediately.
    // Throws std::invalid_argument if this would exceed kHistoryMaxEntries
    // for a brand new (fingerprint, mediator_id) pair.
    const CounterpartyHistoryEntry& record_encounter(const CounterpartyFingerprint& fingerprint,
                                                      const std::string& mediator_id,
                                                      LocalOutcome outcome = LocalOutcome::Unknown,
                                                      std::uint64_t now = 0);

    // Sets the locally_blocked flag, creating an entry (encounter_count=0)
    // if this pair has never been encountered - a user may pre-emptively
    // block a fingerprint they learned about out-of-band, before ever
    // trading with it. Persists immediately.
    const CounterpartyHistoryEntry& set_blocked(const CounterpartyFingerprint& fingerprint,
                                                 const std::string& mediator_id, bool blocked);

    // Appends a timestamped note, creating an entry if needed (same
    // pre-emptive-record rationale as set_blocked()). Throws
    // std::invalid_argument if `text` exceeds kHistoryMaxNoteLength or the
    // entry already holds kHistoryMaxNotesPerEntry notes. Persists
    // immediately.
    const CounterpartyHistoryEntry& add_note(const CounterpartyFingerprint& fingerprint,
                                              const std::string& mediator_id,
                                              const std::string& text, std::uint64_t now = 0);

    // Appends an evidence hash (e.g. a journal message_hash or a future
    // phase's receipt hash) and recomputes confidence. Creates an entry if
    // needed. Persists immediately.
    const CounterpartyHistoryEntry& add_evidence_hash(const CounterpartyFingerprint& fingerprint,
                                                       const std::string& mediator_id,
                                                       const EvidenceHash& hash);

    [[nodiscard]] std::optional<CounterpartyHistoryEntry> find(
        const CounterpartyFingerprint& fingerprint, const std::string& mediator_id) const;

    [[nodiscard]] const std::vector<CounterpartyHistoryEntry>& entries() const noexcept {
        return entries_;
    }

    LocalCounterpartyHistory(const LocalCounterpartyHistory&) = delete;
    LocalCounterpartyHistory& operator=(const LocalCounterpartyHistory&) = delete;
    LocalCounterpartyHistory(LocalCounterpartyHistory&&) = default;
    LocalCounterpartyHistory& operator=(LocalCounterpartyHistory&&) = default;
    ~LocalCounterpartyHistory() = default;

private:
    LocalCounterpartyHistory() = default;

    [[nodiscard]] std::size_t index_of(const CounterpartyFingerprint& fingerprint,
                                        const std::string& mediator_id) const;
    CounterpartyHistoryEntry& get_or_create(const CounterpartyFingerprint& fingerprint,
                                             const std::string& mediator_id, std::uint64_t now);
    void persist() const;

    std::string path_;
    DerivedKey aead_key_;
    std::vector<CounterpartyHistoryEntry> entries_;
};

} // namespace tradep2p
