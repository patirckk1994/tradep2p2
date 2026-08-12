#pragma once

// Durable, disk-backed storage for pending/signed q=7933 blind-signature
// tickets - the piece that makes deferred, operator-approved signing
// possible: a client's verified-but-unsigned request survives a mediator
// restart while it waits for a human operator to sign it later (e.g. after
// a trade settles), rather than being lost the moment the process exits.
// A real NIZK1 proof costs the client ~11 minutes of genuine work, so
// losing a pending ticket to a restart is a real cost, not a minor
// inconvenience - this is why durability was chosen over an in-memory-only
// design (see specs.txt / the session that scoped this feature).
//
// No direct precedent elsewhere in this codebase (unlike
// blindsig_keystore_q7933.hpp, which mirrors blindsig_keystore.hpp almost
// exactly) - built to the SAME atomic-write discipline as keystore.cpp's
// own write_replace_atomic() (tmp file + fsync + rename, never an in-place
// write), one file per ticket in a directory, named by the ticket's own id.
//
// Deliberately UNENCRYPTED, unlike the keystores: a ticket's `c` is already
// an opaque blinded target by construction (the whole point of blind
// signatures), and a signature is only useful together with the client's
// own never-persisted-here blinding factor - neither field is a secret
// this mediator needs to protect at rest. Atomicity and clean rejection of
// truncated/malformed data are what matter here, not confidentiality.
//
// Deliberately stateless/disk-is-truth: every call re-reads or re-writes
// the filesystem directly rather than maintaining an in-memory index that
// could drift out of sync with what a restarted mediator would see - the
// entire reason this type exists is to survive a restart, so a cache that
// needs reconciling after one would defeat the point.

#include "tradep2p/blindsig_blns7933.hpp"
#include "tradep2p/blindsig_blns7933_sign.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace tradep2p::blindsig {

using TicketId = std::array<std::uint8_t, 32>;

enum class TicketStatus : std::uint8_t { kPending = 0, kSigned = 1 };

struct Ticket {
    TicketId ticket_id{};
    blns7933::PolyQ c;
    std::uint64_t received_at_unix_seconds{0};
    TicketStatus status{TicketStatus::kPending};
    // Populated iff status == kSigned; empty otherwise.
    std::optional<blns7933::Signature> signature;
};

// Thrown by submit() when the store already holds
// max_pending_tickets() entries (pending AND already-signed-but-not-yet-
// collected both count - an unclaimed signed ticket still occupies a slot
// until the client that owns it polls it away via remove()).
class Q7933TicketStoreFullError : public std::runtime_error {
public:
    explicit Q7933TicketStoreFullError(const std::string& message) : std::runtime_error(message) {}
};

// Thrown when an existing ticket file fails to parse (truncated, bad
// magic, wrong degree, etc.) - distinct from "no such ticket", which
// find() reports via std::nullopt rather than an exception, since an
// unknown/expired ticket id is an expected, common case (e.g. a client
// polling with a stale or mistyped id), not a bug or corruption.
class Q7933TicketStoreFormatError : public std::runtime_error {
public:
    explicit Q7933TicketStoreFormatError(const std::string& message) : std::runtime_error(message) {}
};

constexpr std::size_t kDefaultMaxPendingTickets = 256;

class Q7933TicketStore {
public:
    // `directory` is created (including parents) if it does not already
    // exist. Does not scan or validate its contents at construction time -
    // every operation reads/writes disk directly on demand.
    explicit Q7933TicketStore(std::string directory,
                               std::size_t max_pending_tickets = kDefaultMaxPendingTickets);

    // Creates a new kPending ticket for `c` under a fresh, unguessable
    // (32 real random bytes, never sequential) ticket id, and returns
    // that id. Throws Q7933TicketStoreFullError if the store is already at
    // capacity - callers (Phase 3's wire handling) map this to
    // BlindSigResponse::Status::Busy.
    [[nodiscard]] TicketId submit(const blns7933::PolyQ& c);

    // Looks up a ticket by id. Returns std::nullopt if no such ticket file
    // exists (unknown, expired, or already collected-and-removed).
    // Throws Q7933TicketStoreFormatError if the file exists but fails to
    // parse.
    [[nodiscard]] std::optional<Ticket> find(const TicketId& ticket_id) const;

    // Every currently-pending ticket's id, for the operator dashboard's
    // "list pending" view (Phase 5). Already-signed tickets are excluded -
    // an operator only needs to see what still requires a decision.
    [[nodiscard]] std::vector<TicketId> list_pending() const;

    // Transitions a kPending ticket to kSigned in place (atomic replace,
    // same file, same id). Throws std::logic_error if no such ticket
    // exists or it is not currently kPending (signing an unknown or
    // already-signed ticket is a caller bug - lobby.cpp's admin channel is
    // single-threaded, same precedent as the existing fee-confirmation
    // commands, so this is not a normal concurrent race to design around).
    void mark_signed(const TicketId& ticket_id, const blns7933::Signature& signature);

    // Deletes a ticket's file entirely. Called once a client has
    // successfully polled and retrieved a kSigned ticket's result - the
    // ticket has served its purpose. A no-op (not an error) if the ticket
    // does not exist, so a repeated or racing removal is harmless.
    void remove(const TicketId& ticket_id) noexcept;

    [[nodiscard]] const std::string& directory() const noexcept { return directory_; }
    [[nodiscard]] std::size_t max_pending_tickets() const noexcept { return max_pending_tickets_; }

private:
    std::string directory_;
    std::size_t max_pending_tickets_;
};

} // namespace tradep2p::blindsig
