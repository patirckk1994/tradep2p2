#pragma once

// Phase 3 of the optional identity system (mediator half): durable,
// restart-surviving storage for the mediator's in-flight room/round state.
// See docs/identity-03-journal-recovery.md ("Mediator-side room
// persistence") and specs.txt SS5 ("Recovery and the persistence
// trade-off") for the design this implements, and the phase report for the
// chosen option restated in full.
//
// THE PRIVACY DECISION THIS FILE IMPLEMENTS (stated here, not just in the
// report, so it stays next to the code it governs):
//
// Today, LobbyServer::Impl's `rooms_` map lives only in process memory - a
// mediator that is seized, subpoenaed, or simply crashes has nothing on
// disk about past or in-flight rooms. That is an ACCIDENTAL privacy
// property, not a designed one, but it is real: no durable file anywhere
// links two counterparties' receive addresses together. Recovery requires
// giving that up to some degree, because the whole point is to survive a
// restart with enough state to answer a recovery request truthfully.
//
// This module implements ranked option 1 from the phase spec: persist the
// room's STATE MACHINE - party client ids, terms, fee, round/leg progress,
// abort reason - but NEVER the two parties' receive addresses. A mediator
// restart therefore recovers "who was in this room and how far did it get",
// which is enough to answer RecoveryStateResponse truthfully and enough to
// know a completed/aborted room should stay gone, but NOT enough to
// silently keep coordinating fund transfers to specific addresses without
// each party re-supplying its own address again first. This was chosen
// over the alternatives because: encrypting full state at rest (option 2)
// still creates a durable ciphertext blob binding both addresses together
// for as long as the operator holds the decryption key, which is a strictly
// larger, longer-lived linkage artifact than this module ever creates, for
// a mediator that does get compromised; and deleting aggressively on
// completion alone (option 3) does not help the exact case this phase
// exists for - a crash WHILE a room is still open - so it was folded in
// only as a supplement (see below), not the primary mechanism.
//
// One deliberate addition beyond the letter of option 1: a persisted room
// is pruned (not just left to go stale) the moment it reaches
// SessionState::Complete or SessionState::Aborted, since there is no
// recovery value left in a room nobody can resume - keeping it around
// would be pure unnecessary retained exposure. This is a light application
// of option 3's spirit layered on top of option 1's primary mechanism, not
// a replacement for it.
//
// What this module deliberately does NOT do: reconnect a live client
// connection to a recovered room, or re-solicit a fresh receive address
// from a reconnecting client. Building that safely (assigning a brand-new,
// unrelated post-restart ClientId to the correct original party slot
// without letting an impersonator race a legitimate party for it) is a
// materially different, larger change to LobbyServer::Impl's concurrency
// model than this phase's mechanical registration process covers - see the
// phase report for the honest limitation this leaves.

#include "tradep2p/mediator.hpp" // SessionState
#include "tradep2p/protocol.hpp" // RoomId, ClientId, TradeTerms, FeeTerms

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace tradep2p {

constexpr std::uint16_t kPersistedRoomFormatVersion = 1;

// Everything the mediator needs to reconstruct one room's MediatorSession
// (via MediatorSession::restore()) after a restart - minus the two receive
// addresses, per the privacy decision above.
struct PersistedRoom {
    RoomId room_id{};
    ClientId party_a{};
    ClientId party_b{};
    TradeTerms terms;
    FeeTerms fee;
    SessionState state{SessionState::WaitingForPeer};
    std::uint32_t round_index{0};
    std::uint8_t leg_index{0};
    std::string abort_reason; // only meaningful when state == Aborted
    std::uint64_t updated_at{0}; // unix seconds; operator-visible bookkeeping only
};

struct PersistedRoomFile {
    std::uint16_t format_version{kPersistedRoomFormatVersion};
    std::vector<PersistedRoom> rooms;
};

// Thrown by decode_persisted_rooms()/load_persisted_rooms() for a
// structurally malformed file (bad magic, unsupported version, truncated
// field). This file is not an AEAD-authenticated format like
// keystore.hpp's (it holds no secret key material - only room metadata,
// which is why it needs confidentiality via file permissions rather than
// encryption at rest), so there is no separate "authentication failure"
// exception type the way keystore.hpp has one.
class PersistenceFormatError : public std::runtime_error {
public:
    explicit PersistenceFormatError(const std::string& message) : std::runtime_error(message) {}
};

[[nodiscard]] std::vector<std::uint8_t> encode_persisted_rooms(const PersistedRoomFile& file);
[[nodiscard]] PersistedRoomFile decode_persisted_rooms(std::span<const std::uint8_t> bytes);

// Atomic, 0600-permissioned, fsync'd tmp-then-rename write - the same
// discipline keystore.cpp's write_replace_atomic() and journal.cpp's
// write_replace_atomic() use, so a crash mid-write never corrupts the
// previous, still-good copy of this file (the rename is the only step that
// ever touches the real path).
void write_persisted_rooms(const std::string& path, const PersistedRoomFile& file);

// Reads and decodes `path`. Returns an empty PersistedRoomFile{} if `path`
// does not exist (first run, or persistence was only just enabled) - that
// is the ONLY circumstance treated as "nothing to report" rather than an
// error; a present-but-malformed file always throws PersistenceFormatError,
// never silently falls back to "no rooms".
[[nodiscard]] PersistedRoomFile load_persisted_rooms(const std::string& path);

} // namespace tradep2p
