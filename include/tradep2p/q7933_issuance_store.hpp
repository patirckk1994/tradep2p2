#pragma once

// Durable server-side storage for credential issuance uniqueness.
//
// Enforces the one-per-room/party/epoch constraint by tracking which
// (room_id, party, epoch) combinations have already exercised their blind
// credential issuance right.
//
// Issuance records are UNENCRYPTED: the mediator is allowed to know which
// rooms have claimed their issuance. No credential serial, blinded message,
// signature, or other client secret is stored here.
//
// Records are immutable one-shot markers. Creation uses O_CREAT|O_EXCL on
// the FINAL path rather than a check-then-rename sequence: the filesystem is
// therefore the serialization point when two workers race to claim the same
// room/party/epoch. The winner fsyncs the complete record; the loser gets
// EEXIST and is rejected. A crash during the winner's write fails closed: a
// truncated marker remains "used" and is reported as corrupt rather than
// silently allowing a second credential to be issued.
//
// Deliberately disk-is-truth like the q7933 ticket store: every call reads
// the filesystem directly, so restart recovery does not depend on rebuilding
// an in-memory index.

#include "tradep2p/q7933_credential.hpp"

#include <stdexcept>
#include <string>

namespace tradep2p::q7933_credential {

class IssuanceStoreError : public std::runtime_error {
public:
    explicit IssuanceStoreError(const std::string& message) : std::runtime_error(message) {}
};

class IssuanceStoreFormatError : public std::runtime_error {
public:
    explicit IssuanceStoreFormatError(const std::string& message) : std::runtime_error(message) {}
};

class IssuanceStore {
public:
    // `directory` is created (including parents) if it does not exist.
    explicit IssuanceStore(std::string directory);

    IssuanceStore(const IssuanceStore&) = delete;
    IssuanceStore& operator=(const IssuanceStore&) = delete;

    // Atomically claim this issuance context. Exactly one concurrent caller
    // can receive true for a previously-unused context; every later caller
    // receives false. Throws on I/O failure.
    [[nodiscard]] bool record_issuance(const IssuanceContext& context);

    // Returns true only for a present, well-formed marker matching `context`.
    // A malformed/truncated marker throws rather than being treated as free.
    [[nodiscard]] bool has_been_issued(const IssuanceContext& context) const;

    // Roll back a marker after a LOCAL failure that occurred before any
    // pending ticket could be durably created. This is deliberately narrow:
    // callers must never use it to make an already-issued credential
    // reissuable. Best-effort/noexcept so an error path cannot mask the
    // original ticket-store failure.
    void rollback_uncommitted_issuance(const IssuanceContext& context) noexcept;

    [[nodiscard]] const std::string& directory() const noexcept { return directory_; }

private:
    [[nodiscard]] std::string compute_record_path(const IssuanceContext& context) const;

    std::string directory_;
};

} // namespace tradep2p::q7933_credential
