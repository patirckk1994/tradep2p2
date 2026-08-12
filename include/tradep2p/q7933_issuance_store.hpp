#pragma once

// Durable server-side storage for credential issuance uniqueness.
//
// Enforces the one-per-room/party/epoch constraint by tracking which
// (room_id, party, epoch) combinations have already issued a credential.
// Uses the same atomic-write discipline as blindsig_ticket_store_q7933.hpp:
// tmp file + fsync + rename, never in-place writes.
//
// Issuance records are UNENCRYPTED: the mediator is allowed to know which
// rooms have claimed their issuance. No secret material is stored here.
// Atomicity and clean rejection of corrupted data are what matter.
//
// Deliberately disk-is-truth like the ticket store: every call re-reads
// or re-writes the filesystem directly, no in-memory cache that needs
// reconciliation. This is necessary for recovery across restarts.

#include "tradep2p/q7933_credential.hpp"

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace tradep2p::q7933_credential {

// Thrown when storage is full or other unrecoverable error occurs.
class IssuanceStoreError : public std::runtime_error {
public:
    explicit IssuanceStoreError(const std::string& message) : std::runtime_error(message) {}
};

// Thrown when a file exists but fails to parse.
class IssuanceStoreFormatError : public std::runtime_error {
public:
    explicit IssuanceStoreFormatError(const std::string& message) : std::runtime_error(message) {}
};

class IssuanceStore {
public:
    // `directory` is created (including parents) if it does not exist.
    // Does not scan or validate at construction.
    explicit IssuanceStore(std::string directory);

    IssuanceStore(const IssuanceStore&) = delete;
    IssuanceStore& operator=(const IssuanceStore&) = delete;

    // Record that a credential was issued for this (room, party, epoch).
    // Returns true if this is the FIRST issuance (allowed).
    // Returns false if a previous issuance already exists (reject duplicate).
    // Throws IssuanceStoreError on unrecoverable I/O errors.
    [[nodiscard]] bool record_issuance(const IssuanceContext& context);

    // Check if a credential has already been issued without recording.
    // Returns true if already issued, false if this is new.
    // Throws IssuanceStoreFormatError if an existing record is corrupt.
    [[nodiscard]] bool has_been_issued(const IssuanceContext& context) const;

    [[nodiscard]] const std::string& directory() const noexcept { return directory_; }

private:
    std::string compute_record_path(const IssuanceContext& context) const;

    std::string directory_;
};

} // namespace tradep2p::q7933_credential
