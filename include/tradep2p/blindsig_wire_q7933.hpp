#pragma once

// Wire types for the q=7933 BLNS23 reference blind-signature path -
// deliberately a FULL parallel set to blindsig_wire.hpp's q=12289/FALCON
// types, not an extension of them. Two real, structural reasons this
// scheme can't reuse those types directly:
//
//   1. This scheme's signature carries BOTH halves explicitly, {s0,s1}
//      (BlindSigResponse only has a single `s` - FALCON's own wire format
//      only ever sends one compressed value and derives the other
//      implicitly, a size optimization this scheme's own Signature type
//      doesn't make).
//   2. This scheme's own NIZK1 public output field named `b` is a full
//      degree-512 polynomial (the published blinding element B) - it is
//      NOT the same thing as BlindSigAssembledRequest's `rho`, a 32-byte
//      hash salt. Same-shaped structs with a field silently meaning
//      something different is worse than two clearly-separate structs.
//
// Also carries the deferred-signing addition the q12289 path doesn't
// have: Status::Pending (a verified-but-not-yet-operator-signed request)
// plus the ticket_id that goes with it, and a new poll message a client
// sends later to check on / collect a pending ticket's result. See
// blindsig_ticket_store_q7933.hpp for the durable store behind this.
//
// Deliberately reuses BlindSigRequestChunk/BlindSigChunkAssembler
// (blindsig_wire.hpp) AS-IS for chunked reassembly of a submission's raw
// bytes: that type and class are already scheme-agnostic (no FALCON-
// specific fields), so duplicating them here would be pure churn. Only
// the MessageType tag those chunks arrive under, and the final decode
// function that turns assembled bytes into a typed request, differ.

#include "tradep2p/blindsig_wire.hpp" // BlindSigRequestChunk, BlindSigChunkAssembler, kMaxBlindSigRequestBytes

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace tradep2p::blindsig {

constexpr std::size_t kQ7933RingDegree = 512; // matches blns7933::Parameters::degree

// Response to Q7933BlindSigInfoRequest (empty payload, no struct needed) -
// same "enabled=false with fields zeroed means not available here,
// don't distinguish why" convention as BlindSigInfoResponse.
struct Q7933BlindSigInfoResponse {
    bool enabled{false};
    std::array<std::uint16_t, kQ7933RingDegree> t{}; // signer's real public key t = f*g^-1 mod q
    std::array<std::uint16_t, kQ7933RingDegree> b{}; // signer's published blinding element B
};

// What a Q7933BlindSigRequestChunk stream's assembled bytes decode to -
// the real NIZK1 public output shape (see blindsig-prover-q7933's own
// Nizk1PublicOutput) plus the raw STARK receipt bytes, opaque to this
// codec, handed to the sidecar's signer-verify-nizk1 unchanged.
struct Q7933BlindSigAssembledRequest {
    std::array<std::uint16_t, kQ7933RingDegree> c{};
    std::array<std::uint16_t, kQ7933RingDegree> b{};
    std::array<std::uint16_t, kQ7933RingDegree> enc_a{};
    std::array<std::uint16_t, kQ7933RingDegree> enc_pk{};
    std::array<std::uint16_t, kQ7933RingDegree> ct1_r{};
    std::array<std::uint16_t, kQ7933RingDegree> ct2_r{};
    std::array<std::uint16_t, kQ7933RingDegree> ct1_mu{};
    std::array<std::uint16_t, kQ7933RingDegree> ct2_mu{};
    std::vector<std::uint8_t> pi1_receipt;
};

// The mediator's response to a blind-sign request OR a ticket poll -
// both use this same struct/message type, since a client handles the
// result of either identically (see lobby.cpp's dispatch).
struct Q7933BlindSigResponse {
    enum class Status : std::uint8_t { Ok = 0, Rejected = 1, Busy = 2, Error = 3, Pending = 4 };
    Status status{Status::Error};
    std::array<std::int16_t, kQ7933RingDegree> s0{}; // only meaningful when status == Ok
    std::array<std::int16_t, kQ7933RingDegree> s1{}; // only meaningful when status == Ok
    std::array<std::uint8_t, 32> ticket_id{};         // only meaningful when status == Pending
    std::string reason;                                // human-readable, for Rejected/Busy/Error
};

// A client's later request to check on / collect a previously-issued
// ticket - sent on any connection (possibly a fresh one after the
// original disconnected), any time after submission.
struct Q7933BlindSigTicketPoll {
    std::array<std::uint8_t, 32> ticket_id{};
};

std::vector<std::uint8_t> encode_q7933_blindsig_info_response(const Q7933BlindSigInfoResponse& message);
Q7933BlindSigInfoResponse decode_q7933_blindsig_info_response(std::span<const std::uint8_t> bytes);

std::vector<std::uint8_t> encode_q7933_blindsig_response(const Q7933BlindSigResponse& message);
Q7933BlindSigResponse decode_q7933_blindsig_response(std::span<const std::uint8_t> bytes);

std::vector<std::uint8_t> encode_q7933_blindsig_assembled_request(const Q7933BlindSigAssembledRequest& request);
Q7933BlindSigAssembledRequest decode_q7933_blindsig_assembled_request(std::span<const std::uint8_t> bytes);

std::vector<std::uint8_t> encode_q7933_blindsig_ticket_poll(const Q7933BlindSigTicketPoll& message);
Q7933BlindSigTicketPoll decode_q7933_blindsig_ticket_poll(std::span<const std::uint8_t> bytes);

} // namespace tradep2p::blindsig
