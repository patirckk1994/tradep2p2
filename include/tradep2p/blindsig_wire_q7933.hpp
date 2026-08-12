#pragma once

// Wire types for the q=7933 BLNS23 reference blind-signature path -
// deliberately parallel to blindsig_wire.hpp's q=12289/FALCON types.
//
// The q7933 request also carries OPTIONAL credential-issuance authorization
// metadata. This metadata is intentionally OUTSIDE the blinded message: the
// mediator may know which completed room/party is exercising its one-time
// issuance right, but the credential's random serial and payload remain
// inside `mu` and therefore hidden by the blind-signature protocol.
//
// A credential request carries the mediator-signed stage-4 completion
// receipt plus a hybrid proof of possession of one party's per-room
// ephemeral key, bound to the exact blinded target `c`. The client never
// names Party A/B; the mediator derives that by verification against the two
// public keys embedded in its own completion receipt. This remains usable
// after the completed room has been pruned from live mediator state.
//
// `credential_issuance == false` preserves the raw experimental primitive
// path used by research/demo callers. It receives no one-per-room guarantee
// and must never be advertised as a replay-protected trade credential.

#include "tradep2p/blindsig_wire.hpp"
#include "tradep2p/protocol.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace tradep2p::blindsig {

constexpr std::size_t kQ7933RingDegree = 512;

struct Q7933BlindSigInfoResponse {
    bool enabled{false};
    std::array<std::uint16_t, kQ7933RingDegree> t{};
    std::array<std::uint16_t, kQ7933RingDegree> b{};
};

struct Q7933BlindSigAssembledRequest {
    std::array<std::uint16_t, kQ7933RingDegree> c{};
    std::array<std::uint16_t, kQ7933RingDegree> b{};
    std::array<std::uint16_t, kQ7933RingDegree> enc_a{};
    std::array<std::uint16_t, kQ7933RingDegree> enc_pk{};
    std::array<std::uint16_t, kQ7933RingDegree> ct1_r{};
    std::array<std::uint16_t, kQ7933RingDegree> ct2_r{};
    std::array<std::uint16_t, kQ7933RingDegree> ct1_mu{};
    std::array<std::uint16_t, kQ7933RingDegree> ct2_mu{};

    // Clear authorization metadata for the credential layer. Room+epoch are
    // not credential contents; they only identify which one-shot issuance
    // right is being exercised. Party is deliberately absent.
    bool credential_issuance{false};
    std::array<std::uint8_t, 32> issuance_room_id{};
    std::uint32_t credential_epoch{0};

    // Present only when credential_issuance=true. The receipt is the normal
    // protocol ReceiptIssued encoding for the completed stage-4 receipt.
    // The two signatures prove possession of whichever party's ephemeral
    // key matches that receipt, over a domain-separated payload containing
    // room, epoch, receipt hash and this request's exact `c`.
    std::vector<std::uint8_t> issuance_completion_receipt;
    std::array<std::uint8_t, kReceiptSignatureLength> issuance_authorization_signature{};
    std::array<std::uint8_t, kReceiptSignatureLengthMlDsa65>
        issuance_authorization_signature_mldsa65{};

    std::vector<std::uint8_t> pi1_receipt;
};

struct Q7933BlindSigResponse {
    enum class Status : std::uint8_t { Ok = 0, Rejected = 1, Busy = 2, Error = 3, Pending = 4 };
    Status status{Status::Error};
    std::array<std::int16_t, kQ7933RingDegree> s0{};
    std::array<std::int16_t, kQ7933RingDegree> s1{};
    std::array<std::uint8_t, 32> ticket_id{};
    std::string reason;
};

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
