#pragma once

// Wire types for the experimental post-quantum blind-signature primitive
// (specs.txt SS9.3a). Only ever compiled in under
// TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL (see CMakeLists.txt) - the four
// MessageType tags these correspond to (protocol.hpp's
// BlindSigInfoRequest/BlindSigInfoResponse/BlindSigRequestChunk/
// BlindSigResponse) are reserved unconditionally so the enum's numbering
// never depends on build flags, but everything else about this protocol -
// including these structs - lives only here, in the gated module.
//
// Deliberately a hand-rolled length-prefixed binary codec (Writer/Reader,
// mirroring protocol.cpp's own internal Writer/Reader class - see that
// file - and disclosure.cpp's independent copy of the same pattern for
// signed payloads), NOT JSON: this is the wire format between mediator and
// client, unrelated to the JSON spoken between the C++ process and the
// blindsig-prover sidecar (see blindsig_subprocess.hpp for that).

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace tradep2p::blindsig {

constexpr std::size_t kRingDegree = 512; // matches FALCON-512 / prover-core's N

// Hard cap on an assembled (post-chunk-reassembly) blind-sign request,
// checked BEFORE allocating - same defensive-cap discipline as
// kMaxRegistryNodes/kMaxOpenOffers elsewhere in this codebase. Generous
// headroom above a real NIZK1 receipt's measured size (see
// REVIEW_REQUEST.md / RESEARCH_STATUS.md for the measured figure).
constexpr std::size_t kMaxBlindSigRequestBytes = 16U * 1024U * 1024U;

// Response to BlindSigInfoRequest (empty payload, no struct needed).
// `enabled=false` (with h/b left zeroed) means this mediator was built
// without the experimental feature, or built with it but not opted into
// at runtime - a client should treat those as equivalent "not available
// here", not distinguish between them.
struct BlindSigInfoResponse {
    bool enabled{false};
    std::array<std::uint16_t, kRingDegree> h{}; // signer's real FALCON public key
    std::array<std::uint16_t, kRingDegree> b{}; // signer's published blinding element B
};

// One chunk of a client's blind-sign submission. See
// BlindSigChunkAssembler below for how a signer reassembles a full
// request from a stream of these, and blindsig_signer.cpp for the
// one-in-flight-request-per-connection scope limitation.
struct BlindSigRequestChunk {
    std::uint32_t total_length{0}; // total assembled byte length across all chunks
    std::uint32_t chunk_index{0};  // must arrive in order, 0..total_chunks-1
    std::uint32_t total_chunks{0};
    std::vector<std::uint8_t> data;
};

// The mediator's response to a (fully assembled, verified, signed)
// blind-sign request.
struct BlindSigResponse {
    enum class Status : std::uint8_t { Ok = 0, Rejected = 1, Busy = 2, Error = 3 };
    Status status{Status::Error};
    std::array<std::int16_t, kRingDegree> s{}; // only meaningful when status == Ok
    std::string reason;                        // human-readable, for Rejected/Busy/Error
};

// What a BlindSigRequestChunk stream's assembled bytes decode to: the
// eight public ring/ciphertext arrays plus the raw NIZK1 STARK receipt
// bytes exactly as blindsig-prover's user-prove-nizk1 wrote them (opaque
// to this codec - handed to the sidecar's signer-verify-nizk1 unchanged).
struct BlindSigAssembledRequest {
    std::array<std::uint16_t, kRingDegree> c{};
    std::array<std::uint8_t, 32> rho{};
    std::array<std::uint16_t, kRingDegree> enc_a{};
    std::array<std::uint16_t, kRingDegree> enc_pk{};
    std::array<std::uint16_t, kRingDegree> ct1_r{};
    std::array<std::uint16_t, kRingDegree> ct2_r{};
    std::array<std::uint16_t, kRingDegree> ct1_mu{};
    std::array<std::uint16_t, kRingDegree> ct2_mu{};
    std::vector<std::uint8_t> pi1_receipt;
};

std::vector<std::uint8_t> encode_blindsig_info_response(const BlindSigInfoResponse& message);
BlindSigInfoResponse decode_blindsig_info_response(std::span<const std::uint8_t> bytes);

std::vector<std::uint8_t> encode_blindsig_request_chunk(const BlindSigRequestChunk& message);
BlindSigRequestChunk decode_blindsig_request_chunk(std::span<const std::uint8_t> bytes);

std::vector<std::uint8_t> encode_blindsig_response(const BlindSigResponse& message);
BlindSigResponse decode_blindsig_response(std::span<const std::uint8_t> bytes);

std::vector<std::uint8_t> encode_blindsig_assembled_request(const BlindSigAssembledRequest& request);
BlindSigAssembledRequest decode_blindsig_assembled_request(std::span<const std::uint8_t> bytes);

// Reassembles one connection's BlindSigRequestChunk stream into a
// complete request. One instance per in-flight request (a connection
// gets a fresh assembler per request - no multiplexing, see
// blindsig_signer.cpp). Every failure mode throws std::runtime_error with
// a specific reason - a hostile or buggy peer's chunk stream must never
// be able to bypass kMaxBlindSigRequestBytes or corrupt the reassembly.
class BlindSigChunkAssembler {
public:
    // Returns true once the final chunk has been accepted, at which point
    // assembled_bytes() holds the complete request and this assembler
    // must not be reused. Throws on: total_length exceeding
    // kMaxBlindSigRequestBytes; a chunk whose total_length/total_chunks
    // disagree with the first chunk seen; an out-of-order chunk_index;
    // more data arriving after total_length bytes have already been
    // collected; a call after completion.
    bool add_chunk(const BlindSigRequestChunk& chunk);

    [[nodiscard]] const std::vector<std::uint8_t>& assembled_bytes() const { return buffer_; }

private:
    std::vector<std::uint8_t> buffer_;
    std::uint32_t expected_total_length_{0};
    std::uint32_t expected_total_chunks_{0};
    std::uint32_t next_chunk_index_{0};
    bool started_{false};
    bool complete_{false};
};

} // namespace tradep2p::blindsig
