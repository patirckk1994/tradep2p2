#include "tradep2p/blindsig_wire.hpp"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using tradep2p::blindsig::BlindSigAssembledRequest;
using tradep2p::blindsig::BlindSigChunkAssembler;
using tradep2p::blindsig::BlindSigInfoResponse;
using tradep2p::blindsig::BlindSigRequestChunk;
using tradep2p::blindsig::BlindSigResponse;
using tradep2p::blindsig::decode_blindsig_assembled_request;
using tradep2p::blindsig::decode_blindsig_info_response;
using tradep2p::blindsig::decode_blindsig_request_chunk;
using tradep2p::blindsig::decode_blindsig_response;
using tradep2p::blindsig::encode_blindsig_assembled_request;
using tradep2p::blindsig::encode_blindsig_info_response;
using tradep2p::blindsig::encode_blindsig_request_chunk;
using tradep2p::blindsig::encode_blindsig_response;
using tradep2p::blindsig::kMaxBlindSigRequestBytes;
using tradep2p::blindsig::kRingDegree;

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <typename ExceptionT, typename Fn>
void require_throws(Fn&& fn, const std::string& message) {
    try {
        fn();
    } catch (const ExceptionT&) {
        return;
    } catch (const std::exception& error) {
        throw std::runtime_error(message + " (wrong exception type thrown: " + error.what() + ")");
    }
    throw std::runtime_error(message + " (no exception thrown)");
}

std::array<std::uint16_t, kRingDegree> sample_u16_array(std::uint16_t seed) {
    std::array<std::uint16_t, kRingDegree> result{};
    for (std::size_t i = 0; i < kRingDegree; ++i) {
        result[i] = static_cast<std::uint16_t>((seed + i * 37U) % 12289U);
    }
    return result;
}

std::array<std::int16_t, kRingDegree> sample_i16_array(std::int16_t seed) {
    std::array<std::int16_t, kRingDegree> result{};
    for (std::size_t i = 0; i < kRingDegree; ++i) {
        result[i] = static_cast<std::int16_t>(((seed + static_cast<int>(i) * 13) % 4001) - 2000);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Round-trip encode/decode for every message type.
// ---------------------------------------------------------------------------

void test_info_response_round_trip() {
    for (const bool enabled : {true, false}) {
        BlindSigInfoResponse message;
        message.enabled = enabled;
        message.h = sample_u16_array(1);
        message.b = sample_u16_array(2);

        const auto decoded = decode_blindsig_info_response(encode_blindsig_info_response(message));
        require(decoded.enabled == message.enabled, "BlindSigInfoResponse.enabled must round-trip");
        require(decoded.h == message.h, "BlindSigInfoResponse.h must round-trip");
        require(decoded.b == message.b, "BlindSigInfoResponse.b must round-trip");
    }
}

void test_request_chunk_round_trip() {
    BlindSigRequestChunk message;
    message.total_length = 9000;
    message.chunk_index = 2;
    message.total_chunks = 5;
    message.data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    const auto decoded = decode_blindsig_request_chunk(encode_blindsig_request_chunk(message));
    require(decoded.total_length == message.total_length, "chunk total_length must round-trip");
    require(decoded.chunk_index == message.chunk_index, "chunk chunk_index must round-trip");
    require(decoded.total_chunks == message.total_chunks, "chunk total_chunks must round-trip");
    require(decoded.data == message.data, "chunk data must round-trip");
}

void test_request_chunk_encode_rejects_oversized_data() {
    BlindSigRequestChunk message;
    message.total_length = kMaxBlindSigRequestBytes + 1U;
    message.chunk_index = 0;
    message.total_chunks = 1;
    message.data.resize(kMaxBlindSigRequestBytes + 1U);

    require_throws<std::invalid_argument>(
        [&] { (void)encode_blindsig_request_chunk(message); },
        "encoding a chunk whose data exceeds kMaxBlindSigRequestBytes must throw");
}

void test_response_round_trip() {
    const std::array<BlindSigResponse::Status, 4> statuses = {
        BlindSigResponse::Status::Ok, BlindSigResponse::Status::Rejected,
        BlindSigResponse::Status::Busy, BlindSigResponse::Status::Error};
    for (const auto status : statuses) {
        BlindSigResponse message;
        message.status = status;
        message.s = sample_i16_array(3);
        message.reason = status == BlindSigResponse::Status::Ok ? "" : "some human-readable reason";

        const auto decoded = decode_blindsig_response(encode_blindsig_response(message));
        require(decoded.status == message.status, "BlindSigResponse.status must round-trip");
        require(decoded.s == message.s, "BlindSigResponse.s must round-trip");
        require(decoded.reason == message.reason, "BlindSigResponse.reason must round-trip");
    }
}

void test_response_decode_rejects_invalid_status() {
    BlindSigResponse message;
    message.status = BlindSigResponse::Status::Ok;
    message.s = sample_i16_array(4);
    message.reason = "";
    auto bytes = encode_blindsig_response(message);
    bytes[0] = 99; // past Status::Error - the encoded status byte is always first

    require_throws<std::runtime_error>(
        [&] { (void)decode_blindsig_response(bytes); },
        "decoding a BlindSigResponse with an out-of-range status byte must throw");
}

void test_assembled_request_round_trip() {
    BlindSigAssembledRequest request;
    request.c = sample_u16_array(10);
    request.rho.fill(0xAB);
    request.enc_a = sample_u16_array(11);
    request.enc_pk = sample_u16_array(12);
    request.ct1_r = sample_u16_array(13);
    request.ct2_r = sample_u16_array(14);
    request.ct1_mu = sample_u16_array(15);
    request.ct2_mu = sample_u16_array(16);
    request.pi1_receipt = {9, 9, 9, 8, 8, 8, 7};

    const auto decoded =
        decode_blindsig_assembled_request(encode_blindsig_assembled_request(request));
    require(decoded.c == request.c, "assembled request c must round-trip");
    require(decoded.rho == request.rho, "assembled request rho must round-trip");
    require(decoded.enc_a == request.enc_a, "assembled request enc_a must round-trip");
    require(decoded.enc_pk == request.enc_pk, "assembled request enc_pk must round-trip");
    require(decoded.ct1_r == request.ct1_r, "assembled request ct1_r must round-trip");
    require(decoded.ct2_r == request.ct2_r, "assembled request ct2_r must round-trip");
    require(decoded.ct1_mu == request.ct1_mu, "assembled request ct1_mu must round-trip");
    require(decoded.ct2_mu == request.ct2_mu, "assembled request ct2_mu must round-trip");
    require(decoded.pi1_receipt == request.pi1_receipt, "assembled request pi1_receipt must round-trip");
}

void test_decode_rejects_trailing_bytes() {
    BlindSigInfoResponse message;
    message.enabled = true;
    message.h = sample_u16_array(20);
    message.b = sample_u16_array(21);
    auto bytes = encode_blindsig_info_response(message);
    bytes.push_back(0);

    require_throws<std::runtime_error>(
        [&] { (void)decode_blindsig_info_response(bytes); },
        "decoding a message with trailing bytes must throw (require_finished)");
}

void test_decode_rejects_truncated_input() {
    BlindSigInfoResponse message;
    message.enabled = true;
    message.h = sample_u16_array(22);
    message.b = sample_u16_array(23);
    auto bytes = encode_blindsig_info_response(message);
    bytes.resize(bytes.size() - 1U);

    require_throws<std::runtime_error>(
        [&] { (void)decode_blindsig_info_response(bytes); },
        "decoding a truncated message must throw");
}

// ---------------------------------------------------------------------------
// BlindSigChunkAssembler
// ---------------------------------------------------------------------------

BlindSigRequestChunk make_chunk(std::uint32_t total_length, std::uint32_t chunk_index,
                                 std::uint32_t total_chunks, std::vector<std::uint8_t> data) {
    BlindSigRequestChunk chunk;
    chunk.total_length = total_length;
    chunk.chunk_index = chunk_index;
    chunk.total_chunks = total_chunks;
    chunk.data = std::move(data);
    return chunk;
}

void test_assembler_single_chunk() {
    BlindSigChunkAssembler assembler;
    const std::vector<std::uint8_t> data = {1, 2, 3, 4};
    const bool complete = assembler.add_chunk(make_chunk(4, 0, 1, data));
    require(complete, "a single chunk covering the whole declared length must complete assembly");
    require(assembler.assembled_bytes() == data, "assembled_bytes() must match the single chunk's data");
}

void test_assembler_multi_chunk_happy_path() {
    BlindSigChunkAssembler assembler;
    require(!assembler.add_chunk(make_chunk(9, 0, 3, {1, 2, 3})),
            "an earlier chunk must not report completion");
    require(!assembler.add_chunk(make_chunk(9, 1, 3, {4, 5, 6})),
            "a middle chunk must not report completion");
    require(assembler.add_chunk(make_chunk(9, 2, 3, {7, 8, 9})),
            "the final chunk must report completion");
    const std::vector<std::uint8_t> expected = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    require(assembler.assembled_bytes() == expected, "assembled bytes must be the concatenation in order");
}

void test_assembler_rejects_oversized_total_length() {
    BlindSigChunkAssembler assembler;
    require_throws<std::runtime_error>(
        [&] {
            (void)assembler.add_chunk(
                make_chunk(static_cast<std::uint32_t>(kMaxBlindSigRequestBytes) + 1U, 0, 1, {1}));
        },
        "a declared total_length above kMaxBlindSigRequestBytes must be rejected before allocating");
}

void test_assembler_rejects_zero_total_chunks() {
    BlindSigChunkAssembler assembler;
    require_throws<std::runtime_error>(
        [&] { (void)assembler.add_chunk(make_chunk(4, 0, 0, {1, 2, 3, 4})); },
        "total_chunks == 0 must be rejected");
}

void test_assembler_rejects_total_length_change_mid_stream() {
    BlindSigChunkAssembler assembler;
    require(!assembler.add_chunk(make_chunk(9, 0, 3, {1, 2, 3})), "first chunk should not complete");
    require_throws<std::runtime_error>(
        [&] { (void)assembler.add_chunk(make_chunk(10, 1, 3, {4, 5, 6})); },
        "a chunk changing total_length mid-stream must be rejected");
}

void test_assembler_rejects_total_chunks_change_mid_stream() {
    BlindSigChunkAssembler assembler;
    require(!assembler.add_chunk(make_chunk(9, 0, 3, {1, 2, 3})), "first chunk should not complete");
    require_throws<std::runtime_error>(
        [&] { (void)assembler.add_chunk(make_chunk(9, 1, 4, {4, 5, 6})); },
        "a chunk changing total_chunks mid-stream must be rejected");
}

void test_assembler_rejects_out_of_order_chunk() {
    BlindSigChunkAssembler assembler;
    require(!assembler.add_chunk(make_chunk(9, 0, 3, {1, 2, 3})), "first chunk should not complete");
    require_throws<std::runtime_error>(
        [&] { (void)assembler.add_chunk(make_chunk(9, 2, 3, {7, 8, 9})); },
        "a chunk arriving out of order (skipping index 1) must be rejected");
}

void test_assembler_rejects_overflow_past_declared_total_length() {
    BlindSigChunkAssembler assembler;
    require(!assembler.add_chunk(make_chunk(5, 0, 2, {1, 2, 3})), "first chunk should not complete");
    require_throws<std::runtime_error>(
        [&] { (void)assembler.add_chunk(make_chunk(5, 1, 2, {4, 5, 6})); },
        "a chunk stream exceeding its own declared total_length must be rejected, "
        "even on what claims to be the final chunk");
}

void test_assembler_rejects_short_final_chunk() {
    // Declares 3 chunks totalling 10 bytes, but the stream only ever
    // delivers 9 - the final chunk_index is reached without reaching
    // expected_total_length_, which must not be silently accepted as done.
    BlindSigChunkAssembler assembler;
    require(!assembler.add_chunk(make_chunk(10, 0, 3, {1, 2, 3})), "first chunk should not complete");
    require(!assembler.add_chunk(make_chunk(10, 1, 3, {4, 5, 6})), "second chunk should not complete");
    require_throws<std::runtime_error>(
        [&] { (void)assembler.add_chunk(make_chunk(10, 2, 3, {7, 8, 9})); },
        "reaching the declared final chunk_index without reaching declared total_length must be rejected");
}

void test_assembler_rejects_reuse_after_completion() {
    BlindSigChunkAssembler assembler;
    require(assembler.add_chunk(make_chunk(3, 0, 1, {1, 2, 3})), "single chunk must complete assembly");
    require_throws<std::runtime_error>(
        [&] { (void)assembler.add_chunk(make_chunk(3, 0, 1, {1, 2, 3})); },
        "add_chunk() after completion must be rejected, not silently restart a new request");
}

} // namespace

int main() {
    try {
        test_info_response_round_trip();
        test_request_chunk_round_trip();
        test_request_chunk_encode_rejects_oversized_data();
        test_response_round_trip();
        test_response_decode_rejects_invalid_status();
        test_assembled_request_round_trip();
        test_decode_rejects_trailing_bytes();
        test_decode_rejects_truncated_input();

        test_assembler_single_chunk();
        test_assembler_multi_chunk_happy_path();
        test_assembler_rejects_oversized_total_length();
        test_assembler_rejects_zero_total_chunks();
        test_assembler_rejects_total_length_change_mid_stream();
        test_assembler_rejects_total_chunks_change_mid_stream();
        test_assembler_rejects_out_of_order_chunk();
        test_assembler_rejects_overflow_past_declared_total_length();
        test_assembler_rejects_short_final_chunk();
        test_assembler_rejects_reuse_after_completion();

        std::cout << "blindsig wire unit tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "blindsig wire test failure: " << error.what() << '\n';
        return 1;
    }
}
