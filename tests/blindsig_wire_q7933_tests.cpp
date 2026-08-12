#include "tradep2p/blindsig_wire_q7933.hpp"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>

using tradep2p::blindsig::Q7933BlindSigAssembledRequest;
using tradep2p::blindsig::Q7933BlindSigInfoResponse;
using tradep2p::blindsig::Q7933BlindSigResponse;
using tradep2p::blindsig::Q7933BlindSigTicketPoll;
using tradep2p::blindsig::decode_q7933_blindsig_assembled_request;
using tradep2p::blindsig::decode_q7933_blindsig_info_response;
using tradep2p::blindsig::decode_q7933_blindsig_response;
using tradep2p::blindsig::decode_q7933_blindsig_ticket_poll;
using tradep2p::blindsig::encode_q7933_blindsig_assembled_request;
using tradep2p::blindsig::encode_q7933_blindsig_info_response;
using tradep2p::blindsig::encode_q7933_blindsig_response;
using tradep2p::blindsig::encode_q7933_blindsig_ticket_poll;
using tradep2p::blindsig::kQ7933RingDegree;

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

std::array<std::uint16_t, kQ7933RingDegree> sample_u16_array(std::uint16_t seed) {
    std::array<std::uint16_t, kQ7933RingDegree> result{};
    for (std::size_t i = 0; i < kQ7933RingDegree; ++i) {
        result[i] = static_cast<std::uint16_t>((seed + i * 17U) % 7933U);
    }
    return result;
}

std::array<std::int16_t, kQ7933RingDegree> sample_i16_array(std::int16_t seed) {
    std::array<std::int16_t, kQ7933RingDegree> result{};
    for (std::size_t i = 0; i < kQ7933RingDegree; ++i) {
        result[i] = static_cast<std::int16_t>(((seed + static_cast<int>(i) * 9) % 6001) - 3000);
    }
    return result;
}

void test_info_response_round_trip() {
    Q7933BlindSigInfoResponse message;
    message.enabled = true;
    message.t = sample_u16_array(1);
    message.b = sample_u16_array(2);
    const auto decoded =
        decode_q7933_blindsig_info_response(encode_q7933_blindsig_info_response(message));
    require(decoded.enabled == message.enabled, "q7933 info enabled must round-trip");
    require(decoded.t == message.t, "q7933 info t must round-trip");
    require(decoded.b == message.b, "q7933 info b must round-trip");
}

void test_response_round_trip() {
    const std::array<Q7933BlindSigResponse::Status, 5> statuses = {
        Q7933BlindSigResponse::Status::Ok,
        Q7933BlindSigResponse::Status::Rejected,
        Q7933BlindSigResponse::Status::Busy,
        Q7933BlindSigResponse::Status::Error,
        Q7933BlindSigResponse::Status::Pending,
    };
    for (const auto status : statuses) {
        Q7933BlindSigResponse message;
        message.status = status;
        message.s0 = sample_i16_array(7);
        message.s1 = sample_i16_array(11);
        message.ticket_id.fill(0x5a);
        message.reason = status == Q7933BlindSigResponse::Status::Ok ? "" : "reason";
        const auto decoded =
            decode_q7933_blindsig_response(encode_q7933_blindsig_response(message));
        require(decoded.status == message.status, "q7933 response status must round-trip");
        require(decoded.s0 == message.s0, "q7933 response s0 must round-trip");
        require(decoded.s1 == message.s1, "q7933 response s1 must round-trip");
        require(decoded.ticket_id == message.ticket_id, "q7933 response ticket id must round-trip");
        require(decoded.reason == message.reason, "q7933 response reason must round-trip");
    }
}

void test_response_decode_rejects_invalid_status() {
    Q7933BlindSigResponse message;
    message.status = Q7933BlindSigResponse::Status::Ok;
    auto bytes = encode_q7933_blindsig_response(message);
    bytes[0] = 99;
    require_throws<std::runtime_error>(
        [&] { (void)decode_q7933_blindsig_response(bytes); },
        "q7933 response with an out-of-range status must throw");
}

Q7933BlindSigAssembledRequest sample_request() {
    Q7933BlindSigAssembledRequest request;
    request.c = sample_u16_array(21);
    request.b = sample_u16_array(22);
    request.enc_a = sample_u16_array(23);
    request.enc_pk = sample_u16_array(24);
    request.ct1_r = sample_u16_array(25);
    request.ct2_r = sample_u16_array(26);
    request.ct1_mu = sample_u16_array(27);
    request.ct2_mu = sample_u16_array(28);
    request.pi1_receipt = {1, 2, 3, 4, 5, 6};
    return request;
}

void test_raw_request_round_trip() {
    const auto request = sample_request();
    const auto decoded =
        decode_q7933_blindsig_assembled_request(encode_q7933_blindsig_assembled_request(request));
    require(decoded.c == request.c, "q7933 request c must round-trip");
    require(decoded.b == request.b, "q7933 request b must round-trip");
    require(decoded.enc_a == request.enc_a, "q7933 request enc_a must round-trip");
    require(decoded.enc_pk == request.enc_pk, "q7933 request enc_pk must round-trip");
    require(decoded.ct1_r == request.ct1_r, "q7933 request ct1_r must round-trip");
    require(decoded.ct2_r == request.ct2_r, "q7933 request ct2_r must round-trip");
    require(decoded.ct1_mu == request.ct1_mu, "q7933 request ct1_mu must round-trip");
    require(decoded.ct2_mu == request.ct2_mu, "q7933 request ct2_mu must round-trip");
    require(!decoded.credential_issuance, "raw request must remain raw");
    require(decoded.credential_epoch == 0U, "raw request must have zero epoch");
    require(decoded.pi1_receipt == request.pi1_receipt, "q7933 request receipt must round-trip");
}

void test_credential_request_round_trip() {
    auto request = sample_request();
    request.credential_issuance = true;
    for (std::size_t i = 0; i < request.issuance_room_id.size(); ++i) {
        request.issuance_room_id[i] = static_cast<std::uint8_t>(i + 1U);
    }
    request.credential_epoch = 42U;
    const auto decoded =
        decode_q7933_blindsig_assembled_request(encode_q7933_blindsig_assembled_request(request));
    require(decoded.credential_issuance, "credential request flag must round-trip");
    require(decoded.issuance_room_id == request.issuance_room_id,
            "credential issuance room must round-trip");
    require(decoded.credential_epoch == 42U, "credential epoch must round-trip");
}

void test_raw_request_rejects_credential_metadata() {
    auto request = sample_request();
    auto bytes = encode_q7933_blindsig_assembled_request(request);
    // Eight 512-coefficient u16 arrays = 8192 bytes. The following byte is
    // the credential flag, then 32-byte room id, then 4-byte epoch.
    constexpr std::size_t flag_offset = 8U * kQ7933RingDegree * 2U;
    bytes[flag_offset + 1U] = 0x42U; // nonzero room id while flag stays false
    require_throws<std::runtime_error>(
        [&] { (void)decode_q7933_blindsig_assembled_request(bytes); },
        "raw request must reject credential-only metadata");
}

void test_ticket_poll_round_trip() {
    Q7933BlindSigTicketPoll message;
    message.ticket_id.fill(0xa5);
    const auto decoded =
        decode_q7933_blindsig_ticket_poll(encode_q7933_blindsig_ticket_poll(message));
    require(decoded.ticket_id == message.ticket_id, "q7933 ticket poll id must round-trip");
}

void test_decode_rejects_trailing_bytes() {
    Q7933BlindSigTicketPoll message;
    auto bytes = encode_q7933_blindsig_ticket_poll(message);
    bytes.push_back(0);
    require_throws<std::runtime_error>(
        [&] { (void)decode_q7933_blindsig_ticket_poll(bytes); },
        "q7933 decode with trailing bytes must throw");
}

} // namespace

int main() {
    try {
        test_info_response_round_trip();
        test_response_round_trip();
        test_response_decode_rejects_invalid_status();
        test_raw_request_round_trip();
        test_credential_request_round_trip();
        test_raw_request_rejects_credential_metadata();
        test_ticket_poll_round_trip();
        test_decode_rejects_trailing_bytes();
        std::cout << "q7933 blindsig wire tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
