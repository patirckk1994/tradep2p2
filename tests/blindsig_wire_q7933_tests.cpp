#include "tradep2p/blindsig_wire_q7933.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

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

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <typename F>
void require_throws(F&& f, const char* message) {
    bool threw = false;
    try {
        f();
    } catch (const std::exception&) {
        threw = true;
    }
    require(threw, message);
}

std::array<std::uint16_t, kQ7933RingDegree> poly_fixture(std::uint16_t offset) {
    std::array<std::uint16_t, kQ7933RingDegree> out{};
    for (std::size_t i = 0U; i < out.size(); ++i) {
        out[i] = static_cast<std::uint16_t>((static_cast<std::uint32_t>(offset) +
                                             static_cast<std::uint32_t>(17U * i)) %
                                            7933U);
    }
    return out;
}

void test_info_roundtrip() {
    Q7933BlindSigInfoResponse message;
    message.enabled = true;
    message.t = poly_fixture(11U);
    message.b = poly_fixture(29U);

    const auto decoded = decode_q7933_blindsig_info_response(
        encode_q7933_blindsig_info_response(message));
    require(decoded.enabled, "q7933 info enabled flag did not round-trip");
    require(decoded.t == message.t, "q7933 info t did not round-trip");
    require(decoded.b == message.b, "q7933 info B did not round-trip");
}

void test_pending_and_ok_response_roundtrip() {
    Q7933BlindSigResponse pending;
    pending.status = Q7933BlindSigResponse::Status::Pending;
    for (std::size_t i = 0U; i < pending.ticket_id.size(); ++i) {
        pending.ticket_id[i] = static_cast<std::uint8_t>(i + 1U);
    }
    const auto pending_decoded = decode_q7933_blindsig_response(
        encode_q7933_blindsig_response(pending));
    require(pending_decoded.status == Q7933BlindSigResponse::Status::Pending,
            "q7933 pending status did not round-trip");
    require(pending_decoded.ticket_id == pending.ticket_id,
            "q7933 pending ticket id did not round-trip");

    Q7933BlindSigResponse ok;
    ok.status = Q7933BlindSigResponse::Status::Ok;
    for (std::size_t i = 0U; i < kQ7933RingDegree; ++i) {
        ok.s0[i] = static_cast<std::int16_t>((static_cast<int>(i) % 101) - 50);
        ok.s1[i] = static_cast<std::int16_t>(50 - (static_cast<int>(i) % 101));
    }
    const auto ok_decoded = decode_q7933_blindsig_response(
        encode_q7933_blindsig_response(ok));
    require(ok_decoded.status == Q7933BlindSigResponse::Status::Ok,
            "q7933 ok status did not round-trip");
    require(ok_decoded.s0 == ok.s0 && ok_decoded.s1 == ok.s1,
            "q7933 signature halves did not round-trip");
}

void test_assembled_request_roundtrip() {
    Q7933BlindSigAssembledRequest request;
    request.c = poly_fixture(1U);
    request.b = poly_fixture(2U);
    request.enc_a = poly_fixture(3U);
    request.enc_pk = poly_fixture(4U);
    request.ct1_r = poly_fixture(5U);
    request.ct2_r = poly_fixture(6U);
    request.ct1_mu = poly_fixture(7U);
    request.ct2_mu = poly_fixture(8U);
    request.pi1_receipt = {0x01U, 0x02U, 0x7fU, 0x80U, 0xffU};

    const auto decoded = decode_q7933_blindsig_assembled_request(
        encode_q7933_blindsig_assembled_request(request));
    require(decoded.c == request.c && decoded.b == request.b,
            "q7933 assembled c/B did not round-trip");
    require(decoded.enc_a == request.enc_a && decoded.enc_pk == request.enc_pk,
            "q7933 assembled encryption parameters did not round-trip");
    require(decoded.ct1_r == request.ct1_r && decoded.ct2_r == request.ct2_r &&
                decoded.ct1_mu == request.ct1_mu && decoded.ct2_mu == request.ct2_mu,
            "q7933 assembled ciphertexts did not round-trip");
    require(decoded.pi1_receipt == request.pi1_receipt,
            "q7933 assembled NIZK1 receipt did not round-trip");
}

void test_ticket_poll_roundtrip() {
    Q7933BlindSigTicketPoll poll;
    for (std::size_t i = 0U; i < poll.ticket_id.size(); ++i) {
        poll.ticket_id[i] = static_cast<std::uint8_t>(0xa0U + (i & 0x0fU));
    }
    const auto decoded = decode_q7933_blindsig_ticket_poll(
        encode_q7933_blindsig_ticket_poll(poll));
    require(decoded.ticket_id == poll.ticket_id,
            "q7933 ticket poll id did not round-trip");
}

void test_malformed_rejected() {
    Q7933BlindSigResponse response;
    response.status = Q7933BlindSigResponse::Status::Pending;
    auto encoded = encode_q7933_blindsig_response(response);

    require_throws([&] {
        const std::vector<std::uint8_t> truncated(encoded.begin(), encoded.end() - 1);
        (void)decode_q7933_blindsig_response(truncated);
    }, "q7933 truncated response must be rejected");

    encoded.push_back(0U);
    require_throws([&] { (void)decode_q7933_blindsig_response(encoded); },
                   "q7933 trailing response bytes must be rejected");

    auto invalid_status = encode_q7933_blindsig_response(response);
    invalid_status[0] = 0xffU;
    require_throws([&] { (void)decode_q7933_blindsig_response(invalid_status); },
                   "q7933 invalid response status must be rejected");

    const std::vector<std::uint8_t> short_poll(31U, 0U);
    require_throws([&] { (void)decode_q7933_blindsig_ticket_poll(short_poll); },
                   "q7933 short ticket poll must be rejected");
}

} // namespace

int main() {
    try {
        test_info_roundtrip();
        test_pending_and_ok_response_roundtrip();
        test_assembled_request_roundtrip();
        test_ticket_poll_roundtrip();
        test_malformed_rejected();
        std::cout << "q7933 wire tests: PASS\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "q7933 wire tests: FAIL: " << e.what() << '\n';
        return 1;
    }
}
