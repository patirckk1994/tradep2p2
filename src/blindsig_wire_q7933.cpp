#include "tradep2p/blindsig_wire_q7933.hpp"

#include "tradep2p/protocol.hpp" // kMaxReasonLength

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace tradep2p::blindsig {
namespace {

class Writer {
public:
    void u8(std::uint8_t value) { out_.push_back(value); }

    void u16(std::uint16_t value) {
        out_.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
        out_.push_back(static_cast<std::uint8_t>(value & 0xffU));
    }

    void u32(std::uint32_t value) {
        for (int shift = 24; shift >= 0; shift -= 8) {
            out_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
        }
    }

    template <std::size_t N>
    void u16_array(const std::array<std::uint16_t, N>& value) {
        for (const auto v : value) {
            u16(v);
        }
    }

    template <std::size_t N>
    void i16_array(const std::array<std::int16_t, N>& value) {
        for (const auto v : value) {
            u16(static_cast<std::uint16_t>(v));
        }
    }

    template <std::size_t N>
    void fixed_bytes(const std::array<std::uint8_t, N>& value) {
        out_.insert(out_.end(), value.begin(), value.end());
    }

    void bytes(std::span<const std::uint8_t> value) {
        if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
            throw std::invalid_argument("byte field exceeds protocol limit");
        }
        u32(static_cast<std::uint32_t>(value.size()));
        out_.insert(out_.end(), value.begin(), value.end());
    }

    void short_string(std::string_view value, std::size_t maximum) {
        if (value.size() > maximum || value.size() > std::numeric_limits<std::uint16_t>::max()) {
            throw std::invalid_argument("string exceeds protocol limit");
        }
        u16(static_cast<std::uint16_t>(value.size()));
        out_.insert(out_.end(), value.begin(), value.end());
    }

    [[nodiscard]] std::vector<std::uint8_t> take() { return std::move(out_); }

private:
    std::vector<std::uint8_t> out_;
};

class Reader {
public:
    explicit Reader(std::span<const std::uint8_t> input) : input_(input) {}

    [[nodiscard]] std::uint8_t u8() {
        require(1U);
        return input_[position_++];
    }

    [[nodiscard]] std::uint16_t u16() {
        require(2U);
        const auto result = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(input_[position_]) << 8U) |
            static_cast<std::uint16_t>(input_[position_ + 1U]));
        position_ += 2U;
        return result;
    }

    [[nodiscard]] std::uint32_t u32() {
        require(4U);
        std::uint32_t result = 0U;
        for (int i = 0; i < 4; ++i) {
            result = (result << 8U) | input_[position_++];
        }
        return result;
    }

    template <std::size_t N>
    [[nodiscard]] std::array<std::uint16_t, N> u16_array() {
        std::array<std::uint16_t, N> result{};
        for (auto& v : result) {
            v = u16();
        }
        return result;
    }

    template <std::size_t N>
    [[nodiscard]] std::array<std::int16_t, N> i16_array() {
        std::array<std::int16_t, N> result{};
        for (auto& v : result) {
            v = static_cast<std::int16_t>(u16());
        }
        return result;
    }

    template <std::size_t N>
    [[nodiscard]] std::array<std::uint8_t, N> fixed_bytes() {
        require(N);
        std::array<std::uint8_t, N> result{};
        std::copy_n(input_.begin() + static_cast<std::ptrdiff_t>(position_), N, result.begin());
        position_ += N;
        return result;
    }

    [[nodiscard]] std::vector<std::uint8_t> bytes(std::size_t maximum) {
        const auto length = static_cast<std::size_t>(u32());
        if (length > maximum) {
            throw std::runtime_error("encoded byte field exceeds protocol limit");
        }
        require(length);
        std::vector<std::uint8_t> result(
            input_.begin() + static_cast<std::ptrdiff_t>(position_),
            input_.begin() + static_cast<std::ptrdiff_t>(position_ + length));
        position_ += length;
        return result;
    }

    [[nodiscard]] std::string short_string(std::size_t maximum) {
        const auto length = static_cast<std::size_t>(u16());
        if (length > maximum) {
            throw std::runtime_error("encoded string exceeds protocol limit");
        }
        require(length);
        std::string result(reinterpret_cast<const char*>(input_.data() + position_), length);
        position_ += length;
        return result;
    }

    void require_finished() const {
        if (position_ != input_.size()) {
            throw std::runtime_error("trailing bytes in message");
        }
    }

private:
    void require(std::size_t count) const {
        if (position_ > input_.size() || count > input_.size() - position_) {
            throw std::runtime_error("truncated message");
        }
    }

    std::span<const std::uint8_t> input_;
    std::size_t position_{0U};
};

} // namespace

std::vector<std::uint8_t> encode_q7933_blindsig_info_response(
    const Q7933BlindSigInfoResponse& message) {
    Writer writer;
    writer.u8(message.enabled ? 1U : 0U);
    writer.u16_array(message.t);
    writer.u16_array(message.b);
    return writer.take();
}

Q7933BlindSigInfoResponse decode_q7933_blindsig_info_response(
    std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    Q7933BlindSigInfoResponse message;
    message.enabled = reader.u8() != 0U;
    message.t = reader.u16_array<kQ7933RingDegree>();
    message.b = reader.u16_array<kQ7933RingDegree>();
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_q7933_blindsig_response(
    const Q7933BlindSigResponse& message) {
    Writer writer;
    writer.u8(static_cast<std::uint8_t>(message.status));
    writer.i16_array(message.s0);
    writer.i16_array(message.s1);
    writer.fixed_bytes(message.ticket_id);
    writer.short_string(message.reason, kMaxReasonLength);
    return writer.take();
}

Q7933BlindSigResponse decode_q7933_blindsig_response(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    Q7933BlindSigResponse message;
    const auto status = reader.u8();
    if (status > static_cast<std::uint8_t>(Q7933BlindSigResponse::Status::Pending)) {
        throw std::runtime_error("invalid q7933 blind-sig response status");
    }
    message.status = static_cast<Q7933BlindSigResponse::Status>(status);
    message.s0 = reader.i16_array<kQ7933RingDegree>();
    message.s1 = reader.i16_array<kQ7933RingDegree>();
    message.ticket_id = reader.fixed_bytes<32U>();
    message.reason = reader.short_string(kMaxReasonLength);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_q7933_blindsig_assembled_request(
    const Q7933BlindSigAssembledRequest& request) {
    if (request.pi1_receipt.size() > kMaxBlindSigRequestBytes) {
        throw std::invalid_argument(
            "q7933 blind-sig assembled request's receipt exceeds protocol limit");
    }
    Writer writer;
    writer.u16_array(request.c);
    writer.u16_array(request.b);
    writer.u16_array(request.enc_a);
    writer.u16_array(request.enc_pk);
    writer.u16_array(request.ct1_r);
    writer.u16_array(request.ct2_r);
    writer.u16_array(request.ct1_mu);
    writer.u16_array(request.ct2_mu);
    writer.u8(request.credential_issuance ? 1U : 0U);
    writer.fixed_bytes(request.issuance_room_id);
    writer.u32(request.credential_epoch);
    writer.bytes(request.pi1_receipt);
    return writer.take();
}

Q7933BlindSigAssembledRequest decode_q7933_blindsig_assembled_request(
    std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    Q7933BlindSigAssembledRequest request;
    request.c = reader.u16_array<kQ7933RingDegree>();
    request.b = reader.u16_array<kQ7933RingDegree>();
    request.enc_a = reader.u16_array<kQ7933RingDegree>();
    request.enc_pk = reader.u16_array<kQ7933RingDegree>();
    request.ct1_r = reader.u16_array<kQ7933RingDegree>();
    request.ct2_r = reader.u16_array<kQ7933RingDegree>();
    request.ct1_mu = reader.u16_array<kQ7933RingDegree>();
    request.ct2_mu = reader.u16_array<kQ7933RingDegree>();
    const auto credential_flag = reader.u8();
    if (credential_flag > 1U) {
        throw std::runtime_error("invalid q7933 credential issuance flag");
    }
    request.credential_issuance = credential_flag == 1U;
    request.issuance_room_id = reader.fixed_bytes<32U>();
    request.credential_epoch = reader.u32();
    request.pi1_receipt = reader.bytes(kMaxBlindSigRequestBytes);
    reader.require_finished();

    if (!request.credential_issuance) {
        const std::array<std::uint8_t, 32> zero_room{};
        if (request.issuance_room_id != zero_room || request.credential_epoch != 0U) {
            throw std::runtime_error(
                "raw q7933 blind-signature request carries credential-only metadata");
        }
    }
    return request;
}

std::vector<std::uint8_t> encode_q7933_blindsig_ticket_poll(
    const Q7933BlindSigTicketPoll& message) {
    Writer writer;
    writer.fixed_bytes(message.ticket_id);
    return writer.take();
}

Q7933BlindSigTicketPoll decode_q7933_blindsig_ticket_poll(
    std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    Q7933BlindSigTicketPoll message;
    message.ticket_id = reader.fixed_bytes<32U>();
    reader.require_finished();
    return message;
}

} // namespace tradep2p::blindsig
