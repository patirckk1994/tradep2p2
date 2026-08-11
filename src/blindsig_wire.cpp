#include "tradep2p/blindsig_wire.hpp"

#include "tradep2p/protocol.hpp" // kMaxReasonLength

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace tradep2p::blindsig {
namespace {

// Local copy of protocol.cpp's own Writer/Reader pattern (anonymous
// namespace there means it isn't reusable across translation units -
// disclosure.cpp already independently duplicates the same pattern for
// the same reason). u8/u16/u32/bytes/require_finished only - this module
// doesn't need u64/fixed_id/short_string.

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

std::vector<std::uint8_t> encode_blindsig_info_response(const BlindSigInfoResponse& message) {
    Writer writer;
    writer.u8(message.enabled ? 1U : 0U);
    writer.u16_array(message.h);
    writer.u16_array(message.b);
    return writer.take();
}

BlindSigInfoResponse decode_blindsig_info_response(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    BlindSigInfoResponse message;
    message.enabled = reader.u8() != 0U;
    message.h = reader.u16_array<kRingDegree>();
    message.b = reader.u16_array<kRingDegree>();
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_blindsig_request_chunk(const BlindSigRequestChunk& message) {
    if (message.data.size() > kMaxBlindSigRequestBytes) {
        throw std::invalid_argument("blind-sig request chunk exceeds protocol limit");
    }
    Writer writer;
    writer.u32(message.total_length);
    writer.u32(message.chunk_index);
    writer.u32(message.total_chunks);
    writer.bytes(message.data);
    return writer.take();
}

BlindSigRequestChunk decode_blindsig_request_chunk(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    BlindSigRequestChunk message;
    message.total_length = reader.u32();
    if (message.total_length > kMaxBlindSigRequestBytes) {
        throw std::runtime_error("blind-sig request declares a length exceeding the protocol limit");
    }
    message.chunk_index = reader.u32();
    message.total_chunks = reader.u32();
    message.data = reader.bytes(kMaxBlindSigRequestBytes);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_blindsig_response(const BlindSigResponse& message) {
    Writer writer;
    writer.u8(static_cast<std::uint8_t>(message.status));
    writer.i16_array(message.s);
    writer.short_string(message.reason, kMaxReasonLength);
    return writer.take();
}

BlindSigResponse decode_blindsig_response(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    BlindSigResponse message;
    const auto status = reader.u8();
    if (status > static_cast<std::uint8_t>(BlindSigResponse::Status::Error)) {
        throw std::runtime_error("invalid blind-sig response status");
    }
    message.status = static_cast<BlindSigResponse::Status>(status);
    message.s = reader.i16_array<kRingDegree>();
    message.reason = reader.short_string(kMaxReasonLength);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_blindsig_assembled_request(const BlindSigAssembledRequest& request) {
    if (request.pi1_receipt.size() > kMaxBlindSigRequestBytes) {
        throw std::invalid_argument("blind-sig assembled request's receipt exceeds protocol limit");
    }
    Writer writer;
    writer.u16_array(request.c);
    writer.fixed_bytes(request.rho);
    writer.u16_array(request.enc_a);
    writer.u16_array(request.enc_pk);
    writer.u16_array(request.ct1_r);
    writer.u16_array(request.ct2_r);
    writer.u16_array(request.ct1_mu);
    writer.u16_array(request.ct2_mu);
    writer.bytes(request.pi1_receipt);
    return writer.take();
}

BlindSigAssembledRequest decode_blindsig_assembled_request(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    BlindSigAssembledRequest request;
    request.c = reader.u16_array<kRingDegree>();
    request.rho = reader.fixed_bytes<32U>();
    request.enc_a = reader.u16_array<kRingDegree>();
    request.enc_pk = reader.u16_array<kRingDegree>();
    request.ct1_r = reader.u16_array<kRingDegree>();
    request.ct2_r = reader.u16_array<kRingDegree>();
    request.ct1_mu = reader.u16_array<kRingDegree>();
    request.ct2_mu = reader.u16_array<kRingDegree>();
    request.pi1_receipt = reader.bytes(kMaxBlindSigRequestBytes);
    reader.require_finished();
    return request;
}

bool BlindSigChunkAssembler::add_chunk(const BlindSigRequestChunk& chunk) {
    if (complete_) {
        throw std::runtime_error("blind-sig chunk received after assembly already completed");
    }
    if (chunk.total_length > kMaxBlindSigRequestBytes) {
        throw std::runtime_error("blind-sig request declares a length exceeding the protocol limit");
    }
    if (chunk.total_chunks == 0U) {
        throw std::runtime_error("blind-sig chunk declares zero total_chunks");
    }
    if (!started_) {
        started_ = true;
        expected_total_length_ = chunk.total_length;
        expected_total_chunks_ = chunk.total_chunks;
        buffer_.reserve(expected_total_length_);
    } else {
        if (chunk.total_length != expected_total_length_ || chunk.total_chunks != expected_total_chunks_) {
            throw std::runtime_error("blind-sig chunk's total_length/total_chunks changed mid-stream");
        }
    }
    if (chunk.chunk_index != next_chunk_index_) {
        throw std::runtime_error("blind-sig chunk arrived out of order");
    }
    // Checked before appending, not just at the end: a hostile peer
    // sending an oversized final chunk must be rejected before it's ever
    // inserted into buffer_, not after paying the allocation.
    if (buffer_.size() + chunk.data.size() > expected_total_length_) {
        throw std::runtime_error("blind-sig chunk stream exceeds its own declared total_length");
    }
    buffer_.insert(buffer_.end(), chunk.data.begin(), chunk.data.end());
    ++next_chunk_index_;

    if (next_chunk_index_ == expected_total_chunks_) {
        if (buffer_.size() != expected_total_length_) {
            throw std::runtime_error("blind-sig chunk stream completed short of its declared total_length");
        }
        complete_ = true;
        return true;
    }
    return false;
}

} // namespace tradep2p::blindsig
