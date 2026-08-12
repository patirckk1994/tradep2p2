#include "tradep2p/blindsig_ticket_store_q7933.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <span>

#include <fcntl.h>
#include <unistd.h>

// Deliberately its own, independent implementation of the same atomic-write
// discipline as keystore.cpp's write_replace_atomic() / blindsig_keystore.cpp
// / blindsig_keystore_q7933.cpp - see this module's header comment for why
// it isn't a shared base. Unlike either keystore, there is no KDF/AEAD layer
// here at all: ticket files are plain, integrity-via-atomicity-and-strict-
// parsing only, never encrypted (see header comment for why that's the
// right call for this specific data).

namespace tradep2p::blindsig {
namespace {

using tradep2p::blns7933::Parameters;
using tradep2p::blns7933::PolyQ;
using tradep2p::blns7933::Signature;

constexpr std::array<std::uint8_t, 4> kMagic = {'T', 'P', 'Q', 'K'}; // TradeP2P Q-ticKet
constexpr std::uint16_t kFormatVersion = 1;
// Real max size: 4 (magic) + 2 (version) + 32 (id) + 8 (received_at) + 1
// (status) + 4 (degree) + 3*512*8 (c, s0, s1 all present) = 12,339 bytes;
// headroom for the same "fail fast on a hostile length field" reason as
// the keystore's own analogous constant.
constexpr std::size_t kMaxFileLength = 32768;

[[noreturn]] void throw_errno(const std::string& message) {
    throw std::runtime_error(message + ": " + std::strerror(errno));
}

std::array<std::uint8_t, 32> random_ticket_id() {
    std::array<std::uint8_t, 32> out{};
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        throw std::runtime_error("q7933 ticket store: RAND_bytes failed while generating a ticket id");
    }
    return out;
}

std::string to_hex(const TicketId& id) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(id.size() * 2U);
    for (const auto byte : id) {
        out.push_back(kDigits[(byte >> 4U) & 0x0fU]);
        out.push_back(kDigits[byte & 0x0fU]);
    }
    return out;
}

std::optional<TicketId> from_hex(const std::string& hex) {
    if (hex.size() != 64U) {
        return std::nullopt;
    }
    TicketId out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        const auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') {
                return c - '0';
            }
            if (c >= 'a' && c <= 'f') {
                return 10 + (c - 'a');
            }
            return -1;
        };
        const int hi = nibble(hex[2U * i]);
        const int lo = nibble(hex[2U * i + 1U]);
        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return out;
}

std::uint64_t now_unix_seconds() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
}

// ---------------------------------------------------------------------
// Writer/Reader - same shape as blindsig_keystore_q7933.cpp's own.
// ---------------------------------------------------------------------

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
    void u64(std::uint64_t value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            out_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
        }
    }
    void i64(std::int64_t value) { u64(static_cast<std::uint64_t>(value)); }
    void poly(const PolyQ& value) {
        for (const auto coeff : value) {
            i64(coeff);
        }
    }
    void bytes(std::span<const std::uint8_t> value) { out_.insert(out_.end(), value.begin(), value.end()); }
    [[nodiscard]] std::vector<std::uint8_t> take() { return std::move(out_); }

private:
    std::vector<std::uint8_t> out_;
};

class Reader {
public:
    explicit Reader(std::span<const std::uint8_t> input) : input_(input) {}
    [[nodiscard]] std::uint8_t u8() {
        require(1U);
        return input_[pos_++];
    }
    [[nodiscard]] std::uint16_t u16() {
        require(2U);
        const auto result = static_cast<std::uint16_t>((static_cast<std::uint16_t>(input_[pos_]) << 8U) |
                                                        static_cast<std::uint16_t>(input_[pos_ + 1U]));
        pos_ += 2U;
        return result;
    }
    [[nodiscard]] std::uint32_t u32() {
        require(4U);
        std::uint32_t result = 0U;
        for (int i = 0; i < 4; ++i) {
            result = (result << 8U) | input_[pos_++];
        }
        return result;
    }
    [[nodiscard]] std::uint64_t u64() {
        require(8U);
        std::uint64_t result = 0U;
        for (int i = 0; i < 8; ++i) {
            result = (result << 8U) | input_[pos_++];
        }
        return result;
    }
    [[nodiscard]] std::int64_t i64() { return static_cast<std::int64_t>(u64()); }
    [[nodiscard]] PolyQ poly(std::size_t count) {
        PolyQ result;
        result.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            result.push_back(i64());
        }
        return result;
    }
    template <std::size_t N>
    [[nodiscard]] std::array<std::uint8_t, N> fixed() {
        require(N);
        std::array<std::uint8_t, N> result{};
        std::copy_n(input_.begin() + static_cast<std::ptrdiff_t>(pos_), N, result.begin());
        pos_ += N;
        return result;
    }
    [[nodiscard]] std::size_t remaining() const { return input_.size() - pos_; }
    void require_finished() const {
        if (pos_ != input_.size()) {
            throw Q7933TicketStoreFormatError("trailing bytes after q7933 ticket record");
        }
    }

private:
    void require(std::size_t count) const {
        if (pos_ > input_.size() || count > input_.size() - pos_) {
            throw Q7933TicketStoreFormatError("truncated q7933 ticket file");
        }
    }
    std::span<const std::uint8_t> input_;
    std::size_t pos_{0U};
};

// ---------------------------------------------------------------------
// File I/O.
// ---------------------------------------------------------------------

void ensure_directory(const std::string& directory) {
    std::error_code error;
    std::filesystem::create_directories(directory, error);
    if (error) {
        throw std::runtime_error("q7933 ticket store: failed to create directory '" + directory +
                                  "': " + error.message());
    }
}

void write_all_and_sync(int fd, std::span<const std::uint8_t> bytes) {
    std::size_t written = 0U;
    while (written < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.data() + written, bytes.size() - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw_errno("failed to write q7933 ticket file contents");
        }
        written += static_cast<std::size_t>(n);
    }
    (void)::fsync(fd);
}

// Atomic tmp-then-rename replace, same discipline as keystore.cpp's own
// write_replace_atomic(): used for BOTH a brand-new ticket (submit()) and
// an in-place status transition (mark_signed()) - a fresh ticket id makes
// "already exists" astronomically unlikely for submit(), but using the
// same replace-capable primitive for both avoids a separate O_EXCL path
// that would need its own collision-retry logic for no real benefit.
void write_replace_atomic(const std::string& path, std::span<const std::uint8_t> bytes) {
    const std::string tmp_path = path + ".tmp";
    ::unlink(tmp_path.c_str()); // best-effort cleanup of a stale prior attempt

    const int fd = ::open(tmp_path.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) {
        throw_errno("failed to create temporary file '" + tmp_path + "'");
    }
    try {
        write_all_and_sync(fd, bytes);
    } catch (...) {
        ::close(fd);
        ::unlink(tmp_path.c_str());
        throw;
    }
    if (::close(fd) != 0) {
        ::unlink(tmp_path.c_str());
        throw_errno("failed to close temporary file '" + tmp_path + "'");
    }
    if (::rename(tmp_path.c_str(), path.c_str()) != 0) {
        const int saved_errno = errno;
        ::unlink(tmp_path.c_str());
        errno = saved_errno;
        throw_errno("failed to atomically replace '" + path + "'");
    }
}

std::optional<std::vector<std::uint8_t>> read_file_if_exists(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        return std::nullopt; // ENOENT or equivalent - caller treats as "no such ticket"
    }
    input.seekg(0, std::ios::end);
    const auto size = input.tellg();
    if (size < 0) {
        throw std::runtime_error("q7933 ticket store: cannot determine size of '" + path + "'");
    }
    input.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    if (!data.empty()) {
        input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (static_cast<std::size_t>(input.gcount()) != data.size()) {
            throw std::runtime_error("q7933 ticket store: failed to fully read '" + path + "'");
        }
    }
    return data;
}

// ---------------------------------------------------------------------
// Ticket encode/decode.
// ---------------------------------------------------------------------

std::vector<std::uint8_t> encode_ticket(const Ticket& ticket) {
    Writer writer;
    writer.bytes(kMagic);
    writer.u16(kFormatVersion);
    writer.bytes(ticket.ticket_id);
    writer.u64(ticket.received_at_unix_seconds);
    writer.u8(static_cast<std::uint8_t>(ticket.status));
    writer.u32(static_cast<std::uint32_t>(Parameters::degree));
    writer.poly(ticket.c);
    if (ticket.status == TicketStatus::kSigned) {
        if (!ticket.signature.has_value()) {
            throw std::invalid_argument("q7933 ticket store: kSigned ticket is missing its signature");
        }
        writer.poly(ticket.signature->s0);
        writer.poly(ticket.signature->s1);
    }
    return writer.take();
}

Ticket decode_ticket(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    const auto magic = reader.fixed<kMagic.size()>();
    if (magic != kMagic) {
        throw Q7933TicketStoreFormatError("not a tradep2p q7933 ticket file (bad magic)");
    }
    const std::uint16_t version = reader.u16();
    if (version != kFormatVersion) {
        throw Q7933TicketStoreFormatError("unsupported q7933 ticket file format version");
    }
    Ticket ticket;
    ticket.ticket_id = reader.fixed<32>();
    ticket.received_at_unix_seconds = reader.u64();
    const std::uint8_t status_raw = reader.u8();
    if (status_raw != static_cast<std::uint8_t>(TicketStatus::kPending) &&
        status_raw != static_cast<std::uint8_t>(TicketStatus::kSigned)) {
        throw Q7933TicketStoreFormatError("unknown q7933 ticket status byte");
    }
    ticket.status = static_cast<TicketStatus>(status_raw);
    const std::uint32_t degree = reader.u32();
    if (degree != static_cast<std::uint32_t>(Parameters::degree)) {
        throw Q7933TicketStoreFormatError("q7933 ticket file has the wrong ring degree");
    }
    ticket.c = reader.poly(degree);
    if (ticket.status == TicketStatus::kSigned) {
        Signature signature;
        signature.s0 = reader.poly(degree);
        signature.s1 = reader.poly(degree);
        ticket.signature = std::move(signature);
    }
    reader.require_finished();
    return ticket;
}

std::string ticket_path(const std::string& directory, const TicketId& ticket_id) {
    return directory + "/" + to_hex(ticket_id) + ".qtkt";
}

} // namespace

Q7933TicketStore::Q7933TicketStore(std::string directory, std::size_t max_pending_tickets)
    : directory_(std::move(directory)), max_pending_tickets_(max_pending_tickets) {
    ensure_directory(directory_);
}

TicketId Q7933TicketStore::submit(const PolyQ& c) {
    std::size_t existing = 0U;
    std::error_code error;
    for (const auto& entry : std::filesystem::directory_iterator(directory_, error)) {
        if (entry.path().extension() == ".qtkt") {
            ++existing;
        }
    }
    if (error) {
        throw std::runtime_error("q7933 ticket store: failed to list directory '" + directory_ +
                                  "': " + error.message());
    }
    if (existing >= max_pending_tickets_) {
        throw Q7933TicketStoreFullError("q7933 ticket store is at capacity (" +
                                        std::to_string(max_pending_tickets_) + " tickets)");
    }

    // 32 real random bytes: collision probability is negligible, but retry
    // a few times against the (astronomically unlikely) case that one
    // still occurs rather than silently overwriting another ticket.
    for (int attempt = 0; attempt < 8; ++attempt) {
        const TicketId ticket_id = random_ticket_id();
        const std::string path = ticket_path(directory_, ticket_id);
        if (std::filesystem::exists(path)) {
            continue;
        }
        Ticket ticket;
        ticket.ticket_id = ticket_id;
        ticket.c = c;
        ticket.received_at_unix_seconds = now_unix_seconds();
        ticket.status = TicketStatus::kPending;
        write_replace_atomic(path, encode_ticket(ticket));
        return ticket_id;
    }
    throw std::runtime_error("q7933 ticket store: failed to allocate a unique ticket id after 8 attempts");
}

std::optional<Ticket> Q7933TicketStore::find(const TicketId& ticket_id) const {
    const auto raw = read_file_if_exists(ticket_path(directory_, ticket_id));
    if (!raw.has_value()) {
        return std::nullopt;
    }
    if (raw->size() > kMaxFileLength) {
        throw Q7933TicketStoreFormatError("q7933 ticket file exceeds the maximum allowed length");
    }
    return decode_ticket(*raw); // throws Q7933TicketStoreFormatError on malformed content
}

std::vector<TicketId> Q7933TicketStore::list_pending() const {
    std::vector<TicketId> result;
    std::error_code error;
    for (const auto& entry : std::filesystem::directory_iterator(directory_, error)) {
        if (entry.path().extension() != ".qtkt") {
            continue;
        }
        const auto id = from_hex(entry.path().stem().string());
        if (!id.has_value()) {
            continue; // not a file this store created; ignore rather than fail the whole listing
        }
        const auto ticket = find(*id);
        if (ticket.has_value() && ticket->status == TicketStatus::kPending) {
            result.push_back(*id);
        }
    }
    if (error) {
        throw std::runtime_error("q7933 ticket store: failed to list directory '" + directory_ +
                                  "': " + error.message());
    }
    return result;
}

void Q7933TicketStore::mark_signed(const TicketId& ticket_id, const Signature& signature) {
    auto ticket = find(ticket_id);
    if (!ticket.has_value()) {
        throw std::logic_error("q7933 ticket store: cannot sign unknown ticket " + to_hex(ticket_id));
    }
    if (ticket->status != TicketStatus::kPending) {
        throw std::logic_error("q7933 ticket store: ticket " + to_hex(ticket_id) + " is not pending");
    }
    ticket->status = TicketStatus::kSigned;
    ticket->signature = signature;
    write_replace_atomic(ticket_path(directory_, ticket_id), encode_ticket(*ticket));
}

void Q7933TicketStore::remove(const TicketId& ticket_id) noexcept {
    ::unlink(ticket_path(directory_, ticket_id).c_str());
}

} // namespace tradep2p::blindsig
