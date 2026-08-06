#include "tradep2p/room_persistence.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace tradep2p {
namespace {

[[noreturn]] void throw_errno(const std::string& message) {
    throw std::runtime_error(message + ": " + std::strerror(errno));
}

// ---------------------------------------------------------------------------
// Binary Writer/Reader, duplicated locally following this codebase's
// established per-module convention (see keystore.cpp/journal.cpp's own
// copies and their comments on why they aren't shared).
// ---------------------------------------------------------------------------

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
    void bytes(std::span<const std::uint8_t> value) {
        out_.insert(out_.end(), value.begin(), value.end());
    }
    void bytes_u16(std::string_view value, std::size_t maximum) {
        if (value.size() > maximum || value.size() > std::numeric_limits<std::uint16_t>::max()) {
            throw std::invalid_argument("persisted room field exceeds protocol limit");
        }
        u16(static_cast<std::uint16_t>(value.size()));
        out_.insert(out_.end(), value.begin(), value.end());
    }
    void bytes_u32(std::span<const std::uint8_t> value) {
        u32(static_cast<std::uint32_t>(value.size()));
        bytes(value);
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
        return input_[pos_++];
    }
    [[nodiscard]] std::uint16_t u16() {
        require(2U);
        const auto result = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(input_[pos_]) << 8U) | input_[pos_ + 1U]);
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
    template <std::size_t N>
    [[nodiscard]] std::array<std::uint8_t, N> fixed() {
        require(N);
        std::array<std::uint8_t, N> result{};
        std::copy_n(input_.begin() + static_cast<std::ptrdiff_t>(pos_), N, result.begin());
        pos_ += N;
        return result;
    }
    [[nodiscard]] std::string string_u16(std::size_t max_len) {
        const auto length = static_cast<std::size_t>(u16());
        if (length > max_len) {
            throw PersistenceFormatError("persisted room field exceeds maximum allowed length");
        }
        require(length);
        std::string result(reinterpret_cast<const char*>(input_.data() + pos_), length);
        pos_ += length;
        return result;
    }
    [[nodiscard]] std::vector<std::uint8_t> bytes_u32(std::size_t max_len) {
        const auto length = static_cast<std::size_t>(u32());
        if (length > max_len) {
            throw PersistenceFormatError("persisted room list exceeds maximum allowed length");
        }
        require(length);
        std::vector<std::uint8_t> result(input_.begin() + static_cast<std::ptrdiff_t>(pos_),
                                          input_.begin() + static_cast<std::ptrdiff_t>(pos_ + length));
        pos_ += length;
        return result;
    }
    void require_finished() const {
        if (pos_ != input_.size()) {
            throw PersistenceFormatError("trailing bytes after persisted room file");
        }
    }

private:
    void require(std::size_t count) const {
        if (pos_ > input_.size() || count > input_.size() - pos_) {
            throw PersistenceFormatError("truncated persisted room file");
        }
    }
    std::span<const std::uint8_t> input_;
    std::size_t pos_{0U};
};

constexpr std::array<std::uint8_t, 4> kMagic = {'T', 'P', 'R', 'S'};
// Generous headroom: one room's real encoding is on the order of a few
// hundred bytes (terms + fee + a short abort reason); this is bounded so a
// corrupted length field fails fast rather than driving an unbounded
// allocation.
constexpr std::size_t kMaxRoomBodyLength = 8192U;
constexpr std::size_t kMaxRoomCount = 4096U; // generous vs. lobby.cpp's kMaxRooms = 256

void append_fee_terms(Writer& writer, const FeeTerms& fee) {
    validate_fee_terms(fee);
    writer.bytes_u16(fee.asset, kMaxAssetCodeLength);
    writer.u64(fee.amount);
    writer.bytes_u16(fee.address, kMaxAddressLength);
}

FeeTerms read_fee_terms(Reader& reader) {
    FeeTerms fee;
    fee.asset = reader.string_u16(kMaxAssetCodeLength);
    fee.amount = reader.u64();
    fee.address = reader.string_u16(kMaxAddressLength);
    validate_fee_terms(fee);
    return fee;
}

std::vector<std::uint8_t> encode_one_room(const PersistedRoom& room) {
    Writer writer;
    writer.bytes(room.room_id);
    writer.bytes(room.party_a);
    writer.bytes(room.party_b);
    const std::vector<std::uint8_t> encoded_terms = encode_terms(room.terms); // protocol.hpp/.cpp
    writer.bytes_u32(encoded_terms);
    append_fee_terms(writer, room.fee);
    writer.u8(static_cast<std::uint8_t>(room.state));
    writer.u32(room.round_index);
    writer.u8(room.leg_index);
    writer.bytes_u16(room.abort_reason, kMaxReasonLength);
    writer.u64(room.updated_at);
    return writer.take();
}

// Every malformed-content failure this function can raise - whether from
// this module's own Reader, or from protocol.hpp's decode_terms()/
// validate_*() functions (which throw std::invalid_argument/
// std::runtime_error, not PersistenceFormatError) - is normalized to
// PersistenceFormatError, so callers have exactly one exception type to
// catch for "this file is not a well-formed persisted-room file", matching
// keystore.hpp's precedent of a single coherent exception contract per
// decode path.
PersistedRoom decode_one_room(std::span<const std::uint8_t> body) {
    try {
        Reader reader(body);
        PersistedRoom room;
        room.room_id = reader.fixed<32U>();
        room.party_a = reader.fixed<16U>();
        room.party_b = reader.fixed<16U>();
        const std::vector<std::uint8_t> encoded_terms = reader.bytes_u32(kMaxRoomBodyLength);
        room.terms = decode_terms(encoded_terms);
        room.fee = read_fee_terms(reader);
        room.state = static_cast<SessionState>(reader.u8());
        room.round_index = reader.u32();
        room.leg_index = reader.u8();
        room.abort_reason = reader.string_u16(kMaxReasonLength);
        room.updated_at = reader.u64();
        reader.require_finished();

        validate_room_id(room.room_id);
        validate_client_id(room.party_a);
        validate_client_id(room.party_b);
        if (room.leg_index > 1U) {
            throw PersistenceFormatError("persisted room has invalid leg index");
        }
        return room;
    } catch (const PersistenceFormatError&) {
        throw;
    } catch (const std::exception& error) {
        throw PersistenceFormatError(std::string("malformed persisted room: ") + error.what());
    }
}

// ---------------------------------------------------------------------------
// Atomic file I/O - same discipline as keystore.cpp's write_replace_atomic()
// (0600, fsync, tmp-then-rename), duplicated locally per this codebase's
// established convention.
// ---------------------------------------------------------------------------

void ensure_parent_directory(const std::string& path) {
    const std::filesystem::path fs_path(path);
    if (fs_path.has_parent_path()) {
        std::error_code error;
        std::filesystem::create_directories(fs_path.parent_path(), error);
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
            throw_errno("failed to write persisted room file contents");
        }
        written += static_cast<std::size_t>(n);
    }
    (void)::fsync(fd);
}

void best_effort_fsync_parent_directory(const std::string& path) noexcept {
    std::filesystem::path parent = std::filesystem::path(path).parent_path();
    if (parent.empty()) {
        parent = ".";
    }
    const int dir_fd = ::open(parent.c_str(), O_RDONLY);
    if (dir_fd >= 0) {
        (void)::fsync(dir_fd);
        (void)::close(dir_fd);
    }
}

std::vector<std::uint8_t> read_file_all(const std::string& path, bool& existed) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        existed = false;
        return {};
    }
    existed = true;
    input.seekg(0, std::ios::end);
    const auto size = input.tellg();
    if (size < 0) {
        throw std::runtime_error("cannot determine size of file: " + path);
    }
    input.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    if (!data.empty()) {
        input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (static_cast<std::size_t>(input.gcount()) != data.size()) {
            throw std::runtime_error("failed to fully read file: " + path);
        }
    }
    return data;
}

} // namespace

std::vector<std::uint8_t> encode_persisted_rooms(const PersistedRoomFile& file) {
    if (file.rooms.size() > kMaxRoomCount) {
        throw std::invalid_argument("persisted room file exceeds maximum room count");
    }
    Writer writer;
    writer.bytes(kMagic);
    writer.u16(file.format_version);
    writer.u32(static_cast<std::uint32_t>(file.rooms.size()));
    for (const auto& room : file.rooms) {
        const std::vector<std::uint8_t> body = encode_one_room(room);
        writer.bytes_u32(body);
    }
    return writer.take();
}

PersistedRoomFile decode_persisted_rooms(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    const auto magic = reader.fixed<kMagic.size()>();
    if (magic != kMagic) {
        throw PersistenceFormatError("not a tradep2p persisted-room file (bad magic)");
    }
    PersistedRoomFile file;
    file.format_version = reader.u16();
    if (file.format_version != kPersistedRoomFormatVersion) {
        throw PersistenceFormatError("unsupported persisted-room file format version");
    }
    const auto count = static_cast<std::size_t>(reader.u32());
    if (count > kMaxRoomCount) {
        throw PersistenceFormatError("persisted room file exceeds maximum room count");
    }
    file.rooms.reserve(count);
    for (std::size_t i = 0U; i < count; ++i) {
        const auto body = reader.bytes_u32(kMaxRoomBodyLength);
        file.rooms.push_back(decode_one_room(body));
    }
    reader.require_finished();
    return file;
}

void write_persisted_rooms(const std::string& path, const PersistedRoomFile& file) {
    ensure_parent_directory(path);
    const std::string tmp_path = path + ".tmp";
    ::unlink(tmp_path.c_str());

    const int fd = ::open(tmp_path.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) {
        throw_errno("failed to create temporary file '" + tmp_path + "'");
    }
    const std::vector<std::uint8_t> bytes = encode_persisted_rooms(file);
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
    ::chmod(path.c_str(), 0600);
    best_effort_fsync_parent_directory(path);
}

PersistedRoomFile load_persisted_rooms(const std::string& path) {
    bool existed = false;
    const std::vector<std::uint8_t> raw = read_file_all(path, existed);
    if (!existed) {
        return PersistedRoomFile{};
    }
    return decode_persisted_rooms(raw);
}

} // namespace tradep2p
