#include "tradep2p/journal.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <unordered_map>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace tradep2p {
namespace {

// ---------------------------------------------------------------------------
// Error helpers (mirrors identity.cpp/keystore.cpp's private helpers -
// duplicated locally on purpose, matching this codebase's existing
// convention of keeping each module's failure paths self-contained).
// ---------------------------------------------------------------------------

[[noreturn]] void throw_openssl_error(const std::string& message) {
    const unsigned long code = ERR_get_error();
    char buffer[256]{};
    if (code != 0U) {
        ERR_error_string_n(code, buffer, sizeof(buffer));
        throw std::runtime_error(message + ": " + buffer);
    }
    throw std::runtime_error(message);
}

[[noreturn]] void throw_errno(const std::string& message) {
    throw std::runtime_error(message + ": " + std::strerror(errno));
}

// ---------------------------------------------------------------------------
// Binary Writer/Reader, matching protocol.cpp/keystore.cpp's big-endian,
// length-prefixed conventions. Duplicated locally rather than shared, same
// rationale keystore.cpp's own copy documents: each module's wire/file
// format parsing stays independently auditable.
// ---------------------------------------------------------------------------

class Writer {
public:
    void reserve(std::size_t total_bytes) { out_.reserve(total_bytes); }
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
    void bytes_u16(std::string_view value) {
        if (value.size() > std::numeric_limits<std::uint16_t>::max()) {
            throw std::invalid_argument("journal field exceeds u16 length prefix");
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
    // Everything left in the input, as a fresh vector - for a trailing
    // variable-length field with no length prefix of its own (its length is
    // implied by context, e.g. a checkpoint signature sized by its suite_id).
    [[nodiscard]] std::vector<std::uint8_t> bytes_remaining() {
        std::vector<std::uint8_t> result(input_.begin() + static_cast<std::ptrdiff_t>(pos_),
                                         input_.end());
        pos_ = input_.size();
        return result;
    }
    [[nodiscard]] std::string string_u16(std::size_t max_len) {
        const auto length = static_cast<std::size_t>(u16());
        if (length > max_len) {
            throw JournalFormatError("journal field exceeds maximum allowed length");
        }
        require(length);
        std::string result(reinterpret_cast<const char*>(input_.data() + pos_), length);
        pos_ += length;
        return result;
    }
    [[nodiscard]] std::size_t position() const { return pos_; }
    [[nodiscard]] std::size_t remaining() const { return input_.size() - pos_; }
    void require_finished() const {
        if (pos_ != input_.size()) {
            throw JournalFormatError("trailing bytes after journal record body");
        }
    }

private:
    void require(std::size_t count) const {
        if (pos_ > input_.size() || count > input_.size() - pos_) {
            throw JournalFormatError("truncated journal record");
        }
    }
    std::span<const std::uint8_t> input_;
    std::size_t pos_{0U};
};

// ---------------------------------------------------------------------------
// File format constants
// ---------------------------------------------------------------------------

constexpr std::uint8_t kRecordKindEntry = 1U;
constexpr std::uint8_t kRecordKindCheckpoint = 2U;
// The suite-tagged checkpoint record kind (see journal.hpp's
// kJournalCheckpointSuiteEd25519V1/kJournalCheckpointSuiteMlDsa65V1) - a
// NEW kind rather than extending kRecordKindCheckpoint's body, since that
// body's 112-byte fixed layout has no room to grow without breaking
// already-written records (Reader::require_finished() would reject the new
// length). Journal::open()'s replay understands both kinds; only
// checkpoint_mldsa65() ever writes this one - checkpoint() keeps writing
// kRecordKindCheckpoint exactly as before.
constexpr std::uint8_t kRecordKindCheckpointSuiteV1 = 3U;
// Generous headroom over the real max entry body (~550 bytes) and the real
// checkpoint bodies (112 bytes for kRecordKindCheckpoint; up to ~3.3KB for
// kRecordKindCheckpointSuiteV1's ML-DSA-65 case) - bounded so a corrupted
// length field fails fast rather than driving an unbounded allocation.
constexpr std::uint32_t kMaxRecordBodyLength = 16384U;

constexpr std::array<std::uint8_t, 4> kHeadMagic = {'T', 'P', 'J', 'H'};
constexpr std::uint16_t kHeadFormatVersion = 1;
// The suite-tagged head-pointer format - written only by checkpoint_mldsa65()
// (checkpoint() keeps writing version 1, byte-for-byte identical to before).
// decode_head() accepts both; see HeadPointer's comment.
constexpr std::uint16_t kHeadFormatVersionSuiteV1 = 2;

// Domain-separates checkpoint signatures from anything else Ed25519 might
// ever sign in this codebase (defense in depth against cross-protocol
// signature reuse), matching the domain-separation spirit of
// identity.hpp's encode_derivation_info().
constexpr std::string_view kCheckpointDomainTag = "tradep2p-journal-checkpoint-v1";
// A DISTINCT domain tag from the one above, not a reuse of it - the
// suite-tagged encoding below embeds an extra field (suite_id), and this
// codebase's convention is that any change to what's actually being signed
// gets a new domain label, never an ambiguous shared one (see receipt.hpp's
// kReceiptSuiteEd25519MlDsa65HybridV1 comment for the same reasoning).
constexpr std::string_view kCheckpointSuiteDomainTag = "tradep2p-journal-checkpoint-suite-v1";

const JournalHash kGenesisHash{}; // 32 zero bytes; not a secret, just a fixed anchor

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

JournalHash sha256_impl(std::span<const std::uint8_t> data) {
    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) {
        throw_openssl_error("failed to allocate EVP_MD_CTX for SHA-256");
    }
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        throw_openssl_error("EVP_DigestInit_ex (SHA-256) failed");
    }
    if (!data.empty() && EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1) {
        throw_openssl_error("EVP_DigestUpdate (SHA-256) failed");
    }
    JournalHash out{};
    unsigned int out_len = 0U;
    if (EVP_DigestFinal_ex(ctx.get(), out.data(), &out_len) != 1 ||
        out_len != kJournalHashLength) {
        throw_openssl_error("EVP_DigestFinal_ex (SHA-256) failed");
    }
    return out;
}

// ---------------------------------------------------------------------------
// Canonical entry encoding: exactly the field order documented in
// journal.hpp. Shared by append() (to compute a new hash) and open()'s
// replay (to recompute and verify an existing one) - there is exactly one
// place this encoding is defined, so the two can never silently drift apart.
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> canonical_entry_bytes(std::uint64_t index,
                                                 const JournalEntryFields& fields) {
    if (fields.mediator_id.size() > kJournalMaxMediatorIdLength) {
        throw std::invalid_argument("journal mediator id exceeds maximum length");
    }
    Writer writer;
    writer.u64(index);
    writer.u16(fields.version);
    writer.bytes(fields.room_id);
    writer.bytes(fields.trade_id);
    writer.bytes_u16(fields.mediator_id);
    writer.bytes(fields.counterparty_fingerprint);
    writer.bytes(fields.terms_commitment);
    writer.u32(fields.round);
    writer.u8(static_cast<std::uint8_t>(fields.direction));
    writer.u16(static_cast<std::uint16_t>(fields.message_type));
    writer.bytes(fields.message_hash);
    writer.u8(static_cast<std::uint8_t>(fields.ack_state));
    writer.u8(static_cast<std::uint8_t>(fields.local_state));
    writer.u64(fields.timestamp);
    return writer.take();
}

JournalEntryFields decode_entry_fields(Reader& reader) {
    JournalEntryFields fields;
    fields.version = reader.u16();
    fields.room_id = reader.fixed<32U>();
    fields.trade_id = reader.fixed<kJournalTradeIdLength>();
    fields.mediator_id = reader.string_u16(kJournalMaxMediatorIdLength);
    fields.counterparty_fingerprint = reader.fixed<32U>();
    fields.terms_commitment = reader.fixed<kJournalHashLength>();
    fields.round = reader.u32();
    fields.direction = static_cast<MessageDirection>(reader.u8());
    fields.message_type = static_cast<MessageType>(reader.u16());
    fields.message_hash = reader.fixed<kJournalHashLength>();
    fields.ack_state = static_cast<AcknowledgementState>(reader.u8());
    fields.local_state = static_cast<SessionState>(reader.u8());
    fields.timestamp = reader.u64();
    return fields;
}

std::vector<std::uint8_t> checkpoint_signed_bytes(std::uint64_t index, const JournalHash& hash,
                                                   std::uint64_t signed_at) {
    Writer writer;
    writer.bytes_u16(kCheckpointDomainTag);
    writer.u64(index);
    writer.bytes(hash);
    writer.u64(signed_at);
    return writer.take();
}

std::vector<std::uint8_t> checkpoint_suite_signed_bytes(std::uint16_t suite_id, std::uint64_t index,
                                                         const JournalHash& hash,
                                                         std::uint64_t signed_at) {
    Writer writer;
    writer.bytes_u16(kCheckpointSuiteDomainTag);
    writer.u16(suite_id);
    writer.u64(index);
    writer.bytes(hash);
    writer.u64(signed_at);
    return writer.take();
}

std::size_t expected_checkpoint_signature_length(std::uint16_t suite_id) {
    if (suite_id == kJournalCheckpointSuiteEd25519V1) {
        return kEd25519SignatureLength;
    }
    if (suite_id == kJournalCheckpointSuiteMlDsa65V1) {
        return kMlDsa65SignatureLength;
    }
    return 0U;
}

// ---------------------------------------------------------------------------
// Local-state transition validity, mirroring tradep2p::SessionState's legal
// transitions (mediator.hpp / mediator.cpp's advance_after_receipt()) at a
// coarse, round-agnostic level - see the honest-limits note in journal.hpp.
// ---------------------------------------------------------------------------

bool is_valid_transition(SessionState from, SessionState to) {
    if (from == to) {
        return true; // logging the same local state twice in a row is fine
    }
    switch (from) {
        case SessionState::WaitingForPeer:
            return to == SessionState::WaitingForSent || to == SessionState::Aborted;
        case SessionState::WaitingForSent:
            return to == SessionState::WaitingForReceived || to == SessionState::Aborted;
        case SessionState::WaitingForReceived:
            // Phase 6: WaitingForReceived -> WaitingForFeeSent no longer
            // happens directly - it now always passes through
            // WaitingForFinalReceiptAck first (see mediator.cpp's
            // advance_after_receipt()). WaitingForReceived -> Complete
            // still happens directly for the no-fee case, since by then the
            // final-tranche leg was already gated on entry, not on exit.
            return to == SessionState::WaitingForSent ||
                   to == SessionState::WaitingForFinalReceiptAck ||
                   to == SessionState::Complete || to == SessionState::Aborted;
        case SessionState::WaitingForFinalReceiptAck:
            return to == SessionState::WaitingForSent ||
                   to == SessionState::WaitingForFeeSent || to == SessionState::Aborted;
        case SessionState::WaitingForFeeSent:
            // WaitingForFeeSent -> Complete happens directly unless the
            // operator opted into require_fee_confirmation (mediator.hpp),
            // in which case it passes through WaitingForFeeConfirmation
            // first instead.
            return to == SessionState::Complete ||
                   to == SessionState::WaitingForFeeConfirmation ||
                   to == SessionState::Aborted;
        case SessionState::WaitingForFeeConfirmation:
            return to == SessionState::Complete || to == SessionState::Aborted;
        case SessionState::Complete:
        case SessionState::Aborted:
            return false; // terminal - a new trade_id starts its own history
    }
    return false;
}

std::string trade_id_hex(const TradeId& id) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const std::uint8_t byte : id) {
        out << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return out.str();
}

// ---------------------------------------------------------------------------
// Low-level POSIX file I/O - duplicated from keystore.cpp's convention
// (owner-only permissions set at creation time, fsync before rename, atomic
// tmp-then-rename replace) for the head-pointer file only; the main log is
// append-only and handled separately (see Journal::open()/append()).
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
            throw_errno("failed to write journal file contents");
        }
        written += static_cast<std::size_t>(n);
    }
    (void)::fsync(fd); // best-effort, matching keystore.cpp's documented posture
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

void write_replace_atomic(const std::string& path, std::span<const std::uint8_t> bytes) {
    ensure_parent_directory(path);
    const std::string tmp_path = path + ".tmp";
    ::unlink(tmp_path.c_str());

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
    ::chmod(path.c_str(), 0600);
    best_effort_fsync_parent_directory(path);
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

std::uint64_t now_unix_seconds() {
    return static_cast<std::uint64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
}

// ---------------------------------------------------------------------------
// Head-pointer file encode/decode.
// ---------------------------------------------------------------------------

// Unified across both head-pointer formats: `suite_id` is implicit
// (kJournalCheckpointSuiteEd25519V1) and `signature` always exactly
// kEd25519SignatureLength bytes for a version-1 file; a version-2 file
// carries `suite_id` explicitly and `signature` sized by whatever that
// suite needs. encode_head() below reproduces the ORIGINAL version-1 byte
// layout exactly (byte-for-byte) whenever suite_id is Ed25519, so
// checkpoint()'s output is unchanged by this generalization.
struct HeadPointer {
    std::uint16_t suite_id{kJournalCheckpointSuiteEd25519V1};
    std::uint64_t index{0};
    JournalHash hash{};
    std::uint64_t signed_at{0};
    std::vector<std::uint8_t> signature;
};

std::vector<std::uint8_t> encode_head(const HeadPointer& head) {
    Writer writer;
    writer.bytes(kHeadMagic);
    if (head.suite_id == kJournalCheckpointSuiteEd25519V1) {
        // Byte-identical to this file's original, pre-suite_id format.
        writer.u16(kHeadFormatVersion);
        writer.u64(head.index);
        writer.bytes(head.hash);
        writer.u64(head.signed_at);
        writer.bytes(std::span<const std::uint8_t>(head.signature));
    } else {
        writer.u16(kHeadFormatVersionSuiteV1);
        writer.u16(head.suite_id);
        writer.u64(head.index);
        writer.bytes(head.hash);
        writer.u64(head.signed_at);
        writer.bytes(std::span<const std::uint8_t>(head.signature));
    }
    return writer.take();
}

HeadPointer decode_head(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    const auto magic = reader.fixed<kHeadMagic.size()>();
    if (magic != kHeadMagic) {
        throw JournalFormatError("not a tradep2p journal head-pointer file (bad magic)");
    }
    const std::uint16_t version = reader.u16();
    HeadPointer head;
    if (version == kHeadFormatVersion) {
        head.suite_id = kJournalCheckpointSuiteEd25519V1;
        head.index = reader.u64();
        head.hash = reader.fixed<kJournalHashLength>();
        head.signed_at = reader.u64();
        const auto signature = reader.fixed<kEd25519SignatureLength>();
        head.signature.assign(signature.begin(), signature.end());
    } else if (version == kHeadFormatVersionSuiteV1) {
        head.suite_id = reader.u16();
        head.index = reader.u64();
        head.hash = reader.fixed<kJournalHashLength>();
        head.signed_at = reader.u64();
        const auto expected_length = expected_checkpoint_signature_length(head.suite_id);
        if (expected_length == 0U || reader.remaining() != expected_length) {
            throw JournalFormatError(
                "journal head-pointer signature length does not match its suite id");
        }
        head.signature = reader.bytes_remaining();
    } else {
        throw JournalFormatError("unsupported journal head-pointer format version");
    }
    reader.require_finished();
    return head;
}

} // namespace

JournalHash sha256(std::span<const std::uint8_t> data) { return sha256_impl(data); }

JournalHash sha256_terms_commitment(const TradeTerms& terms) {
    return sha256_impl(encode_terms(terms));
}

Journal::Journal(Journal&& other) noexcept
    : log_path_(std::move(other.log_path_)),
      head_path_(std::move(other.head_path_)),
      log_fd_(other.log_fd_),
      entries_(std::move(other.entries_)),
      chain_head_(other.chain_head_),
      last_checkpoint_index_(other.last_checkpoint_index_),
      has_checkpoint_(other.has_checkpoint_),
      last_state_by_trade_(std::move(other.last_state_by_trade_)) {
    other.log_fd_ = -1;
}

Journal& Journal::operator=(Journal&& other) noexcept {
    if (this != &other) {
        if (log_fd_ >= 0) {
            ::close(log_fd_);
        }
        log_path_ = std::move(other.log_path_);
        head_path_ = std::move(other.head_path_);
        log_fd_ = other.log_fd_;
        entries_ = std::move(other.entries_);
        chain_head_ = other.chain_head_;
        last_checkpoint_index_ = other.last_checkpoint_index_;
        has_checkpoint_ = other.has_checkpoint_;
        last_state_by_trade_ = std::move(other.last_state_by_trade_);
        other.log_fd_ = -1;
    }
    return *this;
}

Journal::~Journal() {
    if (log_fd_ >= 0) {
        ::close(log_fd_);
    }
}

Journal Journal::open(const std::string& log_path, const std::string& head_path,
                       const Ed25519PublicKey& local_history_public_key,
                       const std::optional<MlDsa65PublicKey>& local_history_public_key_mldsa65) {
    ensure_parent_directory(log_path);
    const int fd = ::open(log_path.c_str(), O_CREAT | O_RDWR | O_APPEND, 0600);
    if (fd < 0) {
        throw_errno("failed to open journal log '" + log_path + "'");
    }

    std::vector<std::uint8_t> raw;
    {
        // Read via pread-equivalent (lseek+read on a scratch position) so
        // the fd's O_APPEND write semantics are never disturbed - every
        // future write() through this fd still lands at the true EOF
        // regardless of what the read cursor did.
        off_t size = ::lseek(fd, 0, SEEK_END);
        if (size < 0) {
            ::close(fd);
            throw_errno("failed to determine journal log size");
        }
        raw.resize(static_cast<std::size_t>(size));
        if (!raw.empty()) {
            std::size_t total_read = 0U;
            while (total_read < raw.size()) {
                const ssize_t n = ::pread(fd, raw.data() + total_read, raw.size() - total_read,
                                          static_cast<off_t>(total_read));
                if (n < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    ::close(fd);
                    throw_errno("failed to read journal log");
                }
                if (n == 0) {
                    break; // shouldn't happen given the size we measured, but stop cleanly
                }
                total_read += static_cast<std::size_t>(n);
            }
            raw.resize(total_read);
        }
    }

    Journal journal;
    journal.log_path_ = log_path;
    journal.head_path_ = head_path;
    journal.log_fd_ = fd;
    journal.chain_head_ = kGenesisHash;

    // Replay: parse framed records in order. A torn trailing record (the
    // last write cut short by a crash) is tolerated - the file is
    // truncated back to the end of the last complete record and replay
    // continues from what remains, exactly the crash-safety property this
    // module exists to provide. Any EARLIER malformed record is fatal
    // (JournalFormatError) - only the very tail gets this leniency, since a
    // torn write can only ever land at the physical end of the file.
    std::unordered_map<std::string, SessionState> last_state_by_trade;
    std::size_t complete_length = 0U;
    std::size_t pos = 0U;
    bool torn_tail = false;

    while (pos < raw.size()) {
        if (raw.size() - pos < 5U) {
            torn_tail = true;
            break;
        }
        const std::uint8_t kind = raw[pos];
        const std::uint32_t body_length = (static_cast<std::uint32_t>(raw[pos + 1U]) << 24U) |
                                           (static_cast<std::uint32_t>(raw[pos + 2U]) << 16U) |
                                           (static_cast<std::uint32_t>(raw[pos + 3U]) << 8U) |
                                           static_cast<std::uint32_t>(raw[pos + 4U]);
        if (body_length > kMaxRecordBodyLength) {
            throw JournalFormatError("journal record body exceeds maximum allowed length");
        }
        const std::size_t body_start = pos + 5U;
        if (raw.size() - body_start < body_length) {
            torn_tail = true;
            break;
        }
        const std::size_t record_end = body_start + body_length;
        std::span<const std::uint8_t> body(raw.data() + body_start, body_length);

        if (kind == kRecordKindEntry) {
            Reader reader(body);
            const std::uint64_t index = reader.u64();
            const JournalEntryFields fields = decode_entry_fields(reader);
            const std::size_t content_end = reader.position();
            const auto previous_hash = reader.fixed<kJournalHashLength>();
            const auto entry_hash = reader.fixed<kJournalHashLength>();
            reader.require_finished();

            if (index != journal.entries_.size()) {
                throw JournalTamperError(
                    "journal entry index out of sequence (deleted, reordered, or inserted entry)");
            }
            if (previous_hash != journal.chain_head_) {
                throw JournalTamperError(
                    "journal chain link mismatch (entry does not follow the previous one)");
            }
            std::vector<std::uint8_t> combined(body.begin(), body.begin() + static_cast<std::ptrdiff_t>(content_end));
            combined.insert(combined.end(), previous_hash.begin(), previous_hash.end());
            const JournalHash recomputed = sha256_impl(combined);
            if (recomputed != entry_hash) {
                throw JournalTamperError(
                    "journal entry hash does not match its recomputation (content tampered)");
            }

            const std::string key = trade_id_hex(fields.trade_id);
            const auto previous_state_it = last_state_by_trade.find(key);
            if (previous_state_it == last_state_by_trade.end()) {
                if (fields.local_state != SessionState::WaitingForPeer) {
                    throw JournalTamperError(
                        "malformed local state transition: a trade's first journal entry "
                        "must begin at WaitingForPeer");
                }
            } else if (!is_valid_transition(previous_state_it->second, fields.local_state)) {
                throw JournalTamperError(
                    "malformed local state transition detected during journal replay");
            }
            last_state_by_trade[key] = fields.local_state;

            JournalEntry entry;
            entry.index = index;
            entry.fields = fields;
            entry.previous_hash = previous_hash;
            entry.entry_hash = entry_hash;
            journal.entries_.push_back(std::move(entry));
            journal.chain_head_ = entry_hash;
        } else if (kind == kRecordKindCheckpoint) {
            Reader reader(body);
            const std::uint64_t index = reader.u64();
            const auto hash = reader.fixed<kJournalHashLength>();
            const std::uint64_t signed_at = reader.u64();
            const auto signature = reader.fixed<kEd25519SignatureLength>();
            reader.require_finished();

            if (index >= journal.entries_.size()) {
                throw JournalTamperError(
                    "checkpoint references an entry index that has not occurred yet");
            }
            if (journal.entries_[index].entry_hash != hash) {
                throw JournalTamperError(
                    "checkpoint hash does not match the entry it claims to checkpoint");
            }
            if (journal.has_checkpoint_ && index < journal.last_checkpoint_index_) {
                throw JournalTamperError(
                    "checkpoint index moved backward (rollback to an older checkpoint "
                    "within the same log)");
            }
            const auto signed_bytes = checkpoint_signed_bytes(index, hash, signed_at);
            if (!ed25519_verify(local_history_public_key, signed_bytes, signature)) {
                throw JournalTamperError(
                    "checkpoint signature does not verify against the local-history public key");
            }
            journal.last_checkpoint_index_ = index;
            journal.has_checkpoint_ = true;
        } else if (kind == kRecordKindCheckpointSuiteV1) {
            Reader reader(body);
            const std::uint16_t suite_id = reader.u16();
            const std::uint64_t index = reader.u64();
            const auto hash = reader.fixed<kJournalHashLength>();
            const std::uint64_t signed_at = reader.u64();
            const auto expected_length = expected_checkpoint_signature_length(suite_id);
            if (expected_length == 0U || reader.remaining() != expected_length) {
                throw JournalFormatError(
                    "journal checkpoint signature length does not match its suite id");
            }
            const auto signature = reader.bytes_remaining();

            if (index >= journal.entries_.size()) {
                throw JournalTamperError(
                    "checkpoint references an entry index that has not occurred yet");
            }
            if (journal.entries_[index].entry_hash != hash) {
                throw JournalTamperError(
                    "checkpoint hash does not match the entry it claims to checkpoint");
            }
            if (journal.has_checkpoint_ && index < journal.last_checkpoint_index_) {
                throw JournalTamperError(
                    "checkpoint index moved backward (rollback to an older checkpoint "
                    "within the same log)");
            }
            const auto signed_bytes = checkpoint_suite_signed_bytes(suite_id, index, hash, signed_at);
            bool verified = false;
            if (suite_id == kJournalCheckpointSuiteMlDsa65V1) {
                if (!local_history_public_key_mldsa65.has_value()) {
                    throw JournalTamperError(
                        "journal contains an ML-DSA-65 checkpoint but no ML-DSA-65 "
                        "local-history public key was supplied to verify it against");
                }
                MlDsa65Signature fixed_signature{};
                std::copy(signature.begin(), signature.end(), fixed_signature.begin());
                verified = mldsa65_verify(*local_history_public_key_mldsa65, signed_bytes,
                                          fixed_signature);
            } else if (suite_id == kJournalCheckpointSuiteEd25519V1) {
                Ed25519Signature fixed_signature{};
                std::copy(signature.begin(), signature.end(), fixed_signature.begin());
                verified = ed25519_verify(local_history_public_key, signed_bytes, fixed_signature);
            } else {
                throw JournalFormatError("unknown journal checkpoint suite id");
            }
            if (!verified) {
                throw JournalTamperError(
                    "checkpoint signature does not verify against the local-history public key");
            }
            journal.last_checkpoint_index_ = index;
            journal.has_checkpoint_ = true;
        } else {
            throw JournalFormatError("unknown journal record kind");
        }

        pos = record_end;
        complete_length = pos;
    }

    if (torn_tail) {
        // Drop the incomplete tail so the next append() starts cleanly.
        // NOTE: do not manually ::close(fd) on this (or any later) error
        // path in this function - journal.log_fd_ already equals fd (set
        // above), so `journal`'s destructor closes it exactly once during
        // stack unwinding; closing it here too would be a double-close.
        if (::ftruncate(fd, static_cast<off_t>(complete_length)) != 0) {
            throw_errno("failed to truncate torn journal write");
        }
    }

    // Seed the live per-trade transition tracker from what replay found, so
    // a subsequent append() keeps validating against the true last state
    // rather than treating every trade as brand new.
    journal.last_state_by_trade_ = std::move(last_state_by_trade);

    // Cross-check the separate head-pointer file, if present, against what
    // replay actually found. This is what catches "an older copy of the
    // main log was restored, but the head-pointer file (or vice versa) was
    // left at its more-advanced value" - see the class comment on Journal
    // for the honest limit (both files rolled back together defeats this).
    bool head_existed = false;
    const std::vector<std::uint8_t> head_raw = read_file_all(head_path, head_existed);
    if (head_existed) {
        const HeadPointer head = decode_head(head_raw); // throws JournalFormatError
        bool head_verified = false;
        if (head.suite_id == kJournalCheckpointSuiteMlDsa65V1) {
            if (!local_history_public_key_mldsa65.has_value()) {
                throw JournalTamperError(
                    "journal head-pointer file is an ML-DSA-65 checkpoint but no ML-DSA-65 "
                    "local-history public key was supplied to verify it against");
            }
            const auto signed_bytes =
                checkpoint_suite_signed_bytes(head.suite_id, head.index, head.hash, head.signed_at);
            MlDsa65Signature fixed_signature{};
            std::copy(head.signature.begin(), head.signature.end(), fixed_signature.begin());
            head_verified =
                mldsa65_verify(*local_history_public_key_mldsa65, signed_bytes, fixed_signature);
        } else {
            const auto signed_bytes = checkpoint_signed_bytes(head.index, head.hash, head.signed_at);
            Ed25519Signature fixed_signature{};
            std::copy(head.signature.begin(), head.signature.end(), fixed_signature.begin());
            head_verified = ed25519_verify(local_history_public_key, signed_bytes, fixed_signature);
        }
        if (!head_verified) {
            throw JournalTamperError(
                "journal head-pointer file signature does not verify - "
                "possibly corrupted or forged independently of the main log");
        }
        if (!journal.has_checkpoint_ || head.index > journal.last_checkpoint_index_) {
            throw JournalRollbackError(
                "journal head-pointer file references a checkpoint further along than "
                "the main log replays to - the main log looks like an older copy of itself");
        }
        if (head.index < journal.entries_.size() &&
            journal.entries_[head.index].entry_hash != head.hash) {
            throw JournalTamperError(
                "journal head-pointer file's hash does not match the corresponding "
                "entry in the main log");
        }
    }

    return journal;
}

JournalEntry Journal::append(JournalEntryFields fields) {
    if (fields.timestamp == 0U) {
        fields.timestamp = now_unix_seconds();
    }

    const std::string key = trade_id_hex(fields.trade_id);
    const auto previous_state_it = last_state_by_trade_.find(key);
    if (previous_state_it == last_state_by_trade_.end()) {
        if (fields.local_state != SessionState::WaitingForPeer) {
            throw JournalTamperError(
                "malformed local state transition: a trade's first journal entry must "
                "begin at WaitingForPeer");
        }
    } else if (!is_valid_transition(previous_state_it->second, fields.local_state)) {
        // Defense in depth: this also protects a live caller from writing
        // an illegal transition into its own journal by mistake, not just
        // replay-time tamper detection - see the class comment on append().
        throw JournalTamperError("attempted to append an invalid local state transition");
    }

    const std::uint64_t index = entries_.size();
    const std::vector<std::uint8_t> content = canonical_entry_bytes(index, fields);
    std::vector<std::uint8_t> hash_input = content;
    hash_input.insert(hash_input.end(), chain_head_.begin(), chain_head_.end());
    const JournalHash entry_hash = sha256_impl(hash_input);

    Writer body_writer;
    body_writer.bytes(std::span<const std::uint8_t>(content));
    body_writer.bytes(chain_head_);
    body_writer.bytes(entry_hash);
    const std::vector<std::uint8_t> body = body_writer.take();

    Writer record_writer;
    record_writer.u8(kRecordKindEntry);
    record_writer.u32(static_cast<std::uint32_t>(body.size()));
    record_writer.bytes(std::span<const std::uint8_t>(body));
    write_all_and_sync(log_fd_, record_writer.take());

    JournalEntry entry;
    entry.index = index;
    entry.fields = fields;
    entry.previous_hash = chain_head_;
    entry.entry_hash = entry_hash;
    entries_.push_back(entry);
    chain_head_ = entry_hash;
    last_state_by_trade_[key] = fields.local_state;
    return entry;
}

void Journal::checkpoint(const Ed25519PrivateSeed& local_history_private_key) {
    if (entries_.empty()) {
        throw std::logic_error("cannot checkpoint a journal with no entries");
    }
    const std::uint64_t index = entries_.back().index;
    const JournalHash hash = chain_head_;
    const std::uint64_t signed_at = now_unix_seconds();
    const auto signed_bytes = checkpoint_signed_bytes(index, hash, signed_at);
    const Ed25519Signature signature = ed25519_sign(local_history_private_key, signed_bytes);

    Writer body_writer;
    body_writer.u64(index);
    body_writer.bytes(hash);
    body_writer.u64(signed_at);
    body_writer.bytes(signature);
    const std::vector<std::uint8_t> body = body_writer.take();

    Writer record_writer;
    record_writer.u8(kRecordKindCheckpoint);
    record_writer.u32(static_cast<std::uint32_t>(body.size()));
    record_writer.bytes(std::span<const std::uint8_t>(body));
    write_all_and_sync(log_fd_, record_writer.take());

    HeadPointer head;
    head.suite_id = kJournalCheckpointSuiteEd25519V1;
    head.index = index;
    head.hash = hash;
    head.signed_at = signed_at;
    head.signature.assign(signature.begin(), signature.end());
    write_replace_atomic(head_path_, encode_head(head));

    last_checkpoint_index_ = index;
    has_checkpoint_ = true;
}

void Journal::checkpoint_mldsa65(const MlDsa65PrivateSeed& local_history_private_key_mldsa65) {
    if (entries_.empty()) {
        throw std::logic_error("cannot checkpoint a journal with no entries");
    }
    const std::uint64_t index = entries_.back().index;
    const JournalHash hash = chain_head_;
    const std::uint64_t signed_at = now_unix_seconds();
    const auto signed_bytes = checkpoint_suite_signed_bytes(kJournalCheckpointSuiteMlDsa65V1, index,
                                                            hash, signed_at);
    const EvpPkeyPtr key = load_mldsa65_private_key(local_history_private_key_mldsa65);
    const MlDsa65Signature signature = mldsa65_sign(key.get(), signed_bytes);

    Writer body_writer;
    // Reserving the exact, statically-known total up front (2 + 8 + hash +
    // 8 + signature) is what actually matters here - not just performance.
    // Without it, GCC 15's -Wstringop-overflow static analysis mis-infers
    // the vector's post-growth capacity through this many inlined
    // push_back()s ahead of the bytes(hash) insert() below (a known GCC
    // false-positive class for this exact push-then-bulk-insert shape),
    // and reports (verified false) that a 6-byte region was overflowed by
    // a real 32-byte write. A single reserve() gives the optimizer an
    // exact, provable bound and removes the ambiguity outright, verified
    // by rebuilding: the warning is gone with this present, and the
    // resulting object code was already correct either way (insert()
    // always reallocates/grows correctly on its own) - this is a
    // diagnostic-clarity fix, not a correctness fix.
    body_writer.reserve(2U + 8U + hash.size() + 8U + signature.size());
    body_writer.u16(kJournalCheckpointSuiteMlDsa65V1);
    body_writer.u64(index);
    body_writer.bytes(hash);
    body_writer.u64(signed_at);
    body_writer.bytes(signature);
    const std::vector<std::uint8_t> body = body_writer.take();

    Writer record_writer;
    record_writer.u8(kRecordKindCheckpointSuiteV1);
    record_writer.u32(static_cast<std::uint32_t>(body.size()));
    record_writer.bytes(std::span<const std::uint8_t>(body));
    write_all_and_sync(log_fd_, record_writer.take());

    HeadPointer head;
    head.suite_id = kJournalCheckpointSuiteMlDsa65V1;
    head.index = index;
    head.hash = hash;
    head.signed_at = signed_at;
    head.signature.assign(signature.begin(), signature.end());
    write_replace_atomic(head_path_, encode_head(head));

    last_checkpoint_index_ = index;
    has_checkpoint_ = true;
}

std::optional<JournalEntry> Journal::latest_for_trade(const TradeId& trade_id) const {
    for (auto it = entries_.rbegin(); it != entries_.rend(); ++it) {
        if (it->fields.trade_id == trade_id) {
            return *it;
        }
    }
    return std::nullopt;
}

} // namespace tradep2p
