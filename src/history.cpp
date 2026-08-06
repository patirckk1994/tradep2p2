#include "tradep2p/history.hpp"

#include <openssl/crypto.h>
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
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// NOTE for reviewers / history_tests.cpp's grep-style network check: this
// file intentionally never includes secure_channel.hpp, dashboard_client.hpp,
// or any socket header (<sys/socket.h>, <netinet/*.h>, etc.), and never calls
// connect()/send()/SSL_*. Everything here is local file I/O and local AEAD
// encryption only - see history.hpp's "no network calls" security invariant.

namespace tradep2p {
namespace {

// ---------------------------------------------------------------------------
// Error helpers (mirrors identity.cpp/keystore.cpp/journal.cpp's private
// helpers - duplicated locally on purpose, matching this codebase's
// established convention of keeping each module's failure paths
// self-contained and independently auditable).
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

std::uint64_t now_unix_seconds() {
    return static_cast<std::uint64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
}

// ---------------------------------------------------------------------------
// Binary Writer/Reader, duplicated locally per this codebase's established
// per-module convention (see keystore.cpp/journal.cpp/room_persistence.cpp's
// own copies).
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
            throw std::invalid_argument("history field exceeds protocol limit");
        }
        u16(static_cast<std::uint16_t>(value.size()));
        out_.insert(out_.end(), value.begin(), value.end());
    }

    [[nodiscard]] std::vector<std::uint8_t> take() { return std::move(out_); }
    [[nodiscard]] const std::vector<std::uint8_t>& view() const { return out_; }

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
            throw HistoryFormatError("history field exceeds maximum allowed length");
        }
        require(length);
        std::string result(reinterpret_cast<const char*>(input_.data() + pos_), length);
        pos_ += length;
        return result;
    }
    [[nodiscard]] std::vector<std::uint8_t> bytes_u32(std::size_t max_len) {
        const auto length = static_cast<std::size_t>(u32());
        if (length > max_len) {
            throw HistoryFormatError("history payload exceeds maximum allowed length");
        }
        require(length);
        std::vector<std::uint8_t> result(input_.begin() + static_cast<std::ptrdiff_t>(pos_),
                                          input_.begin() + static_cast<std::ptrdiff_t>(pos_ + length));
        pos_ += length;
        return result;
    }
    [[nodiscard]] std::size_t position() const { return pos_; }
    void require_finished() const {
        if (pos_ != input_.size()) {
            throw HistoryFormatError("trailing bytes after history record");
        }
    }

private:
    void require(std::size_t count) const {
        if (pos_ > input_.size() || count > input_.size() - pos_) {
            throw HistoryFormatError("truncated history file");
        }
    }
    std::span<const std::uint8_t> input_;
    std::size_t pos_{0U};
};

// ---------------------------------------------------------------------------
// File format constants
// ---------------------------------------------------------------------------

constexpr std::array<std::uint8_t, 4> kMagic = {'T', 'P', 'C', 'H'}; // TradeP2P Counterparty History
constexpr std::size_t kAeadKeyLength = 32;   // ChaCha20-Poly1305 key
constexpr std::size_t kAeadNonceLength = 12; // IETF ChaCha20-Poly1305
constexpr std::size_t kAeadTagLength = 16;
// Generous headroom vs. a real payload (kHistoryMaxEntries entries at a few
// hundred bytes each, plus notes/evidence up to their own per-entry caps) -
// bounded so a corrupted length field fails fast rather than driving an
// unbounded allocation.
constexpr std::size_t kMaxCiphertextLength = 64UL * 1024UL * 1024UL;

// This module's own domain-separated identifier for deriving the AEAD key
// from the keystore's master secret under key_scope::kLocalHistory (see
// history.hpp's security-invariants comment for why sharing the label with
// the journal's checkpoint-signing key derivation is safe: HKDF's `info`
// parameter, which this identifier feeds into via derive_scoped_key(), is
// what keeps the two outputs independent).
constexpr std::string_view kAeadKeyIdentifier = "counterparty-history-store-v1";

// ---------------------------------------------------------------------------
// AEAD: ChaCha20-Poly1305 (IETF, 96-bit nonce, 128-bit tag) - the same
// primitive keystore.cpp uses, duplicated locally per this codebase's
// established per-module convention rather than shared.
// ---------------------------------------------------------------------------

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const noexcept { EVP_CIPHER_CTX_free(ctx); }
};
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

struct Sealed {
    std::vector<std::uint8_t> ciphertext;
    std::array<std::uint8_t, kAeadTagLength> tag{};
};

Sealed chacha20poly1305_seal(const DerivedKey& key,
                              const std::array<std::uint8_t, kAeadNonceLength>& nonce,
                              std::span<const std::uint8_t> aad,
                              std::span<const std::uint8_t> plaintext) {
    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw_openssl_error("failed to allocate AEAD cipher context");
    }
    if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
        throw_openssl_error("failed to initialize ChaCha20-Poly1305 cipher");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()),
                             nullptr) != 1) {
        throw_openssl_error("failed to set AEAD nonce length");
    }
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        throw_openssl_error("failed to set AEAD key/nonce");
    }

    int scratch_len = 0;
    if (!aad.empty() &&
        EVP_EncryptUpdate(ctx.get(), nullptr, &scratch_len, aad.data(),
                           static_cast<int>(aad.size())) != 1) {
        throw_openssl_error("failed to authenticate history associated data");
    }

    Sealed sealed;
    sealed.ciphertext.resize(plaintext.size());
    int written = 0;
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(ctx.get(), sealed.ciphertext.data(), &written, plaintext.data(),
                           static_cast<int>(plaintext.size())) != 1) {
        throw_openssl_error("failed to encrypt history payload");
    }
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), sealed.ciphertext.data() + written, &final_len) != 1) {
        throw_openssl_error("failed to finalize history encryption");
    }
    sealed.ciphertext.resize(static_cast<std::size_t>(written + final_len));

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG,
                             static_cast<int>(sealed.tag.size()), sealed.tag.data()) != 1) {
        throw_openssl_error("failed to obtain AEAD authentication tag");
    }
    return sealed;
}

// Throws HistoryAuthenticationError (never returns a partially-decrypted
// buffer) if the tag does not verify - the plaintext buffer is cleansed
// before the exception unwinds in every failure path, matching
// keystore.cpp's chacha20poly1305_open() discipline exactly.
std::vector<std::uint8_t> chacha20poly1305_open(
    const DerivedKey& key, const std::array<std::uint8_t, kAeadNonceLength>& nonce,
    std::span<const std::uint8_t> aad, std::span<const std::uint8_t> ciphertext,
    const std::array<std::uint8_t, kAeadTagLength>& tag) {
    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw_openssl_error("failed to allocate AEAD cipher context");
    }
    if (EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
        throw_openssl_error("failed to initialize ChaCha20-Poly1305 cipher");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()),
                             nullptr) != 1) {
        throw_openssl_error("failed to set AEAD nonce length");
    }
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        throw_openssl_error("failed to set AEAD key/nonce");
    }

    int scratch_len = 0;
    if (!aad.empty() &&
        EVP_DecryptUpdate(ctx.get(), nullptr, &scratch_len, aad.data(),
                           static_cast<int>(aad.size())) != 1) {
        throw_openssl_error("failed to authenticate history associated data");
    }

    std::vector<std::uint8_t> plaintext(ciphertext.size());
    int written = 0;
    if (!ciphertext.empty() &&
        EVP_DecryptUpdate(ctx.get(), plaintext.data(), &written, ciphertext.data(),
                           static_cast<int>(ciphertext.size())) != 1) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw HistoryAuthenticationError(
            "history authentication failed (wrong keystore or corrupted file)");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, static_cast<int>(tag.size()),
                             const_cast<std::uint8_t*>(tag.data())) != 1) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw_openssl_error("failed to set AEAD authentication tag");
    }

    int final_len = 0;
    const int ok = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + written, &final_len);
    if (ok != 1) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw HistoryAuthenticationError(
            "history authentication failed (wrong keystore or corrupted file)");
    }
    plaintext.resize(static_cast<std::size_t>(written + final_len));
    return plaintext;
}

// ---------------------------------------------------------------------------
// Entry / payload encode-decode
// ---------------------------------------------------------------------------

void encode_entry(Writer& writer, const CounterpartyHistoryEntry& entry) {
    writer.bytes(entry.fingerprint);
    writer.u8(static_cast<std::uint8_t>(entry.scope));
    writer.bytes_u16(entry.mediator_id, kHistoryMaxMediatorIdLength);
    writer.u64(entry.first_seen);
    writer.u64(entry.last_seen);
    writer.u64(entry.encounter_count);

    if (entry.outcome_labels.size() > std::numeric_limits<std::uint16_t>::max()) {
        throw std::invalid_argument("history entry has too many outcome labels");
    }
    writer.u16(static_cast<std::uint16_t>(entry.outcome_labels.size()));
    for (const LocalOutcome outcome : entry.outcome_labels) {
        writer.u8(static_cast<std::uint8_t>(outcome));
    }

    writer.u8(entry.locally_blocked ? 1U : 0U);

    if (entry.notes.size() > std::numeric_limits<std::uint16_t>::max()) {
        throw std::invalid_argument("history entry has too many notes");
    }
    writer.u16(static_cast<std::uint16_t>(entry.notes.size()));
    for (const HistoryNote& note : entry.notes) {
        writer.u64(note.recorded_at);
        writer.bytes_u16(note.text, kHistoryMaxNoteLength);
    }

    if (entry.evidence_hashes.size() > std::numeric_limits<std::uint16_t>::max()) {
        throw std::invalid_argument("history entry has too many evidence hashes");
    }
    writer.u16(static_cast<std::uint16_t>(entry.evidence_hashes.size()));
    for (const EvidenceHash& hash : entry.evidence_hashes) {
        writer.bytes(hash);
    }

    writer.u8(static_cast<std::uint8_t>(entry.confidence));
}

CounterpartyHistoryEntry decode_entry(Reader& reader) {
    CounterpartyHistoryEntry entry;
    entry.fingerprint = reader.fixed<kCounterpartyFingerprintLength>();
    const std::uint8_t scope_raw = reader.u8();
    if (scope_raw != static_cast<std::uint8_t>(FingerprintScope::PerMediator)) {
        throw HistoryFormatError("unknown fingerprint scope identifier");
    }
    entry.scope = static_cast<FingerprintScope>(scope_raw);
    entry.mediator_id = reader.string_u16(kHistoryMaxMediatorIdLength);
    entry.first_seen = reader.u64();
    entry.last_seen = reader.u64();
    entry.encounter_count = reader.u64();

    const auto outcome_count = static_cast<std::size_t>(reader.u16());
    entry.outcome_labels.reserve(outcome_count);
    for (std::size_t i = 0U; i < outcome_count; ++i) {
        const std::uint8_t raw = reader.u8();
        if (raw > static_cast<std::uint8_t>(LocalOutcome::Incomplete)) {
            throw HistoryFormatError("unknown local outcome identifier");
        }
        entry.outcome_labels.push_back(static_cast<LocalOutcome>(raw));
    }

    const std::uint8_t blocked_raw = reader.u8();
    if (blocked_raw > 1U) {
        throw HistoryFormatError("invalid locally_blocked flag");
    }
    entry.locally_blocked = blocked_raw == 1U;

    const auto note_count = static_cast<std::size_t>(reader.u16());
    entry.notes.reserve(note_count);
    for (std::size_t i = 0U; i < note_count; ++i) {
        HistoryNote note;
        note.recorded_at = reader.u64();
        note.text = reader.string_u16(kHistoryMaxNoteLength);
        entry.notes.push_back(std::move(note));
    }

    const auto evidence_count = static_cast<std::size_t>(reader.u16());
    entry.evidence_hashes.reserve(evidence_count);
    for (std::size_t i = 0U; i < evidence_count; ++i) {
        entry.evidence_hashes.push_back(reader.fixed<32U>());
    }

    const std::uint8_t confidence_raw = reader.u8();
    if (confidence_raw > static_cast<std::uint8_t>(ConfidenceLevel::High)) {
        throw HistoryFormatError("unknown confidence level identifier");
    }
    entry.confidence = static_cast<ConfidenceLevel>(confidence_raw);

    return entry;
}

std::vector<std::uint8_t> encode_payload(const std::vector<CounterpartyHistoryEntry>& entries) {
    Writer writer;
    if (entries.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument("history store has too many entries to encode");
    }
    writer.u32(static_cast<std::uint32_t>(entries.size()));
    for (const auto& entry : entries) {
        encode_entry(writer, entry);
    }
    return writer.take();
}

std::vector<CounterpartyHistoryEntry> decode_payload(std::span<const std::uint8_t> plaintext) {
    Reader reader(plaintext);
    const auto count = static_cast<std::size_t>(reader.u32());
    if (count > kHistoryMaxEntries) {
        throw HistoryFormatError("history store exceeds maximum allowed entry count");
    }
    std::vector<CounterpartyHistoryEntry> entries;
    entries.reserve(count);
    for (std::size_t i = 0U; i < count; ++i) {
        entries.push_back(decode_entry(reader));
    }
    reader.require_finished();
    return entries;
}

// ---------------------------------------------------------------------------
// Whole-file encode/decode. The header (magic + format version) doubles as
// the AEAD's associated data, matching keystore.cpp's convention of binding
// non-secret metadata into the AEAD tag so tampering with it is also
// detected, even though the header carries nothing secret here.
// ---------------------------------------------------------------------------

struct DecodedFile {
    std::uint16_t format_version{0};
    std::array<std::uint8_t, kAeadNonceLength> nonce{};
    std::vector<std::uint8_t> ciphertext;
    std::array<std::uint8_t, kAeadTagLength> tag{};
    std::vector<std::uint8_t> aad;
};

DecodedFile decode_file(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    const auto magic = reader.fixed<kMagic.size()>();
    if (magic != kMagic) {
        throw HistoryFormatError("not a tradep2p counterparty history file (bad magic)");
    }
    const std::uint16_t format_version = reader.u16();
    if (format_version != kHistoryFormatVersion) {
        throw HistoryFormatError("unsupported history file format version");
    }
    const std::size_t aad_length = reader.position();

    const auto nonce = reader.fixed<kAeadNonceLength>();
    auto ciphertext = reader.bytes_u32(kMaxCiphertextLength);
    const auto tag = reader.fixed<kAeadTagLength>();
    reader.require_finished();

    DecodedFile out;
    out.format_version = format_version;
    out.nonce = nonce;
    out.ciphertext = std::move(ciphertext);
    out.tag = tag;
    out.aad.assign(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(aad_length));
    return out;
}

// ---------------------------------------------------------------------------
// Atomic file I/O - same discipline as keystore.cpp/journal.cpp's
// write_replace_atomic() (0600, fsync, tmp-then-rename), duplicated locally.
// A single atomic-replace helper covers both "file does not exist yet" and
// "file already exists": rename() over a nonexistent destination simply
// creates it, so there is no separate O_CREAT|O_EXCL "first write" path the
// way keystore.hpp's create() needs (this store has no "already exists"
// error case to enforce - see history.hpp's class comment).
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
            throw_errno("failed to write history file contents");
        }
        written += static_cast<std::size_t>(n);
    }
    (void)::fsync(fd); // best-effort, matching keystore.cpp/journal.cpp's documented posture
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

// ---------------------------------------------------------------------------
// Hex helpers, mirroring protocol.cpp's id_to_hex/id_from_hex convention
// (lowercase hex, rejects an all-zero result - the same "never a valid
// identifier" convention room_id/client_id use, since journal.hpp documents
// all-zero as its own "unknown" sentinel for counterparty_fingerprint).
// Duplicated locally rather than shared, matching this codebase's existing
// per-module convention (see e.g. journal.cpp's own trade_id_hex()).
// ---------------------------------------------------------------------------

[[nodiscard]] int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

template <std::size_t N>
[[nodiscard]] std::string bytes_to_hex(const std::array<std::uint8_t, N>& bytes) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (const std::uint8_t byte : bytes) {
        stream << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return stream.str();
}

template <std::size_t N>
[[nodiscard]] std::array<std::uint8_t, N> bytes_from_hex(std::string_view text, const char* label) {
    if (text.size() != N * 2U) {
        throw std::invalid_argument(std::string(label) + " has wrong length");
    }
    std::array<std::uint8_t, N> result{};
    for (std::size_t i = 0U; i < N; ++i) {
        const int high = hex_value(text[i * 2U]);
        const int low = hex_value(text[i * 2U + 1U]);
        if (high < 0 || low < 0) {
            throw std::invalid_argument(std::string(label) + " is not hexadecimal");
        }
        result[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return result;
}

void reject_all_zero(std::span<const std::uint8_t> bytes, const char* label) {
    const bool all_zero = std::all_of(bytes.begin(), bytes.end(),
                                       [](std::uint8_t byte) { return byte == 0U; });
    if (all_zero) {
        throw std::invalid_argument(std::string(label) + " must not be zero");
    }
}

} // namespace

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

DisplayCategory classify_for_display(const std::optional<CounterpartyHistoryEntry>& entry) {
    if (!entry.has_value()) {
        return DisplayCategory::UnknownIdentity;
    }
    if (entry->locally_blocked) {
        return DisplayCategory::LocallyBlocked;
    }
    bool any_incomplete = false;
    bool any_successful = false;
    for (const LocalOutcome outcome : entry->outcome_labels) {
        if (outcome == LocalOutcome::Incomplete) {
            any_incomplete = true;
        } else if (outcome == LocalOutcome::Successful) {
            any_successful = true;
        }
    }
    // A defect is worth surfacing even if other encounters went fine - see
    // the conservative tie-break rationale in history.hpp's comment on
    // classify_for_display().
    if (any_incomplete) {
        return DisplayCategory::PreviousIncompleteInteraction;
    }
    if (any_successful) {
        return DisplayCategory::PreviousSuccessfulInteraction;
    }
    // A record can exist with zero actual encounters (a pre-emptive block
    // and/or note recorded purely from out-of-band information - see
    // get_or_create()). Such a record is not blocked and carries no
    // recorded outcome, so from a TRADING-history point of view this
    // counterparty has genuinely never been encountered; "previously
    // encountered" would overstate what is known, so this falls back to
    // unknown identity rather than claiming an encounter that never
    // happened. Observed via manual dashboard testing: a preemptively
    // noted-but-unblocked fingerprint must not display as "previously
    // encountered".
    if (entry->encounter_count == 0U) {
        return DisplayCategory::UnknownIdentity;
    }
    return DisplayCategory::PreviouslyEncountered;
}

std::uint64_t settlement_count(const CounterpartyHistoryEntry& entry) {
    return static_cast<std::uint64_t>(
        std::count(entry.outcome_labels.begin(), entry.outcome_labels.end(), LocalOutcome::Successful));
}

std::uint64_t incomplete_count(const CounterpartyHistoryEntry& entry) {
    return static_cast<std::uint64_t>(
        std::count(entry.outcome_labels.begin(), entry.outcome_labels.end(), LocalOutcome::Incomplete));
}

std::string fingerprint_to_hex(const CounterpartyFingerprint& fingerprint) {
    reject_all_zero(fingerprint, "counterparty fingerprint");
    return bytes_to_hex(fingerprint);
}

CounterpartyFingerprint fingerprint_from_hex(std::string_view text) {
    const auto result = bytes_from_hex<kCounterpartyFingerprintLength>(text, "counterparty fingerprint");
    reject_all_zero(result, "counterparty fingerprint");
    return result;
}

std::string evidence_hash_to_hex(const EvidenceHash& hash) { return bytes_to_hex(hash); }

EvidenceHash evidence_hash_from_hex(std::string_view text) {
    return bytes_from_hex<32U>(text, "evidence hash");
}

const char* local_outcome_name(LocalOutcome outcome) {
    switch (outcome) {
        case LocalOutcome::Unknown: return "unknown";
        case LocalOutcome::Successful: return "successful";
        case LocalOutcome::Incomplete: return "incomplete";
    }
    return "unknown";
}

const char* confidence_level_name(ConfidenceLevel level) {
    switch (level) {
        case ConfidenceLevel::Unknown: return "unknown";
        case ConfidenceLevel::Low: return "low";
        case ConfidenceLevel::Medium: return "medium";
        case ConfidenceLevel::High: return "high";
    }
    return "unknown";
}

const char* display_category_name(DisplayCategory category) {
    switch (category) {
        case DisplayCategory::UnknownIdentity: return "unknown identity";
        case DisplayCategory::PreviouslyEncountered: return "previously encountered";
        case DisplayCategory::PreviousSuccessfulInteraction: return "previous successful interaction";
        case DisplayCategory::PreviousIncompleteInteraction: return "previous incomplete interaction";
        case DisplayCategory::LocallyBlocked: return "locally blocked";
    }
    return "unknown identity";
}

// ---------------------------------------------------------------------------
// LocalCounterpartyHistory
// ---------------------------------------------------------------------------

LocalCounterpartyHistory LocalCounterpartyHistory::open(const std::string& path,
                                                         const IdentityKeystore& keystore) {
    // keystore.master_secret() itself throws std::logic_error if locked -
    // reused here rather than duplicating that check, so there is exactly
    // one place that decides "is this keystore usable right now".
    const DerivedKey aead_key =
        derive_scoped_key(keystore.master_secret(), key_scope::kLocalHistory, kAeadKeyIdentifier);

    LocalCounterpartyHistory history;
    history.path_ = path;
    history.aead_key_ = DerivedKey(aead_key.bytes());

    bool existed = false;
    const std::vector<std::uint8_t> raw = read_file_all(path, existed);
    if (!existed) {
        return history; // nothing on disk yet; entries_ starts empty
    }

    const DecodedFile decoded = decode_file(raw); // throws HistoryFormatError
    std::vector<std::uint8_t> plaintext = chacha20poly1305_open(
        history.aead_key_, decoded.nonce, decoded.aad, decoded.ciphertext,
        decoded.tag); // throws HistoryAuthenticationError
    history.entries_ = decode_payload(plaintext); // throws HistoryFormatError
    OPENSSL_cleanse(plaintext.data(), plaintext.size());

    return history;
}

void LocalCounterpartyHistory::persist() const {
    Writer header_writer;
    header_writer.bytes(kMagic);
    header_writer.u16(kHistoryFormatVersion);
    const std::vector<std::uint8_t>& aad = header_writer.view();

    const std::vector<std::uint8_t> plaintext_payload = encode_payload(entries_);

    std::array<std::uint8_t, kAeadNonceLength> nonce{};
    {
        const std::vector<std::uint8_t> nonce_bytes = random_bytes(kAeadNonceLength);
        std::copy(nonce_bytes.begin(), nonce_bytes.end(), nonce.begin());
    }

    const Sealed sealed = chacha20poly1305_seal(aead_key_, nonce, aad, plaintext_payload);

    Writer file_writer;
    file_writer.bytes(aad);
    file_writer.bytes(nonce);
    file_writer.u32(static_cast<std::uint32_t>(sealed.ciphertext.size()));
    file_writer.bytes(sealed.ciphertext);
    file_writer.bytes(sealed.tag);

    write_replace_atomic(path_, file_writer.take());
}

std::size_t LocalCounterpartyHistory::index_of(const CounterpartyFingerprint& fingerprint,
                                                const std::string& mediator_id) const {
    for (std::size_t i = 0U; i < entries_.size(); ++i) {
        if (entries_[i].fingerprint == fingerprint && entries_[i].mediator_id == mediator_id) {
            return i;
        }
    }
    return entries_.size();
}

CounterpartyHistoryEntry& LocalCounterpartyHistory::get_or_create(
    const CounterpartyFingerprint& fingerprint, const std::string& mediator_id, std::uint64_t now) {
    if (mediator_id.size() > kHistoryMaxMediatorIdLength) {
        throw std::invalid_argument("mediator id exceeds maximum length");
    }
    const std::size_t idx = index_of(fingerprint, mediator_id);
    if (idx != entries_.size()) {
        return entries_[idx];
    }
    if (entries_.size() >= kHistoryMaxEntries) {
        throw std::invalid_argument("counterparty history store is full");
    }
    CounterpartyHistoryEntry entry;
    entry.fingerprint = fingerprint;
    entry.scope = FingerprintScope::PerMediator;
    entry.mediator_id = mediator_id;
    entry.first_seen = now;
    entry.last_seen = now;
    entries_.push_back(std::move(entry));
    return entries_.back();
}

namespace {
void recompute_confidence(CounterpartyHistoryEntry& entry) {
    // An honest, non-manipulable-by-a-counterparty, purely local heuristic
    // about how well-backed THIS RECORD is - not a trust score about the
    // counterparty (see history.hpp's ConfidenceLevel comment). Evidence
    // hashes are the strongest signal available this phase (receipts do not
    // exist until phase 6); repeated encounters alone are weaker.
    if (entry.evidence_hashes.empty() && entry.encounter_count <= 1U) {
        entry.confidence = ConfidenceLevel::Unknown;
    } else if (entry.evidence_hashes.empty()) {
        entry.confidence = ConfidenceLevel::Low;
    } else if (entry.evidence_hashes.size() < 3U) {
        entry.confidence = ConfidenceLevel::Medium;
    } else {
        entry.confidence = ConfidenceLevel::High;
    }
}
} // namespace

const CounterpartyHistoryEntry& LocalCounterpartyHistory::record_encounter(
    const CounterpartyFingerprint& fingerprint, const std::string& mediator_id, LocalOutcome outcome,
    std::uint64_t now) {
    if (now == 0U) {
        now = now_unix_seconds();
    }
    CounterpartyHistoryEntry& entry = get_or_create(fingerprint, mediator_id, now);
    entry.last_seen = now;
    ++entry.encounter_count;
    if (outcome != LocalOutcome::Unknown && entry.outcome_labels.size() < kHistoryMaxOutcomesPerEntry) {
        entry.outcome_labels.push_back(outcome);
    }
    recompute_confidence(entry);
    persist();
    return entry;
}

const CounterpartyHistoryEntry& LocalCounterpartyHistory::set_blocked(
    const CounterpartyFingerprint& fingerprint, const std::string& mediator_id, bool blocked) {
    CounterpartyHistoryEntry& entry = get_or_create(fingerprint, mediator_id, now_unix_seconds());
    entry.locally_blocked = blocked;
    persist();
    return entry;
}

const CounterpartyHistoryEntry& LocalCounterpartyHistory::add_note(
    const CounterpartyFingerprint& fingerprint, const std::string& mediator_id, const std::string& text,
    std::uint64_t now) {
    if (text.size() > kHistoryMaxNoteLength) {
        throw std::invalid_argument("note text exceeds maximum length");
    }
    if (now == 0U) {
        now = now_unix_seconds();
    }
    CounterpartyHistoryEntry& entry = get_or_create(fingerprint, mediator_id, now);
    if (entry.notes.size() >= kHistoryMaxNotesPerEntry) {
        throw std::invalid_argument("counterparty already has the maximum number of notes");
    }
    entry.notes.push_back(HistoryNote{now, text});
    persist();
    return entry;
}

const CounterpartyHistoryEntry& LocalCounterpartyHistory::add_evidence_hash(
    const CounterpartyFingerprint& fingerprint, const std::string& mediator_id, const EvidenceHash& hash) {
    CounterpartyHistoryEntry& entry = get_or_create(fingerprint, mediator_id, now_unix_seconds());
    if (entry.evidence_hashes.size() >= kHistoryMaxEvidenceHashesPerEntry) {
        throw std::invalid_argument("counterparty already has the maximum number of evidence hashes");
    }
    entry.evidence_hashes.push_back(hash);
    recompute_confidence(entry);
    persist();
    return entry;
}

std::optional<CounterpartyHistoryEntry> LocalCounterpartyHistory::find(
    const CounterpartyFingerprint& fingerprint, const std::string& mediator_id) const {
    const std::size_t idx = index_of(fingerprint, mediator_id);
    if (idx == entries_.size()) {
        return std::nullopt;
    }
    return entries_[idx];
}

} // namespace tradep2p
