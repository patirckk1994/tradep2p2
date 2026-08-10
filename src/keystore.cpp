#include "tradep2p/keystore.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <memory>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace tradep2p {
namespace {

// ---------------------------------------------------------------------------
// Error helper (mirrors identity.cpp's private throw_openssl_error(), not
// exported from there, so duplicated locally on purpose - keeps this
// module's failure paths self-contained and independently auditable).
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
// Binary Writer/Reader for the keystore file format, matching the
// big-endian, length-prefixed conventions already used in
// protocol.cpp's Writer/Reader and identity.cpp's append_u8/append_u16 - the
// only difference is that Reader here throws KeystoreFormatError (not a
// bare std::runtime_error) on any structural problem, since "malformed
// keystore file" is a distinct, expected failure mode this module's callers
// need to catch separately from an AEAD authentication failure.
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

    void bytes_u16(std::span<const std::uint8_t> value) {
        if (value.size() > std::numeric_limits<std::uint16_t>::max()) {
            throw std::invalid_argument("keystore field exceeds u16 length prefix");
        }
        u16(static_cast<std::uint16_t>(value.size()));
        bytes(value);
    }

    void bytes_u32(std::span<const std::uint8_t> value) {
        if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
            throw std::invalid_argument("keystore field exceeds u32 length prefix");
        }
        u32(static_cast<std::uint32_t>(value.size()));
        bytes(value);
    }

    [[nodiscard]] const std::vector<std::uint8_t>& view() const { return out_; }
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
            (static_cast<std::uint16_t>(input_[pos_]) << 8U) |
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

    template <std::size_t N>
    [[nodiscard]] std::array<std::uint8_t, N> fixed() {
        require(N);
        std::array<std::uint8_t, N> result{};
        std::copy_n(input_.begin() + static_cast<std::ptrdiff_t>(pos_), N, result.begin());
        pos_ += N;
        return result;
    }

    [[nodiscard]] std::vector<std::uint8_t> bytes_u16(std::size_t max_len) {
        const auto length = static_cast<std::size_t>(u16());
        if (length > max_len) {
            throw KeystoreFormatError("keystore field exceeds maximum allowed length");
        }
        require(length);
        std::vector<std::uint8_t> result(
            input_.begin() + static_cast<std::ptrdiff_t>(pos_),
            input_.begin() + static_cast<std::ptrdiff_t>(pos_ + length));
        pos_ += length;
        return result;
    }

    [[nodiscard]] std::vector<std::uint8_t> bytes_u32(std::size_t max_len) {
        const auto length = static_cast<std::size_t>(u32());
        if (length > max_len) {
            throw KeystoreFormatError("keystore field exceeds maximum allowed length");
        }
        require(length);
        std::vector<std::uint8_t> result(
            input_.begin() + static_cast<std::ptrdiff_t>(pos_),
            input_.begin() + static_cast<std::ptrdiff_t>(pos_ + length));
        pos_ += length;
        return result;
    }

    [[nodiscard]] std::size_t position() const { return pos_; }

    void require_finished() const {
        if (pos_ != input_.size()) {
            throw KeystoreFormatError("trailing bytes after keystore record");
        }
    }

private:
    void require(std::size_t count) const {
        if (pos_ > input_.size() || count > input_.size() - pos_) {
            throw KeystoreFormatError("truncated keystore file");
        }
    }

    std::span<const std::uint8_t> input_;
    std::size_t pos_{0U};
};

// ---------------------------------------------------------------------------
// File format constants
// ---------------------------------------------------------------------------

constexpr std::array<std::uint8_t, 4> kMagic = {'T', 'P', 'K', 'S'};
constexpr std::uint8_t kPayloadVersion = 1;
// Generous but still bounded caps, so a corrupted/hostile length field fails
// fast via Reader::require() rather than driving an unbounded allocation.
// The real payload is 37 bytes (1 + 32 + 4); 4096 is pure headroom.
constexpr std::size_t kMaxKdfSaltLength = 256;
constexpr std::size_t kMaxCiphertextLength = 4096;

// ---------------------------------------------------------------------------
// Low-level POSIX file I/O: exclusive create, atomic tmp-then-rename
// replace, and a bare "read everything" helper. Mirrors the
// tmp-file-then-rename idiom already used by
// LobbyServer::Impl::write_state_snapshot() (src/lobby.cpp), but adds owner
// -only permissions set BEFORE the file is populated (via the mode argument
// to open(), not a post-hoc chmod) and an fsync before the rename, neither
// of which that display-only snapshot needed.
// ---------------------------------------------------------------------------

void ensure_parent_directory(const std::string& path) {
    const std::filesystem::path fs_path(path);
    if (fs_path.has_parent_path()) {
        std::error_code error;
        std::filesystem::create_directories(fs_path.parent_path(), error);
        // A genuine failure here (e.g. permission denied) will surface
        // again as an open() failure immediately after, with errno intact.
    }
}

// Best-effort: writes every byte, then fsyncs. fsync's return value is
// intentionally not treated as fatal - on some filesystems/platforms (e.g.
// certain overlay or network filesystems) fsync can be a no-op or
// unsupported, and this module would rather finish the write than claim a
// durability guarantee it cannot keep. This is the one documented place
// this module's "fsync if supported" promise is soft rather than absolute.
void write_all_and_sync(int fd, std::span<const std::uint8_t> bytes) {
    std::size_t written = 0U;
    while (written < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.data() + written, bytes.size() - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw_errno("failed to write keystore file contents");
        }
        written += static_cast<std::size_t>(n);
    }
    (void)::fsync(fd); // best-effort; see comment above
}

// Best-effort: fsyncing the containing directory helps ensure the rename
// itself (the directory-entry update) survives a crash on filesystems that
// support it. Not all do; failures here are silently ignored on purpose -
// this is pure defense-in-depth on top of the rename already being atomic
// from any reader's point of view.
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

// Creates a brand-new file at `path` and writes `bytes` to it. Uses
// O_CREAT|O_EXCL so "the file already exists" is detected atomically by the
// kernel (no separate stat-then-write race), and mode 0600 so the file is
// owner-only-readable/writable from the instant it is created, before a
// single byte of content lands in it.
void write_new_exclusive(const std::string& path, std::span<const std::uint8_t> bytes) {
    ensure_parent_directory(path);
    const int fd = ::open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) {
        if (errno == EEXIST) {
            throw KeystoreAlreadyExistsError("refusing to overwrite existing file: " + path);
        }
        throw_errno("failed to create file '" + path + "'");
    }
    try {
        write_all_and_sync(fd, bytes);
    } catch (...) {
        ::close(fd);
        ::unlink(path.c_str());
        throw;
    }
    if (::close(fd) != 0) {
        ::unlink(path.c_str());
        throw_errno("failed to close file '" + path + "'");
    }
}

// Writes `bytes` to a 0600 temporary file next to `path`, fsyncs it, then
// atomically renames it over `path` (which may or may not already exist -
// this is the "replace a file this keystore already owns" path, used by
// change_passphrase()/rotate_service_scoped_key(), never by create()).
// A crash at any point before the rename() call leaves the original `path`
// completely untouched, since rename() is the only step that ever touches
// it; a crash during/after rename() is atomic at the filesystem level (the
// directory entry either still points at the old inode or already points at
// the fully-written new one - there is no observable partial state).
void write_replace_atomic(const std::string& path, std::span<const std::uint8_t> bytes) {
    ensure_parent_directory(path);
    const std::string tmp_path = path + ".tmp";
    // Best-effort cleanup of a stale temp file left behind by a previous
    // crashed attempt; ignored if it doesn't exist. This module assumes at
    // most one writer touches a given keystore path at a time (matching the
    // existing single-writer-thread convention in lobby.cpp's own snapshot
    // writer) - it does not implement cross-process locking.
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
    // rename() preserves the temp file's mode (already 0600), so this is
    // redundant on POSIX - kept anyway as cheap, explicit defense-in-depth
    // against an unexpected umask/ACL interaction.
    ::chmod(path.c_str(), 0600);
    best_effort_fsync_parent_directory(path);
}

std::vector<std::uint8_t> read_file_all(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        throw std::runtime_error("cannot open keystore file: " + path);
    }
    input.seekg(0, std::ios::end);
    const auto size = input.tellg();
    if (size < 0) {
        throw std::runtime_error("cannot determine size of keystore file: " + path);
    }
    input.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    if (!data.empty()) {
        input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (static_cast<std::size_t>(input.gcount()) != data.size()) {
            throw std::runtime_error("failed to fully read keystore file: " + path);
        }
    }
    return data;
}

// ---------------------------------------------------------------------------
// Passphrase -> AEAD key derivation.
//
// Argon2id via OpenSSL 3.2+'s EVP_KDF is the primary, expected path against
// this repository's linked OpenSSL 3.5.5 (confirmed present: `openssl list
// -kdf-algorithms` includes ARGON2ID). PBKDF2-HMAC-SHA256 is wired in ONLY
// as a last-resort runtime fallback for a hypothetical OpenSSL 3.0/3.1 build
// that lacks Argon2id - the chosen algorithm is always recorded in the file
// itself (`kdf_algorithm`), so a keystore never silently changes meaning.
// ---------------------------------------------------------------------------

bool argon2id_available() {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
    if (kdf != nullptr) {
        EVP_KDF_free(kdf);
        return true;
    }
    // Fetch failure is an expected, not exceptional, outcome of this probe -
    // clear the error queue so it doesn't leak into an unrelated later
    // throw_openssl_error() call.
    ERR_clear_error();
    return false;
}

KdfAlgorithm choose_kdf_algorithm() {
    return argon2id_available() ? KdfAlgorithm::kArgon2id : KdfAlgorithm::kPbkdf2Sha256Fallback;
}

DerivedKey derive_key_argon2id(const std::string& passphrase, std::span<const std::uint8_t> salt,
                                std::uint32_t memcost_kib, std::uint32_t iterations,
                                std::uint32_t lanes) {
    EvpKdfPtr kdf(EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr));
    if (!kdf) {
        throw_openssl_error("failed to fetch Argon2id (requires OpenSSL 3.2+ with EVP_KDF support)");
    }
    EvpKdfCtxPtr kctx(EVP_KDF_CTX_new(kdf.get()));
    if (!kctx) {
        throw_openssl_error("failed to create Argon2id KDF context");
    }

    std::uint32_t local_iter = iterations;
    std::uint32_t local_memcost = memcost_kib;
    std::uint32_t local_lanes = lanes;

    std::array<OSSL_PARAM, 6> params{};
    std::size_t index = 0U;
    params[index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_PASSWORD, const_cast<char*>(passphrase.data()), passphrase.size());
    params[index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, const_cast<std::uint8_t*>(salt.data()), salt.size());
    params[index++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &local_iter);
    params[index++] =
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &local_memcost);
    params[index++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &local_lanes);
    params[index++] = OSSL_PARAM_construct_end();

    std::array<std::uint8_t, kKeystoreAeadKeyLength> out_bytes{};
    if (EVP_KDF_derive(kctx.get(), out_bytes.data(), out_bytes.size(), params.data()) <= 0) {
        OPENSSL_cleanse(out_bytes.data(), out_bytes.size());
        throw_openssl_error("Argon2id key derivation failed");
    }
    DerivedKey key(out_bytes);
    OPENSSL_cleanse(out_bytes.data(), out_bytes.size());
    return key;
}

DerivedKey derive_key_pbkdf2_fallback(const std::string& passphrase,
                                       std::span<const std::uint8_t> salt,
                                       std::uint32_t iterations) {
    std::array<std::uint8_t, kKeystoreAeadKeyLength> out_bytes{};
    if (PKCS5_PBKDF2_HMAC(passphrase.data(), static_cast<int>(passphrase.size()), salt.data(),
                          static_cast<int>(salt.size()), static_cast<int>(iterations),
                          EVP_sha256(), static_cast<int>(out_bytes.size()),
                          out_bytes.data()) != 1) {
        OPENSSL_cleanse(out_bytes.data(), out_bytes.size());
        throw_openssl_error("PBKDF2 fallback key derivation failed");
    }
    DerivedKey key(out_bytes);
    OPENSSL_cleanse(out_bytes.data(), out_bytes.size());
    return key;
}

DerivedKey derive_aead_key(KdfAlgorithm algorithm, const std::string& passphrase,
                            std::span<const std::uint8_t> salt, std::uint32_t memcost_kib,
                            std::uint32_t iterations, std::uint32_t lanes) {
    switch (algorithm) {
        case KdfAlgorithm::kArgon2id:
            return derive_key_argon2id(passphrase, salt, memcost_kib, iterations, lanes);
        case KdfAlgorithm::kPbkdf2Sha256Fallback:
            return derive_key_pbkdf2_fallback(passphrase, salt, iterations);
    }
    throw KeystoreFormatError("unknown KDF algorithm identifier in keystore file");
}

// ---------------------------------------------------------------------------
// AEAD: ChaCha20-Poly1305 (IETF, 96-bit nonce, 128-bit tag). Chosen to match
// this codebase's existing TLS 1.3 ciphersuite preference order
// (TLS_CHACHA20_POLY1305_SHA256 listed first in secure_channel.cpp's
// harden_context()); AES-256-GCM would have been an equally valid choice per
// the phase spec.
// ---------------------------------------------------------------------------

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const noexcept { EVP_CIPHER_CTX_free(ctx); }
};
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

struct Sealed {
    std::vector<std::uint8_t> ciphertext;
    std::array<std::uint8_t, kKeystoreAeadTagLength> tag{};
};

Sealed chacha20poly1305_seal(const DerivedKey& key,
                              const std::array<std::uint8_t, kKeystoreAeadNonceLength>& nonce,
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
        throw_openssl_error("failed to authenticate keystore associated data");
    }

    Sealed sealed;
    sealed.ciphertext.resize(plaintext.size());
    int written = 0;
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(ctx.get(), sealed.ciphertext.data(), &written, plaintext.data(),
                           static_cast<int>(plaintext.size())) != 1) {
        throw_openssl_error("failed to encrypt keystore payload");
    }
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), sealed.ciphertext.data() + written, &final_len) != 1) {
        throw_openssl_error("failed to finalize keystore encryption");
    }
    sealed.ciphertext.resize(static_cast<std::size_t>(written + final_len));

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG,
                             static_cast<int>(sealed.tag.size()), sealed.tag.data()) != 1) {
        throw_openssl_error("failed to obtain AEAD authentication tag");
    }
    return sealed;
}

// Throws KeystoreAuthenticationError (never returns a partially-decrypted
// buffer) if the tag does not verify. The plaintext buffer is cleansed
// before the exception unwinds in every failure path below - a caller must
// never be able to observe decrypted bytes that failed authentication.
std::vector<std::uint8_t> chacha20poly1305_open(
    const DerivedKey& key, const std::array<std::uint8_t, kKeystoreAeadNonceLength>& nonce,
    std::span<const std::uint8_t> aad, std::span<const std::uint8_t> ciphertext,
    const std::array<std::uint8_t, kKeystoreAeadTagLength>& tag) {
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
        throw_openssl_error("failed to authenticate keystore associated data");
    }

    std::vector<std::uint8_t> plaintext(ciphertext.size());
    int written = 0;
    if (!ciphertext.empty() &&
        EVP_DecryptUpdate(ctx.get(), plaintext.data(), &written, ciphertext.data(),
                           static_cast<int>(ciphertext.size())) != 1) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw KeystoreAuthenticationError(
            "keystore authentication failed (wrong passphrase or corrupted file)");
    }

    // The tag must be set before EVP_DecryptFinal_ex, which is the call
    // that actually performs the verification.
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, static_cast<int>(tag.size()),
                             const_cast<std::uint8_t*>(tag.data())) != 1) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw_openssl_error("failed to set AEAD authentication tag");
    }

    int final_len = 0;
    const int ok = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + written, &final_len);
    if (ok != 1) {
        // Tag mismatch. Deliberately the SAME exception type/message as
        // above and as anywhere else authentication fails in this module -
        // "wrong passphrase" and "tampered ciphertext/nonce/tag" must be
        // indistinguishable to a caller, so neither timing nor error text
        // narrows a passphrase search.
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw KeystoreAuthenticationError(
            "keystore authentication failed (wrong passphrase or corrupted file)");
    }
    plaintext.resize(static_cast<std::size_t>(written + final_len));
    return plaintext;
}

// ---------------------------------------------------------------------------
// Encrypted payload (the plaintext that goes INTO the AEAD): a fixed-width
// 37-byte record. Kept intentionally simple/fixed-size rather than
// open-ended, so its own parsing can't itself become a source of malformed-
// input bugs.
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> encode_payload(const MasterSecret& secret,
                                          std::uint32_t key_generation) {
    Writer writer;
    writer.u8(kPayloadVersion);
    writer.bytes(secret.span());
    writer.u32(key_generation);
    return writer.take();
}

struct DecodedPayload {
    MasterSecret master_secret;
    std::uint32_t key_generation{0};
};

DecodedPayload decode_payload(std::span<const std::uint8_t> plaintext) {
    Reader reader(plaintext);
    const std::uint8_t version = reader.u8();
    if (version != kPayloadVersion) {
        throw KeystoreFormatError("unsupported keystore payload version");
    }
    const auto secret_bytes = reader.fixed<kMasterSecretLength>();
    const std::uint32_t key_generation = reader.u32();
    reader.require_finished();

    DecodedPayload out;
    out.master_secret = MasterSecret(secret_bytes);
    out.key_generation = key_generation;
    return out;
}

// ---------------------------------------------------------------------------
// Whole-file encode/decode. The header (everything up to and including the
// cached identity public key) doubles as the AEAD's associated data - see
// build_and_write()/load() below, which pass the exact same bytes to both
// the file writer and the AEAD seal/open calls.
// ---------------------------------------------------------------------------

struct DecodedFile {
    std::uint16_t format_version{0};
    std::array<std::uint8_t, kKeystoreIdentityIdLength> identity_id{};
    std::string alias;
    std::uint64_t created_at{0};
    KdfAlgorithm kdf_algorithm{KdfAlgorithm::kArgon2id};
    std::vector<std::uint8_t> kdf_salt;
    std::uint32_t kdf_memcost_kib{0};
    std::uint32_t kdf_iterations{0};
    std::uint32_t kdf_lanes{0};
    AeadAlgorithm aead_algorithm{AeadAlgorithm::kChaCha20Poly1305};
    Ed25519PublicKey identity_public_key{};
    std::array<std::uint8_t, kKeystoreAeadNonceLength> nonce{};
    std::vector<std::uint8_t> ciphertext;
    std::array<std::uint8_t, kKeystoreAeadTagLength> tag{};
    std::vector<std::uint8_t> aad;
};

DecodedFile decode_file(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);

    const auto magic = reader.fixed<kMagic.size()>();
    if (magic != kMagic) {
        throw KeystoreFormatError("not a tradep2p identity keystore file (bad magic)");
    }
    const std::uint16_t format_version = reader.u16();
    if (format_version != kKeystoreFormatVersion) {
        throw KeystoreFormatError("unsupported keystore format version");
    }
    const auto identity_id = reader.fixed<kKeystoreIdentityIdLength>();
    const auto alias_bytes = reader.bytes_u16(kKeystoreMaxAliasLength);
    const std::uint64_t created_at = reader.u64();

    const std::uint8_t kdf_algorithm_raw = reader.u8();
    if (kdf_algorithm_raw != static_cast<std::uint8_t>(KdfAlgorithm::kArgon2id) &&
        kdf_algorithm_raw != static_cast<std::uint8_t>(KdfAlgorithm::kPbkdf2Sha256Fallback)) {
        throw KeystoreFormatError("unknown KDF algorithm identifier");
    }
    const auto kdf_salt = reader.bytes_u16(kMaxKdfSaltLength);
    const std::uint32_t kdf_memcost_kib = reader.u32();
    const std::uint32_t kdf_iterations = reader.u32();
    const std::uint32_t kdf_lanes = reader.u32();

    const std::uint8_t aead_algorithm_raw = reader.u8();
    if (aead_algorithm_raw != static_cast<std::uint8_t>(AeadAlgorithm::kChaCha20Poly1305)) {
        throw KeystoreFormatError("unknown AEAD algorithm identifier");
    }
    const auto identity_public_key = reader.fixed<kEd25519PublicKeyLength>();

    // Everything read so far is the header/AAD portion.
    const std::size_t aad_length = reader.position();

    const auto nonce = reader.fixed<kKeystoreAeadNonceLength>();
    auto ciphertext = reader.bytes_u32(kMaxCiphertextLength);
    const auto tag = reader.fixed<kKeystoreAeadTagLength>();
    reader.require_finished();

    DecodedFile out;
    out.format_version = format_version;
    out.identity_id = identity_id;
    out.alias.assign(alias_bytes.begin(), alias_bytes.end());
    out.created_at = created_at;
    out.kdf_algorithm = static_cast<KdfAlgorithm>(kdf_algorithm_raw);
    out.kdf_salt = kdf_salt;
    out.kdf_memcost_kib = kdf_memcost_kib;
    out.kdf_iterations = kdf_iterations;
    out.kdf_lanes = kdf_lanes;
    out.aead_algorithm = static_cast<AeadAlgorithm>(aead_algorithm_raw);
    out.identity_public_key = identity_public_key;
    out.nonce = nonce;
    out.ciphertext = std::move(ciphertext);
    out.tag = tag;
    out.aad.assign(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(aad_length));
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// IdentityKeystore
// ---------------------------------------------------------------------------

IdentityKeystore IdentityKeystore::build_and_write(
    const std::string& path, const std::string& passphrase, const std::string& alias,
    std::uint64_t created_at, const std::array<std::uint8_t, kKeystoreIdentityIdLength>& identity_id,
    std::uint32_t key_generation, MasterSecret master_secret, bool allow_overwrite) {
    if (alias.size() > kKeystoreMaxAliasLength) {
        throw std::invalid_argument("alias exceeds maximum length");
    }

    const KdfAlgorithm kdf_algorithm = choose_kdf_algorithm();
    const std::vector<std::uint8_t> kdf_salt = random_bytes(kArgon2SaltLength);
    const std::uint32_t memcost_kib =
        kdf_algorithm == KdfAlgorithm::kArgon2id ? kArgon2DefaultMemCostKib : 0U;
    const std::uint32_t iterations = kdf_algorithm == KdfAlgorithm::kArgon2id
                                          ? kArgon2DefaultIterations
                                          : kPbkdf2FallbackIterations;
    const std::uint32_t lanes = kdf_algorithm == KdfAlgorithm::kArgon2id ? kArgon2DefaultLanes : 0U;

    // A fresh Argon2id salt every single time this is called (create,
    // change-passphrase, rotate) means a fresh AEAD key every time too, so
    // the nonce below never needs to worry about key reuse across calls -
    // it is still generated fresh regardless, since that is the correct
    // baseline discipline for any AEAD key, cached or not.
    const DerivedKey aead_key =
        derive_aead_key(kdf_algorithm, passphrase, kdf_salt, memcost_kib, iterations, lanes);

    // The cached "who am I" public key is re-derived from the master secret
    // every time this function runs, so it can never drift from whatever
    // master secret actually ends up inside the encrypted payload.
    const Ed25519KeyPair identity_pair =
        derive_ed25519_keypair(master_secret, key_scope::kKeystoreIdentity, "");

    const std::vector<std::uint8_t> plaintext_payload = encode_payload(master_secret, key_generation);

    std::array<std::uint8_t, kKeystoreAeadNonceLength> nonce{};
    {
        const std::vector<std::uint8_t> nonce_bytes = random_bytes(kKeystoreAeadNonceLength);
        std::copy(nonce_bytes.begin(), nonce_bytes.end(), nonce.begin());
    }

    Writer header_writer;
    header_writer.bytes(kMagic);
    header_writer.u16(kKeystoreFormatVersion);
    header_writer.bytes(identity_id);
    header_writer.bytes_u16(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(alias.data()), alias.size()));
    header_writer.u64(created_at);
    header_writer.u8(static_cast<std::uint8_t>(kdf_algorithm));
    header_writer.bytes_u16(kdf_salt);
    header_writer.u32(memcost_kib);
    header_writer.u32(iterations);
    header_writer.u32(lanes);
    header_writer.u8(static_cast<std::uint8_t>(AeadAlgorithm::kChaCha20Poly1305));
    header_writer.bytes(identity_pair.public_key);
    const std::vector<std::uint8_t>& aad = header_writer.view();

    const Sealed sealed = chacha20poly1305_seal(aead_key, nonce, aad, plaintext_payload);

    Writer file_writer;
    file_writer.bytes(aad);
    file_writer.bytes(nonce);
    file_writer.bytes_u32(sealed.ciphertext);
    file_writer.bytes(sealed.tag);
    const std::vector<std::uint8_t> file_bytes = file_writer.take();

    if (allow_overwrite) {
        write_replace_atomic(path, file_bytes);
    } else {
        write_new_exclusive(path, file_bytes);
    }

    IdentityKeystore result;
    result.path_ = path;
    result.format_version_ = kKeystoreFormatVersion;
    result.identity_id_ = identity_id;
    result.alias_ = alias;
    result.created_at_ = created_at;
    result.identity_public_key_ = identity_pair.public_key;
    result.key_generation_ = key_generation;
    result.kdf_algorithm_ = kdf_algorithm;
    result.kdf_salt_ = kdf_salt;
    result.kdf_memcost_kib_ = memcost_kib;
    result.kdf_iterations_ = iterations;
    result.kdf_lanes_ = lanes;
    result.master_secret_ = std::move(master_secret);
    return result;
}

IdentityKeystore IdentityKeystore::load(const std::string& path, const std::string& passphrase) {
    const std::vector<std::uint8_t> raw = read_file_all(path);
    const DecodedFile decoded = decode_file(raw); // throws KeystoreFormatError

    const DerivedKey aead_key =
        derive_aead_key(decoded.kdf_algorithm, passphrase, decoded.kdf_salt,
                         decoded.kdf_memcost_kib, decoded.kdf_iterations, decoded.kdf_lanes);

    std::vector<std::uint8_t> plaintext = chacha20poly1305_open(
        aead_key, decoded.nonce, decoded.aad, decoded.ciphertext, decoded.tag); // throws KeystoreAuthenticationError

    DecodedPayload payload = decode_payload(plaintext); // throws KeystoreFormatError
    OPENSSL_cleanse(plaintext.data(), plaintext.size());

    // Defense in depth: the cached public key is already covered by the
    // AEAD's associated data (so tampering with it alone would already have
    // failed authentication above), but re-derive and compare anyway so a
    // future refactor that narrows the AAD can't silently regress this
    // invariant without a test failing here first.
    const Ed25519KeyPair recomputed =
        derive_ed25519_keypair(payload.master_secret, key_scope::kKeystoreIdentity, "");
    if (!constant_time_equal(recomputed.public_key, decoded.identity_public_key)) {
        throw KeystoreAuthenticationError(
            "keystore authentication failed (wrong passphrase or corrupted file)");
    }

    IdentityKeystore result;
    result.path_ = path;
    result.format_version_ = decoded.format_version;
    result.identity_id_ = decoded.identity_id;
    result.alias_ = decoded.alias;
    result.created_at_ = decoded.created_at;
    result.identity_public_key_ = decoded.identity_public_key;
    result.key_generation_ = payload.key_generation;
    result.kdf_algorithm_ = decoded.kdf_algorithm;
    result.kdf_salt_ = decoded.kdf_salt;
    result.kdf_memcost_kib_ = decoded.kdf_memcost_kib;
    result.kdf_iterations_ = decoded.kdf_iterations;
    result.kdf_lanes_ = decoded.kdf_lanes;
    result.master_secret_ = std::move(payload.master_secret);
    return result;
}

IdentityKeystore IdentityKeystore::create(const std::string& path, const std::string& passphrase,
                                           const std::string& alias) {
    std::array<std::uint8_t, kKeystoreIdentityIdLength> identity_id{};
    {
        const std::vector<std::uint8_t> random_id = random_bytes(kKeystoreIdentityIdLength);
        std::copy(random_id.begin(), random_id.end(), identity_id.begin());
    }
    const std::uint64_t created_at =
        static_cast<std::uint64_t>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

    return build_and_write(path, passphrase, alias, created_at, identity_id, /*key_generation=*/0U,
                            generate_master_secret(), /*allow_overwrite=*/false);
}

IdentityKeystore IdentityKeystore::unlock(const std::string& path, const std::string& passphrase) {
    return load(path, passphrase);
}

PublicIdentity IdentityKeystore::display_public_identity(const std::string& path) {
    const std::vector<std::uint8_t> raw = read_file_all(path);
    const DecodedFile decoded = decode_file(raw); // no passphrase, no decryption attempted

    PublicIdentity out;
    out.identity_id = decoded.identity_id;
    out.alias = decoded.alias;
    out.created_at = decoded.created_at;
    out.identity_public_key = decoded.identity_public_key;
    // key_generation lives inside the encrypted payload (its integrity is
    // authenticated by the AEAD tag); it is not readable without a
    // passphrase, so it is not meaningful here. Callers that need the
    // authenticated value must unlock() and read key_generation() /
    // public_identity() from the resulting instance instead.
    out.key_generation = 0U;
    return out;
}

void IdentityKeystore::change_passphrase(const std::string& path, const std::string& old_passphrase,
                                          const std::string& new_passphrase) {
    IdentityKeystore existing = load(path, old_passphrase); // verifies old_passphrase + integrity
    if (!existing.master_secret_.has_value()) {
        throw std::logic_error("internal error: freshly loaded keystore was not unlocked");
    }
    // Re-encrypt under the new passphrase with a fresh salt/key/nonce and
    // atomically replace the file. No intermediate plaintext-adjacent file
    // is ever written - build_and_write()'s only disk write is the final,
    // fully-encrypted temp-then-rename record.
    (void)build_and_write(path, new_passphrase, existing.alias_, existing.created_at_,
                          existing.identity_id_, existing.key_generation_,
                          std::move(*existing.master_secret_), /*allow_overwrite=*/true);
}

void IdentityKeystore::export_encrypted_backup(const std::string& src_path,
                                                const std::string& dest_path,
                                                const std::string& passphrase) {
    // Proves the caller actually knows the passphrase (and that the source
    // file is not already corrupt) before producing a portable backup.
    // Nothing decrypted here is ever written anywhere - only the verbatim
    // encrypted bytes already on disk are copied.
    (void)load(src_path, passphrase);
    const std::vector<std::uint8_t> raw = read_file_all(src_path);
    write_new_exclusive(dest_path, raw); // refuses to clobber an existing dest_path
}

void IdentityKeystore::import_encrypted_backup(const std::string& src_path,
                                                const std::string& dest_path,
                                                const std::string& passphrase) {
    // Same verification as export - a malformed or tampered backup is
    // rejected here (KeystoreFormatError / KeystoreAuthenticationError) with
    // dest_path left completely untouched, never partially written.
    (void)load(src_path, passphrase);
    const std::vector<std::uint8_t> raw = read_file_all(src_path);
    write_new_exclusive(dest_path, raw); // refuses to clobber an existing dest_path
}

void IdentityKeystore::destroy(const std::string& path) {
    std::error_code size_error;
    const auto file_size = std::filesystem::file_size(path, size_error);
    if (size_error) {
        throw std::runtime_error("cannot stat keystore file for destruction: " + path + ": " +
                                  size_error.message());
    }

    const int fd = ::open(path.c_str(), O_WRONLY);
    if (fd < 0) {
        throw_errno("cannot open keystore file for destruction: " + path);
    }

    // Best-effort shred: a zero pass followed by a random pass, both
    // exactly the file's current length (so the file is never grown or
    // shrunk mid-overwrite). This is NOT a durability/security guarantee -
    // see the class doc comment in keystore.hpp and this phase's report for
    // the honest limitations (copy-on-write filesystems, SSD wear
    // leveling, filesystem journaling, and OS page/swap caches can all
    // retain a copy of the original bytes that this pass never touches).
    try {
        const std::vector<std::uint8_t> zeros(static_cast<std::size_t>(file_size), 0x00U);
        if (::lseek(fd, 0, SEEK_SET) == static_cast<off_t>(-1)) {
            throw_errno("failed to seek during keystore destruction");
        }
        write_all_and_sync(fd, zeros);

        const std::vector<std::uint8_t> random_pass = random_bytes(static_cast<std::size_t>(file_size));
        if (::lseek(fd, 0, SEEK_SET) == static_cast<off_t>(-1)) {
            throw_errno("failed to seek during keystore destruction");
        }
        write_all_and_sync(fd, random_pass);
    } catch (...) {
        ::close(fd);
        throw;
    }
    ::close(fd);

    if (::unlink(path.c_str()) != 0) {
        throw_errno("failed to remove keystore file after overwriting it: " + path);
    }
}

void IdentityKeystore::destroy() {
    destroy(path_);
    lock();
    path_.clear();
}

void IdentityKeystore::lock() noexcept {
    master_secret_.reset(); // optional::reset() destroys the MasterSecret, which self-cleanses
}

void IdentityKeystore::rotate_service_scoped_key(const std::string& passphrase) {
    if (!master_secret_.has_value()) {
        throw std::logic_error("cannot rotate a service-scoped key on a locked keystore");
    }
    // Verify `passphrase` actually matches what is currently on disk before
    // re-encrypting under it. Without this check, a mistyped passphrase
    // would silently become the keystore's new passphrase as a side effect
    // of rotation - this call must fail closed (KeystoreAuthenticationError)
    // instead, exactly like change_passphrase() does for its old_passphrase.
    (void)load(path_, passphrase);

    const std::uint32_t new_generation = key_generation_ + 1U;
    MasterSecret secret_copy(master_secret_->bytes());
    IdentityKeystore rebuilt = build_and_write(path_, passphrase, alias_, created_at_, identity_id_,
                                                new_generation, std::move(secret_copy),
                                                /*allow_overwrite=*/true);
    *this = std::move(rebuilt);
}

Ed25519KeyPair IdentityKeystore::derive_scoped_keypair(std::string_view label,
                                                        std::string_view identifier) const {
    if (!master_secret_.has_value()) {
        throw std::logic_error("cannot derive a scoped keypair from a locked keystore");
    }
    // Fold the current key generation into the identifier so
    // rotate_service_scoped_key() changes the derived key without touching
    // the master secret. Encoding: the generation is rendered as a
    // canonical (no leading zero) decimal integer immediately followed by
    // '#'. Splitting any combined string on its FIRST '#' recovers exactly
    // (generation, identifier) for any identifier value, so two distinct
    // (identifier, generation) pairs can never produce the same combined
    // string - the same injectivity argument identity.hpp's own
    // encode_derivation_info() makes for (label, identifier), just applied
    // one level up here.
    const std::string combined = std::to_string(key_generation_) + "#" + std::string(identifier);
    return derive_ed25519_keypair(*master_secret_, label, combined);
}

PublicIdentity IdentityKeystore::public_identity() const {
    PublicIdentity out;
    out.identity_id = identity_id_;
    out.alias = alias_;
    out.created_at = created_at_;
    out.identity_public_key = identity_public_key_;
    out.key_generation = key_generation_;
    return out;
}

const MasterSecret& IdentityKeystore::master_secret() const {
    if (!master_secret_.has_value()) {
        throw std::logic_error("keystore is locked");
    }
    return *master_secret_;
}

MlDsa65PublicKey IdentityKeystore::identity_public_key_mldsa65() const {
    return derive_mldsa65_keypair(master_secret(), key_scope::kKeystoreIdentityMlDsa65, "").public_key;
}

} // namespace tradep2p
