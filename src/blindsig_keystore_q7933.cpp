#include "tradep2p/blindsig_keystore_q7933.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <span>
#include <utility>

#include <fcntl.h>
#include <unistd.h>

// Deliberately its own, independent implementation of blindsig_keystore.cpp's
// exact security pattern (Writer/Reader, KDF derivation, AEAD seal/open,
// atomic file writes), not a shared base or a reuse of that module's
// internal-linkage helpers - same reasoning as that file's own comment on
// why it doesn't share code with keystore.cpp either. This file's own
// Writer/Reader additionally carry i64/PolyQ support, since this payload's
// six trapdoor/public-key polynomials are int64_t-coefficient vectors of
// runtime-known length (the production degree, 512), not fixed-size
// std::array<uint16_t,...> like the FALCON keystore's fields.

namespace tradep2p::blindsig {
namespace {

using tradep2p::KeystoreAlreadyExistsError;
using tradep2p::KeystoreAuthenticationError;
using tradep2p::KeystoreFormatError;
using tradep2p::blns7933::NTRUTrapdoorGenerator;
using tradep2p::blns7933::Parameters;
using tradep2p::blns7933::PolyQ;
using tradep2p::blns7933::PublicKey;
using tradep2p::blns7933::RingArithmetic;
using tradep2p::blns7933::TrapdoorKey;

constexpr std::size_t kAeadKeyLength = 32;
constexpr std::size_t kAeadNonceLength = 12;
constexpr std::size_t kAeadTagLength = 16;
constexpr std::size_t kArgon2SaltLength = 16;
constexpr std::uint32_t kArgon2DefaultMemCostKib = 65536; // 64 MiB, RFC 9106 SS4 interactive default
constexpr std::uint32_t kArgon2DefaultIterations = 3;
constexpr std::uint32_t kArgon2DefaultLanes = 4;
constexpr std::uint32_t kPbkdf2FallbackIterations = 600000;

constexpr std::array<std::uint8_t, 4> kMagic = {'T', 'P', 'Q', '7'}; // TradeP2P Q7933
constexpr std::size_t kMaxKdfSaltLength = 256;
// Real payload is 1 (version) + 4 (degree) + 8 (modulus) + 6*512*8 (f,g,F,G,t,b
// as i64 coefficients) = 24,589 bytes; headroom for the same "fail fast on a
// hostile length field" reason as the FALCON keystore's own constant.
constexpr std::size_t kMaxCiphertextLength = 65536;

enum class KdfAlgorithm : std::uint8_t { kArgon2id = 1, kPbkdf2Sha256Fallback = 2 };
enum class AeadAlgorithm : std::uint8_t { kChaCha20Poly1305 = 1 };

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

std::vector<std::uint8_t> random_bytes(std::size_t count) {
    std::vector<std::uint8_t> out(count);
    if (!out.empty() && RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        throw_openssl_error("q7933 keystore: RAND_bytes failed");
    }
    return out;
}

// ---------------------------------------------------------------------
// Writer/Reader - same shape as blindsig_keystore.cpp's own, plus i64/poly
// support for this payload's runtime-length int64_t coefficient arrays.
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
    void i64(std::int64_t value) {
        const auto bits = static_cast<std::uint64_t>(value);
        for (int shift = 56; shift >= 0; shift -= 8) {
            out_.push_back(static_cast<std::uint8_t>((bits >> shift) & 0xffU));
        }
    }
    void poly(const PolyQ& value) {
        for (const auto coeff : value) {
            i64(coeff);
        }
    }
    void bytes(std::span<const std::uint8_t> value) { out_.insert(out_.end(), value.begin(), value.end()); }
    void bytes_u16(std::span<const std::uint8_t> value) {
        if (value.size() > std::numeric_limits<std::uint16_t>::max()) {
            throw std::invalid_argument("q7933 keystore field exceeds u16 length prefix");
        }
        out_.push_back(static_cast<std::uint8_t>((value.size() >> 8U) & 0xffU));
        out_.push_back(static_cast<std::uint8_t>(value.size() & 0xffU));
        bytes(value);
    }
    void bytes_u32(std::span<const std::uint8_t> value) {
        if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
            throw std::invalid_argument("q7933 keystore field exceeds u32 length prefix");
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
    [[nodiscard]] std::int64_t i64() {
        require(8U);
        std::uint64_t bits = 0U;
        for (int i = 0; i < 8; ++i) {
            bits = (bits << 8U) | input_[pos_++];
        }
        return static_cast<std::int64_t>(bits);
    }
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
    [[nodiscard]] std::vector<std::uint8_t> bytes_u16(std::size_t max_len) {
        const auto length = static_cast<std::size_t>(u16());
        if (length > max_len) {
            throw KeystoreFormatError("q7933 keystore field exceeds maximum allowed length");
        }
        require(length);
        std::vector<std::uint8_t> result(input_.begin() + static_cast<std::ptrdiff_t>(pos_),
                                          input_.begin() + static_cast<std::ptrdiff_t>(pos_ + length));
        pos_ += length;
        return result;
    }
    [[nodiscard]] std::vector<std::uint8_t> bytes_u32(std::size_t max_len) {
        const auto length = static_cast<std::size_t>(u32());
        if (length > max_len) {
            throw KeystoreFormatError("q7933 keystore field exceeds maximum allowed length");
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
            throw KeystoreFormatError("trailing bytes after q7933 keystore record");
        }
    }

private:
    void require(std::size_t count) const {
        if (pos_ > input_.size() || count > input_.size() - pos_) {
            throw KeystoreFormatError("truncated q7933 keystore file");
        }
    }
    std::span<const std::uint8_t> input_;
    std::size_t pos_{0U};
};

// ---------------------------------------------------------------------
// File I/O - same atomic-write discipline as blindsig_keystore.cpp.
// ---------------------------------------------------------------------

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
            throw_errno("failed to write q7933 keystore file contents");
        }
        written += static_cast<std::size_t>(n);
    }
    (void)::fsync(fd); // best-effort, matching keystore.cpp's own documented soft guarantee
}

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

std::vector<std::uint8_t> read_file_all(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        throw std::runtime_error("cannot open q7933 keystore file: " + path);
    }
    input.seekg(0, std::ios::end);
    const auto size = input.tellg();
    if (size < 0) {
        throw std::runtime_error("cannot determine size of q7933 keystore file: " + path);
    }
    input.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    if (!data.empty()) {
        input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (static_cast<std::size_t>(input.gcount()) != data.size()) {
            throw std::runtime_error("failed to fully read q7933 keystore file: " + path);
        }
    }
    return data;
}

// ---------------------------------------------------------------------
// KDF - same Argon2id-primary/PBKDF2-fallback discipline as
// blindsig_keystore.cpp.
// ---------------------------------------------------------------------

bool argon2id_available() {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
    if (kdf != nullptr) {
        EVP_KDF_free(kdf);
        return true;
    }
    ERR_clear_error();
    return false;
}

KdfAlgorithm choose_kdf_algorithm() {
    return argon2id_available() ? KdfAlgorithm::kArgon2id : KdfAlgorithm::kPbkdf2Sha256Fallback;
}

struct EvpKdfDeleter {
    void operator()(EVP_KDF* k) const noexcept { EVP_KDF_free(k); }
};
struct EvpKdfCtxDeleter {
    void operator()(EVP_KDF_CTX* c) const noexcept { EVP_KDF_CTX_free(c); }
};
using EvpKdfPtr = std::unique_ptr<EVP_KDF, EvpKdfDeleter>;
using EvpKdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, EvpKdfCtxDeleter>;

std::array<std::uint8_t, kAeadKeyLength> derive_key_argon2id(const std::string& passphrase,
                                                              std::span<const std::uint8_t> salt,
                                                              std::uint32_t memcost_kib,
                                                              std::uint32_t iterations, std::uint32_t lanes) {
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
    params[index++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                                          const_cast<char*>(passphrase.data()), passphrase.size());
    params[index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, const_cast<std::uint8_t*>(salt.data()), salt.size());
    params[index++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &local_iter);
    params[index++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &local_memcost);
    params[index++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &local_lanes);
    params[index++] = OSSL_PARAM_construct_end();

    std::array<std::uint8_t, kAeadKeyLength> out{};
    if (EVP_KDF_derive(kctx.get(), out.data(), out.size(), params.data()) <= 0) {
        OPENSSL_cleanse(out.data(), out.size());
        throw_openssl_error("Argon2id key derivation failed");
    }
    return out;
}

std::array<std::uint8_t, kAeadKeyLength> derive_key_pbkdf2_fallback(const std::string& passphrase,
                                                                     std::span<const std::uint8_t> salt,
                                                                     std::uint32_t iterations) {
    std::array<std::uint8_t, kAeadKeyLength> out{};
    if (PKCS5_PBKDF2_HMAC(passphrase.data(), static_cast<int>(passphrase.size()), salt.data(),
                          static_cast<int>(salt.size()), static_cast<int>(iterations), EVP_sha256(),
                          static_cast<int>(out.size()), out.data()) != 1) {
        OPENSSL_cleanse(out.data(), out.size());
        throw_openssl_error("PBKDF2 fallback key derivation failed");
    }
    return out;
}

std::array<std::uint8_t, kAeadKeyLength> derive_aead_key(KdfAlgorithm algorithm, const std::string& passphrase,
                                                          std::span<const std::uint8_t> salt,
                                                          std::uint32_t memcost_kib, std::uint32_t iterations,
                                                          std::uint32_t lanes) {
    switch (algorithm) {
        case KdfAlgorithm::kArgon2id:
            return derive_key_argon2id(passphrase, salt, memcost_kib, iterations, lanes);
        case KdfAlgorithm::kPbkdf2Sha256Fallback:
            return derive_key_pbkdf2_fallback(passphrase, salt, iterations);
    }
    throw KeystoreFormatError("unknown KDF algorithm identifier in q7933 keystore file");
}

// ---------------------------------------------------------------------
// AEAD - ChaCha20-Poly1305, same as blindsig_keystore.cpp.
// ---------------------------------------------------------------------

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const noexcept { EVP_CIPHER_CTX_free(ctx); }
};
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

struct Sealed {
    std::vector<std::uint8_t> ciphertext;
    std::array<std::uint8_t, kAeadTagLength> tag{};
};

Sealed chacha20poly1305_seal(const std::array<std::uint8_t, kAeadKeyLength>& key,
                              const std::array<std::uint8_t, kAeadNonceLength>& nonce,
                              std::span<const std::uint8_t> aad, std::span<const std::uint8_t> plaintext) {
    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw_openssl_error("failed to allocate AEAD cipher context");
    }
    if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
        throw_openssl_error("failed to initialize ChaCha20-Poly1305 cipher");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1) {
        throw_openssl_error("failed to set AEAD nonce length");
    }
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        throw_openssl_error("failed to set AEAD key/nonce");
    }
    int scratch_len = 0;
    if (!aad.empty() &&
        EVP_EncryptUpdate(ctx.get(), nullptr, &scratch_len, aad.data(), static_cast<int>(aad.size())) != 1) {
        throw_openssl_error("failed to authenticate q7933 keystore associated data");
    }
    Sealed sealed;
    sealed.ciphertext.resize(plaintext.size());
    int written = 0;
    if (!plaintext.empty() && EVP_EncryptUpdate(ctx.get(), sealed.ciphertext.data(), &written, plaintext.data(),
                                                 static_cast<int>(plaintext.size())) != 1) {
        throw_openssl_error("failed to encrypt q7933 keystore payload");
    }
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), sealed.ciphertext.data() + written, &final_len) != 1) {
        throw_openssl_error("failed to finalize q7933 keystore encryption");
    }
    sealed.ciphertext.resize(static_cast<std::size_t>(written + final_len));
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, static_cast<int>(sealed.tag.size()),
                             sealed.tag.data()) != 1) {
        throw_openssl_error("failed to obtain AEAD authentication tag");
    }
    return sealed;
}

std::vector<std::uint8_t> chacha20poly1305_open(const std::array<std::uint8_t, kAeadKeyLength>& key,
                                                 const std::array<std::uint8_t, kAeadNonceLength>& nonce,
                                                 std::span<const std::uint8_t> aad,
                                                 std::span<const std::uint8_t> ciphertext,
                                                 const std::array<std::uint8_t, kAeadTagLength>& tag) {
    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw_openssl_error("failed to allocate AEAD cipher context");
    }
    if (EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
        throw_openssl_error("failed to initialize ChaCha20-Poly1305 cipher");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1) {
        throw_openssl_error("failed to set AEAD nonce length");
    }
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        throw_openssl_error("failed to set AEAD key/nonce");
    }
    int scratch_len = 0;
    if (!aad.empty() &&
        EVP_DecryptUpdate(ctx.get(), nullptr, &scratch_len, aad.data(), static_cast<int>(aad.size())) != 1) {
        throw_openssl_error("failed to authenticate q7933 keystore associated data");
    }
    std::vector<std::uint8_t> plaintext(ciphertext.size());
    int written = 0;
    if (!ciphertext.empty() && EVP_DecryptUpdate(ctx.get(), plaintext.data(), &written, ciphertext.data(),
                                                  static_cast<int>(ciphertext.size())) != 1) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw KeystoreAuthenticationError("q7933 keystore authentication failed (wrong passphrase or corrupted file)");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, static_cast<int>(tag.size()),
                             const_cast<std::uint8_t*>(tag.data())) != 1) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw_openssl_error("failed to set AEAD authentication tag");
    }
    int final_len = 0;
    const int ok = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + written, &final_len);
    if (ok != 1) {
        // Same exception type/message regardless of cause (wrong passphrase
        // vs. tampered file) - see blindsig_keystore.cpp's identical reasoning.
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw KeystoreAuthenticationError("q7933 keystore authentication failed (wrong passphrase or corrupted file)");
    }
    plaintext.resize(static_cast<std::size_t>(written + final_len));
    return plaintext;
}

// ---------------------------------------------------------------------
// Payload: version + degree + modulus + f,g,F,G,t,b (each `degree` i64
// coefficients). degree/modulus are stored explicitly (not just implied
// by the payload version) so a corrupted or foreign-format file fails
// with a precise "degree mismatch" error instead of a generic truncation
// error partway through a 512-coefficient array read.
// ---------------------------------------------------------------------

constexpr std::uint8_t kPayloadVersion = 1;

std::vector<std::uint8_t> encode_payload(const TrapdoorKey& trapdoor, const PublicKey& public_key,
                                          const PolyQ& b) {
    Writer writer;
    writer.u8(kPayloadVersion);
    writer.u32(static_cast<std::uint32_t>(Parameters::degree));
    writer.i64(Parameters::modulus);
    writer.poly(trapdoor.f);
    writer.poly(trapdoor.g);
    writer.poly(trapdoor.F);
    writer.poly(trapdoor.G);
    writer.poly(public_key.t);
    writer.poly(b);
    return writer.take();
}

struct DecodedPayload {
    TrapdoorKey trapdoor;
    PublicKey public_key;
    PolyQ b;
};

DecodedPayload decode_payload(std::span<const std::uint8_t> plaintext) {
    Reader reader(plaintext);
    const std::uint8_t version = reader.u8();
    if (version != kPayloadVersion) {
        throw KeystoreFormatError("unsupported q7933 keystore payload version");
    }
    const std::uint32_t degree = reader.u32();
    if (degree != static_cast<std::uint32_t>(Parameters::degree)) {
        throw KeystoreFormatError("q7933 keystore payload has the wrong ring degree");
    }
    const std::int64_t modulus = reader.i64();
    if (modulus != Parameters::modulus) {
        throw KeystoreFormatError("q7933 keystore payload has the wrong ring modulus");
    }

    DecodedPayload out;
    out.trapdoor.f = reader.poly(degree);
    out.trapdoor.g = reader.poly(degree);
    out.trapdoor.F = reader.poly(degree);
    out.trapdoor.G = reader.poly(degree);
    out.public_key.t = reader.poly(degree);
    out.b = reader.poly(degree);
    reader.require_finished();
    return out;
}

// ---------------------------------------------------------------------
// Whole-file encode/decode. Header (magic..aead_algorithm) doubles as AAD.
// ---------------------------------------------------------------------

struct DecodedFile {
    std::uint16_t format_version{0};
    KdfAlgorithm kdf_algorithm{KdfAlgorithm::kArgon2id};
    std::vector<std::uint8_t> kdf_salt;
    std::uint32_t kdf_memcost_kib{0};
    std::uint32_t kdf_iterations{0};
    std::uint32_t kdf_lanes{0};
    std::array<std::uint8_t, kAeadNonceLength> nonce{};
    std::vector<std::uint8_t> ciphertext;
    std::array<std::uint8_t, kAeadTagLength> tag{};
    std::vector<std::uint8_t> aad;
};

DecodedFile decode_file(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    const auto magic = reader.fixed<kMagic.size()>();
    if (magic != kMagic) {
        throw KeystoreFormatError("not a tradep2p q7933 keystore file (bad magic)");
    }
    const std::uint16_t format_version = reader.u16();
    if (format_version != kQ7933KeystoreFormatVersion) {
        throw KeystoreFormatError("unsupported q7933 keystore format version");
    }
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

    const std::size_t aad_length = reader.position();

    const auto nonce = reader.fixed<kAeadNonceLength>();
    auto ciphertext = reader.bytes_u32(kMaxCiphertextLength);
    const auto tag = reader.fixed<kAeadTagLength>();
    reader.require_finished();

    DecodedFile out;
    out.format_version = format_version;
    out.kdf_algorithm = static_cast<KdfAlgorithm>(kdf_algorithm_raw);
    out.kdf_salt = kdf_salt;
    out.kdf_memcost_kib = kdf_memcost_kib;
    out.kdf_iterations = kdf_iterations;
    out.kdf_lanes = kdf_lanes;
    out.nonce = nonce;
    out.ciphertext = std::move(ciphertext);
    out.tag = tag;
    out.aad.assign(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(aad_length));
    return out;
}

// ---------------------------------------------------------------------
// Invariant validation, shared between create() (defense in depth against
// a caller bug persisting an already-broken keystore) and unlock() (the
// requirement this type actually exists for: a passphrase-correct file
// must still describe a genuine NTRU trapdoor before being trusted).
// ---------------------------------------------------------------------

void require_canonical(const RingArithmetic& ring, const PolyQ& value, const char* field_name) {
    if (value.size() != ring.degree()) {
        throw KeystoreFormatError(std::string("q7933 keystore: ") + field_name + " has the wrong degree");
    }
    const auto q = ring.modulus();
    for (const auto coeff : value) {
        if (coeff < 0 || coeff >= q) {
            throw KeystoreFormatError(std::string("q7933 keystore: ") + field_name +
                                      " contains a non-canonical coefficient");
        }
    }
}

void validate_invariants(const TrapdoorKey& trapdoor, const PublicKey& public_key, const PolyQ& b) {
    const RingArithmetic ring(Parameters::degree, Parameters::modulus);

    const auto require_degree = [&ring](const PolyQ& v, const char* name) {
        if (v.size() != ring.degree()) {
            throw KeystoreFormatError(std::string("q7933 keystore: trapdoor ") + name + " has the wrong degree");
        }
    };
    require_degree(trapdoor.f, "f");
    require_degree(trapdoor.g, "g");
    require_degree(trapdoor.F, "F");
    require_degree(trapdoor.G, "G");
    require_canonical(ring, public_key.t, "public key t");
    require_canonical(ring, b, "b");

    const NTRUTrapdoorGenerator generator(ring);
    if (!generator.verify_ntru_relation(trapdoor)) {
        throw KeystoreFormatError("q7933 keystore: trapdoor fails the exact fG-gF=q relation");
    }

    const PublicKey derived = generator.derive_public(trapdoor);
    if (!ring.equal(derived.t, public_key.t)) {
        throw KeystoreFormatError("q7933 keystore: stored public key t does not match f*g^-1 derived from the trapdoor");
    }
}

} // namespace

Q7933Keystore Q7933Keystore::create(const std::string& path, const std::string& passphrase,
                                     const TrapdoorKey& trapdoor, const PublicKey& public_key, const PolyQ& b) {
    validate_invariants(trapdoor, public_key, b);

    const KdfAlgorithm kdf_algorithm = choose_kdf_algorithm();
    const std::vector<std::uint8_t> kdf_salt = random_bytes(kArgon2SaltLength);
    const std::uint32_t memcost_kib = kdf_algorithm == KdfAlgorithm::kArgon2id ? kArgon2DefaultMemCostKib : 0U;
    const std::uint32_t iterations =
        kdf_algorithm == KdfAlgorithm::kArgon2id ? kArgon2DefaultIterations : kPbkdf2FallbackIterations;
    const std::uint32_t lanes = kdf_algorithm == KdfAlgorithm::kArgon2id ? kArgon2DefaultLanes : 0U;

    const auto aead_key = derive_aead_key(kdf_algorithm, passphrase, kdf_salt, memcost_kib, iterations, lanes);

    const std::vector<std::uint8_t> plaintext_payload = encode_payload(trapdoor, public_key, b);

    std::array<std::uint8_t, kAeadNonceLength> nonce{};
    {
        const std::vector<std::uint8_t> nonce_bytes = random_bytes(kAeadNonceLength);
        std::copy(nonce_bytes.begin(), nonce_bytes.end(), nonce.begin());
    }

    Writer header_writer;
    header_writer.bytes(kMagic);
    header_writer.u16(kQ7933KeystoreFormatVersion);
    header_writer.u8(static_cast<std::uint8_t>(kdf_algorithm));
    header_writer.bytes_u16(kdf_salt);
    header_writer.u32(memcost_kib);
    header_writer.u32(iterations);
    header_writer.u32(lanes);
    header_writer.u8(static_cast<std::uint8_t>(AeadAlgorithm::kChaCha20Poly1305));
    const std::vector<std::uint8_t>& aad = header_writer.view();

    const Sealed sealed = chacha20poly1305_seal(aead_key, nonce, aad, plaintext_payload);

    Writer file_writer;
    file_writer.bytes(aad);
    file_writer.bytes(nonce);
    file_writer.bytes_u32(sealed.ciphertext);
    file_writer.bytes(sealed.tag);
    write_new_exclusive(path, file_writer.take()); // throws KeystoreAlreadyExistsError if path exists

    Q7933Keystore result;
    result.path_ = path;
    result.trapdoor_ = trapdoor;
    result.public_key_ = public_key;
    result.b_ = b;
    return result;
}

Q7933Keystore Q7933Keystore::unlock(const std::string& path, const std::string& passphrase) {
    const std::vector<std::uint8_t> raw = read_file_all(path);
    const DecodedFile decoded = decode_file(raw); // throws KeystoreFormatError

    const auto aead_key = derive_aead_key(decoded.kdf_algorithm, passphrase, decoded.kdf_salt,
                                           decoded.kdf_memcost_kib, decoded.kdf_iterations, decoded.kdf_lanes);

    std::vector<std::uint8_t> plaintext = chacha20poly1305_open(
        aead_key, decoded.nonce, decoded.aad, decoded.ciphertext, decoded.tag); // throws KeystoreAuthenticationError

    DecodedPayload payload = decode_payload(plaintext); // throws KeystoreFormatError
    OPENSSL_cleanse(plaintext.data(), plaintext.size());

    // Passphrase was right and the file wasn't tampered with (AEAD tag
    // verified) - but a right-looking payload can still not be a genuine
    // trapdoor (a bug elsewhere, not an attack). Check before trusting it.
    validate_invariants(payload.trapdoor, payload.public_key, payload.b); // throws KeystoreFormatError

    Q7933Keystore result;
    result.path_ = path;
    result.trapdoor_ = std::move(payload.trapdoor);
    result.public_key_ = std::move(payload.public_key);
    result.b_ = std::move(payload.b);
    return result;
}

void Q7933Keystore::lock() noexcept {
    trapdoor_.reset(); // TrapdoorKey's own destructor cleanses f/g/F/G.
}

const TrapdoorKey& Q7933Keystore::trapdoor() const {
    if (!trapdoor_.has_value()) {
        throw std::logic_error("q7933 keystore is locked");
    }
    return *trapdoor_;
}

const PublicKey& Q7933Keystore::public_key() const {
    if (!trapdoor_.has_value()) {
        throw std::logic_error("q7933 keystore is locked");
    }
    return public_key_;
}

const PolyQ& Q7933Keystore::b() const {
    if (!trapdoor_.has_value()) {
        throw std::logic_error("q7933 keystore is locked");
    }
    return b_;
}

} // namespace tradep2p::blindsig
