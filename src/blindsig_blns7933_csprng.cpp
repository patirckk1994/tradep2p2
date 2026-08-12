#include "tradep2p/blindsig_blns7933_csprng.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <cstring>
#include <stdexcept>
#include <string>

namespace tradep2p::blns7933 {
namespace {

// Same shape/quantity of entropy as this codebase's other real-key seed
// draws (e.g. blindsig_falcon.cpp's 48-byte FALCON RNG seed): generously
// more than the 256-bit security level anything here targets, cheap to
// afford once per CryptoRng construction.
constexpr std::size_t kRealSeedBytes = 64;

// Squeeze granularity: one EVP_DigestFinalXOF call produces this many
// bytes before a fresh seed||counter absorption is needed (see the
// header's comment on why - EVP_MD_CTX does not support multi-call
// squeezing). Large enough that refills are rare relative to the
// rejection-sampling draw volumes this module actually issues, small
// enough that a single refill's cost is negligible either way.
constexpr std::size_t kBufferBytes = 4096;

[[noreturn]] void throw_openssl_error(const std::string& message) {
    const unsigned long code = ERR_get_error();
    char buffer[256]{};
    if (code != 0U) {
        ERR_error_string_n(code, buffer, sizeof(buffer));
        throw std::runtime_error(message + ": " + buffer);
    }
    throw std::runtime_error(message);
}

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX* ctx) const noexcept { EVP_MD_CTX_free(ctx); }
};
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

} // namespace

struct CryptoRng::Impl {
    std::vector<std::uint8_t> seed;
    std::uint64_t counter = 0;
    std::vector<std::uint8_t> buffer = std::vector<std::uint8_t>(kBufferBytes);
    std::size_t pos = kBufferBytes; // forces a refill on the very first operator() call

    ~Impl() {
        OPENSSL_cleanse(seed.data(), seed.size());
        OPENSSL_cleanse(buffer.data(), buffer.size());
    }
};

CryptoRng::CryptoRng() : impl_(std::make_unique<Impl>()) {
    impl_->seed.resize(kRealSeedBytes);
    if (RAND_bytes(impl_->seed.data(), static_cast<int>(impl_->seed.size())) != 1) {
        throw_openssl_error("blindsig CryptoRng: RAND_bytes failed while seeding");
    }
}

CryptoRng::CryptoRng(std::uint64_t seed) : impl_(std::make_unique<Impl>()) {
    impl_->seed.resize(sizeof(seed));
    for (std::size_t i = 0; i < sizeof(seed); ++i) {
        impl_->seed[i] = static_cast<std::uint8_t>(seed >> (8U * i));
    }
}

CryptoRng::~CryptoRng() = default;
CryptoRng::CryptoRng(CryptoRng&&) noexcept = default;
CryptoRng& CryptoRng::operator=(CryptoRng&&) noexcept = default;

void CryptoRng::refill() {
    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) {
        throw_openssl_error("blindsig CryptoRng: EVP_MD_CTX_new failed");
    }
    if (EVP_DigestInit_ex(ctx.get(), EVP_shake256(), nullptr) != 1) {
        throw_openssl_error("blindsig CryptoRng: EVP_DigestInit_ex(SHAKE256) failed");
    }
    if (EVP_DigestUpdate(ctx.get(), impl_->seed.data(), impl_->seed.size()) != 1) {
        throw_openssl_error("blindsig CryptoRng: EVP_DigestUpdate(seed) failed");
    }
    std::array<std::uint8_t, sizeof(std::uint64_t)> counter_bytes{};
    for (std::size_t i = 0; i < counter_bytes.size(); ++i) {
        counter_bytes[i] = static_cast<std::uint8_t>(impl_->counter >> (8U * i));
    }
    if (EVP_DigestUpdate(ctx.get(), counter_bytes.data(), counter_bytes.size()) != 1) {
        throw_openssl_error("blindsig CryptoRng: EVP_DigestUpdate(counter) failed");
    }
    if (EVP_DigestFinalXOF(ctx.get(), impl_->buffer.data(), impl_->buffer.size()) != 1) {
        throw_openssl_error("blindsig CryptoRng: EVP_DigestFinalXOF failed");
    }
    ++impl_->counter;
    impl_->pos = 0;
}

CryptoRng::result_type CryptoRng::operator()() {
    if (impl_->pos + sizeof(result_type) > impl_->buffer.size()) {
        refill();
    }
    result_type value = 0;
    std::memcpy(&value, impl_->buffer.data() + impl_->pos, sizeof(value));
    impl_->pos += sizeof(value);
    return value;
}

} // namespace tradep2p::blns7933
