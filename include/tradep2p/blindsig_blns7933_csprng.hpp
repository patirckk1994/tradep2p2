#pragma once

// Cryptographically secure replacement for std::mt19937_64, which every
// module in this reference substrate (TrapGen's f,g sampling, sign()'s
// ffSampling draws) used up to this point - documented from the start as
// an explicitly known, unresolved gap (see blindsig_blns7933.hpp's
// generate() doc comment and README.md's own RNG caveat), never silently
// treated as good enough.
//
// Satisfies the standard UniformRandomBitGenerator requirements
// (result_type, operator(), min(), max()), so it is a drop-in replacement
// everywhere std::mt19937_64& was passed to std::uniform_int_distribution
// or read directly via rng() - no call site needs its own random-number
// USE to change, only the type it holds a reference to.
//
// Construction: seed 64 bytes from OpenSSL's RAND_bytes (or, for
// reproducible tests/diagnostics only, an explicit small integer seed -
// NOT a substitute for real entropy, purely for repeatable test runs,
// exactly analogous to how std::mt19937_64(seed) was used before this),
// then squeeze output via SHAKE256(seed || counter) in fixed-size blocks,
// incrementing counter and re-squeezing a fresh block whenever the current
// one is exhausted. This project's own existing FALCON wrapper
// (blindsig_falcon.cpp) already seeds a SHAKE256-based PRNG from
// RAND_bytes for exactly the same reason - this follows that same
// established pattern rather than inventing a different one.
//
// Why counter-based re-squeezing rather than one EVP_DigestFinalXOF call
// per output word: OpenSSL's EVP_MD_CTX interface does NOT support calling
// EVP_DigestFinalXOF() more than once per context to continue squeezing
// (verified empirically against the actual linked OpenSSL build before
// relying on it - a second call on the same context returns failure, not
// more output) - the full desired output length must be requested in one
// call. Re-absorbing seed||counter into a fresh context for each refill
// and incrementing counter is a standard, sound construction (comparable
// in spirit to counter-mode keystream generation from a keyed PRF) that
// works within that real constraint.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace tradep2p::blns7933 {

class CryptoRng {
public:
    using result_type = std::uint64_t;

    // Seeds from OpenSSL's CSPRNG (RAND_bytes) - the real, secure
    // constructor. Throws std::runtime_error if RAND_bytes fails.
    CryptoRng();

    // Deterministic, reproducible construction from a plain integer seed -
    // for tests and diagnostics ONLY, so runs stay reproducible across
    // machines and invocations. This is NOT cryptographically secure on
    // its own: a small integer seed carries far less entropy than real OS
    // randomness, exactly the same caveat std::mt19937_64(seed) always
    // carried. It exercises the identical SHAKE256-squeeze code path as
    // the real constructor above, unlike the previous std::mt19937_64
    // setup, where tests ran a structurally different generator than any
    // real usage would.
    explicit CryptoRng(std::uint64_t seed);

    ~CryptoRng();

    // Non-copyable: duplicating an RNG's internal state (a live SHAKE256
    // seed plus counter) would make two "independent" draws reproduce each
    // other - a real secrecy failure for any real use, not just a style
    // preference. Every existing call site already only ever takes rng by
    // reference, so this costs nothing in practice.
    CryptoRng(const CryptoRng&) = delete;
    CryptoRng& operator=(const CryptoRng&) = delete;
    CryptoRng(CryptoRng&&) noexcept;
    CryptoRng& operator=(CryptoRng&&) noexcept;

    [[nodiscard]] result_type operator()();

    static constexpr result_type min() { return 0; }
    static constexpr result_type max() { return UINT64_MAX; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    void refill();
};

} // namespace tradep2p::blns7933
