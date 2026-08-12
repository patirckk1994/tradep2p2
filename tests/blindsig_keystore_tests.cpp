#include "tradep2p/blindsig_falcon.hpp"
#include "tradep2p/blindsig_keystore.hpp"
#include "tradep2p/keystore.hpp" // KeystoreAlreadyExistsError / KeystoreAuthenticationError

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

using tradep2p::blindsig::BlindSigKeystore;
using tradep2p::blindsig::FalconKeyPair;
using tradep2p::blindsig::falcon_keygen;
using tradep2p::blindsig::kRingDegree;

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <typename ExceptionT, typename Fn>
void require_throws(Fn&& fn, const std::string& message) {
    try {
        fn();
    } catch (const ExceptionT&) {
        return;
    } catch (const std::exception& error) {
        throw std::runtime_error(message + " (wrong exception type thrown: " + error.what() + ")");
    }
    throw std::runtime_error(message + " (no exception thrown)");
}

std::vector<std::uint8_t> read_all(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        throw std::runtime_error("test helper: cannot open " + path.string());
    }
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(input),
                                      std::istreambuf_iterator<char>());
}

void write_all(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        throw std::runtime_error("test helper: cannot create " + path.string());
    }
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

std::filesystem::path make_temp_dir() {
    std::string tmpl = (std::filesystem::temp_directory_path() / "tp2p_blindsig_ks_test_XXXXXX").string();
    if (::mkdtemp(tmpl.data()) == nullptr) {
        throw std::runtime_error(std::string("mkdtemp failed: ") + std::strerror(errno));
    }
    return std::filesystem::path(tmpl);
}

std::array<std::uint16_t, kRingDegree> sample_b(std::uint16_t seed) {
    std::array<std::uint16_t, kRingDegree> result{};
    for (std::size_t i = 0; i < kRingDegree; ++i) {
        result[i] = static_cast<std::uint16_t>((seed + i * 41U) % 12289U);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Create -> unlock round trip: trapdoor, public key and b must all survive
// AEAD-encrypted-at-rest custody unchanged. Uses one real falcon_keygen()
// call shared across every test below (Zf(keygen) is not free, and no test
// here needs a distinct keypair from any other).
// ---------------------------------------------------------------------------

void test_create_unlock_round_trip(const std::filesystem::path& dir, const FalconKeyPair& keypair) {
    const auto path = dir / "roundtrip.bks";
    const auto b = sample_b(1);
    auto ks = BlindSigKeystore::create(path.string(), "correct horse battery staple", keypair, b);
    require(ks.is_unlocked(), "a freshly created blindsig keystore must be unlocked");
    require(ks.public_key().h == keypair.public_key.h, "create() must return the same public key given to it");
    require(ks.trapdoor().f == keypair.trapdoor.f, "create() must return the same trapdoor.f given to it");
    require(ks.trapdoor().g == keypair.trapdoor.g, "create() must return the same trapdoor.g given to it");
    require(ks.trapdoor().F == keypair.trapdoor.F, "create() must return the same trapdoor.F given to it");
    require(ks.trapdoor().G == keypair.trapdoor.G, "create() must return the same trapdoor.G given to it");
    require(ks.b() == b, "create() must return the same b given to it");

    auto unlocked = BlindSigKeystore::unlock(path.string(), "correct horse battery staple");
    require(unlocked.is_unlocked(), "unlock() must return an unlocked instance");
    require(unlocked.public_key().h == keypair.public_key.h, "public key must survive a create/unlock round trip");
    require(unlocked.trapdoor().f == keypair.trapdoor.f, "trapdoor.f must survive a create/unlock round trip");
    require(unlocked.trapdoor().g == keypair.trapdoor.g, "trapdoor.g must survive a create/unlock round trip");
    require(unlocked.trapdoor().F == keypair.trapdoor.F, "trapdoor.F must survive a create/unlock round trip");
    require(unlocked.trapdoor().G == keypair.trapdoor.G, "trapdoor.G must survive a create/unlock round trip");
    require(unlocked.b() == b, "b must survive a create/unlock round trip");
}

// ---------------------------------------------------------------------------
// Wrong passphrase is rejected as an authentication failure, and does not
// corrupt the file - the correct passphrase must still work afterward.
// ---------------------------------------------------------------------------

void test_wrong_passphrase_rejected(const std::filesystem::path& dir, const FalconKeyPair& keypair) {
    const auto path = dir / "wrongpass.bks";
    (void)BlindSigKeystore::create(path.string(), "correct-passphrase", keypair, sample_b(2));

    require_throws<tradep2p::KeystoreAuthenticationError>(
        [&] { (void)BlindSigKeystore::unlock(path.string(), "incorrect-passphrase"); },
        "unlocking a blindsig keystore with the wrong passphrase must fail with an authentication error");

    auto ok = BlindSigKeystore::unlock(path.string(), "correct-passphrase");
    require(ok.is_unlocked(), "the correct passphrase must still unlock after a prior failed attempt");
}

// ---------------------------------------------------------------------------
// Tampering the file's authenticated contents (here: the final byte, always
// part of the AEAD tag regardless of payload size - see encode in
// blindsig_keystore.cpp: aad || nonce || ciphertext_len || ciphertext || tag)
// must be rejected, never silently accepted.
// ---------------------------------------------------------------------------

void test_corrupted_file_rejected(const std::filesystem::path& dir, const FalconKeyPair& keypair) {
    const auto path = dir / "corrupted.bks";
    (void)BlindSigKeystore::create(path.string(), "aead-pass", keypair, sample_b(3));

    auto bytes = read_all(path);
    require(!bytes.empty(), "a real blindsig keystore file must not be empty");
    bytes.back() ^= 0x01U;
    write_all(path, bytes);

    require_throws<tradep2p::KeystoreAuthenticationError>(
        [&] { (void)BlindSigKeystore::unlock(path.string(), "aead-pass"); },
        "a tampered blindsig keystore file must be rejected as an authentication failure, not silently accepted");
}

// ---------------------------------------------------------------------------
// No create-if-missing path (deliberate, unlike lobby.cpp's operational-key
// loader - see blindsig_keystore.hpp's file comment): unlocking a path that
// was never created must fail, not silently generate a fresh trapdoor.
// ---------------------------------------------------------------------------

void test_unlock_missing_file_rejected(const std::filesystem::path& dir) {
    const auto path = dir / "does-not-exist.bks";
    require_throws<std::runtime_error>(
        [&] { (void)BlindSigKeystore::unlock(path.string(), "whatever"); },
        "unlocking a blindsig keystore path that was never created must fail, not auto-generate one");
}

// ---------------------------------------------------------------------------
// create() never silently overwrites an existing file (O_CREAT|O_EXCL, not
// a racy stat-then-write) - mirrors keystore_tests.cpp's own
// test_no_silent_overwrite for IdentityKeystore.
// ---------------------------------------------------------------------------

void test_create_no_silent_overwrite(const std::filesystem::path& dir, const FalconKeyPair& keypair) {
    const auto path = dir / "no-overwrite.bks";
    (void)BlindSigKeystore::create(path.string(), "first-pass", keypair, sample_b(4));

    require_throws<tradep2p::KeystoreAlreadyExistsError>(
        [&] { (void)BlindSigKeystore::create(path.string(), "second-pass", keypair, sample_b(5)); },
        "create() must refuse to overwrite an existing blindsig keystore file");

    // The original file must be untouched by the rejected attempt.
    auto still_original = BlindSigKeystore::unlock(path.string(), "first-pass");
    require(still_original.is_unlocked(), "the original file must remain intact after a rejected overwrite");
}

// ---------------------------------------------------------------------------
// lock() clears in-memory secret state; every accessor must then refuse
// rather than return stale or default-initialized data.
// ---------------------------------------------------------------------------

void test_locked_accessors_rejected(const std::filesystem::path& dir, const FalconKeyPair& keypair) {
    const auto path = dir / "locked.bks";
    auto ks = BlindSigKeystore::create(path.string(), "lock-pass", keypair, sample_b(6));
    require(ks.is_unlocked(), "freshly created keystore must start unlocked");

    ks.lock();
    require(!ks.is_unlocked(), "lock() must clear is_unlocked()");

    require_throws<std::logic_error>([&] { (void)ks.trapdoor(); },
                                      "trapdoor() on a locked blindsig keystore must throw");
    require_throws<std::logic_error>([&] { (void)ks.public_key(); },
                                      "public_key() on a locked blindsig keystore must throw");
    require_throws<std::logic_error>([&] { (void)ks.b(); },
                                      "b() on a locked blindsig keystore must throw");
}

} // namespace

int main() {
    std::filesystem::path dir;
    try {
        dir = make_temp_dir();
        const FalconKeyPair keypair = falcon_keygen();

        test_create_unlock_round_trip(dir, keypair);
        test_wrong_passphrase_rejected(dir, keypair);
        test_corrupted_file_rejected(dir, keypair);
        test_unlock_missing_file_rejected(dir);
        test_create_no_silent_overwrite(dir, keypair);
        test_locked_accessors_rejected(dir, keypair);

        std::error_code ignored;
        std::filesystem::remove_all(dir, ignored);

        std::cout << "blindsig keystore unit tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "blindsig keystore test failure: " << error.what() << '\n';
        if (!dir.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(dir, ignored);
        }
        return 1;
    }
}
