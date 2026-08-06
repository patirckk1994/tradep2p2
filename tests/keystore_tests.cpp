#include "tradep2p/keystore.hpp"

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
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

// Runs `fn`, and requires that it throws exactly an ExceptionT (any other
// exception type, or no exception at all, is a test failure). Used
// throughout for the negative-test requirements from
// docs/identity-02-keystore.md (wrong passphrase, corrupted AEAD fields,
// malformed files, no-silent-overwrite, locked-state misuse).
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
    std::string tmpl = (std::filesystem::temp_directory_path() / "tp2p_keystore_test_XXXXXX").string();
    if (::mkdtemp(tmpl.data()) == nullptr) {
        throw std::runtime_error(std::string("mkdtemp failed: ") + std::strerror(errno));
    }
    return std::filesystem::path(tmpl);
}

// ---------------------------------------------------------------------------
// Round trip: create -> lock -> unlock -> verify keys match.
// ---------------------------------------------------------------------------

void test_create_lock_unlock_round_trip(const std::filesystem::path& dir) {
    const auto path = dir / "roundtrip.ks";
    auto ks = tradep2p::IdentityKeystore::create(path.string(), "correct horse battery staple", "alice");
    require(ks.is_unlocked(), "a freshly created keystore must be unlocked");
    require(ks.alias() == "alice", "alias must round-trip through create()");

    const tradep2p::Ed25519PublicKey original_pub = ks.identity_public_key();
    const auto original_secret = ks.master_secret().bytes();

    ks.lock();
    require(!ks.is_unlocked(), "lock() must clear is_unlocked()");

    auto unlocked = tradep2p::IdentityKeystore::unlock(path.string(), "correct horse battery staple");
    require(unlocked.is_unlocked(), "unlock() must return an unlocked instance");
    require(unlocked.alias() == "alice", "alias must survive an unlock() round trip");
    require(unlocked.identity_public_key() == original_pub,
            "identity public key must survive a lock/unlock round trip");
    require(unlocked.master_secret().bytes() == original_secret,
            "master secret bytes must survive a lock/unlock round trip");
}

// ---------------------------------------------------------------------------
// Wrong passphrase is rejected, without narrowing the search space (same
// exception type/message as any other authentication failure - see
// test_corrupted_aead_rejected() below for the tampered-file counterpart).
// ---------------------------------------------------------------------------

void test_wrong_passphrase_rejected(const std::filesystem::path& dir) {
    const auto path = dir / "wrongpass.ks";
    (void)tradep2p::IdentityKeystore::create(path.string(), "correct-passphrase", "bob");

    require_throws<tradep2p::KeystoreAuthenticationError>(
        [&] { (void)tradep2p::IdentityKeystore::unlock(path.string(), "incorrect-passphrase"); },
        "unlocking with the wrong passphrase must fail with an authentication error");

    // The right passphrase must still work - confirms the file itself is
    // intact and the previous failure was purely passphrase-related.
    auto ok = tradep2p::IdentityKeystore::unlock(path.string(), "correct-passphrase");
    require(ok.alias() == "bob", "the correct passphrase must still unlock after a prior failed attempt");
}

// ---------------------------------------------------------------------------
// Corrupted AEAD nonce/ciphertext/tag are each rejected as an authentication
// failure, never silently accepted and never silently "regenerating" a
// fresh identity. The file's fixed-size AEAD suffix is:
//   nonce(12) + ciphertext_len(4) + ciphertext(37) + tag(16) = 69 bytes
// (the 37-byte ciphertext length follows directly from the fixed 37-byte
// encrypted payload: 1 payload-version byte + 32-byte master secret + 4-byte
// key generation counter - see encode_payload() in src/keystore.cpp).
// ---------------------------------------------------------------------------

void test_corrupted_aead_rejected(const std::filesystem::path& dir) {
    const auto path = dir / "aead_source.ks";
    const std::string passphrase = "aead-pass";
    (void)tradep2p::IdentityKeystore::create(path.string(), passphrase);
    const auto original = read_all(path);

    constexpr std::size_t kSuffixLength = 12U + 4U + 37U + 16U;
    require(original.size() >= kSuffixLength,
            "a real keystore file must be at least as long as its fixed AEAD suffix");
    const std::size_t suffix_start = original.size() - kSuffixLength;

    auto corrupted_copy = [&](std::size_t offset_in_suffix) {
        std::vector<std::uint8_t> bytes = original;
        bytes[suffix_start + offset_in_suffix] ^= 0x01U;
        return bytes;
    };

    {
        const auto bad_path = dir / "aead_bad_nonce.ks";
        write_all(bad_path, corrupted_copy(0)); // first byte of the nonce
        require_throws<tradep2p::KeystoreAuthenticationError>(
            [&] { (void)tradep2p::IdentityKeystore::unlock(bad_path.string(), passphrase); },
            "a corrupted nonce must be rejected as an authentication failure");
    }
    {
        const auto bad_path = dir / "aead_bad_ciphertext.ks";
        write_all(bad_path, corrupted_copy(12U + 4U)); // first byte of the ciphertext
        require_throws<tradep2p::KeystoreAuthenticationError>(
            [&] { (void)tradep2p::IdentityKeystore::unlock(bad_path.string(), passphrase); },
            "corrupted ciphertext must be rejected as an authentication failure");
    }
    {
        const auto bad_path = dir / "aead_bad_tag.ks";
        write_all(bad_path, corrupted_copy(kSuffixLength - 1U)); // last byte = last byte of the tag
        require_throws<tradep2p::KeystoreAuthenticationError>(
            [&] { (void)tradep2p::IdentityKeystore::unlock(bad_path.string(), passphrase); },
            "a corrupted authentication tag must be rejected as an authentication failure");
    }

    // Untouched original must still be fine (sanity check on the test itself).
    auto still_ok = tradep2p::IdentityKeystore::unlock(path.string(), passphrase);
    require(still_ok.is_unlocked(), "the untouched original file must still unlock normally");
}

// ---------------------------------------------------------------------------
// change_passphrase() re-encrypts, the old passphrase stops working, the new
// one works, keys are preserved, and no leftover .tmp file remains.
// ---------------------------------------------------------------------------

void test_change_passphrase(const std::filesystem::path& dir) {
    const auto path = dir / "changepass.ks";
    auto ks = tradep2p::IdentityKeystore::create(path.string(), "old-pass", "carol");
    const tradep2p::Ed25519PublicKey original_pub = ks.identity_public_key();
    const auto original_secret = ks.master_secret().bytes();

    tradep2p::IdentityKeystore::change_passphrase(path.string(), "old-pass", "new-pass");

    require_throws<tradep2p::KeystoreAuthenticationError>(
        [&] { (void)tradep2p::IdentityKeystore::unlock(path.string(), "old-pass"); },
        "the old passphrase must no longer unlock the keystore after change_passphrase");

    auto reloaded = tradep2p::IdentityKeystore::unlock(path.string(), "new-pass");
    require(reloaded.identity_public_key() == original_pub,
            "identity public key must survive change_passphrase");
    require(reloaded.master_secret().bytes() == original_secret,
            "master secret must survive change_passphrase unchanged");
    require(reloaded.alias() == "carol", "alias must survive change_passphrase");

    const auto tmp_path = std::filesystem::path(path.string() + ".tmp");
    require(!std::filesystem::exists(tmp_path),
            "no leftover .tmp file must remain after a successful change_passphrase");

    // A rejected change_passphrase (wrong old passphrase) must not modify the file.
    require_throws<tradep2p::KeystoreAuthenticationError>(
        [&] { tradep2p::IdentityKeystore::change_passphrase(path.string(), "totally-wrong", "irrelevant"); },
        "change_passphrase with the wrong old passphrase must be rejected");
    auto still_ok = tradep2p::IdentityKeystore::unlock(path.string(), "new-pass");
    require(still_ok.identity_public_key() == original_pub,
            "a rejected change_passphrase attempt must not modify the file");
}

// ---------------------------------------------------------------------------
// Import/export round trip, including rejecting a tampered or malformed
// backup, and refusing to silently overwrite an existing destination.
// ---------------------------------------------------------------------------

void test_import_export_round_trip(const std::filesystem::path& dir) {
    const auto src = dir / "export_src.ks";
    const auto backup = dir / "export_backup.ks";
    const auto restored = dir / "export_restored.ks";
    const std::string passphrase = "backup-pass";

    auto ks = tradep2p::IdentityKeystore::create(src.string(), passphrase, "dave");
    const tradep2p::Ed25519PublicKey original_pub = ks.identity_public_key();
    const auto original_secret = ks.master_secret().bytes();

    tradep2p::IdentityKeystore::export_encrypted_backup(src.string(), backup.string(), passphrase);
    require(std::filesystem::exists(backup), "export_encrypted_backup must create the backup file");

    const auto backup_should_not_exist = dir / "export_backup_wrong_pass.ks";
    require_throws<tradep2p::KeystoreAuthenticationError>(
        [&] {
            tradep2p::IdentityKeystore::export_encrypted_backup(src.string(), backup_should_not_exist.string(),
                                                                 "wrong-pass");
        },
        "export_encrypted_backup must refuse to export under the wrong passphrase");
    require(!std::filesystem::exists(backup_should_not_exist),
            "a failed export must not leave a partial backup file behind");

    require_throws<tradep2p::KeystoreAlreadyExistsError>(
        [&] {
            tradep2p::IdentityKeystore::export_encrypted_backup(src.string(), backup.string(), passphrase);
        },
        "export_encrypted_backup must refuse to overwrite an existing destination file");

    tradep2p::IdentityKeystore::import_encrypted_backup(backup.string(), restored.string(), passphrase);
    auto reloaded = tradep2p::IdentityKeystore::unlock(restored.string(), passphrase);
    require(reloaded.identity_public_key() == original_pub,
            "imported keystore must have the same identity public key as the original");
    require(reloaded.master_secret().bytes() == original_secret,
            "imported keystore must have the same master secret as the original");
    require(reloaded.alias() == "dave", "imported keystore must preserve the alias");

    // Tampered backup (flip the final tag byte) must be rejected on import.
    auto tampered_bytes = read_all(backup);
    require(!tampered_bytes.empty(), "backup file must be non-empty");
    tampered_bytes.back() ^= 0x01U;
    const auto tampered_backup = dir / "export_backup_tampered.ks";
    write_all(tampered_backup, tampered_bytes);
    const auto restored_from_tampered = dir / "export_restored_from_tampered.ks";
    require_throws<tradep2p::KeystoreAuthenticationError>(
        [&] {
            tradep2p::IdentityKeystore::import_encrypted_backup(tampered_backup.string(),
                                                                 restored_from_tampered.string(), passphrase);
        },
        "import_encrypted_backup must reject a tampered backup file");
    require(!std::filesystem::exists(restored_from_tampered),
            "a rejected (tampered) import must not create the destination file");

    // A malformed (not-a-keystore-at-all) backup must also be rejected.
    const auto malformed_backup = dir / "export_backup_malformed.ks";
    write_all(malformed_backup, std::vector<std::uint8_t>{1, 2, 3, 4, 5});
    const auto restored_from_malformed = dir / "export_restored_from_malformed.ks";
    require_throws<tradep2p::KeystoreFormatError>(
        [&] {
            tradep2p::IdentityKeystore::import_encrypted_backup(malformed_backup.string(),
                                                                 restored_from_malformed.string(), passphrase);
        },
        "import_encrypted_backup must reject a malformed (non-keystore) backup file");
    require(!std::filesystem::exists(restored_from_malformed),
            "a rejected (malformed) import must not create the destination file");

    // Importing on top of an existing destination must also be refused.
    require_throws<tradep2p::KeystoreAlreadyExistsError>(
        [&] {
            tradep2p::IdentityKeystore::import_encrypted_backup(backup.string(), restored.string(), passphrase);
        },
        "import_encrypted_backup must refuse to overwrite an existing destination file");
}

// ---------------------------------------------------------------------------
// Atomicity: simulate the on-disk state that exists between the temp-file
// write and the rename (i.e. what a crash at that exact point, or a mocked-
// out rename() call, would leave behind) and verify the original file is
// completely untouched. Also verifies that a stray leftover temp file from
// such a "crash" does not interfere with a subsequent, real replace
// operation.
// ---------------------------------------------------------------------------

void test_atomicity_simulated_crash(const std::filesystem::path& dir) {
    const auto path = dir / "atomic.ks";
    const std::string passphrase = "atomic-pass";
    auto ks = tradep2p::IdentityKeystore::create(path.string(), passphrase, "atomic-alias");
    const tradep2p::Ed25519PublicKey original_pub = ks.identity_public_key();
    const auto original_bytes = read_all(path);

    // This is exactly the on-disk state that exists after
    // write_replace_atomic() has written+fsynced its temp file but before
    // rename() has run - whether reached by an actual process kill or by
    // mocking out rename(), the observable state for anything reading
    // `path` is identical, since `path` itself is never touched before
    // rename() executes.
    const auto tmp_path = std::filesystem::path(path.string() + ".tmp");
    write_all(tmp_path, std::vector<std::uint8_t>{'c', 'r', 'a', 's', 'h', 0, 1, 2, 3});
    require(std::filesystem::exists(tmp_path), "test setup: stray tmp file must exist");

    const auto bytes_with_stray_tmp = read_all(path);
    require(bytes_with_stray_tmp == original_bytes,
            "the presence of a stray .tmp file must not affect the real keystore file's contents");

    auto reloaded = tradep2p::IdentityKeystore::unlock(path.string(), passphrase);
    require(reloaded.identity_public_key() == original_pub,
            "the keystore must still unlock correctly after a simulated crash-before-rename");

    // A real replacing operation must still succeed despite the stray tmp
    // file (proving the "clean up a stale tmp before creating a new one"
    // logic works), and must not leave any tmp file behind afterward.
    tradep2p::IdentityKeystore::change_passphrase(path.string(), passphrase, "atomic-pass-2");
    require(!std::filesystem::exists(tmp_path),
            "no .tmp file should remain after a successful atomic replace, even if one existed before it started");

    auto reloaded2 = tradep2p::IdentityKeystore::unlock(path.string(), "atomic-pass-2");
    require(reloaded2.identity_public_key() == original_pub,
            "identity must be preserved across a real replace performed after a simulated crash");
}

// ---------------------------------------------------------------------------
// Permission check: the file must be owner-only (0600) on creation.
// ---------------------------------------------------------------------------

void test_owner_only_permissions(const std::filesystem::path& dir) {
    const auto path = dir / "perm.ks";
    (void)tradep2p::IdentityKeystore::create(path.string(), "perm-pass");

    struct stat file_stat {};
    require(::stat(path.string().c_str(), &file_stat) == 0, "stat() on a new keystore file must succeed");
    const mode_t permission_bits = file_stat.st_mode & 0777U;
    require(permission_bits == (S_IRUSR | S_IWUSR),
            "a newly created keystore file must have owner-only (0600) permissions");
}

// ---------------------------------------------------------------------------
// Malformed keystore files (truncated, wrong format version, garbage) are
// rejected with a structured KeystoreFormatError, never a crash and never a
// silent fallback - checked both via unlock() and via
// display_public_identity() (which must reject the same files without ever
// touching a passphrase/KDF).
// ---------------------------------------------------------------------------

void test_malformed_keystore_rejected(const std::filesystem::path& dir) {
    const auto valid_path = dir / "valid_for_corruption.ks";
    (void)tradep2p::IdentityKeystore::create(valid_path.string(), "some-pass");
    const auto valid_bytes = read_all(valid_path);
    require(valid_bytes.size() > 16U, "sanity: a real keystore file must have a nontrivial size");

    {
        const auto path = dir / "truncated.ks";
        write_all(path, std::vector<std::uint8_t>(valid_bytes.begin(), valid_bytes.begin() + 8));
        require_throws<tradep2p::KeystoreFormatError>(
            [&] { (void)tradep2p::IdentityKeystore::unlock(path.string(), "irrelevant"); },
            "a truncated keystore file must be rejected as a format error");
    }
    {
        const auto path = dir / "badmagic.ks";
        std::vector<std::uint8_t> bad = valid_bytes;
        bad[0] ^= 0xFFU;
        bad[1] ^= 0xFFU;
        write_all(path, bad);
        require_throws<tradep2p::KeystoreFormatError>(
            [&] { (void)tradep2p::IdentityKeystore::unlock(path.string(), "irrelevant"); },
            "a keystore file with a bad magic must be rejected as a format error");
    }
    {
        // Bytes 4-5 are the u16 format_version field, immediately after the
        // 4-byte magic.
        const auto path = dir / "badversion.ks";
        std::vector<std::uint8_t> bad = valid_bytes;
        bad[4] = 0xFFU;
        bad[5] = 0xFFU;
        write_all(path, bad);
        require_throws<tradep2p::KeystoreFormatError>(
            [&] { (void)tradep2p::IdentityKeystore::unlock(path.string(), "irrelevant"); },
            "a keystore file with an unsupported format version must be rejected as a format error");
    }
    {
        const auto path = dir / "garbage.ks";
        write_all(path, std::vector<std::uint8_t>(96, 0x5AU));
        require_throws<tradep2p::KeystoreFormatError>(
            [&] { (void)tradep2p::IdentityKeystore::unlock(path.string(), "irrelevant"); },
            "a garbage file must be rejected as a format error, not crash or silently succeed");
    }
    {
        const auto path = dir / "truncated_for_display.ks";
        write_all(path, std::vector<std::uint8_t>(valid_bytes.begin(), valid_bytes.begin() + 4));
        require_throws<tradep2p::KeystoreFormatError>(
            [&] { (void)tradep2p::IdentityKeystore::display_public_identity(path.string()); },
            "display_public_identity must reject a truncated file as a format error, without a passphrase");
    }
}

// ---------------------------------------------------------------------------
// create() must never silently overwrite an existing file.
// ---------------------------------------------------------------------------

void test_no_silent_overwrite(const std::filesystem::path& dir) {
    const auto path = dir / "overwrite.ks";
    (void)tradep2p::IdentityKeystore::create(path.string(), "first-pass", "first-alias");

    require_throws<tradep2p::KeystoreAlreadyExistsError>(
        [&] { (void)tradep2p::IdentityKeystore::create(path.string(), "second-pass", "second-alias"); },
        "create() must refuse to overwrite an existing keystore file");

    auto ks = tradep2p::IdentityKeystore::unlock(path.string(), "first-pass");
    require(ks.alias() == "first-alias", "a rejected create() call must not modify the pre-existing file");
}

// ---------------------------------------------------------------------------
// rotate_service_scoped_key() changes derived keys without touching the
// master secret, and persists durably.
// ---------------------------------------------------------------------------

void test_rotate_and_scoped_derivation(const std::filesystem::path& dir) {
    const auto path = dir / "rotate.ks";
    auto ks = tradep2p::IdentityKeystore::create(path.string(), "rotate-pass");
    const auto original_secret = ks.master_secret().bytes();
    require(ks.key_generation() == 0U, "a freshly created keystore must start at key_generation 0");

    const auto pair_before = ks.derive_scoped_keypair(tradep2p::key_scope::kLogin, "svc-1");

    ks.rotate_service_scoped_key("rotate-pass");
    require(ks.key_generation() == 1U, "rotate_service_scoped_key must increment the generation counter");
    require(ks.master_secret().bytes() == original_secret,
            "rotate_service_scoped_key must not change the master secret");

    const auto pair_after = ks.derive_scoped_keypair(tradep2p::key_scope::kLogin, "svc-1");
    require(pair_before.public_key != pair_after.public_key,
            "rotate_service_scoped_key must change the derived keypair for the same (label, identifier)");

    auto reloaded = tradep2p::IdentityKeystore::unlock(path.string(), "rotate-pass");
    require(reloaded.key_generation() == 1U, "the rotated generation must be persisted to disk");
    const auto pair_reloaded = reloaded.derive_scoped_keypair(tradep2p::key_scope::kLogin, "svc-1");
    require(pair_reloaded.public_key == pair_after.public_key,
            "the reloaded keystore must derive the same post-rotation keypair");

    // rotate_service_scoped_key with the wrong passphrase must be rejected
    // and must not bump the persisted generation.
    require_throws<tradep2p::KeystoreAuthenticationError>(
        [&] { reloaded.rotate_service_scoped_key("wrong-pass"); },
        "rotate_service_scoped_key with the wrong passphrase must be rejected");
    auto reloaded_again = tradep2p::IdentityKeystore::unlock(path.string(), "rotate-pass");
    require(reloaded_again.key_generation() == 1U,
            "a rejected rotation attempt must not change the persisted key_generation");
}

// ---------------------------------------------------------------------------
// Operations that need the master secret must fail on a locked instance;
// header-only fields must remain readable while locked.
// ---------------------------------------------------------------------------

void test_locked_operations_rejected(const std::filesystem::path& dir) {
    const auto path = dir / "locked_ops.ks";
    auto ks = tradep2p::IdentityKeystore::create(path.string(), "locked-pass");
    ks.lock();
    require(!ks.is_unlocked(), "lock() must clear is_unlocked()");

    require_throws<std::logic_error>([&] { (void)ks.master_secret(); },
                                      "master_secret() on a locked keystore must throw");
    require_throws<std::logic_error>(
        [&] { (void)ks.derive_scoped_keypair(tradep2p::key_scope::kLogin, "svc"); },
        "derive_scoped_keypair() on a locked keystore must throw");
    require_throws<std::logic_error>([&] { ks.rotate_service_scoped_key("locked-pass"); },
                                      "rotate_service_scoped_key() on a locked keystore must throw");

    // Header-only fields must remain readable while locked.
    (void)ks.identity_id();
    (void)ks.identity_public_key();
    (void)ks.created_at();
    require(ks.alias().empty(), "alias() must remain readable (and correct) while locked");
}

// ---------------------------------------------------------------------------
// display_public_identity() (no passphrase) vs public_identity() (from an
// already-unlocked instance) - fields present in the plaintext header must
// match either way.
// ---------------------------------------------------------------------------

void test_display_public_identity(const std::filesystem::path& dir) {
    const auto path = dir / "display.ks";
    auto ks = tradep2p::IdentityKeystore::create(path.string(), "display-pass", "erin");

    auto pub = tradep2p::IdentityKeystore::display_public_identity(path.string());
    require(pub.alias == "erin", "display_public_identity must report the alias without a passphrase");
    require(pub.identity_public_key == ks.identity_public_key(),
            "display_public_identity's public key must match the unlocked instance's");
    require(pub.identity_id == ks.identity_id(), "display_public_identity's identity id must match");

    auto pub_from_instance = ks.public_identity();
    require(pub_from_instance.key_generation == ks.key_generation(),
            "public_identity() from an instance must report the authenticated key_generation");
}

// ---------------------------------------------------------------------------
// destroy() removes the file (best-effort shred + unlink).
// ---------------------------------------------------------------------------

void test_destroy(const std::filesystem::path& dir) {
    const auto path = dir / "destroy.ks";
    (void)tradep2p::IdentityKeystore::create(path.string(), "destroy-pass");
    require(std::filesystem::exists(path), "keystore file must exist before destroy()");

    tradep2p::IdentityKeystore::destroy(path.string());
    require(!std::filesystem::exists(path), "destroy() must remove the keystore file");
}

} // namespace

int main() {
    std::filesystem::path dir;
    try {
        dir = make_temp_dir();

        test_create_lock_unlock_round_trip(dir);
        test_wrong_passphrase_rejected(dir);
        test_corrupted_aead_rejected(dir);
        test_change_passphrase(dir);
        test_import_export_round_trip(dir);
        test_atomicity_simulated_crash(dir);
        test_owner_only_permissions(dir);
        test_malformed_keystore_rejected(dir);
        test_no_silent_overwrite(dir);
        test_rotate_and_scoped_derivation(dir);
        test_locked_operations_rejected(dir);
        test_display_public_identity(dir);
        test_destroy(dir);

        std::error_code ignored;
        std::filesystem::remove_all(dir, ignored);

        std::cout << "keystore unit tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "keystore test failure: " << error.what() << '\n';
        if (!dir.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(dir, ignored);
        }
        return 1;
    }
}
