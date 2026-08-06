#include "tradep2p/history.hpp"
#include "tradep2p/keystore.hpp"

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

std::filesystem::path make_temp_dir() {
    std::string tmpl = (std::filesystem::temp_directory_path() / "tp2p_history_test_XXXXXX").string();
    if (::mkdtemp(tmpl.data()) == nullptr) {
        throw std::runtime_error(std::string("mkdtemp failed: ") + std::strerror(errno));
    }
    return std::filesystem::path(tmpl);
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

std::string read_text_file(const std::filesystem::path& path) {
    const auto raw = read_all(path);
    return std::string(raw.begin(), raw.end());
}

// Strips '//' line comments (naive, no string-literal awareness - fine here
// since neither history.cpp nor history.hpp has a "//" inside a string
// literal). Used only by the network-reference grep below, so that this
// module's own explanatory comments (which legitimately NAME the forbidden
// headers/symbols in prose, e.g. "this file never includes secure_channel.hpp")
// don't trip the check meant to catch an actual #include/usage.
std::string strip_cpp_line_comments(const std::string& text) {
    std::string result;
    result.reserve(text.size());
    std::size_t i = 0U;
    while (i < text.size()) {
        if (text[i] == '/' && i + 1U < text.size() && text[i + 1U] == '/') {
            while (i < text.size() && text[i] != '\n') {
                ++i;
            }
            continue;
        }
        result.push_back(text[i]);
        ++i;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

tradep2p::CounterpartyFingerprint fingerprint_fixture(std::uint8_t seed) {
    tradep2p::CounterpartyFingerprint fp{};
    fp[0] = seed;
    fp[1] = 0x01U; // ensure non-zero even if seed == 0
    return fp;
}

tradep2p::EvidenceHash evidence_hash_fixture(std::uint8_t seed) {
    tradep2p::EvidenceHash hash{};
    hash[0] = seed;
    hash[1] = 0x02U;
    return hash;
}

// ---------------------------------------------------------------------------
// Recording an encounter updates first/last seen and encounter count.
// ---------------------------------------------------------------------------

void test_record_encounter_updates_counts(const std::filesystem::path& dir) {
    auto ks = tradep2p::IdentityKeystore::create((dir / "ks1.ks").string(), "pass1", "op1");
    auto history = tradep2p::LocalCounterpartyHistory::open((dir / "history1.dat").string(), ks);

    const auto fp = fingerprint_fixture(0x10);
    const std::string mediator = "mediator-a.example:9443";

    require(!history.find(fp, mediator).has_value(),
            "an unencountered counterparty must not be found before any record_encounter call");

    const auto& e1 = history.record_encounter(fp, mediator, tradep2p::LocalOutcome::Unknown, 1000);
    require(e1.first_seen == 1000U && e1.last_seen == 1000U,
            "the first encounter must set first_seen and last_seen to the same timestamp");
    require(e1.encounter_count == 1U, "the first encounter must set encounter_count to 1");

    const auto& e2 = history.record_encounter(fp, mediator, tradep2p::LocalOutcome::Successful, 2000);
    require(e2.first_seen == 1000U, "first_seen must not change on a later encounter");
    require(e2.last_seen == 2000U, "last_seen must advance to the latest encounter's timestamp");
    require(e2.encounter_count == 2U, "encounter_count must increment on each repeat encounter");
    require(e2.outcome_labels.size() == 1U && e2.outcome_labels[0] == tradep2p::LocalOutcome::Successful,
            "a non-Unknown outcome must be appended to outcome_labels");

    const auto found = history.find(fp, mediator);
    require(found.has_value() && found->encounter_count == 2U,
            "find() must reflect exactly what record_encounter() persisted");

    // Reopening the store under the same keystore must replay the identical
    // persisted state - this is what proves record_encounter() actually
    // wrote to disk, not just updated in-memory state.
    auto reopened = tradep2p::LocalCounterpartyHistory::open((dir / "history1.dat").string(), ks);
    const auto reopened_found = reopened.find(fp, mediator);
    require(reopened_found.has_value() && reopened_found->encounter_count == 2U &&
                reopened_found->first_seen == 1000U && reopened_found->last_seen == 2000U,
            "reopening the history store must replay the exact persisted encounter counts/timestamps");
}

// ---------------------------------------------------------------------------
// Blocked flag suppresses/overrides the display classification, including
// for a counterparty pre-emptively blocked before any real encounter.
// ---------------------------------------------------------------------------

void test_blocked_flag_and_display_category(const std::filesystem::path& dir) {
    auto ks = tradep2p::IdentityKeystore::create((dir / "ks2.ks").string(), "pass2");
    auto history = tradep2p::LocalCounterpartyHistory::open((dir / "history2.dat").string(), ks);

    const auto fp = fingerprint_fixture(0x20);
    const std::string mediator = "mediator-b:1";

    require(tradep2p::classify_for_display(history.find(fp, mediator)) ==
                tradep2p::DisplayCategory::UnknownIdentity,
            "a never-seen counterparty must classify as unknown identity");

    history.record_encounter(fp, mediator, tradep2p::LocalOutcome::Successful);
    require(tradep2p::classify_for_display(history.find(fp, mediator)) ==
                tradep2p::DisplayCategory::PreviousSuccessfulInteraction,
            "a counterparty with only successful encounters must classify as previous successful interaction");

    history.set_blocked(fp, mediator, true);
    require(tradep2p::classify_for_display(history.find(fp, mediator)) ==
                tradep2p::DisplayCategory::LocallyBlocked,
            "the locally_blocked flag must override a prior successful-interaction classification");

    history.set_blocked(fp, mediator, false);
    require(tradep2p::classify_for_display(history.find(fp, mediator)) ==
                tradep2p::DisplayCategory::PreviousSuccessfulInteraction,
            "unblocking must restore the outcome-based classification");

    // Pre-emptive block: never actually encountered, blocked purely on
    // out-of-band information.
    const auto fp2 = fingerprint_fixture(0x21);
    history.set_blocked(fp2, mediator, true);
    const auto found2 = history.find(fp2, mediator);
    require(found2.has_value() && found2->encounter_count == 0U,
            "a pre-emptive block must create a record without fabricating an encounter");
    require(tradep2p::classify_for_display(found2) == tradep2p::DisplayCategory::LocallyBlocked,
            "a pre-emptively blocked, never-encountered counterparty must still classify as locally blocked");
}

// ---------------------------------------------------------------------------
// Fingerprint scoping: the same fingerprint under two different mediator ids
// must be recorded as two independent entries, never merged.
// ---------------------------------------------------------------------------

void test_fingerprint_scoping_is_per_mediator(const std::filesystem::path& dir) {
    auto ks = tradep2p::IdentityKeystore::create((dir / "ks3.ks").string(), "pass3");
    auto history = tradep2p::LocalCounterpartyHistory::open((dir / "history3.dat").string(), ks);

    const auto fp = fingerprint_fixture(0x30);

    history.record_encounter(fp, "mediator-x:1", tradep2p::LocalOutcome::Successful, 100);
    history.record_encounter(fp, "mediator-y:1", tradep2p::LocalOutcome::Incomplete, 200);
    history.record_encounter(fp, "mediator-x:1", tradep2p::LocalOutcome::Successful, 300);

    require(history.entries().size() == 2U,
            "the identical fingerprint under two different mediator ids must produce two distinct "
            "entries, not one merged entry - confirms per-mediator scoping is the actual behavior, "
            "not just the documented intent");

    const auto at_x = history.find(fp, "mediator-x:1");
    const auto at_y = history.find(fp, "mediator-y:1");
    require(at_x.has_value() && at_x->encounter_count == 2U,
            "mediator-x's record must reflect only encounters recorded at mediator-x");
    require(at_y.has_value() && at_y->encounter_count == 1U,
            "mediator-y's record must reflect only encounters recorded at mediator-y, independent of "
            "mediator-x's encounter count");
    require(tradep2p::classify_for_display(at_x) == tradep2p::DisplayCategory::PreviousSuccessfulInteraction,
            "mediator-x's record must not inherit mediator-y's incomplete outcome");
    require(tradep2p::classify_for_display(at_y) == tradep2p::DisplayCategory::PreviousIncompleteInteraction,
            "mediator-y's record must reflect its own incomplete outcome");
}

// ---------------------------------------------------------------------------
// Local notes and evidence hashes: (a) never appear in plaintext on disk,
// and (b) survive the keystore's own encrypted-export/import path, because
// this module's AEAD key is deterministically re-derived from the master
// secret alone.
// ---------------------------------------------------------------------------

void test_notes_and_evidence_survive_keystore_backup(const std::filesystem::path& dir) {
    const auto src_ks_path = dir / "ks4_src.ks";
    const auto backup_path = dir / "ks4_backup.ks";
    const auto imported_ks_path = dir / "ks4_imported.ks";
    const std::string passphrase = "backup-pass-4";

    auto ks = tradep2p::IdentityKeystore::create(src_ks_path.string(), passphrase, "op4");

    const auto history_path = dir / "history4.dat";
    auto history = tradep2p::LocalCounterpartyHistory::open(history_path.string(), ks);
    const auto fp = fingerprint_fixture(0x40);
    const std::string mediator = "mediator-secret:1";
    const std::string secret_note_text =
        "VERY-SECRET-NOTE-CONTENT-should-never-appear-in-plaintext-on-disk";
    history.add_note(fp, mediator, secret_note_text, 500);

    const auto evidence = evidence_hash_fixture(0x41);
    history.add_evidence_hash(fp, mediator, evidence);

    // The on-disk file must never contain the note text in plaintext.
    const auto raw = read_all(history_path);
    const std::string raw_as_string(raw.begin(), raw.end());
    require(raw_as_string.find(secret_note_text) == std::string::npos,
            "the note text must never appear in plaintext in the encrypted history file");

    // Export the keystore's encrypted backup and import it under a new path
    // - this is the ONLY cross-machine path this phase provides (manual,
    // still encrypted end-to-end - see history.hpp's "not gossip" comment).
    tradep2p::IdentityKeystore::export_encrypted_backup(src_ks_path.string(), backup_path.string(), passphrase);
    tradep2p::IdentityKeystore::import_encrypted_backup(backup_path.string(), imported_ks_path.string(),
                                                        passphrase);

    auto imported_ks = tradep2p::IdentityKeystore::unlock(imported_ks_path.string(), passphrase);
    require(imported_ks.master_secret().bytes() == ks.master_secret().bytes(),
            "the imported keystore must have the identical master secret");

    // Manually copying the history file alongside the keystore backup (the
    // only sync path this phase permits) and opening it under the IMPORTED
    // keystore must decrypt to the exact same notes/evidence - proving the
    // AEAD key is deterministically re-derivable from the master secret
    // alone, with nothing ever crossing between the two keystores in
    // plaintext.
    auto reopened = tradep2p::LocalCounterpartyHistory::open(history_path.string(), imported_ks);
    const auto found = reopened.find(fp, mediator);
    require(found.has_value(), "the counterparty record must be recoverable after the keystore "
                               "backup/import round trip");
    require(found->notes.size() == 1U && found->notes[0].text == secret_note_text,
            "the note text must decrypt correctly under the imported keystore");
    require(found->evidence_hashes.size() == 1U && found->evidence_hashes[0] == evidence,
            "the evidence hash must decrypt correctly under the imported keystore");

    // A different, unrelated keystore must NOT be able to open this file.
    auto unrelated_ks = tradep2p::IdentityKeystore::create((dir / "ks4_unrelated.ks").string(),
                                                            "unrelated-pass");
    require_throws<tradep2p::HistoryAuthenticationError>(
        [&] { (void)tradep2p::LocalCounterpartyHistory::open(history_path.string(), unrelated_ks); },
        "an unrelated keystore's master secret must not be able to decrypt another keystore's "
        "history file");
}

// ---------------------------------------------------------------------------
// Malformed / tampered files are rejected with the correct, distinct
// exception types - never silently accepted.
// ---------------------------------------------------------------------------

void test_malformed_and_tampered_files_rejected(const std::filesystem::path& dir) {
    auto ks = tradep2p::IdentityKeystore::create((dir / "ks5.ks").string(), "pass5");
    const auto history_path = dir / "history5.dat";
    {
        auto history = tradep2p::LocalCounterpartyHistory::open(history_path.string(), ks);
        history.record_encounter(fingerprint_fixture(0x50), "mediator-z:1",
                                 tradep2p::LocalOutcome::Successful);
    }
    const auto original = read_all(history_path);
    require(original.size() > 20U, "sanity: a real history file must have a nontrivial size");

    {
        const auto bad_path = dir / "bad_magic.dat";
        auto bad = original;
        bad[0] ^= 0xFFU;
        write_all(bad_path, bad);
        require_throws<tradep2p::HistoryFormatError>(
            [&] { (void)tradep2p::LocalCounterpartyHistory::open(bad_path.string(), ks); },
            "a bad-magic history file must be rejected as a format error");
    }
    {
        const auto bad_path = dir / "truncated.dat";
        write_all(bad_path, std::vector<std::uint8_t>(original.begin(), original.begin() + 4));
        require_throws<tradep2p::HistoryFormatError>(
            [&] { (void)tradep2p::LocalCounterpartyHistory::open(bad_path.string(), ks); },
            "a truncated history file must be rejected as a format error");
    }
    {
        // Flip the final byte (part of the AEAD tag) - must be an
        // authentication failure, not a format error, and never silently
        // accepted.
        const auto bad_path = dir / "bad_tag.dat";
        auto bad = original;
        bad.back() ^= 0x01U;
        write_all(bad_path, bad);
        require_throws<tradep2p::HistoryAuthenticationError>(
            [&] { (void)tradep2p::LocalCounterpartyHistory::open(bad_path.string(), ks); },
            "a corrupted authentication tag must be rejected as an authentication failure");
    }

    // The untouched original must still open correctly (sanity check).
    auto still_ok = tradep2p::LocalCounterpartyHistory::open(history_path.string(), ks);
    require(still_ok.entries().size() == 1U, "the untouched original file must still open normally");
}

// ---------------------------------------------------------------------------
// A missing history file is treated as "nothing recorded yet", not an error.
// ---------------------------------------------------------------------------

void test_missing_file_opens_empty(const std::filesystem::path& dir) {
    auto ks = tradep2p::IdentityKeystore::create((dir / "ks6.ks").string(), "pass6");
    auto history = tradep2p::LocalCounterpartyHistory::open((dir / "does_not_exist.dat").string(), ks);
    require(history.entries().empty(), "opening a nonexistent history path must start with zero entries");
    require(!std::filesystem::exists(dir / "does_not_exist.dat"),
            "open() alone (with no mutating call) must not create the file on disk");
}

// ---------------------------------------------------------------------------
// A locked keystore must not be usable to open a history store.
// ---------------------------------------------------------------------------

void test_locked_keystore_rejected(const std::filesystem::path& dir) {
    auto ks = tradep2p::IdentityKeystore::create((dir / "ks7.ks").string(), "pass7");
    ks.lock();
    require_throws<std::logic_error>(
        [&] { (void)tradep2p::LocalCounterpartyHistory::open((dir / "history7.dat").string(), ks); },
        "opening a history store against a locked keystore must be rejected");
}

// ---------------------------------------------------------------------------
// Atomic file replacement: a stray leftover .tmp file (simulating a crash
// between write+fsync and rename) must neither corrupt the real file nor
// block a subsequent real write - same pattern as keystore_tests.cpp /
// journal_tests.cpp's atomic-write crash simulation.
// ---------------------------------------------------------------------------

void test_atomic_write_crash_simulation(const std::filesystem::path& dir) {
    auto ks = tradep2p::IdentityKeystore::create((dir / "ks8.ks").string(), "pass8");
    const auto history_path = dir / "history8.dat";
    auto history = tradep2p::LocalCounterpartyHistory::open(history_path.string(), ks);
    history.record_encounter(fingerprint_fixture(0x80), "mediator-crash:1",
                             tradep2p::LocalOutcome::Successful);
    const auto original_bytes = read_all(history_path);

    const auto tmp_path = std::filesystem::path(history_path.string() + ".tmp");
    write_all(tmp_path, std::vector<std::uint8_t>{'c', 'r', 'a', 's', 'h', 0, 1, 2, 3});
    require(std::filesystem::exists(tmp_path), "test setup: stray tmp file must exist");
    require(read_all(history_path) == original_bytes,
            "a stray .tmp file must not affect the real history file's contents");

    auto reloaded = tradep2p::LocalCounterpartyHistory::open(history_path.string(), ks);
    require(reloaded.entries().size() == 1U,
            "the history file must still open correctly despite a stray .tmp file");

    reloaded.record_encounter(fingerprint_fixture(0x81), "mediator-crash:1",
                              tradep2p::LocalOutcome::Incomplete);
    require(!std::filesystem::exists(tmp_path),
            "no .tmp file should remain after a successful atomic replace, even if one existed before "
            "it started");
    auto reloaded_again = tradep2p::LocalCounterpartyHistory::open(history_path.string(), ks);
    require(reloaded_again.entries().size() == 2U,
            "the real write performed after a simulated crash must be the one that is actually "
            "persisted");
}

// ---------------------------------------------------------------------------
// Permission check: the file must be owner-only (0600).
// ---------------------------------------------------------------------------

void test_owner_only_permissions(const std::filesystem::path& dir) {
    auto ks = tradep2p::IdentityKeystore::create((dir / "ks9.ks").string(), "pass9");
    const auto history_path = dir / "history9.dat";
    auto history = tradep2p::LocalCounterpartyHistory::open(history_path.string(), ks);
    history.record_encounter(fingerprint_fixture(0x90), "mediator-perm:1",
                             tradep2p::LocalOutcome::Successful);

    struct stat file_stat {};
    require(::stat(history_path.c_str(), &file_stat) == 0, "stat() on the history file must succeed");
    require((file_stat.st_mode & 0777U) == (S_IRUSR | S_IWUSR),
            "the history file must have owner-only (0600) permissions");
}

// ---------------------------------------------------------------------------
// Fingerprint hex round trip + all-zero rejection.
// ---------------------------------------------------------------------------

void test_fingerprint_hex_helpers() {
    const auto fp = fingerprint_fixture(0xAB);
    const auto hex = tradep2p::fingerprint_to_hex(fp);
    require(hex.size() == 64U, "a 32-byte fingerprint must hex-encode to 64 characters");
    const auto decoded = tradep2p::fingerprint_from_hex(hex);
    require(decoded == fp, "fingerprint hex encode/decode must round-trip exactly");

    const tradep2p::CounterpartyFingerprint zero{};
    require_throws<std::invalid_argument>(
        [&] { (void)tradep2p::fingerprint_to_hex(zero); },
        "an all-zero fingerprint must be rejected as never a valid identifier");

    const std::string zero_hex(64U, '0');
    require_throws<std::invalid_argument>(
        [&] { (void)tradep2p::fingerprint_from_hex(zero_hex); },
        "parsing an all-zero fingerprint hex string must be rejected");
}

// ---------------------------------------------------------------------------
// Nothing in this module makes a network call. A unit test cannot prove a
// negative about runtime behavior, so this is a best-effort static grep of
// the module's own source for anything network-shaped, located relative to
// this test file's own compiled path (robust to in-source vs. out-of-source
// build directories, unlike a path relative to the test's current working
// directory at ctest run time).
// ---------------------------------------------------------------------------

void test_no_network_references_in_history_module() {
    const std::filesystem::path this_file(__FILE__); // .../tests/history_tests.cpp
    const std::filesystem::path project_root = this_file.parent_path().parent_path();
    const std::filesystem::path cpp_path = project_root / "src" / "history.cpp";
    const std::filesystem::path hpp_path = project_root / "include" / "tradep2p" / "history.hpp";

    if (!std::filesystem::exists(cpp_path) || !std::filesystem::exists(hpp_path)) {
        std::cout << "  (skipping static network-reference grep: could not locate "
                  << cpp_path.string() << " relative to the compiled test binary)\n";
        return;
    }

    const std::string cpp_text = strip_cpp_line_comments(read_text_file(cpp_path));
    const std::string hpp_text = strip_cpp_line_comments(read_text_file(hpp_path));

    // Deliberately specific (not a bare "SSL_", which would false-positive
    // on this module's legitimate OPENSSL_cleanse()/OPENSSL_* crypto calls -
    // "OPENSSL_cleanse" itself contains the substring "SSL_"). Each of these
    // is unambiguously either a TLS handshake/record API or a raw socket
    // API; none has a legitimate reason to appear in a local-file-only,
    // AEAD-at-rest module like this one.
    const std::vector<std::string> forbidden_tokens = {
        "secure_channel.hpp", "dashboard_client.hpp",
        "SSL_CTX", "SSL_write(", "SSL_read(", "SSL_connect(", "SSL_accept(",
        "::socket(", "::connect(", "::send(", "::recv(", "BIO_",
        "sys/socket.h", "netinet/", "getaddrinfo(",
    };
    for (const auto& token : forbidden_tokens) {
        require(cpp_text.find(token) == std::string::npos,
                ("src/history.cpp must not reference network-shaped symbol '" + token +
                 "' - this module must never touch the network")
                    .c_str());
        require(hpp_text.find(token) == std::string::npos,
                ("include/tradep2p/history.hpp must not reference network-shaped symbol '" + token +
                 "' - this module must never touch the network")
                    .c_str());
    }
}

} // namespace

int main() {
    std::filesystem::path dir;
    try {
        dir = make_temp_dir();

        test_record_encounter_updates_counts(dir);
        test_blocked_flag_and_display_category(dir);
        test_fingerprint_scoping_is_per_mediator(dir);
        test_notes_and_evidence_survive_keystore_backup(dir);
        test_malformed_and_tampered_files_rejected(dir);
        test_missing_file_opens_empty(dir);
        test_locked_keystore_rejected(dir);
        test_atomic_write_crash_simulation(dir);
        test_owner_only_permissions(dir);
        test_fingerprint_hex_helpers();
        test_no_network_references_in_history_module();

        std::error_code ignored;
        std::filesystem::remove_all(dir, ignored);

        std::cout << "history unit tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "history test failure: " << error.what() << '\n';
        if (!dir.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(dir, ignored);
        }
        return 1;
    }
}
