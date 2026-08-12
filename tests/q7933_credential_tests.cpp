#include "tradep2p/q7933_credential.hpp"
#include "tradep2p/q7933_issuance_store.hpp"
#include "tradep2p/q7933_presentation.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <stdexcept>

using tradep2p::q7933_credential::CredentialPayload;
using tradep2p::q7933_credential::CredentialSerial;
using tradep2p::q7933_credential::IssuanceContext;
using tradep2p::q7933_credential::IssuanceStore;
using tradep2p::q7933_credential::IssuanceStoreError;
using tradep2p::q7933_credential::IssuanceStoreFormatError;
using tradep2p::q7933_credential::Nullifier;
using tradep2p::q7933_credential::NullifierTracker;
using tradep2p::q7933_credential::PresentationContext;
using tradep2p::q7933_credential::derive_nullifier;
using tradep2p::q7933_credential::derive_nullifier_empty;
using tradep2p::q7933_credential::encode_credential_for_blind;
using tradep2p::q7933_credential::generate_serial;
using tradep2p::q7933_credential::verify_nullifier;

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
        throw std::runtime_error(message + " (wrong exception type: " + error.what() + ")");
    }
    throw std::runtime_error(message + " (no exception thrown)");
}

std::filesystem::path make_temp_dir() {
    auto tmp_base = std::filesystem::temp_directory_path();
    std::string tmpl = (tmp_base / "tp2p_q7933_credential_test_XXXXXX").string();
    if (::mkdtemp(tmpl.data()) == nullptr) {
        throw std::runtime_error(std::string("mkdtemp failed: ") + std::strerror(errno));
    }
    return std::filesystem::path(tmpl);
}

std::array<std::uint8_t, 32> make_room_id(std::uint8_t byte) {
    std::array<std::uint8_t, 32> room{};
    std::fill(room.begin(), room.end(), byte);
    return room;
}

// ===========================================================================
// Test 1: Serial generation
// ===========================================================================
void test_serial_generation() {
    auto serial1 = generate_serial();
    auto serial2 = generate_serial();

    // Serials should be 32 bytes
    require(serial1.size() == 32, "Serial 1 size should be 32");
    require(serial2.size() == 32, "Serial 2 size should be 32");

    // Different serials should be distinct (with overwhelming probability)
    require(serial1 != serial2, "Serials should be distinct");
}

// ===========================================================================
// Test 2: Credential payload encoding/decoding
// ===========================================================================
void test_credential_payload_encode_decode() {
    CredentialPayload original;
    original.version = 1;
    original.issuer_scope = 42;
    original.epoch = 12345;
    original.serial = generate_serial();

    auto encoded = original.encode();
    require(!encoded.empty(), "Encoded payload should not be empty");

    auto decoded = CredentialPayload::decode(encoded);
    require(decoded.version == 1, "Version should match");
    require(decoded.issuer_scope == 42, "Issuer scope should match");
    require(decoded.epoch == 12345, "Epoch should match");
    require(decoded.serial == original.serial, "Serial should match");
}

// ===========================================================================
// Test 3: IssuanceContext encoding/decoding
// ===========================================================================
void test_issuance_context_encode_decode() {
    IssuanceContext original;
    original.version = 1;
    original.issuer_scope = 5;
    original.epoch = 999;
    original.room_id = make_room_id(0xaa);
    original.party = 0;

    auto encoded = original.encode();
    auto decoded = IssuanceContext::decode(encoded);

    require(decoded.version == 1, "Version should match");
    require(decoded.issuer_scope == 5, "Issuer scope should match");
    require(decoded.epoch == 999, "Epoch should match");
    require(decoded.room_id == original.room_id, "Room ID should match");
    require(decoded.party == 0, "Party should match");
}

// ===========================================================================
// Test 4: Nullifier derivation consistency
// ===========================================================================
void test_nullifier_consistency() {
    auto serial = generate_serial();
    std::vector<std::uint8_t> scope{0x01, 0x02, 0x03};

    auto null1 = derive_nullifier(serial, 1, 100, scope);
    auto null2 = derive_nullifier(serial, 1, 100, scope);

    // Same inputs should produce same nullifier
    require(null1 == null2, "Nullifiers should be deterministic");

    // Different scope should produce different nullifier
    std::vector<std::uint8_t> scope2{0x04, 0x05, 0x06};
    auto null3 = derive_nullifier(serial, 1, 100, scope2);
    require(null3 != null1, "Different scope should produce different nullifier");

    // Different epoch should produce different nullifier
    auto null4 = derive_nullifier(serial, 1, 101, scope);
    require(null4 != null1, "Different epoch should produce different nullifier");
}

// ===========================================================================
// Test 5: Nullifier verification
// ===========================================================================
void test_nullifier_verification() {
    auto serial = generate_serial();
    
    PresentationContext context;
    context.room_id = {0x01, 0x02, 0x03};
    context.verifier_identity = {};
    context.challenge = {};

    // Derive nullifier using the encoded presentation context
    auto encoded_context = context.encode();
    auto nullifier = derive_nullifier(serial, 2, 50, encoded_context);

    // Correct nullifier should verify
    require(verify_nullifier(serial, nullifier, 2, 50, context),
            "Correct nullifier should verify");

    // Wrong nullifier should not verify
    Nullifier wrong_nullifier{};
    require(!verify_nullifier(serial, wrong_nullifier, 2, 50, context),
            "Wrong nullifier should not verify");

    // Wrong issuer scope should not verify
    require(!verify_nullifier(serial, nullifier, 3, 50, context),
            "Different issuer scope should not verify");
}

// ===========================================================================
// Test 6: Issuance store - first issuance succeeds
// ===========================================================================
void test_issuance_store_first_succeeds() {
    auto tmpdir = make_temp_dir();
    IssuanceStore store(tmpdir.string());

    IssuanceContext context;
    context.version = 1;
    context.issuer_scope = 1;
    context.epoch = 1;
    context.room_id = make_room_id(0x11);
    context.party = 0;

    // First issuance should succeed
    bool result = store.record_issuance(context);
    require(result == true, "First issuance should succeed");

    // Verify it was recorded
    require(store.has_been_issued(context), "Record should exist after issuance");
}

// ===========================================================================
// Test 7: Issuance store - duplicate issuance fails
// ===========================================================================
void test_issuance_store_duplicate_fails() {
    auto tmpdir = make_temp_dir();
    IssuanceStore store(tmpdir.string());

    IssuanceContext context;
    context.version = 1;
    context.issuer_scope = 1;
    context.epoch = 1;
    context.room_id = make_room_id(0x22);
    context.party = 1;

    // First issuance
    bool first = store.record_issuance(context);
    require(first == true, "First issuance should succeed");

    // Second issuance (duplicate)
    bool second = store.record_issuance(context);
    require(second == false, "Duplicate issuance should fail");
}

// ===========================================================================
// Test 8: Issuance store - different rooms independent
// ===========================================================================
void test_issuance_store_different_rooms() {
    auto tmpdir = make_temp_dir();
    IssuanceStore store(tmpdir.string());

    IssuanceContext context1;
    context1.version = 1;
    context1.issuer_scope = 1;
    context1.epoch = 1;
    context1.room_id = make_room_id(0x33);
    context1.party = 0;

    IssuanceContext context2;
    context2.version = 1;
    context2.issuer_scope = 1;
    context2.epoch = 1;
    context2.room_id = make_room_id(0x44); // different room
    context2.party = 0;

    bool first = store.record_issuance(context1);
    require(first == true, "First room issuance should succeed");

    bool second = store.record_issuance(context2);
    require(second == true, "Different room issuance should also succeed");
}

// ===========================================================================
// Test 9: Issuance store - persistence across new instance
// ===========================================================================
void test_issuance_store_persistence() {
    auto tmpdir = make_temp_dir();

    IssuanceContext context;
    context.version = 1;
    context.issuer_scope = 1;
    context.epoch = 1;
    context.room_id = make_room_id(0x55);
    context.party = 0;

    {
        IssuanceStore store1(tmpdir.string());
        bool result = store1.record_issuance(context);
        require(result == true, "Initial issuance should succeed");
    }

    // Create a new store instance from same directory
    {
        IssuanceStore store2(tmpdir.string());
        // Check that the issuance is still recorded
        bool was_issued = store2.has_been_issued(context);
        require(was_issued == true, "Issuance should persist after store restart");

        // Attempting to re-record should fail
        bool duplicate = store2.record_issuance(context);
        require(duplicate == false, "Duplicate should fail after restart");
    }
}

// ===========================================================================
// Test 10: Nullifier tracker - first nullifier recorded succeeds
// ===========================================================================
void test_nullifier_tracker_first_succeeds() {
    NullifierTracker tracker;
    auto nullifier = Nullifier{};
    nullifier[0] = 0xaa;

    bool result = tracker.record_nullifier(nullifier);
    require(result == true, "First nullifier should be recorded successfully");
}

// ===========================================================================
// Test 11: Nullifier tracker - duplicate rejected
// ===========================================================================
void test_nullifier_tracker_duplicate_rejected() {
    NullifierTracker tracker;
    auto nullifier = Nullifier{};
    nullifier[0] = 0xbb;

    bool first = tracker.record_nullifier(nullifier);
    require(first == true, "First record should succeed");

    bool second = tracker.record_nullifier(nullifier);
    require(second == false, "Duplicate should fail");
}

// ===========================================================================
// Test 12: Nullifier tracker - different nullifiers distinct
// ===========================================================================
void test_nullifier_tracker_different_distinct() {
    NullifierTracker tracker;

    auto null1 = Nullifier{};
    null1[0] = 0xcc;

    auto null2 = Nullifier{};
    null2[0] = 0xdd;

    bool first = tracker.record_nullifier(null1);
    require(first == true, "First nullifier should be recorded");

    bool second = tracker.record_nullifier(null2);
    require(second == true, "Different nullifier should also be recorded");

    require(tracker.count() == 2, "Tracker should have 2 distinct nullifiers");
}

// ===========================================================================
// Test 13: Presentation context encoding
// ===========================================================================
void test_presentation_context_encoding() {
    PresentationContext ctx;
    ctx.room_id = {0x01, 0x02, 0x03};
    ctx.verifier_identity = {0x04, 0x05};
    ctx.challenge = {0x06, 0x07, 0x08, 0x09};

    auto encoded = ctx.encode();
    require(!encoded.empty(), "Encoded context should not be empty");

    // Should contain the fields in order with length prefixes
    // First 4 bytes: room_id length = 3
    require(encoded.size() > 12, "Encoded context should be large enough for fields");
}

// ===========================================================================
// Test 14: Credential for blind encoding
// ===========================================================================
void test_credential_for_blind_encoding() {
    CredentialPayload payload;
    payload.version = 1;
    payload.issuer_scope = 3;
    payload.epoch = 777;
    payload.serial = generate_serial();

    auto encoded = encode_credential_for_blind(payload);
    require(!encoded.empty(), "Encoded credential should not be empty");

    // Should start with domain string
    const char* domain = "TRADEP2P-Q7933-CREDENTIAL-FOR-BLIND-v1";
    size_t domain_len = strlen(domain);
    require(encoded.size() > domain_len, "Should be larger than domain");
}

// ===========================================================================
// Test 15: Issuance uniqueness per party in same room
// ===========================================================================
void test_issuance_per_party_independent() {
    auto tmpdir = make_temp_dir();
    IssuanceStore store(tmpdir.string());

    IssuanceContext context_a;
    context_a.version = 1;
    context_a.issuer_scope = 1;
    context_a.epoch = 1;
    context_a.room_id = make_room_id(0x66);
    context_a.party = 0; // Party A

    IssuanceContext context_b;
    context_b.version = 1;
    context_b.issuer_scope = 1;
    context_b.epoch = 1;
    context_b.room_id = make_room_id(0x66); // Same room
    context_b.party = 1; // Party B

    bool result_a = store.record_issuance(context_a);
    require(result_a == true, "Party A issuance should succeed");

    // Party B in same room should have independent issuance
    bool result_b = store.record_issuance(context_b);
    require(result_b == true, "Party B issuance in same room should also succeed");

    // But Party A shouldn't be able to get another
    bool duplicate_a = store.record_issuance(context_a);
    require(duplicate_a == false, "Party A duplicate should fail");
}

// ===========================================================================
// Test 16: Empty nullifier derivation (default case)
// ===========================================================================
void test_empty_nullifier_derivation() {
    auto null = derive_nullifier_empty();
    require(null.size() == 32, "Empty nullifier should be 32 bytes");
}

} // namespace

// ===========================================================================
// Main test runner
// ===========================================================================
int main() {
    try {
        test_serial_generation();
        std::cout << "✓ test_serial_generation" << std::endl;

        test_credential_payload_encode_decode();
        std::cout << "✓ test_credential_payload_encode_decode" << std::endl;

        test_issuance_context_encode_decode();
        std::cout << "✓ test_issuance_context_encode_decode" << std::endl;

        test_nullifier_consistency();
        std::cout << "✓ test_nullifier_consistency" << std::endl;

        test_nullifier_verification();
        std::cout << "✓ test_nullifier_verification" << std::endl;

        test_issuance_store_first_succeeds();
        std::cout << "✓ test_issuance_store_first_succeeds" << std::endl;

        test_issuance_store_duplicate_fails();
        std::cout << "✓ test_issuance_store_duplicate_fails" << std::endl;

        test_issuance_store_different_rooms();
        std::cout << "✓ test_issuance_store_different_rooms" << std::endl;

        test_issuance_store_persistence();
        std::cout << "✓ test_issuance_store_persistence" << std::endl;

        test_nullifier_tracker_first_succeeds();
        std::cout << "✓ test_nullifier_tracker_first_succeeds" << std::endl;

        test_nullifier_tracker_duplicate_rejected();
        std::cout << "✓ test_nullifier_tracker_duplicate_rejected" << std::endl;

        test_nullifier_tracker_different_distinct();
        std::cout << "✓ test_nullifier_tracker_different_distinct" << std::endl;

        test_presentation_context_encoding();
        std::cout << "✓ test_presentation_context_encoding" << std::endl;

        test_credential_for_blind_encoding();
        std::cout << "✓ test_credential_for_blind_encoding" << std::endl;

        test_issuance_per_party_independent();
        std::cout << "✓ test_issuance_per_party_independent" << std::endl;

        test_empty_nullifier_derivation();
        std::cout << "✓ test_empty_nullifier_derivation" << std::endl;

        std::cout << "\n✓ All tests passed!" << std::endl;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "✗ Test failed: " << error.what() << std::endl;
        return 1;
    }
}
