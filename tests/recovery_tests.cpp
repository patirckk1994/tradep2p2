#include "tradep2p/journal.hpp"
#include "tradep2p/mediator.hpp"
#include "tradep2p/protocol.hpp"
#include "tradep2p/recovery.hpp"
#include "tradep2p/room_persistence.hpp"

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
    std::string tmpl = (std::filesystem::temp_directory_path() / "tp2p_recovery_test_XXXXXX").string();
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

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

tradep2p::RoomId room_fixture(std::uint8_t seed = 0x51) {
    tradep2p::RoomId room{};
    room[0] = seed;
    return room;
}

tradep2p::ClientId client_fixture(std::uint8_t seed) {
    tradep2p::ClientId id{};
    id[0] = seed;
    return id;
}

tradep2p::TradeTerms terms_fixture() {
    tradep2p::TradeTerms terms;
    terms.asset_a = "BTC";
    terms.asset_b = "QRL";
    terms.total_a = 10U;
    terms.total_b = 20U;
    terms.rounds = 2U;
    terms.first_sender = tradep2p::Party::A;
    return terms;
}

tradep2p::FeeTerms no_fee_fixture() { return tradep2p::FeeTerms{}; }

tradep2p::FeeTerms fee_fixture() {
    return tradep2p::FeeTerms{"BTC", 1U, "mediator-fee-address"};
}

// ---------------------------------------------------------------------------
// Wire message round trips + capability-negotiation bounds.
// ---------------------------------------------------------------------------

void test_recovery_message_round_trip() {
    const tradep2p::RecoveryStateRequestMessage request{room_fixture()};
    const auto decoded_request =
        tradep2p::decode_recovery_state_request(tradep2p::encode_recovery_state_request(request));
    require(decoded_request.room_id == room_fixture(), "recovery request room id must round-trip");

    tradep2p::RecoveryStateResponseMessage found_response;
    found_response.room_id = room_fixture();
    found_response.found = true;
    found_response.terms = terms_fixture();
    found_response.fee = fee_fixture();
    found_response.state = static_cast<std::uint8_t>(tradep2p::SessionState::WaitingForReceived);
    found_response.round_index = 1U;
    found_response.leg_index = 1U;
    found_response.party_a_connected = true;
    found_response.party_b_connected = false;
    found_response.reason = "";

    const auto decoded_found = tradep2p::decode_recovery_state_response(
        tradep2p::encode_recovery_state_response(found_response));
    require(decoded_found.found, "found flag must round-trip true");
    require(decoded_found.room_id == room_fixture(), "room id must round-trip");
    require(decoded_found.terms.total_b == terms_fixture().total_b, "terms must round-trip");
    require(decoded_found.fee.amount == fee_fixture().amount, "fee must round-trip");
    require(decoded_found.state == static_cast<std::uint8_t>(tradep2p::SessionState::WaitingForReceived),
            "state byte must round-trip");
    require(decoded_found.round_index == 1U && decoded_found.leg_index == 1U,
            "round/leg index must round-trip");
    require(decoded_found.party_a_connected && !decoded_found.party_b_connected,
            "connection flags must round-trip independently");

    tradep2p::RecoveryStateResponseMessage not_found_response;
    not_found_response.room_id = room_fixture();
    not_found_response.found = false;
    not_found_response.reason = "room not found";
    const auto decoded_not_found = tradep2p::decode_recovery_state_response(
        tradep2p::encode_recovery_state_response(not_found_response));
    require(!decoded_not_found.found, "found flag must round-trip false");
    require(decoded_not_found.reason == "room not found", "reason text must round-trip when not found");
    require(decoded_not_found.round_index == 0U && decoded_not_found.leg_index == 0U,
            "unused fields must decode to their defaults when found is false");
}

void test_message_type_bounds() {
    // The two new message types must validate as accepted.
    tradep2p::validate_message_type(tradep2p::MessageType::RecoveryStateRequest);
    tradep2p::validate_message_type(tradep2p::MessageType::RecoveryStateResponse);

    // Phase 4b added RecognitionChallenge(31)/RecognitionResponse(32) as the
    // new contiguous top of the range - accepted here for the same
    // "MessageType values are contiguous and bounds-checked" reason, and
    // covered in full by tests/recognition_tests.cpp; this file only checks
    // that the type range itself moved.
    tradep2p::validate_message_type(tradep2p::MessageType::RecognitionChallenge);
    tradep2p::validate_message_type(tradep2p::MessageType::RecognitionResponse);
    // Phase 5 added TradeEphemeralKey(33) as the new contiguous top of the
    // range - see tests/ephemeral_tests.cpp for its own coverage.
    tradep2p::validate_message_type(tradep2p::MessageType::TradeEphemeralKey);
    // Phase 6 added ReceiptAck(34)/ReceiptIssued(35)/ReceiptAckRequired(36)
    // - see tests/receipt_tests.cpp for its own coverage.
    tradep2p::validate_message_type(tradep2p::MessageType::ReceiptAck);
    tradep2p::validate_message_type(tradep2p::MessageType::ReceiptIssued);
    tradep2p::validate_message_type(tradep2p::MessageType::ReceiptAckRequired);
    // Phase 8 added ReceiptDisclosure(37) - see tests/disclosure_tests.cpp
    // for its own coverage.
    tradep2p::validate_message_type(tradep2p::MessageType::ReceiptDisclosure);
    // Optional fee-confirmation gate added FeeConfirmationPending(38) - see
    // mediator.hpp's SessionState::WaitingForFeeConfirmation.
    tradep2p::validate_message_type(tradep2p::MessageType::FeeConfirmationPending);
    // The mediator's retained price history added GetCandles(39)/
    // CandleData(40) as the new contiguous top of the range - see
    // tests/protocol_tests.cpp's test_candle_serialization() for their own
    // encode/decode coverage.
    tradep2p::validate_message_type(tradep2p::MessageType::GetCandles);
    tradep2p::validate_message_type(tradep2p::MessageType::CandleData);

    // Anything past the new upper bound must still be rejected - this is
    // the mechanism that lets an OLDER build (or, symmetrically, a build
    // that predates some future phase) safely reject a message type it
    // does not understand instead of misinterpreting the bytes as
    // something else: MessageType values are contiguous and bounds-checked,
    // never wrapped or reinterpreted.
    bool threw = false;
    try {
        tradep2p::validate_message_type(static_cast<tradep2p::MessageType>(41));
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "a message type value past the new upper bound must still be rejected");

    threw = false;
    try {
        tradep2p::validate_message_type(static_cast<tradep2p::MessageType>(0));
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "message type 0 must still be rejected");
}

// ---------------------------------------------------------------------------
// Mediator-side persisted room format: encode/decode round trip, malformed
// rejection, and atomic-write crash simulation (reusing the keystore's
// atomic-write test pattern from phase 2, per the phase-3 spec).
// ---------------------------------------------------------------------------

void test_persisted_room_round_trip() {
    tradep2p::PersistedRoomFile file;
    tradep2p::PersistedRoom room_one;
    room_one.room_id = room_fixture(0x61);
    room_one.party_a = client_fixture(0x01);
    room_one.party_b = client_fixture(0x02);
    room_one.terms = terms_fixture();
    room_one.fee = no_fee_fixture();
    room_one.state = tradep2p::SessionState::WaitingForSent;
    room_one.round_index = 0U;
    room_one.leg_index = 0U;
    room_one.updated_at = 1700000000ULL;

    tradep2p::PersistedRoom room_two;
    room_two.room_id = room_fixture(0x62);
    room_two.party_a = client_fixture(0x03);
    room_two.party_b = client_fixture(0x04);
    room_two.terms = terms_fixture();
    room_two.fee = fee_fixture();
    room_two.state = tradep2p::SessionState::Aborted;
    room_two.round_index = 1U;
    room_two.leg_index = 1U;
    room_two.abort_reason = "peer disconnected";
    room_two.updated_at = 1700000100ULL;

    file.rooms.push_back(room_one);
    file.rooms.push_back(room_two);

    const auto decoded = tradep2p::decode_persisted_rooms(tradep2p::encode_persisted_rooms(file));
    require(decoded.rooms.size() == 2U, "both persisted rooms must round-trip");
    require(decoded.rooms[0].room_id == room_one.room_id, "room id must round-trip");
    require(decoded.rooms[0].party_a == room_one.party_a && decoded.rooms[0].party_b == room_one.party_b,
            "party ids must round-trip");
    require(decoded.rooms[0].terms.total_a == room_one.terms.total_a, "terms must round-trip");
    require(decoded.rooms[0].state == tradep2p::SessionState::WaitingForSent, "state must round-trip");
    require(decoded.rooms[1].fee.amount == fee_fixture().amount, "fee must round-trip");
    require(decoded.rooms[1].abort_reason == "peer disconnected", "abort reason must round-trip");
    require(decoded.rooms[1].leg_index == 1U, "leg index must round-trip");

    // No receive-address field exists on PersistedRoom at all - this is
    // enforced at compile time by the struct's shape (see
    // room_persistence.hpp's file comment for why), not something a
    // runtime test can additionally check.
}

void test_persisted_room_malformed_and_missing(const std::filesystem::path& dir) {
    const auto missing_path = (dir / "does_not_exist.rooms").string();
    const auto loaded = tradep2p::load_persisted_rooms(missing_path);
    require(loaded.rooms.empty(), "loading a nonexistent persisted-room file must return an empty file, not throw");

    const auto bad_magic_path = (dir / "bad_magic.rooms").string();
    write_all(bad_magic_path, std::vector<std::uint8_t>{'X', 'X', 'X', 'X', 0, 1, 0, 0, 0, 0});
    require_throws<tradep2p::PersistenceFormatError>(
        [&] { (void)tradep2p::load_persisted_rooms(bad_magic_path); },
        "a bad-magic persisted-room file must be rejected as a format error");

    const auto truncated_path = (dir / "truncated.rooms").string();
    write_all(truncated_path, std::vector<std::uint8_t>{'T', 'P', 'R'});
    require_throws<tradep2p::PersistenceFormatError>(
        [&] { (void)tradep2p::load_persisted_rooms(truncated_path); },
        "a truncated persisted-room file must be rejected as a format error");
}

void test_persisted_room_atomic_write_crash_simulation(const std::filesystem::path& dir) {
    const auto path = (dir / "atomic.rooms").string();

    tradep2p::PersistedRoomFile file;
    tradep2p::PersistedRoom room;
    room.room_id = room_fixture(0x71);
    room.party_a = client_fixture(0x11);
    room.party_b = client_fixture(0x12);
    room.terms = terms_fixture();
    room.fee = no_fee_fixture();
    room.state = tradep2p::SessionState::WaitingForReceived;
    file.rooms.push_back(room);
    tradep2p::write_persisted_rooms(path, file);
    const auto original_bytes = read_all(path);

    // Exactly the on-disk state that exists after write_persisted_rooms()'s
    // internal write_replace_atomic() has written+fsynced its temp file but
    // before rename() has run.
    const auto tmp_path = std::filesystem::path(path + ".tmp");
    write_all(tmp_path, std::vector<std::uint8_t>{'c', 'r', 'a', 's', 'h', 0, 1, 2, 3});
    require(std::filesystem::exists(tmp_path), "test setup: stray tmp file must exist");
    require(read_all(path) == original_bytes,
            "a stray .tmp file must not affect the real persisted-room file's contents");

    const auto reloaded = tradep2p::load_persisted_rooms(path);
    require(reloaded.rooms.size() == 1U && reloaded.rooms[0].room_id == room.room_id,
            "the persisted-room file must still load correctly after a simulated crash-before-rename");

    // A real subsequent write must still succeed despite the stray tmp
    // file, and must not leave any tmp file behind afterward.
    tradep2p::PersistedRoomFile updated = file;
    updated.rooms[0].round_index = 1U;
    tradep2p::write_persisted_rooms(path, updated);
    require(!std::filesystem::exists(tmp_path),
            "no .tmp file should remain after a successful atomic replace, even if one existed before it started");
    const auto reloaded_again = tradep2p::load_persisted_rooms(path);
    require(reloaded_again.rooms[0].round_index == 1U,
            "the real write performed after a simulated crash must be the one that is actually persisted");
}

void test_persisted_room_file_permissions(const std::filesystem::path& dir) {
    const auto path = (dir / "perm.rooms").string();
    tradep2p::PersistedRoomFile file;
    file.rooms.push_back(tradep2p::PersistedRoom{});
    file.rooms[0].room_id = room_fixture(0x81);
    file.rooms[0].party_a = client_fixture(0x21);
    file.rooms[0].party_b = client_fixture(0x22);
    file.rooms[0].terms = terms_fixture();
    tradep2p::write_persisted_rooms(path, file);

    struct stat file_stat {};
    require(::stat(path.c_str(), &file_stat) == 0, "stat() on the persisted-room file must succeed");
    require((file_stat.st_mode & 0777U) == (S_IRUSR | S_IWUSR),
            "the persisted-room file must have owner-only (0600) permissions - it names both "
            "parties' client ids and trade terms, even though it never names addresses");
}

// ---------------------------------------------------------------------------
// "Mediator restart mid-room" recovery: drive a real MediatorSession
// through each of the four specified checkpoints, capture its persistable
// state (addresses deliberately left blank, mirroring the option-1 privacy
// choice), round-trip that capture through encode/decode_persisted_rooms
// (simulating "written to disk, read back after a restart"), and confirm
// MediatorSession::restore() reconstructs a session whose state/round/leg
// exactly match the pre-crash session at that checkpoint.
//
// This is deliberately exercised at the MediatorSession level, the same way
// protocol_tests.cpp's test_mediator_flow()/test_mediator_fee_flow() already
// do, rather than via a full LobbyServer/TLS integration harness - no test
// in this repository spins up a real socket-level mediator server (see the
// phase report for this scoping note), and LobbyServer::Impl's RoomEntry is
// a private nested type with no test-visible seam of its own.
// ---------------------------------------------------------------------------

tradep2p::PersistedRoom capture(const tradep2p::MediatorSession& session, const tradep2p::RoomId& room_id,
                                 const tradep2p::ClientId& party_a, const tradep2p::ClientId& party_b,
                                 const tradep2p::FeeTerms& fee) {
    tradep2p::PersistedRoom snapshot;
    snapshot.room_id = room_id;
    snapshot.party_a = party_a;
    snapshot.party_b = party_b;
    snapshot.terms = session.terms();
    snapshot.fee = fee;
    snapshot.state = session.state();
    snapshot.round_index = session.round_index();
    snapshot.leg_index = session.leg_index();
    if (session.state() == tradep2p::SessionState::Aborted) {
        snapshot.abort_reason = session.abort_reason();
    }
    return snapshot;
}

tradep2p::MediatorSession restore_from_disk(const tradep2p::PersistedRoom& persisted) {
    // Round-trip through the actual on-disk encoding, not just the in-memory
    // struct, so this test also exercises the real persistence format.
    tradep2p::PersistedRoomFile file;
    file.rooms.push_back(persisted);
    const auto decoded = tradep2p::decode_persisted_rooms(tradep2p::encode_persisted_rooms(file));
    const auto& room = decoded.rooms.at(0);
    return tradep2p::MediatorSession::restore(room.room_id, room.terms, /*receive_address_a=*/"",
                                              /*receive_address_b=*/"", room.fee, room.state,
                                              room.round_index, room.leg_index, room.abort_reason);
}

void acknowledge_current_turn(tradep2p::MediatorSession& session) {
    // Phase 6: transparently pass both parties' acknowledgement through
    // SessionState::WaitingForFinalReceiptAck (mediator.hpp) - see the
    // identical helper and comment in tests/protocol_tests.cpp.
    if (session.state() == tradep2p::SessionState::WaitingForFinalReceiptAck) {
        session.acknowledge_final_receipt(tradep2p::Party::A);
        session.acknowledge_final_receipt(tradep2p::Party::B);
        return;
    }
    const auto turn = session.current_turn();
    const tradep2p::RoundSignalMessage signal{turn.room_id, turn.round_index, turn.sender};
    session.sender_reported_sent(turn.sender, signal);
    session.receiver_reported_received(tradep2p::other_party(turn.sender), signal);
}

void test_mediator_restart_mid_room_recovery() {
    const auto room_id = room_fixture(0x91);
    const auto party_a = client_fixture(0x31);
    const auto party_b = client_fixture(0x32);
    const auto fee = no_fee_fixture();

    // Checkpoint 1: before either party acknowledged a round - right after
    // join(), still on round 0, leg 0.
    {
        tradep2p::MediatorSession session({terms_fixture(), "addr-a"}, room_id, fee);
        session.join({room_id, "addr-b"});
        const auto persisted = capture(session, room_id, party_a, party_b, fee);
        auto restored = restore_from_disk(persisted);
        require(restored.state() == tradep2p::SessionState::WaitingForSent,
                "checkpoint 1: restored state must match pre-crash state");
        require(restored.round_index() == 0U && restored.leg_index() == 0U,
                "checkpoint 1: restored round/leg must match pre-crash round/leg");
        require(restored.terms().total_a == terms_fixture().total_a,
                "checkpoint 1: restored terms must match pre-crash terms");
    }

    // Checkpoint 2: after one party acknowledged (sender reported Sent,
    // receiver has not yet reported Received) - mid-leg.
    {
        tradep2p::MediatorSession session({terms_fixture(), "addr-a"}, room_id, fee);
        session.join({room_id, "addr-b"});
        const auto turn = session.current_turn();
        session.sender_reported_sent(turn.sender, {turn.room_id, turn.round_index, turn.sender});
        require(session.state() == tradep2p::SessionState::WaitingForReceived,
                "test setup: session must be mid-leg before capturing checkpoint 2");

        const auto persisted = capture(session, room_id, party_a, party_b, fee);
        auto restored = restore_from_disk(persisted);
        require(restored.state() == tradep2p::SessionState::WaitingForReceived,
                "checkpoint 2: restored state must match pre-crash state");
        require(restored.round_index() == 0U && restored.leg_index() == 0U,
                "checkpoint 2: restored round/leg must match pre-crash round/leg");
    }

    // Checkpoint 3: after both parties acknowledged the round but before
    // the next round started - i.e. exactly the transition point where
    // round_index has just advanced.
    {
        tradep2p::MediatorSession session({terms_fixture(), "addr-a"}, room_id, fee);
        session.join({room_id, "addr-b"});
        acknowledge_current_turn(session); // leg 0
        acknowledge_current_turn(session); // leg 1 -> round advances to 1
        require(session.round_index() == 1U,
                "test setup: round must have advanced before capturing checkpoint 3");

        const auto persisted = capture(session, room_id, party_a, party_b, fee);
        auto restored = restore_from_disk(persisted);
        require(restored.round_index() == 1U, "checkpoint 3: restored round must match pre-crash round");
        require(restored.leg_index() == 0U, "checkpoint 3: restored leg must match pre-crash leg");
        require(restored.state() == tradep2p::SessionState::WaitingForSent,
                "checkpoint 3: restored state must match pre-crash state");
    }

    // Checkpoint 4: immediately before final settlement - the last leg of
    // the last round, one acknowledgement away from Complete.
    {
        tradep2p::MediatorSession session({terms_fixture(), "addr-a"}, room_id, fee);
        session.join({room_id, "addr-b"});
        // Advance to the final round (leg 0 of it), then acknowledge that
        // round's first leg in full so only the very last leg remains.
        while (session.round_index() < terms_fixture().rounds - 1U) {
            acknowledge_current_turn(session);
        }
        require(session.leg_index() == 0U, "test setup: must be at leg 0 of the final round");
        acknowledge_current_turn(session); // completes leg 0 of the final round
        require(session.leg_index() == 1U, "test setup: must now be at leg 1 (the last leg) of the final round");
        // Phase 6: leg 1 of the final round (no fee configured here - see
        // no_fee_fixture()) is the trade's actual final tranche, so it is
        // now gated behind SessionState::WaitingForFinalReceiptAck - both
        // parties must acknowledge before it becomes sendable. This
        // checkpoint is specifically about the ordinary WaitingForReceived
        // state on that final leg, not the gate itself (which
        // tests/receipt_tests.cpp already covers directly), so resolve it
        // here before proceeding.
        acknowledge_current_turn(session);
        require(session.state() == tradep2p::SessionState::WaitingForSent,
                "test setup: the final-receipt gate must have opened into WaitingForSent");

        const auto turn = session.current_turn();
        session.sender_reported_sent(turn.sender, {turn.room_id, turn.round_index, turn.sender});
        require(session.state() == tradep2p::SessionState::WaitingForReceived,
                "test setup: session must be one acknowledgement away from Complete");

        const auto persisted = capture(session, room_id, party_a, party_b, fee);
        auto restored = restore_from_disk(persisted);
        require(restored.state() == tradep2p::SessionState::WaitingForReceived,
                "checkpoint 4: restored state must match pre-crash state");
        require(restored.round_index() == terms_fixture().rounds - 1U,
                "checkpoint 4: restored round must be the final round");

        // The recovered session, once its (now-blank) addresses are
        // re-supplied, must still be able to complete correctly - proving
        // restore() produces a session that is not just inspectable but
        // genuinely resumable in principle (the wiring to actually resume
        // a live connection is the explicitly out-of-scope part - see the
        // phase report - not the state machine itself).
        auto resumable = tradep2p::MediatorSession::restore(
            persisted.room_id, persisted.terms, "addr-a", "addr-b", persisted.fee, persisted.state,
            persisted.round_index, persisted.leg_index, persisted.abort_reason);
        const auto final_turn = resumable.current_turn();
        resumable.receiver_reported_received(tradep2p::other_party(final_turn.sender),
                                             {final_turn.room_id, final_turn.round_index, final_turn.sender});
        require(resumable.state() == tradep2p::SessionState::Complete,
                "a restored session with its addresses re-supplied must be able to reach "
                "Complete via the ordinary API, proving restore() is not a dead-end state");
    }
}

// ---------------------------------------------------------------------------
// Recovery classification: the four categories from
// docs/identity-03-journal-recovery.md.
// ---------------------------------------------------------------------------

tradep2p::JournalEntry entry_fixture(tradep2p::SessionState local_state, std::uint32_t round,
                                     tradep2p::AcknowledgementState ack,
                                     tradep2p::MessageDirection direction, tradep2p::MessageType type) {
    tradep2p::JournalEntry entry;
    entry.index = 0U;
    entry.fields.local_state = local_state;
    entry.fields.round = round;
    entry.fields.ack_state = ack;
    entry.fields.direction = direction;
    entry.fields.message_type = type;
    return entry;
}

tradep2p::RecoveryStateResponseMessage response_fixture(bool found, std::uint32_t round_index) {
    tradep2p::RecoveryStateResponseMessage response;
    response.found = found;
    response.round_index = round_index;
    return response;
}

void test_is_value_bearing_message_type() {
    require(tradep2p::is_value_bearing_message_type(tradep2p::MessageType::Sent),
            "Sent must be classified as value-bearing");
    require(!tradep2p::is_value_bearing_message_type(tradep2p::MessageType::Received),
            "Received must not be classified as value-bearing");
    require(!tradep2p::is_value_bearing_message_type(tradep2p::MessageType::CreateOffer),
            "CreateOffer must not be classified as value-bearing");
    require(!tradep2p::is_value_bearing_message_type(tradep2p::MessageType::ListOffers),
            "ListOffers must not be classified as value-bearing");
}

void test_classify_recovery_action_categories() {
    using tradep2p::AcknowledgementState;
    using tradep2p::MessageDirection;
    using tradep2p::RecoveryActionCategory;
    using tradep2p::SessionState;

    // No local entry at all.
    {
        const auto result = tradep2p::classify_recovery_action(std::nullopt, std::nullopt);
        require(result.category == RecoveryActionCategory::UnknownRequiresReconciliation,
                "no local journal entry must classify as unknown");
    }

    // Mediator unreachable.
    {
        const auto local = entry_fixture(SessionState::WaitingForSent, 0, AcknowledgementState::Pending,
                                         MessageDirection::Outbound, tradep2p::MessageType::Sent);
        const auto result = tradep2p::classify_recovery_action(local, std::nullopt);
        require(result.category == RecoveryActionCategory::UnknownRequiresReconciliation,
                "an unreachable mediator must classify as unknown, not assumed safe or committed");
    }

    // Mediator has no record; local journal already shows the trade finished.
    {
        const auto local = entry_fixture(SessionState::Complete, 1, AcknowledgementState::Acknowledged,
                                         MessageDirection::Inbound, tradep2p::MessageType::Complete);
        const auto result = tradep2p::classify_recovery_action(local, response_fixture(false, 0));
        require(result.category == RecoveryActionCategory::AlreadyCommitted,
                "a finished trade with no mediator record (pruned) must classify as already committed");
    }

    // Mediator has no record; local journal still shows the trade open.
    {
        const auto local = entry_fixture(SessionState::WaitingForSent, 0, AcknowledgementState::Pending,
                                         MessageDirection::Outbound, tradep2p::MessageType::Sent);
        const auto result = tradep2p::classify_recovery_action(local, response_fixture(false, 0));
        require(result.category == RecoveryActionCategory::UnknownRequiresReconciliation,
                "an in-progress trade with no mediator record at all must classify as unknown");
    }

    // Mediator ahead of local.
    {
        const auto local = entry_fixture(SessionState::WaitingForReceived, 0, AcknowledgementState::Pending,
                                         MessageDirection::Outbound, tradep2p::MessageType::Sent);
        const auto result = tradep2p::classify_recovery_action(local, response_fixture(true, 1));
        require(result.category == RecoveryActionCategory::AlreadyCommitted,
                "the mediator reporting a later round than the local journal must classify as "
                "already committed");
    }

    // Local ahead of mediator.
    {
        const auto local = entry_fixture(SessionState::WaitingForSent, 2, AcknowledgementState::Pending,
                                         MessageDirection::Outbound, tradep2p::MessageType::Sent);
        const auto result = tradep2p::classify_recovery_action(local, response_fixture(true, 1));
        require(result.category == RecoveryActionCategory::UnknownRequiresReconciliation,
                "the local journal reporting a later round than the mediator must classify as unknown");
    }

    // Same round, already acknowledged locally.
    {
        const auto local = entry_fixture(SessionState::WaitingForSent, 1, AcknowledgementState::Acknowledged,
                                         MessageDirection::Inbound, tradep2p::MessageType::Received);
        const auto result = tradep2p::classify_recovery_action(local, response_fixture(true, 1));
        require(result.category == RecoveryActionCategory::AlreadyCommitted,
                "an already-acknowledged local entry at the same round must classify as already committed");
    }

    // Same round, pending, value-bearing outbound Sent - the unsafe case.
    {
        const auto local = entry_fixture(SessionState::WaitingForReceived, 0, AcknowledgementState::Pending,
                                         MessageDirection::Outbound, tradep2p::MessageType::Sent);
        const auto result = tradep2p::classify_recovery_action(local, response_fixture(true, 0));
        require(result.category == RecoveryActionCategory::UnsafeRequiresConfirmation,
                "an unconfirmed outbound Sent at the same round must require explicit user confirmation");
    }

    // Same round, pending, but not value-bearing - safe to retry.
    {
        const auto local = entry_fixture(SessionState::WaitingForSent, 0, AcknowledgementState::Pending,
                                         MessageDirection::Outbound, tradep2p::MessageType::JoinOffer);
        const auto result = tradep2p::classify_recovery_action(local, response_fixture(true, 0));
        require(result.category == RecoveryActionCategory::SafeIdempotentRetry,
                "a pending, non-value-bearing action at the same round must be safe to retry");
    }

    // Same round, NotApplicable ack state - unknown.
    {
        const auto local = entry_fixture(SessionState::WaitingForPeer, 0, AcknowledgementState::NotApplicable,
                                         MessageDirection::Outbound, tradep2p::MessageType::JoinOffer);
        const auto result = tradep2p::classify_recovery_action(local, response_fixture(true, 0));
        require(result.category == RecoveryActionCategory::UnknownRequiresReconciliation,
                "an entry with no applicable acknowledgement tracking must classify as unknown");
    }
}

} // namespace

int main() {
    std::filesystem::path dir;
    try {
        dir = make_temp_dir();

        test_recovery_message_round_trip();
        test_message_type_bounds();
        test_persisted_room_round_trip();
        test_persisted_room_malformed_and_missing(dir);
        test_persisted_room_atomic_write_crash_simulation(dir);
        test_persisted_room_file_permissions(dir);
        test_mediator_restart_mid_room_recovery();
        test_is_value_bearing_message_type();
        test_classify_recovery_action_categories();

        std::error_code ignored;
        std::filesystem::remove_all(dir, ignored);

        std::cout << "recovery unit tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "recovery test failure: " << error.what() << '\n';
        if (!dir.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(dir, ignored);
        }
        return 1;
    }
}
