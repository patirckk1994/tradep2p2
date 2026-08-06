#include "tradep2p/journal.hpp"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
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
    std::string tmpl = (std::filesystem::temp_directory_path() / "tp2p_journal_test_XXXXXX").string();
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

tradep2p::RoomId room_fixture(std::uint8_t seed = 0x11) {
    tradep2p::RoomId room{};
    room[0] = seed;
    return room;
}

tradep2p::TradeId trade_fixture(std::uint8_t seed = 0x22) {
    tradep2p::TradeId trade{};
    trade[0] = seed;
    return trade;
}

tradep2p::JournalEntryFields make_fields(tradep2p::SessionState state, std::uint32_t round,
                                          tradep2p::MessageDirection direction,
                                          tradep2p::MessageType type,
                                          tradep2p::AcknowledgementState ack,
                                          tradep2p::TradeId trade_id = trade_fixture()) {
    tradep2p::JournalEntryFields fields;
    fields.room_id = room_fixture();
    fields.trade_id = trade_id;
    fields.mediator_id = "mediator.example:8443";
    fields.round = round;
    fields.direction = direction;
    fields.message_type = type;
    fields.message_hash = tradep2p::sha256(std::vector<std::uint8_t>{1, 2, 3});
    fields.ack_state = ack;
    fields.local_state = state;
    // timestamp left at 0 - append() fills in wall-clock time.
    return fields;
}

// ---------------------------------------------------------------------------
// Round trip: append several valid entries, verify the hash chain fields
// and that entries()/latest_for_trade() report exactly what was written.
// ---------------------------------------------------------------------------

void test_append_and_hash_chain(const std::filesystem::path& dir) {
    const auto log_path = (dir / "chain.log").string();
    const auto head_path = (dir / "chain.head").string();
    const auto keypair = tradep2p::generate_ed25519_keypair();

    auto journal = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
    require(journal.entries().empty(), "a freshly opened journal must start empty");

    const auto e0 = journal.append(make_fields(
        tradep2p::SessionState::WaitingForPeer, 0, tradep2p::MessageDirection::Outbound,
        tradep2p::MessageType::JoinOffer, tradep2p::AcknowledgementState::NotApplicable));
    const auto e1 = journal.append(make_fields(
        tradep2p::SessionState::WaitingForSent, 0, tradep2p::MessageDirection::Inbound,
        tradep2p::MessageType::TradeReady, tradep2p::AcknowledgementState::NotApplicable));
    const auto e2 = journal.append(make_fields(
        tradep2p::SessionState::WaitingForReceived, 0, tradep2p::MessageDirection::Outbound,
        tradep2p::MessageType::Sent, tradep2p::AcknowledgementState::Pending));

    require(journal.entries().size() == 3U, "three appended entries must all be recorded");
    require(e0.index == 0U && e1.index == 1U && e2.index == 2U, "entry indices must be sequential");

    const tradep2p::JournalHash genesis{};
    require(e0.previous_hash == genesis, "the first entry's previous_hash must be the genesis constant");
    require(e1.previous_hash == e0.entry_hash,
            "each entry's previous_hash must equal the prior entry's entry_hash");
    require(e2.previous_hash == e1.entry_hash, "chain linkage must hold across the whole journal");
    require(e0.entry_hash != e1.entry_hash && e1.entry_hash != e2.entry_hash,
            "distinct entries must not accidentally hash identically");

    const auto latest = journal.latest_for_trade(trade_fixture());
    require(latest.has_value() && latest->index == e2.index,
            "latest_for_trade must return the most recently appended entry for that trade id");
    require(!journal.latest_for_trade(trade_fixture(0xEE)).has_value(),
            "latest_for_trade must return nullopt for a trade id that was never journaled");

    // Re-opening must replay the exact same chain without complaint.
    auto reopened = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
    require(reopened.entries().size() == 3U, "reopening must replay every previously-appended entry");
    require(reopened.entries().back().entry_hash == e2.entry_hash,
            "reopened chain head must match what was written");
}

// ---------------------------------------------------------------------------
// Checkpoints: signed with the local-history key, verified on open(); a
// wrong public key must be rejected.
// ---------------------------------------------------------------------------

void test_checkpoint_sign_and_verify(const std::filesystem::path& dir) {
    const auto log_path = (dir / "checkpoint.log").string();
    const auto head_path = (dir / "checkpoint.head").string();
    const auto keypair = tradep2p::generate_ed25519_keypair();
    const auto wrong_keypair = tradep2p::generate_ed25519_keypair();

    auto journal = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
    journal.append(make_fields(tradep2p::SessionState::WaitingForPeer, 0,
                               tradep2p::MessageDirection::Outbound, tradep2p::MessageType::JoinOffer,
                               tradep2p::AcknowledgementState::NotApplicable));
    journal.append(make_fields(tradep2p::SessionState::WaitingForSent, 0,
                               tradep2p::MessageDirection::Inbound, tradep2p::MessageType::TradeReady,
                               tradep2p::AcknowledgementState::NotApplicable));
    journal.checkpoint(keypair.private_seed);

    require(std::filesystem::exists(head_path), "checkpoint() must create the head-pointer file");

    auto reopened = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
    require(reopened.entries().size() == 2U, "reopening after a checkpoint must still replay all entries");

    require_throws<tradep2p::JournalTamperError>(
        [&] { (void)tradep2p::Journal::open(log_path, head_path, wrong_keypair.public_key); },
        "opening with the wrong local-history public key must reject the checkpoint signature");

    // checkpoint() on an empty journal is a caller error, not tamper.
    auto empty_log = (dir / "empty.log").string();
    auto empty_head = (dir / "empty.head").string();
    auto empty_journal = tradep2p::Journal::open(empty_log, empty_head, keypair.public_key);
    require_throws<std::logic_error>(
        [&] { empty_journal.checkpoint(keypair.private_seed); },
        "checkpointing a journal with no entries must be rejected");
}

// ---------------------------------------------------------------------------
// Low-level record splicing helpers, used by the tamper tests below.
// Mirrors journal.cpp's own outer record framing exactly (see journal.hpp's
// class comment on Journal): one byte record kind, then a 4-byte big-endian
// body length, then that many body bytes. Splicing at this level (whole
// records only) lets these tests exercise "modify/remove/reorder an entry"
// without needing to reconstruct the entry body's internal field layout.
// ---------------------------------------------------------------------------

struct RawRecord {
    std::uint8_t kind{};
    std::vector<std::uint8_t> body;
};

std::vector<RawRecord> parse_raw_records(const std::vector<std::uint8_t>& raw) {
    std::vector<RawRecord> records;
    std::size_t pos = 0U;
    while (pos < raw.size()) {
        if (raw.size() - pos < 5U) {
            break; // torn tail; not expected in these tests
        }
        RawRecord record;
        record.kind = raw[pos];
        const std::uint32_t length = (static_cast<std::uint32_t>(raw[pos + 1U]) << 24U) |
                                      (static_cast<std::uint32_t>(raw[pos + 2U]) << 16U) |
                                      (static_cast<std::uint32_t>(raw[pos + 3U]) << 8U) |
                                      static_cast<std::uint32_t>(raw[pos + 4U]);
        const std::size_t body_start = pos + 5U;
        if (raw.size() - body_start < length) {
            break;
        }
        record.body.assign(raw.begin() + static_cast<std::ptrdiff_t>(body_start),
                           raw.begin() + static_cast<std::ptrdiff_t>(body_start + length));
        records.push_back(std::move(record));
        pos = body_start + length;
    }
    return records;
}

std::vector<std::uint8_t> serialize_raw_records(const std::vector<RawRecord>& records) {
    std::vector<std::uint8_t> out;
    for (const auto& record : records) {
        out.push_back(record.kind);
        const auto length = static_cast<std::uint32_t>(record.body.size());
        out.push_back(static_cast<std::uint8_t>((length >> 24U) & 0xffU));
        out.push_back(static_cast<std::uint8_t>((length >> 16U) & 0xffU));
        out.push_back(static_cast<std::uint8_t>((length >> 8U) & 0xffU));
        out.push_back(static_cast<std::uint8_t>(length & 0xffU));
        out.insert(out.end(), record.body.begin(), record.body.end());
    }
    return out;
}

// Builds a log with six valid, hash-chained entries for one trade going
// WaitingForPeer -> WaitingForSent -> WaitingForReceived -> WaitingForSent
// (round 1) -> WaitingForReceived (round 1) -> Complete - a legal
// transition sequence matching tradep2p::SessionState's actual state
// machine (Complete is only reachable from WaitingForReceived, never
// directly from WaitingForSent) - and returns its path plus the signing
// keypair used.
struct TamperFixture {
    std::string log_path;
    std::string head_path;
    tradep2p::Ed25519KeyPair keypair;
};

TamperFixture build_tamper_fixture(const std::filesystem::path& dir, const std::string& name) {
    TamperFixture fixture;
    fixture.log_path = (dir / (name + ".log")).string();
    fixture.head_path = (dir / (name + ".head")).string();
    fixture.keypair = tradep2p::generate_ed25519_keypair();

    auto journal = tradep2p::Journal::open(fixture.log_path, fixture.head_path, fixture.keypair.public_key);
    journal.append(make_fields(tradep2p::SessionState::WaitingForPeer, 0,
                               tradep2p::MessageDirection::Outbound, tradep2p::MessageType::JoinOffer,
                               tradep2p::AcknowledgementState::NotApplicable));
    journal.append(make_fields(tradep2p::SessionState::WaitingForSent, 0,
                               tradep2p::MessageDirection::Inbound, tradep2p::MessageType::TradeReady,
                               tradep2p::AcknowledgementState::NotApplicable));
    journal.append(make_fields(tradep2p::SessionState::WaitingForReceived, 0,
                               tradep2p::MessageDirection::Outbound, tradep2p::MessageType::Sent,
                               tradep2p::AcknowledgementState::Pending));
    journal.append(make_fields(tradep2p::SessionState::WaitingForSent, 1,
                               tradep2p::MessageDirection::Inbound, tradep2p::MessageType::Received,
                               tradep2p::AcknowledgementState::Acknowledged));
    journal.append(make_fields(tradep2p::SessionState::WaitingForReceived, 1,
                               tradep2p::MessageDirection::Outbound, tradep2p::MessageType::Sent,
                               tradep2p::AcknowledgementState::Pending));
    journal.append(make_fields(tradep2p::SessionState::Complete, 1,
                               tradep2p::MessageDirection::Inbound, tradep2p::MessageType::Received,
                               tradep2p::AcknowledgementState::Acknowledged));
    return fixture;
}

void test_tamper_modified_entry_detected(const std::filesystem::path& dir) {
    const auto fixture = build_tamper_fixture(dir, "tamper_modify");
    auto records = parse_raw_records(read_all(fixture.log_path));
    require(records.size() == 6U, "fixture must contain exactly six entry records");

    // Flip a byte well inside the third record's body (past the fixed
    // index/version/room_id/trade_id prefix, so it lands in field content
    // rather than accidentally changing the body length interpretation).
    require(records[2].body.size() > 40U, "sanity: entry body must be long enough to tamper safely");
    records[2].body[40] ^= 0x01U;
    write_all(fixture.log_path, serialize_raw_records(records));

    require_throws<tradep2p::JournalTamperError>(
        [&] { (void)tradep2p::Journal::open(fixture.log_path, fixture.head_path, fixture.keypair.public_key); },
        "a modified entry must be detected as a hash mismatch on reopen");
}

void test_tamper_removed_middle_entry_detected(const std::filesystem::path& dir) {
    const auto fixture = build_tamper_fixture(dir, "tamper_remove");
    auto records = parse_raw_records(read_all(fixture.log_path));
    require(records.size() == 6U, "fixture must contain exactly six entry records");

    records.erase(records.begin() + 2); // drop the third entry
    write_all(fixture.log_path, serialize_raw_records(records));

    require_throws<tradep2p::JournalTamperError>(
        [&] { (void)tradep2p::Journal::open(fixture.log_path, fixture.head_path, fixture.keypair.public_key); },
        "removing an interior entry must be detected on reopen");
}

void test_tamper_reordered_entries_detected(const std::filesystem::path& dir) {
    const auto fixture = build_tamper_fixture(dir, "tamper_reorder");
    auto records = parse_raw_records(read_all(fixture.log_path));
    require(records.size() == 6U, "fixture must contain exactly six entry records");

    std::swap(records[1], records[2]); // swap two adjacent entries
    write_all(fixture.log_path, serialize_raw_records(records));

    require_throws<tradep2p::JournalTamperError>(
        [&] { (void)tradep2p::Journal::open(fixture.log_path, fixture.head_path, fixture.keypair.public_key); },
        "reordering entries must be detected on reopen");
}

// ---------------------------------------------------------------------------
// Rollback-to-an-older-checkpoint detection: the head-pointer file must
// never be allowed to reference progress further along than the main log
// currently replays to.
// ---------------------------------------------------------------------------

void test_rollback_to_old_checkpoint_detected(const std::filesystem::path& dir) {
    const auto log_path = (dir / "rollback.log").string();
    const auto head_path = (dir / "rollback.head").string();
    const auto keypair = tradep2p::generate_ed25519_keypair();

    auto journal = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
    journal.append(make_fields(tradep2p::SessionState::WaitingForPeer, 0,
                               tradep2p::MessageDirection::Outbound, tradep2p::MessageType::JoinOffer,
                               tradep2p::AcknowledgementState::NotApplicable));
    journal.checkpoint(keypair.private_seed);

    // Snapshot the log at this earlier, legitimately-checkpointed state.
    const auto old_log_bytes = read_all(log_path);

    journal.append(make_fields(tradep2p::SessionState::WaitingForSent, 0,
                               tradep2p::MessageDirection::Inbound, tradep2p::MessageType::TradeReady,
                               tradep2p::AcknowledgementState::NotApplicable));
    journal.append(make_fields(tradep2p::SessionState::WaitingForReceived, 0,
                               tradep2p::MessageDirection::Outbound, tradep2p::MessageType::Sent,
                               tradep2p::AcknowledgementState::Pending));
    journal.checkpoint(keypair.private_seed); // head now points past the old snapshot

    // Simulate restoring an older copy of ONLY the main log (e.g. from a
    // stale backup) while the head-pointer file is left at its more-advanced
    // value - the exact scenario this check exists to catch.
    write_all(log_path, old_log_bytes);

    require_throws<tradep2p::JournalRollbackError>(
        [&] { (void)tradep2p::Journal::open(log_path, head_path, keypair.public_key); },
        "restoring an older copy of the main log under a newer head-pointer file must be "
        "detected as a rollback");
}

// ---------------------------------------------------------------------------
// Malformed local-state-transition detection. append() enforces the exact
// same tradep2p::SessionState transition table that Journal::open()'s
// replay uses (both call the same internal validator), so exercising it
// live here covers the replay path by construction.
// ---------------------------------------------------------------------------

void test_malformed_state_transition_rejected(const std::filesystem::path& dir) {
    const auto log_path = (dir / "transitions.log").string();
    const auto head_path = (dir / "transitions.head").string();
    const auto keypair = tradep2p::generate_ed25519_keypair();
    auto journal = tradep2p::Journal::open(log_path, head_path, keypair.public_key);

    // A brand-new trade id's first entry must be WaitingForPeer.
    require_throws<tradep2p::JournalTamperError>(
        [&] {
            journal.append(make_fields(tradep2p::SessionState::Complete, 0,
                                       tradep2p::MessageDirection::Outbound,
                                       tradep2p::MessageType::JoinOffer,
                                       tradep2p::AcknowledgementState::NotApplicable,
                                       trade_fixture(0x30)));
        },
        "a trade's first journal entry must be rejected if it is not WaitingForPeer");

    journal.append(make_fields(tradep2p::SessionState::WaitingForPeer, 0,
                               tradep2p::MessageDirection::Outbound, tradep2p::MessageType::JoinOffer,
                               tradep2p::AcknowledgementState::NotApplicable, trade_fixture(0x31)));
    journal.append(make_fields(tradep2p::SessionState::WaitingForSent, 0,
                               tradep2p::MessageDirection::Inbound, tradep2p::MessageType::TradeReady,
                               tradep2p::AcknowledgementState::NotApplicable, trade_fixture(0x31)));

    // WaitingForSent may only advance to WaitingForReceived or Aborted -
    // jumping straight to WaitingForFeeSent is illegal.
    require_throws<tradep2p::JournalTamperError>(
        [&] {
            journal.append(make_fields(tradep2p::SessionState::WaitingForFeeSent, 0,
                                       tradep2p::MessageDirection::Outbound, tradep2p::MessageType::Sent,
                                       tradep2p::AcknowledgementState::Pending, trade_fixture(0x31)));
        },
        "an illegal local-state jump must be rejected");

    // Terminal states must not accept any further transition for that trade.
    journal.append(make_fields(tradep2p::SessionState::WaitingForReceived, 0,
                               tradep2p::MessageDirection::Outbound, tradep2p::MessageType::Sent,
                               tradep2p::AcknowledgementState::Pending, trade_fixture(0x31)));
    journal.append(make_fields(tradep2p::SessionState::Aborted, 0,
                               tradep2p::MessageDirection::Inbound, tradep2p::MessageType::Abort,
                               tradep2p::AcknowledgementState::NotApplicable, trade_fixture(0x31)));
    require_throws<tradep2p::JournalTamperError>(
        [&] {
            journal.append(make_fields(tradep2p::SessionState::WaitingForPeer, 0,
                                       tradep2p::MessageDirection::Outbound, tradep2p::MessageType::JoinOffer,
                                       tradep2p::AcknowledgementState::NotApplicable, trade_fixture(0x31)));
        },
        "a terminal state (Aborted) must not accept a further transition for the same trade id");
}

// ---------------------------------------------------------------------------
// Crash-injection windows (docs/identity-03-journal-recovery.md). Since a
// crash is, by definition, "the process stops running", these are modeled
// as: perform exactly the operations that would have happened up to the
// named point, drop the in-memory Journal (simulating the process dying
// with nothing further buffered - append()/checkpoint() are each a single
// synchronous write+fsync, so there is nothing else in flight to lose), and
// reopen fresh, asserting exactly the expected durable state survived.
// ---------------------------------------------------------------------------

void test_crash_windows(const std::filesystem::path& dir) {
    const auto log_path = (dir / "crash.log").string();
    const auto head_path = (dir / "crash.head").string();
    const auto keypair = tradep2p::generate_ed25519_keypair();
    const auto trade = trade_fixture(0x40);

    // Window 1: "before sending a message" - nothing has been journaled
    // yet. Simulated by simply not having appended anything for this trade.
    {
        auto journal = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
        require(!journal.latest_for_trade(trade).has_value(),
                "before any action, the journal must have nothing recorded for this trade");
    }

    // Window 2: "after sending but before journaling" - by construction,
    // this module always journals BEFORE the corresponding network action
    // is attempted (append() is called, then the message is sent) rather
    // than after, specifically so this window cannot lose information: the
    // client's own call sequence is journal-then-send, not send-then-
    // journal. Model the "about to send" journal entry itself:
    {
        auto journal = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
        journal.append(make_fields(tradep2p::SessionState::WaitingForPeer, 0,
                                   tradep2p::MessageDirection::Outbound,
                                   tradep2p::MessageType::JoinOffer,
                                   tradep2p::AcknowledgementState::NotApplicable, trade));
        // "crash" here: journal goes out of scope, nothing further happens.
    }
    {
        auto journal = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
        const auto latest = journal.latest_for_trade(trade);
        require(latest.has_value() && latest->fields.local_state == tradep2p::SessionState::WaitingForPeer,
                "the journal entry recorded before the send attempt must survive a crash "
                "immediately afterward");
    }

    // Window 3: "after journaling but before receiving an acknowledgement" -
    // the outbound Sent signal is journaled as Pending; a crash before the
    // matching acknowledgement arrives must leave it as Pending, not
    // silently promote it.
    {
        auto journal = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
        journal.append(make_fields(tradep2p::SessionState::WaitingForSent, 0,
                                   tradep2p::MessageDirection::Inbound, tradep2p::MessageType::TradeReady,
                                   tradep2p::AcknowledgementState::NotApplicable, trade));
        journal.append(make_fields(tradep2p::SessionState::WaitingForReceived, 0,
                                   tradep2p::MessageDirection::Outbound, tradep2p::MessageType::Sent,
                                   tradep2p::AcknowledgementState::Pending, trade));
    }
    {
        auto journal = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
        const auto latest = journal.latest_for_trade(trade);
        require(latest.has_value() && latest->fields.ack_state == tradep2p::AcknowledgementState::Pending,
                "an unacknowledged Sent signal must still read as Pending after a crash, "
                "never silently upgraded to Acknowledged");
    }

    // Window 4: "after receiving an acknowledgement" - the client records
    // the acknowledgement as its own new entry once it actually arrives.
    {
        auto journal = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
        journal.append(make_fields(tradep2p::SessionState::WaitingForReceived, 0,
                                   tradep2p::MessageDirection::Inbound, tradep2p::MessageType::Sent,
                                   tradep2p::AcknowledgementState::Acknowledged, trade));
    }
    {
        auto journal = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
        const auto latest = journal.latest_for_trade(trade);
        require(latest.has_value() && latest->fields.ack_state == tradep2p::AcknowledgementState::Acknowledged,
                "a confirmed acknowledgement must survive a crash immediately afterward");
    }

    // Window 5: "between trade rounds" - round advances from 0 to 1.
    {
        auto journal = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
        journal.append(make_fields(tradep2p::SessionState::WaitingForSent, 1,
                                   tradep2p::MessageDirection::Inbound, tradep2p::MessageType::Received,
                                   tradep2p::AcknowledgementState::Acknowledged, trade));
    }
    {
        auto journal = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
        const auto latest = journal.latest_for_trade(trade);
        require(latest.has_value() && latest->fields.round == 1U,
                "the advanced round number must survive a crash between rounds");
    }

    // Window 6: "immediately before final settlement" - the last entry
    // before Complete.
    {
        auto journal = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
        journal.append(make_fields(tradep2p::SessionState::WaitingForReceived, 1,
                                   tradep2p::MessageDirection::Outbound, tradep2p::MessageType::Sent,
                                   tradep2p::AcknowledgementState::Pending, trade));
    }
    {
        auto journal = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
        const auto latest = journal.latest_for_trade(trade);
        require(latest.has_value() && latest->fields.local_state == tradep2p::SessionState::WaitingForReceived &&
                    latest->fields.round == 1U,
                "the state immediately before final settlement must survive a crash there");
    }
}

// ---------------------------------------------------------------------------
// Atomic file replacement: reuses the keystore atomic-write test pattern
// (phase 2) - simulate the on-disk state that exists between the
// head-pointer temp-file write and its rename, and confirm the presence of
// a stray .tmp file neither corrupts a subsequent open() nor blocks a real
// checkpoint() from succeeding afterward.
// ---------------------------------------------------------------------------

void test_atomic_head_replacement_simulated_crash(const std::filesystem::path& dir) {
    const auto log_path = (dir / "atomic.log").string();
    const auto head_path = (dir / "atomic.head").string();
    const auto keypair = tradep2p::generate_ed25519_keypair();

    auto journal = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
    journal.append(make_fields(tradep2p::SessionState::WaitingForPeer, 0,
                               tradep2p::MessageDirection::Outbound, tradep2p::MessageType::JoinOffer,
                               tradep2p::AcknowledgementState::NotApplicable));
    journal.checkpoint(keypair.private_seed);
    const auto original_head_bytes = read_all(head_path);

    // Exactly the on-disk state that exists after write_replace_atomic()
    // has written+fsynced its temp file but before rename() has run.
    const auto tmp_path = std::filesystem::path(head_path + ".tmp");
    write_all(tmp_path, std::vector<std::uint8_t>{'c', 'r', 'a', 's', 'h', 0, 1, 2, 3});
    require(std::filesystem::exists(tmp_path), "test setup: stray tmp file must exist");

    require(read_all(head_path) == original_head_bytes,
            "a stray .tmp file must not affect the real head-pointer file's contents");

    auto reopened = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
    require(reopened.entries().size() == 1U,
            "the journal must still open correctly despite a stray .tmp file next to the head pointer");

    // A real checkpoint (after one more entry) must still succeed despite
    // the stray tmp file, and must not leave any tmp file behind afterward.
    reopened.append(make_fields(tradep2p::SessionState::WaitingForSent, 0,
                                tradep2p::MessageDirection::Inbound, tradep2p::MessageType::TradeReady,
                                tradep2p::AcknowledgementState::NotApplicable));
    reopened.checkpoint(keypair.private_seed);
    require(!std::filesystem::exists(tmp_path),
            "no .tmp file should remain after a successful checkpoint, even if one existed before it started");
}

// ---------------------------------------------------------------------------
// Permission check: both files must be owner-only (0600).
// ---------------------------------------------------------------------------

void test_owner_only_permissions(const std::filesystem::path& dir) {
    const auto log_path = (dir / "perm.log").string();
    const auto head_path = (dir / "perm.head").string();
    const auto keypair = tradep2p::generate_ed25519_keypair();

    auto journal = tradep2p::Journal::open(log_path, head_path, keypair.public_key);
    journal.append(make_fields(tradep2p::SessionState::WaitingForPeer, 0,
                               tradep2p::MessageDirection::Outbound, tradep2p::MessageType::JoinOffer,
                               tradep2p::AcknowledgementState::NotApplicable));
    journal.checkpoint(keypair.private_seed);

    struct stat log_stat {};
    require(::stat(log_path.c_str(), &log_stat) == 0, "stat() on the journal log must succeed");
    require((log_stat.st_mode & 0777U) == (S_IRUSR | S_IWUSR),
            "the journal log file must have owner-only (0600) permissions");

    struct stat head_stat {};
    require(::stat(head_path.c_str(), &head_stat) == 0, "stat() on the head-pointer file must succeed");
    require((head_stat.st_mode & 0777U) == (S_IRUSR | S_IWUSR),
            "the head-pointer file must have owner-only (0600) permissions");
}

// ---------------------------------------------------------------------------
// Malformed files are rejected with a structured JournalFormatError.
// ---------------------------------------------------------------------------

void test_malformed_journal_rejected(const std::filesystem::path& dir) {
    const auto log_path = (dir / "malformed.log").string();
    const auto head_path = (dir / "malformed.head").string();
    const auto keypair = tradep2p::generate_ed25519_keypair();

    // A COMPLETE record (body_length matches the actual trailing bytes)
    // with an unrecognized kind byte - deliberately not a torn/incomplete
    // record (that case is tolerated, not rejected - see the torn-write
    // test just below), so this must reach the "unknown record kind" check.
    write_all(log_path, std::vector<std::uint8_t>{9, 0, 0, 0, 3, 1, 2, 3}); // kind=9, body_length=3, body={1,2,3}
    require_throws<tradep2p::JournalFormatError>(
        [&] { (void)tradep2p::Journal::open(log_path, head_path, keypair.public_key); },
        "an unknown record kind must be rejected as a format error");

    // A torn trailing write (incomplete record) must NOT be treated as a
    // format error - it must be silently truncated and tolerated.
    const auto ok_log_path = (dir / "torn.log").string();
    const auto ok_head_path = (dir / "torn.head").string();
    {
        auto journal = tradep2p::Journal::open(ok_log_path, ok_head_path, keypair.public_key);
        journal.append(make_fields(tradep2p::SessionState::WaitingForPeer, 0,
                                   tradep2p::MessageDirection::Outbound, tradep2p::MessageType::JoinOffer,
                                   tradep2p::AcknowledgementState::NotApplicable));
    }
    {
        // Append a torn (truncated) second record directly.
        std::ofstream out(ok_log_path, std::ios::binary | std::ios::app);
        const std::vector<std::uint8_t> torn = {1, 0, 0, 0, 100, 'x', 'y'}; // claims 100 body bytes, has 2
        out.write(reinterpret_cast<const char*>(torn.data()), static_cast<std::streamsize>(torn.size()));
    }
    auto recovered = tradep2p::Journal::open(ok_log_path, ok_head_path, keypair.public_key);
    require(recovered.entries().size() == 1U,
            "a torn trailing record must be tolerated (truncated away), not rejected as tamper/format error");
}

} // namespace

int main() {
    std::filesystem::path dir;
    try {
        dir = make_temp_dir();

        test_append_and_hash_chain(dir);
        test_checkpoint_sign_and_verify(dir);
        test_tamper_modified_entry_detected(dir);
        test_tamper_removed_middle_entry_detected(dir);
        test_tamper_reordered_entries_detected(dir);
        test_rollback_to_old_checkpoint_detected(dir);
        test_malformed_state_transition_rejected(dir);
        test_crash_windows(dir);
        test_atomic_head_replacement_simulated_crash(dir);
        test_owner_only_permissions(dir);
        test_malformed_journal_rejected(dir);

        std::error_code ignored;
        std::filesystem::remove_all(dir, ignored);

        std::cout << "journal unit tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "journal test failure: " << error.what() << '\n';
        if (!dir.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(dir, ignored);
        }
        return 1;
    }
}
