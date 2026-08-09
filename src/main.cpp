#include "tradep2p/disclosure.hpp"
#include "tradep2p/ephemeral.hpp"
#include "tradep2p/history.hpp"
#include "tradep2p/journal.hpp"
#include "tradep2p/keystore.hpp"
#include "tradep2p/lobby.hpp"
#include "tradep2p/mediator_auth.hpp"
#include "tradep2p/protocol.hpp"
#include "tradep2p/receipt.hpp"
#include "tradep2p/recognition.hpp"
#include "tradep2p/recovery.hpp"
#include "tradep2p/registry.hpp"
#include "tradep2p/secure_channel.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <csignal>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>

namespace {

using tradep2p::AbortMessage;
using tradep2p::CancelOfferMessage;
using tradep2p::CreateOfferMessage;
using tradep2p::ClientTlsPolicy;
using tradep2p::connect_raw_tcp;
using tradep2p::connect_raw_via_socks5;
using tradep2p::CounterpartyFingerprint;
using tradep2p::CounterpartyHistoryEntry;
using tradep2p::IdentityKeystore;
using tradep2p::JoinOfferMessage;
using tradep2p::Journal;
using tradep2p::JournalEntry;
using tradep2p::LocalCounterpartyHistory;
using tradep2p::LocalOutcome;
using tradep2p::Endpoint;
using tradep2p::Frame;
using tradep2p::LobbyServer;
using tradep2p::MessageType;
using tradep2p::Party;
using tradep2p::RecoveryStateRequestMessage;
using tradep2p::RecoveryStateResponseMessage;
using tradep2p::RegistryNode;
using tradep2p::RegistryServer;
using tradep2p::RoomId;
using tradep2p::RoundSignalMessage;
using tradep2p::SecureChannel;
using tradep2p::ServerTlsIdentity;
using tradep2p::SessionState;
using tradep2p::TradeTerms;
using tradep2p::TurnMessage;

bool log_enabled() noexcept {
    static const bool enabled = [] {
        if (const char* value = std::getenv("TRADEP2P_LOG_ENABLED")) {
            const std::string env_value(value);
            return env_value != "0" && env_value != "false" && env_value != "FALSE";
        }
        return false;
    }();
    return enabled;
}

void append_log(const std::string& message) {
    if (!log_enabled()) {
        return;
    }

    if (const char* value = std::getenv("TRADEP2P_LOG_FILE")) {
        const std::string path(value);
        if (path.empty()) {
            return;
        }

        std::FILE* file = std::fopen(path.c_str(), "a");
        if (file == nullptr) {
            return;
        }

        const std::time_t now = std::time(nullptr);
        std::tm tm{};
        if (::localtime_r(&now, &tm) != nullptr) {
            std::fprintf(file,
                         "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                         tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                         tm.tm_hour, tm.tm_min, tm.tm_sec, message.c_str());
        } else {
            std::fprintf(file, "%s\n", message.c_str());
        }
        std::fflush(file);
        std::fclose(file);
    }
}

std::uint16_t parse_port(const std::string& value) {
    std::size_t used = 0U;
    const auto parsed = std::stoul(value, &used, 10);
    if (used != value.size() || parsed == 0U || parsed > 65535U) {
        throw std::invalid_argument("invalid port");
    }
    return static_cast<std::uint16_t>(parsed);
}

Endpoint parse_endpoint(const std::string& text) {
    if (!text.empty() && text.front() == '[') {
        const auto close = text.find(']');
        if (close == std::string::npos || close + 2U >= text.size() ||
            text[close + 1U] != ':') {
            throw std::invalid_argument("endpoint must be [ipv6]:port");
        }
        return Endpoint{text.substr(1U, close - 1U),
                        parse_port(text.substr(close + 2U))};
    }

    const auto separator = text.rfind(':');
    if (separator == std::string::npos || separator == 0U ||
        separator + 1U >= text.size()) {
        throw std::invalid_argument("endpoint must be host:port");
    }
    return Endpoint{text.substr(0U, separator),
                    parse_port(text.substr(separator + 1U))};
}

std::uint64_t parse_u64(const std::string& value, const char* name) {
    if (value.empty() || value.front() < '0' || value.front() > '9') {
        throw std::invalid_argument(std::string("invalid ") + name);
    }

    std::uint64_t parsed = 0U;
    const char* begin = value.data();
    const char* end = begin + value.size();
    const auto [ptr, error] = std::from_chars(begin, end, parsed, 10);
    if (error != std::errc{} || ptr != end || parsed == 0U) {
        throw std::invalid_argument(std::string("invalid ") + name);
    }
    return parsed;
}

std::uint32_t parse_u32(const std::string& value, const char* name) {
    const auto parsed = parse_u64(value, name);
    if (parsed > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument(std::string(name) + " is too large");
    }
    return static_cast<std::uint32_t>(parsed);
}

const char* party_name(Party party) {
    return party == Party::A ? "A" : "B";
}

void print_client_help() {
    std::cout
        << "Commands:\n"
        << "  /offer SELL_SYMBOL SELL_AMOUNT BUY_SYMBOL BUY_AMOUNT ROUNDS RECEIVE_ADDRESS\n"
        << "      publish an open room; your address receives BUY_SYMBOL\n"
        << "  /offers [AFTER_ROOM_ID] [LIMIT]\n"
        << "      list up to 32 open rooms; use the printed cursor for the next page\n"
        << "  /join ROOM_ID RECEIVE_ADDRESS\n"
        << "      take an offer; your address receives SELL_SYMBOL\n"
        << "  /cancel ROOM_ID\n"
        << "      cancel your still-open offer\n"
        << "  /sent ROOM_ID\n"
        << "  /received ROOM_ID\n"
        << "  /abort ROOM_ID\n"
        << "  /recovery request ROOM_ID\n"
        << "      ask the mediator what it has on file for a room you remember\n"
        << "  /recognize ROOM_ID [ml-dsa-65|ed25519]\n"
        << "      requires an unlocked keystore; asks the counterparty in that room to prove\n"
        << "      control of their per-mediator pseudonym key, right now - a locally-verified\n"
        << "      \"have I traded with this key before\" count, nothing more (specs.txt SS8);\n"
        << "      an incoming challenge is auto-answered if a keystore is unlocked\n"
        << "  /receipts ROOM_ID\n"
        << "      show this session's mediator-signed staged receipts for a room, if any\n"
        << "      (receipt acks/final-tranche gating are handled automatically - specs.txt SS9.1)\n"
        << "  /disclose SOURCE_ROOM_ID TARGET_ROOM_ID\n"
        << "      privately show SOURCE_ROOM_ID's receipt chain to the counterparty currently in\n"
        << "      TARGET_ROOM_ID - bound to that recipient and that room only, not broadcastable\n"
        << "      (specs.txt SS9.2)\n"
        << "  /keystore create PATH PASSPHRASE [ALIAS]\n"
        << "  /keystore unlock PATH PASSPHRASE\n"
        << "  /keystore lock\n"
        << "  /keystore rotate PASSPHRASE\n"
        << "  /keystore destroy PATH\n"
        << "  /keystore show-identity [PATH]\n"
        << "      with PATH: read the header without unlocking; without: show the loaded keystore\n"
        << "  /journal status\n"
        << "      requires an unlocked keystore; opens/verifies this identity's local journal\n"
        << "  /history list\n"
        << "  /history show FINGERPRINT\n"
        << "  /block FINGERPRINT\n"
        << "  /unblock FINGERPRINT\n"
        << "  /note FINGERPRINT TEXT...\n"
        << "      history/block/unblock/note require an unlocked keystore; FINGERPRINT is 64 hex "
           "chars, scoped to this session's mediator (" << "see /help again after connecting)\n"
        << "  /help\n"
        << "  /quit\n";
}

// ---------------------------------------------------------------------------
// Phase 4 CLI wiring: keystore/journal/history are entirely local operations
// (no wire messages except /recovery request, which reuses the ordinary
// send/print-on-receive pattern every other command here already follows).
// One IdentityKeystore/Journal/LocalCounterpartyHistory is held per
// interactive session, lazily opened - see ensure_journal_open()/
// ensure_history_open() below. The journal's local-history signing key is
// derived directly from the master secret (NOT via
// IdentityKeystore::derive_scoped_keypair(), which folds in the service-
// scoped key generation counter) so that rotating a service-scoped key
// (e.g. after a suspected login-key compromise) never invalidates
// already-checkpointed journal entries signed under an earlier generation -
// journal continuity is a different concern from service-key rotation and
// deliberately is not coupled to it here.
// ---------------------------------------------------------------------------

struct ClientState {
    std::unordered_map<std::string, Party> room_parties;
    std::unordered_map<std::string, TurnMessage> current_turns;

    std::optional<IdentityKeystore> keystore;
    std::string keystore_path; // path of the currently loaded keystore, if any
    std::optional<Journal> journal;
    std::optional<LocalCounterpartyHistory> history;
    // This session's mediator endpoint text (e.g. "host:port"), used as the
    // implicit mediator_id for history/journal entries - matches the design
    // choice that a CLI client process only ever talks to one mediator at a
    // time, so there is no need for a separate CLI argument to say which
    // mediator a history/journal record belongs to.
    std::string mediator_id;

    // Phase 4b (personal counterparty recognition): outstanding challenges
    // THIS client has issued as a verifier (via /recognize), never
    // persisted - a live handshake has no reason to survive a restart. One
    // tracker per session, matching the one-journal/one-history-per-session
    // convention above.
    tradep2p::RecognitionChallengeTracker recognition_tracker;
    // room id (hex) -> the counterparty fingerprint this client has
    // actually verified control of for that room this session (i.e. a
    // RecognitionResponse that passed recognition_tracker.consume()).
    // Consulted when the room reaches Complete/Abort to decide whether
    // there is anything to record in the local history at all - per
    // specs.txt SS8, "no key presented" is the normal case and must not
    // produce a history entry.
    std::unordered_map<std::string, tradep2p::CounterpartyFingerprint> room_recognized_fingerprint;

    // Phase 5 (per-trade ephemeral identities): this room's own freshly
    // generated (never derived - see ephemeral.hpp) trade signing keypair,
    // and the counterparty's announced public key once their
    // TradeEphemeralKey message arrives. Neither map is persisted - an
    // ephemeral key that doesn't survive a crash is the documented,
    // deliberate limitation (specs.txt SS5); a fresh reconnect simply
    // generates and announces a new one.
    std::unordered_map<std::string, tradep2p::Ed25519KeyPair> room_ephemeral_keypair;
    std::unordered_map<std::string, tradep2p::Ed25519PublicKey> room_counterparty_ephemeral_key;
    // room id (hex) -> counterparty's ClientId, for TradeMessageContext's
    // `recipient` field - populated from TradeReadyMessage::peer_id.
    std::unordered_map<std::string, tradep2p::ClientId> room_peer_id;
    // room id (hex) -> this room's TradeTerms, cached from TradeReadyMessage
    // so a ReceiptAck's terms_commitment can be computed the same way the
    // mediator computes it from its own session.terms() - see
    // lobby.cpp's handle_receipt_ack().
    std::unordered_map<std::string, TradeTerms> room_terms;

    // Phase 6 (staged receipts): this room's received chain of
    // IssuedReceipts, in stage order, kept for this session only (not
    // persisted - a natural follow-on, same limitation as phase 5's
    // ephemeral keys). mediator_receipt_key pins the FIRST mediator receipt
    // public key this session ever sees for THIS mediator_id - trust on
    // first use, the same bootstrapping caveat specs.txt SS1.3 already
    // names for the unauthenticated registry; a mismatch on any later
    // receipt is a loud, printed warning, not a silent accept.
    std::unordered_map<std::string, std::vector<tradep2p::IssuedReceipt>> room_receipts;
    std::optional<tradep2p::Ed25519PublicKey> mediator_receipt_key;
};

std::string default_journal_log_path(const std::string& keystore_path) {
    return keystore_path + ".journal.log";
}
std::string default_journal_head_path(const std::string& keystore_path) {
    return keystore_path + ".journal.head";
}
std::string default_history_path(const std::string& keystore_path) {
    return keystore_path + ".history";
}

void require_unlocked_keystore(const ClientState& state) {
    if (!state.keystore.has_value() || !state.keystore->is_unlocked()) {
        throw std::invalid_argument(
            "no unlocked keystore; run /keystore create or /keystore unlock first");
    }
}

// Opens (or reuses an already-open) Journal for the currently unlocked
// keystore. See the class comment above for why the local-history key is
// derived directly from the master secret rather than through the
// keystore's generation-folding derive_scoped_keypair().
Journal& ensure_journal_open(ClientState& state) {
    require_unlocked_keystore(state);
    if (!state.journal.has_value()) {
        const auto local_history_keypair = tradep2p::derive_ed25519_keypair(
            state.keystore->master_secret(), tradep2p::key_scope::kLocalHistory, "");
        state.journal = Journal::open(default_journal_log_path(state.keystore_path),
                                      default_journal_head_path(state.keystore_path),
                                      local_history_keypair.public_key);
    }
    return *state.journal;
}

LocalCounterpartyHistory& ensure_history_open(ClientState& state) {
    require_unlocked_keystore(state);
    if (!state.history.has_value()) {
        state.history = LocalCounterpartyHistory::open(default_history_path(state.keystore_path),
                                                        *state.keystore);
    }
    return *state.history;
}

// Phase 4b: this client's own per-mediator pseudonym keypair, used both to
// sign an incoming RecognitionChallenge (proving control to a counterparty)
// and to issue challenges of its own via /recognize. Derived DIRECTLY from
// the master secret rather than through IdentityKeystore::
// derive_scoped_keypair() - deliberately bypassing that method's key-
// generation folding, for the exact continuity reason
// ensure_journal_open() above already documents for the local-history key:
// rotating a service-scoped key must never silently reset accumulated
// counterparty recognition back to "unknown key".
tradep2p::Ed25519KeyPair mediator_pseudonym_keypair(const ClientState& state) {
    return tradep2p::derive_ed25519_keypair(state.keystore->master_secret(),
                                            tradep2p::key_scope::kMediatorPseudonym, state.mediator_id);
}

// Post-quantum counterpart of the above - same rationale (direct
// derivation, distinct key_scope label so the two algorithms' seeds stay
// independent - see key_scope::kMediatorPseudonymMlDsa65's own comment).
tradep2p::MlDsa65KeyPair mediator_pseudonym_keypair_mldsa65(const ClientState& state) {
    return tradep2p::derive_mldsa65_keypair(
        state.keystore->master_secret(),
        tradep2p::key_scope::kMediatorPseudonymMlDsa65, state.mediator_id);
}

template <std::size_t N>
std::string hex_encode(const std::array<std::uint8_t, N>& bytes) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (const std::uint8_t byte : bytes) {
        stream << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return stream.str();
}

template <std::size_t N>
bool is_all_zero(const std::array<std::uint8_t, N>& bytes) {
    return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t b) { return b == 0U; });
}

template <std::size_t N>
std::array<std::uint8_t, N> hex_decode(const std::string& text) {
    if (text.size() != N * 2U) {
        throw std::invalid_argument("expected " + std::to_string(N * 2U) + " hex characters, got " +
                                    std::to_string(text.size()));
    }
    std::array<std::uint8_t, N> out{};
    for (std::size_t i = 0; i < N; ++i) {
        out[i] = static_cast<std::uint8_t>(std::stoul(text.substr(i * 2U, 2U), nullptr, 16));
    }
    return out;
}

const char* session_state_name(SessionState state) {
    switch (state) {
        case SessionState::WaitingForPeer: return "waiting_for_peer";
        case SessionState::WaitingForSent: return "waiting_for_sent";
        case SessionState::WaitingForReceived: return "waiting_for_received";
        case SessionState::WaitingForFeeSent: return "waiting_for_fee_sent";
        case SessionState::WaitingForFinalReceiptAck: return "waiting_for_final_receipt_ack";
        case SessionState::WaitingForFeeConfirmation: return "waiting_for_fee_confirmation";
        case SessionState::Complete: return "complete";
        case SessionState::Aborted: return "aborted";
    }
    return "unknown";
}

const char* ack_state_name(tradep2p::AcknowledgementState state) {
    switch (state) {
        case tradep2p::AcknowledgementState::NotApplicable: return "n/a";
        case tradep2p::AcknowledgementState::Pending: return "pending";
        case tradep2p::AcknowledgementState::Acknowledged: return "acknowledged";
    }
    return "unknown";
}

const char* recovery_category_name(tradep2p::RecoveryActionCategory category) {
    switch (category) {
        case tradep2p::RecoveryActionCategory::SafeIdempotentRetry: return "safe idempotent retry";
        case tradep2p::RecoveryActionCategory::UnsafeRequiresConfirmation:
            return "UNSAFE - requires explicit user confirmation";
        case tradep2p::RecoveryActionCategory::AlreadyCommitted: return "already committed";
        case tradep2p::RecoveryActionCategory::UnknownRequiresReconciliation:
            return "unknown - requires manual reconciliation";
    }
    return "unknown";
}

void print_public_identity(const tradep2p::PublicIdentity& identity) {
    std::cout << "  identity id:  " << hex_encode(identity.identity_id) << '\n'
              << "  alias:        " << (identity.alias.empty() ? "(none)" : identity.alias) << '\n'
              << "  public key:   " << hex_encode(identity.identity_public_key) << '\n'
              << "  created at:   " << identity.created_at << " (unix seconds)\n"
              << "  key gen:      " << identity.key_generation << '\n';
}

void print_journal_entry(const JournalEntry& entry) {
    std::cout << "  #" << entry.index
              << " room=" << (is_all_zero(entry.fields.room_id) ? std::string("-")
                                                                 : tradep2p::room_id_to_hex(entry.fields.room_id))
              << " trade=" << hex_encode(entry.fields.trade_id)
              << " round=" << entry.fields.round
              << " dir=" << (entry.fields.direction == tradep2p::MessageDirection::Outbound ? "out" : "in")
              << " msg_type=" << static_cast<unsigned int>(entry.fields.message_type)
              << " ack=" << ack_state_name(entry.fields.ack_state)
              << " local_state=" << session_state_name(entry.fields.local_state)
              << " ts=" << entry.fields.timestamp << '\n';
}

void print_journal_status(const Journal& journal) {
    const auto& entries = journal.entries();
    std::cout << "journal chain verified OK: " << entries.size()
              << (entries.size() == 1U ? " entry\n" : " entries\n");
    if (entries.empty()) {
        return;
    }
    const std::size_t show = std::min<std::size_t>(5U, entries.size());
    std::cout << "last " << show << (show == 1U ? " entry:\n" : " entries:\n");
    for (std::size_t i = entries.size() - show; i < entries.size(); ++i) {
        print_journal_entry(entries[i]);
    }
}

void print_history_entry(const CounterpartyHistoryEntry& entry) {
    std::cout << "  " << tradep2p::fingerprint_to_hex(entry.fingerprint)
              << "\n    mediator:    " << entry.mediator_id
              << "\n    first seen:  " << entry.first_seen
              << "\n    last seen:   " << entry.last_seen
              << "\n    encounters:  " << entry.encounter_count
              << "\n    settled:     " << tradep2p::settlement_count(entry) << "x"
              << "\n    incomplete:  " << tradep2p::incomplete_count(entry) << "x"
              << "\n    blocked:     " << (entry.locally_blocked ? "YES" : "no")
              << "\n    confidence:  " << tradep2p::confidence_level_name(entry.confidence)
              << "\n    display:     " << tradep2p::display_category_name(tradep2p::classify_for_display(entry))
              << "\n    notes:       " << entry.notes.size()
              << "\n    evidence:    " << entry.evidence_hashes.size() << '\n';
    for (const auto& note : entry.notes) {
        std::cout << "      [" << note.recorded_at << "] " << note.text << '\n';
    }
}

// Phase 4b: if this session verified a counterparty's key control for
// `room` (via a consumed RecognitionResponse - see the RecognitionResponse
// case below), record the room's outcome against that fingerprint in the
// local history and forget the room's recognition state. A no-op if no key
// was ever recognized for this room - "no key presented" must never
// manufacture a history entry (specs.txt SS8.4). Requires an unlocked
// keystore to actually persist anything; if the keystore was locked in the
// meantime, the recognition is silently dropped rather than recorded
// against a keystore that is no longer available to authorize the write.
void record_recognized_room_outcome(ClientState& state, const std::string& room,
                                    tradep2p::LocalOutcome outcome) {
    const auto it = state.room_recognized_fingerprint.find(room);
    if (it == state.room_recognized_fingerprint.end()) {
        return;
    }
    const auto fingerprint = it->second;
    state.room_recognized_fingerprint.erase(it);
    if (!state.keystore.has_value() || !state.keystore->is_unlocked()) {
        return;
    }
    auto& history = ensure_history_open(state);
    const auto& entry = history.record_encounter(fingerprint, state.mediator_id, outcome);
    std::cout << "  local history: " << tradep2p::fingerprint_to_hex(fingerprint) << " now settled "
              << tradep2p::settlement_count(entry) << "x, incomplete " << tradep2p::incomplete_count(entry)
              << "x, on this mediator\n";
}

void handle_server_frame(SecureChannel& channel, const Frame& frame, ClientState& state) {
    switch (frame.type) {
    case MessageType::OfferCreated: {
        const auto message = tradep2p::decode_offer_created(frame.payload);
        std::cout << "offer room created: "
                  << tradep2p::room_id_to_hex(message.room_id) << '\n';
        break;
    }
    case MessageType::OfferList: {
        const auto message = tradep2p::decode_offer_list(frame.payload);
        std::cout << "open offers: " << message.offers.size() << '\n';
        for (const auto& offer : message.offers) {
            std::cout << "  " << tradep2p::room_id_to_hex(offer.room_id)
                      << " | SELL " << offer.terms.total_a << ' ' << offer.terms.asset_a
                      << " | BUY " << offer.terms.total_b << ' ' << offer.terms.asset_b
                      << " | rounds " << offer.terms.rounds << '\n';
        }
        if (message.has_more) {
            std::cout << "more offers: /offers "
                      << tradep2p::room_id_to_hex(message.next_cursor)
                      << '\n';
        }
        break;
    }
    case MessageType::OfferCancelled: {
        const auto message = tradep2p::decode_offer_cancelled(frame.payload);
        std::cout << "offer cancelled: "
                  << tradep2p::room_id_to_hex(message.room_id) << '\n';
        break;
    }
    case MessageType::TradeReady: {
        const auto message = tradep2p::decode_trade_ready(frame.payload);
        const std::string room = tradep2p::room_id_to_hex(message.room_id);
        state.room_parties[room] = message.assigned_party;
        state.room_peer_id[room] = message.peer_id;
        state.room_terms[room] = message.terms;
        std::cout << "\nroom ready: " << room << '\n'
                  << "  your party: " << party_name(message.assigned_party) << '\n'
                  << "  peer: " << tradep2p::client_id_to_hex(message.peer_id) << '\n'
                  << "  trade: " << message.terms.total_a << ' '
                  << message.terms.asset_a << " <-> "
                  << message.terms.total_b << ' ' << message.terms.asset_b << '\n'
                  << "  rounds: " << message.terms.rounds << '\n'
                  << "  party A receive address: " << message.receive_address_a << '\n'
                  << "  party B receive address: " << message.receive_address_b << '\n';

        // Phase 5: every room automatically announces a fresh ephemeral
        // trade key, unlike phase 4b's opt-in /recognize - an ephemeral key
        // reveals nothing linkable by construction (freshly random, never
        // derived - ephemeral.hpp), so there is no privacy cost to make
        // this the default the way there is for the per-mediator pseudonym.
        auto ephemeral_keypair = tradep2p::generate_ephemeral_trade_keypair();
        tradep2p::TradeEphemeralKeyMessage announce;
        announce.room_id = message.room_id;
        announce.ephemeral_public_key = ephemeral_keypair.public_key;
        state.room_ephemeral_keypair.erase(room);
        state.room_ephemeral_keypair.emplace(room, std::move(ephemeral_keypair));
        state.room_counterparty_ephemeral_key.erase(room);
        channel.send_frame(MessageType::TradeEphemeralKey,
                           tradep2p::encode_trade_ephemeral_key(announce));
        break;
    }
    case MessageType::Turn: {
        const auto message = tradep2p::decode_turn(frame.payload);
        const std::string room = tradep2p::room_id_to_hex(message.room_id);
        state.current_turns[room] = message;
        const auto party_it = state.room_parties.find(room);
        const bool mine = party_it != state.room_parties.end() &&
                          party_it->second == message.sender;
        std::cout << "\nroom " << room << " round "
                  << (message.round_index + 1U) << ": "
                  << (mine ? "SEND " : "EXPECT ")
                  << message.amount << ' ' << message.asset
                  << " to " << message.destination << '\n'
                  << (mine ? "Use /sent ROOM_ID after sending externally.\n"
                           : "Use /received ROOM_ID after verifying externally.\n");
        break;
    }
    case MessageType::Sent: {
        const auto message = tradep2p::decode_round_signal(frame.payload);
        const std::string room = tradep2p::room_id_to_hex(message.room_id);
        std::cout << "peer reported sent in room "
                  << room << '\n';
        break;
    }
    case MessageType::Received: {
        const auto message = tradep2p::decode_round_signal(frame.payload);
        const std::string room = tradep2p::room_id_to_hex(message.room_id);
        std::cout << "peer reported receipt in room "
                  << room << '\n';
        break;
    }
    case MessageType::Complete: {
        const auto message = tradep2p::decode_complete(frame.payload);
        const std::string room = tradep2p::room_id_to_hex(message.room_id);
        state.room_parties.erase(room);
        state.current_turns.erase(room);
        state.room_counterparty_ephemeral_key.erase(room);
        state.room_peer_id.erase(room);
        state.room_terms.erase(room);
        // room_receipts AND room_ephemeral_keypair are deliberately NOT
        // cleared here - phase 8 (selective disclosure) needs THIS room's
        // own ephemeral private key to later sign a disclosure of THIS
        // room's receipt chain to a counterparty in some future
        // negotiation (see /disclose below). Both stay available for the
        // rest of this session after the negotiation state above, which
        // has no further use, is discarded.
        record_recognized_room_outcome(state, room, tradep2p::LocalOutcome::Successful);
        std::cout << "room complete: " << room << '\n';
        break;
    }
    case MessageType::Abort: {
        const auto message = tradep2p::decode_abort(frame.payload);
        const std::string room = tradep2p::room_id_to_hex(message.room_id);
        state.room_parties.erase(room);
        state.current_turns.erase(room);
        state.room_ephemeral_keypair.erase(room);
        state.room_counterparty_ephemeral_key.erase(room);
        state.room_peer_id.erase(room);
        state.room_terms.erase(room);
        record_recognized_room_outcome(state, room, tradep2p::LocalOutcome::Incomplete);
        std::cout << "room aborted: " << room << " - " << message.reason << '\n';
        break;
    }
    case MessageType::RecognitionChallenge: {
        const auto message = tradep2p::decode_recognition_challenge(frame.payload);
        const std::string room = tradep2p::room_id_to_hex(message.room_id);
        if (!state.keystore.has_value() || !state.keystore->is_unlocked()) {
            // Declining is not evidence of anything (specs.txt SS8.2) - this
            // client simply has nothing to prove control of right now.
            std::cout << "\nroom " << room
                      << ": counterparty requested recognition proof, but no keystore is "
                         "unlocked - declining (no response sent)\n";
            break;
        }
        tradep2p::RecognitionChallengeFields fields;
        fields.suite_id = message.suite_id;
        fields.protocol_version = tradep2p::kProtocolVersion;
        fields.mediator_id = state.mediator_id;
        fields.room_id = message.room_id;
        fields.nonce = message.nonce;
        fields.created_at = message.created_at;
        fields.expires_at = message.expires_at;

        // Answer with whichever suite the challenge asked for - both keys
        // are cheap, deterministic derivations (no persistence, no cost to
        // deriving one that goes unused), so there's no reason to gate this
        // on a client-wide default the way /recognize's own outgoing suite
        // choice below does.
        tradep2p::RecognitionResponseMessage response;
        response.room_id = message.room_id;
        response.nonce = message.nonce;
        response.suite_id = message.suite_id;
        if (message.suite_id == tradep2p::kRecognitionSuiteEd25519V1) {
            const auto own_keypair = mediator_pseudonym_keypair(state);
            response.prover_public_key.assign(own_keypair.public_key.begin(),
                                              own_keypair.public_key.end());
            const auto signature =
                tradep2p::sign_recognition_response(own_keypair.private_seed, fields);
            response.signature.assign(signature.begin(), signature.end());
        } else if (message.suite_id == tradep2p::kRecognitionSuiteMlDsa65V1) {
            const auto own_keypair = mediator_pseudonym_keypair_mldsa65(state);
            response.prover_public_key.assign(own_keypair.public_key.begin(),
                                              own_keypair.public_key.end());
            const auto signature =
                tradep2p::sign_recognition_response_mldsa65(own_keypair.private_seed, fields);
            response.signature.assign(signature.begin(), signature.end());
        } else {
            std::cout << "\nroom " << room
                      << ": counterparty's recognition challenge named an unknown suite_id "
                      << message.suite_id << " - declining (no response sent)\n";
            break;
        }
        channel.send_frame(MessageType::RecognitionResponse,
                           tradep2p::encode_recognition_response(response));
        std::cout << "\nroom " << room << ": answered counterparty's recognition challenge\n";
        break;
    }
    case MessageType::RecognitionResponse: {
        const auto message = tradep2p::decode_recognition_response(frame.payload);
        const std::string room = tradep2p::room_id_to_hex(message.room_id);
        const auto fingerprint = state.recognition_tracker.consume(state.mediator_id, message);
        if (!fingerprint.has_value()) {
            std::cout << "\nroom " << room
                      << ": recognition response did not verify (unknown/expired/already-"
                         "answered challenge, or a bad signature) - treated as no proof, not "
                         "evidence of anything\n";
            break;
        }
        state.room_recognized_fingerprint[room] = *fingerprint;
        std::cout << "\nroom " << room << ": counterparty proved control of "
                  << tradep2p::fingerprint_to_hex(*fingerprint) << '\n';
        if (state.keystore.has_value() && state.keystore->is_unlocked()) {
            auto& history = ensure_history_open(state);
            const auto found = history.find(*fingerprint, state.mediator_id);
            std::cout << "  " << tradep2p::display_category_name(tradep2p::classify_for_display(found));
            if (found.has_value()) {
                std::cout << " (settled " << tradep2p::settlement_count(*found) << "x, incomplete "
                          << tradep2p::incomplete_count(*found) << "x, on this mediator)";
            }
            std::cout << '\n';
        }
        break;
    }
    case MessageType::Error: {
        const auto message = tradep2p::decode_error(frame.payload);
        std::cout << "server rejected request: " << message.reason << '\n';
        break;
    }
    case MessageType::RecoveryStateResponse: {
        const auto message = tradep2p::decode_recovery_state_response(frame.payload);
        std::cout << "\nrecovery response for room " << tradep2p::room_id_to_hex(message.room_id) << ":\n";
        if (!message.found) {
            std::cout << "  found: no (" << message.reason << ")\n";
            break;
        }
        std::cout << "  found: yes\n"
                  << "  state: " << session_state_name(static_cast<SessionState>(message.state)) << '\n'
                  << "  round: " << (message.round_index + 1U) << "  leg: "
                  << static_cast<unsigned int>(message.leg_index) << '\n'
                  << "  trade: " << message.terms.total_a << ' ' << message.terms.asset_a << " <-> "
                  << message.terms.total_b << ' ' << message.terms.asset_b << '\n'
                  << "  party A connected: " << (message.party_a_connected ? "yes" : "no") << '\n'
                  << "  party B connected: " << (message.party_b_connected ? "yes" : "no") << '\n';
        if (!message.reason.empty()) {
            std::cout << "  reason: " << message.reason << '\n';
        }
        // Best-effort cross-reference against the local journal, if one is
        // currently open in this session - see recovery.hpp for exactly
        // what classify_recovery_action() does and does not conclude.
        // Deliberately does not auto-open the journal (a recovery-state
        // query should not itself require an unlocked keystore); this only
        // runs if a journal was already opened earlier in the session, e.g.
        // via /journal status.
        if (state.journal.has_value()) {
            std::optional<JournalEntry> matching_entry;
            for (const auto& entry : state.journal->entries()) {
                if (entry.fields.room_id == message.room_id) {
                    matching_entry = entry; // entries() is chronological; last match wins
                }
            }
            const auto classification = tradep2p::classify_recovery_action(matching_entry, message);
            std::cout << "  local journal cross-check: " << recovery_category_name(classification.category)
                      << "\n    " << classification.explanation << '\n';
        }
        break;
    }
    case MessageType::TradeEphemeralKey: {
        const auto message = tradep2p::decode_trade_ephemeral_key(frame.payload);
        const std::string room = tradep2p::room_id_to_hex(message.room_id);
        const auto parsed = tradep2p::parse_ed25519_public_key(message.ephemeral_public_key);
        if (!parsed.has_value()) {
            std::cout << "\nroom " << room << ": counterparty announced a malformed ephemeral key\n";
            break;
        }
        state.room_counterparty_ephemeral_key[room] = *parsed;
        std::cout << "\nroom " << room << ": counterparty announced ephemeral trade key "
                  << hex_encode(*parsed) << "\n"
                  << "  (unlinkable to their long-term identity or any other room by design - "
                     "specs.txt SS5)\n";
        break;
    }
    case MessageType::ReceiptAckRequired: {
        const auto message = tradep2p::decode_receipt_ack_required(frame.payload);
        const std::string room = tradep2p::room_id_to_hex(message.room_id);
        std::cout << "\nroom " << room
                  << ": the mediator requires a receipt acknowledgement before the final "
                     "tranche can be sent (specs.txt SS9.1's withholding fix)\n";
        const auto keypair_it = state.room_ephemeral_keypair.find(room);
        const auto terms_it = state.room_terms.find(room);
        if (keypair_it == state.room_ephemeral_keypair.end() || terms_it == state.room_terms.end()) {
            std::cout << "  cannot acknowledge: missing this room's ephemeral key or cached "
                         "terms for this session\n";
            break;
        }
        // Signed over the SAME fields the mediator will independently
        // reconstruct from its own authoritative session state (room id,
        // fixed stage, terms commitment derived from the TradeTerms both
        // sides already agree on, and this client's own timestamp) - see
        // lobby.cpp's handle_receipt_ack().
        tradep2p::ReceiptAckFields fields;
        fields.mediator_id = state.mediator_id;
        fields.room_id = message.room_id;
        fields.stage = tradep2p::ReceiptStage::PenultimateObligationsComplete;
        fields.terms_commitment = tradep2p::trade_payload_hash(tradep2p::encode_terms(terms_it->second));
        fields.timestamp = static_cast<std::uint64_t>(std::time(nullptr));
        const auto signature =
            tradep2p::sign_receipt_ack(keypair_it->second.private_seed, fields);
        tradep2p::ReceiptAckMessage ack;
        ack.room_id = message.room_id;
        ack.stage = static_cast<std::uint8_t>(tradep2p::ReceiptStage::PenultimateObligationsComplete);
        ack.timestamp = fields.timestamp;
        ack.signature = signature;
        channel.send_frame(MessageType::ReceiptAck, tradep2p::encode_receipt_ack(ack));
        std::cout << "  acknowledged automatically (signed with this room's ephemeral trade "
                     "key)\n";
        break;
    }
    case MessageType::ReceiptIssued: {
        const auto message = tradep2p::decode_receipt_issued(frame.payload);
        const std::string room = tradep2p::room_id_to_hex(message.room_id);
        const auto stage = static_cast<tradep2p::ReceiptStage>(message.stage);

        tradep2p::IssuedReceipt issued;
        issued.fields.mediator_id = message.mediator_id;
        issued.fields.room_id = message.room_id;
        issued.fields.terms_commitment = message.terms_commitment;
        issued.fields.party_a_ephemeral_key = message.party_a_ephemeral_key;
        issued.fields.party_b_ephemeral_key = message.party_b_ephemeral_key;
        issued.fields.mediator_public_key = message.mediator_public_key;
        issued.fields.stage = stage;
        issued.fields.completed = message.completed;
        issued.fields.timestamp = message.timestamp;
        issued.fields.nonce = message.nonce;
        issued.fields.previous_stage_hash = message.previous_stage_hash;
        issued.mediator_signature = message.mediator_signature;

        std::cout << "\nroom " << room << ": receipt issued - stage "
                  << tradep2p::receipt_stage_name(stage) << (message.completed ? " (completed)" : "")
                  << '\n';

        // Trust-on-first-use pinning of this session's mediator receipt key
        // - see ClientState::mediator_receipt_key's comment.
        if (!state.mediator_receipt_key.has_value()) {
            state.mediator_receipt_key = message.mediator_public_key;
            std::cout << "  pinned mediator receipt key for this session: "
                      << hex_encode(*state.mediator_receipt_key) << '\n';
        } else if (*state.mediator_receipt_key != message.mediator_public_key) {
            std::cout << "  WARNING: this receipt's mediator public key does not match the one "
                         "pinned earlier this session - treating as untrusted\n";
            break;
        }

        if (!tradep2p::verify_receipt(*state.mediator_receipt_key, issued.fields,
                                      issued.mediator_signature)) {
            std::cout << "  WARNING: receipt signature does not verify - discarding\n";
            break;
        }

        auto& chain = state.room_receipts[room];
        chain.push_back(issued);
        try {
            tradep2p::verify_receipt_chain(chain, *state.mediator_receipt_key);
            std::cout << "  receipt chain for this room verifies (" << chain.size()
                      << " stage(s) so far)\n";
        } catch (const tradep2p::ReceiptChainError& error) {
            std::cout << "  WARNING: receipt chain does not verify: " << error.what() << '\n';
        }
        break;
    }
    case MessageType::ReceiptDisclosure: {
        const auto message = tradep2p::decode_receipt_disclosure(frame.payload);
        const std::string room = tradep2p::room_id_to_hex(message.room_id);
        std::cout << "\nroom " << room << ": counterparty disclosed " << message.chain.size()
                  << " receipt(s) from a prior trade\n";

        const auto keypair_it = state.room_ephemeral_keypair.find(room);
        if (keypair_it == state.room_ephemeral_keypair.end()) {
            std::cout << "  cannot verify: no ephemeral key for this room in this session\n";
            break;
        }

        std::vector<tradep2p::IssuedReceipt> chain;
        chain.reserve(message.chain.size());
        for (const auto& wire : message.chain) {
            tradep2p::IssuedReceipt issued;
            issued.fields.mediator_id = wire.mediator_id;
            issued.fields.room_id = wire.room_id;
            issued.fields.terms_commitment = wire.terms_commitment;
            issued.fields.party_a_ephemeral_key = wire.party_a_ephemeral_key;
            issued.fields.party_b_ephemeral_key = wire.party_b_ephemeral_key;
            issued.fields.mediator_public_key = wire.mediator_public_key;
            issued.fields.stage = static_cast<tradep2p::ReceiptStage>(wire.stage);
            issued.fields.completed = wire.completed;
            issued.fields.timestamp = wire.timestamp;
            issued.fields.nonce = wire.nonce;
            issued.fields.previous_stage_hash = wire.previous_stage_hash;
            issued.mediator_signature = wire.mediator_signature;
            chain.push_back(issued);
        }

        tradep2p::DisclosureFields fields;
        fields.mediator_id = state.mediator_id;
        fields.room_id = message.room_id;
        fields.recipient_ephemeral_key = message.recipient_ephemeral_key;
        fields.disclosed_chain_hash = message.disclosed_chain_hash;
        fields.timestamp = message.timestamp;
        fields.nonce = message.nonce;

        const auto own_public_key = keypair_it->second.public_key;
        if (fields.recipient_ephemeral_key != own_public_key) {
            std::cout << "  WARNING: this disclosure is not bound to my ephemeral key for this "
                         "room - ignoring\n";
            break;
        }

        const auto failure = tradep2p::verify_disclosure_bundle(
            chain, fields, message.signature, message.room_id, own_public_key);
        if (failure.has_value()) {
            std::cout << "  WARNING: disclosure did not verify: " << *failure << '\n';
            break;
        }
        std::cout << "  disclosure verifies: the counterparty genuinely holds this chain "
                     "(mediator id \""
                  << (chain.empty() ? std::string{} : chain.front().fields.mediator_id)
                  << "\" - not independently verified if different from this room's own mediator)\n";
        for (const auto& issued : chain) {
            std::cout << "    stage " << tradep2p::receipt_stage_name(issued.fields.stage)
                      << (issued.fields.completed ? " (completed)" : "") << '\n';
        }
        break;
    }
    default:
        throw std::runtime_error("unexpected server message");
    }
}

bool handle_client_line(SecureChannel& channel,
                        ClientState& state,
                        const std::string& line) {
    if (line.empty()) {
        return true;
    }
    if (line.front() != '/') {
        throw std::invalid_argument("only protocol commands are accepted; use /help");
    }

    std::istringstream stream(line);
    std::string command;
    stream >> command;

    if (command == "/help") {
        print_client_help();
        return true;
    }
    if (command == "/quit") {
        channel.send_frame(MessageType::Disconnect, {});
        return false;
    }
    if (command == "/offers") {
        tradep2p::ListOffersMessage request;
        std::string cursor_text;
        std::string limit_text;
        std::string extra;
        if (stream >> cursor_text) {
            request.has_cursor = true;
            request.after_room_id = tradep2p::room_id_from_hex(cursor_text);
            if (stream >> limit_text) {
                const auto parsed_limit = parse_u32(limit_text, "offer page size");
                if (parsed_limit > tradep2p::kMaxOfferPageEntries) {
                    throw std::invalid_argument("offer page size exceeds 32");
                }
                request.limit = static_cast<std::uint16_t>(parsed_limit);
            }
        }
        if (stream >> extra) {
            throw std::invalid_argument("invalid /offers syntax");
        }
        channel.send_frame(
            MessageType::ListOffers, tradep2p::encode_list_offers(request));
        return true;
    }
    if (command == "/offer") {
        std::string asset_a;
        std::string total_a_text;
        std::string asset_b;
        std::string total_b_text;
        std::string rounds_text;
        std::string address;
        std::string extra;
        if (!(stream >> asset_a >> total_a_text >> asset_b >>
              total_b_text >> rounds_text >> address) || (stream >> extra)) {
            throw std::invalid_argument("invalid /offer syntax; use /help");
        }

        TradeTerms terms;
        terms.asset_a = asset_a;
        terms.total_a = parse_u64(total_a_text, "sell amount");
        terms.asset_b = asset_b;
        terms.total_b = parse_u64(total_b_text, "buy amount");
        terms.rounds = parse_u32(rounds_text, "round count");
        terms.first_sender = Party::A;
        tradep2p::validate_terms(terms);
        tradep2p::validate_address(address);

        channel.send_frame(
            MessageType::CreateOffer,
            tradep2p::encode_create_offer(CreateOfferMessage{terms, address}));
        return true;
    }
    if (command == "/join") {
        std::string room_text;
        std::string address;
        std::string extra;
        if (!(stream >> room_text >> address) || (stream >> extra)) {
            throw std::invalid_argument("invalid /join syntax");
        }
        channel.send_frame(
            MessageType::JoinOffer,
            tradep2p::encode_join_offer(JoinOfferMessage{
                tradep2p::room_id_from_hex(room_text), address}));
        return true;
    }
    if (command == "/cancel") {
        std::string room_text;
        std::string extra;
        if (!(stream >> room_text) || (stream >> extra)) {
            throw std::invalid_argument("invalid /cancel syntax");
        }
        channel.send_frame(
            MessageType::CancelOffer,
            tradep2p::encode_cancel_offer(CancelOfferMessage{
                tradep2p::room_id_from_hex(room_text)}));
        return true;
    }
    if (command == "/sent" || command == "/received") {
        std::string room_text;
        std::string extra;
        if (!(stream >> room_text) || (stream >> extra)) {
            throw std::invalid_argument("missing or invalid room id");
        }
        const RoomId room_id = tradep2p::room_id_from_hex(room_text);
        const std::string canonical_room = tradep2p::room_id_to_hex(room_id);
        const auto turn_it = state.current_turns.find(canonical_room);
        const auto party_it = state.room_parties.find(canonical_room);
        if (turn_it == state.current_turns.end() ||
            party_it == state.room_parties.end()) {
            throw std::invalid_argument("no current turn for that room");
        }
        const bool am_sender = party_it->second == turn_it->second.sender;
        if (command == "/sent" && !am_sender) {
            throw std::invalid_argument("you are not the sender for the current turn");
        }
        if (command == "/received" && am_sender) {
            throw std::invalid_argument("you are not the receiver for the current turn");
        }
        const RoundSignalMessage signal{
            room_id, turn_it->second.round_index, turn_it->second.sender};
        const MessageType signal_type = command == "/sent" ? MessageType::Sent : MessageType::Received;
        channel.send_frame(signal_type, tradep2p::encode_round_signal(signal));

        // Phase 5: locally sign a statement about this exact round action
        // with this room's ephemeral trade key, independent of the wire
        // message just sent above (RoundSignalMessage's own wire shape is
        // untouched - see ephemeral.hpp's file comment for why). This is
        // the client-verifiable, mediator-independent evidence phase 6's
        // receipts will build on; for now it is computed, printed, and held
        // only in memory for this session (not yet persisted - see
        // ephemeral.hpp's documented scope).
        const auto keypair_it = state.room_ephemeral_keypair.find(canonical_room);
        if (keypair_it != state.room_ephemeral_keypair.end()) {
            tradep2p::TradeMessageContext context;
            context.mediator_id = state.mediator_id;
            context.room_id = room_id;
            context.round = turn_it->second.round_index;
            context.message_type = signal_type;
            context.payload_hash = tradep2p::trade_payload_hash(tradep2p::encode_round_signal(signal));
            context.sender_ephemeral_public_key = keypair_it->second.public_key;
            const auto peer_id_it = state.room_peer_id.find(canonical_room);
            if (peer_id_it != state.room_peer_id.end()) {
                context.recipient = peer_id_it->second;
            }
            context.timestamp = static_cast<std::uint64_t>(std::time(nullptr));
            const auto signature =
                tradep2p::sign_trade_message(keypair_it->second.private_seed, context);
            std::cout << "  signed with this room's ephemeral trade key (round "
                      << (context.round + 1U) << ", " << (command == "/sent" ? "sent" : "received")
                      << "): " << hex_encode(signature) << '\n';
        }
        return true;
    }
    if (command == "/abort") {
        std::string room_text;
        std::string extra;
        if (!(stream >> room_text) || (stream >> extra)) {
            throw std::invalid_argument("missing or invalid room id");
        }
        channel.send_frame(
            MessageType::Abort,
            tradep2p::encode_abort(AbortMessage{
                tradep2p::room_id_from_hex(room_text), "user aborted"}));
        return true;
    }
    if (command == "/recovery") {
        std::string sub;
        std::string room_text;
        std::string extra;
        if (!(stream >> sub) || sub != "request" || !(stream >> room_text) || (stream >> extra)) {
            throw std::invalid_argument("usage: /recovery request ROOM_ID");
        }
        channel.send_frame(
            MessageType::RecoveryStateRequest,
            tradep2p::encode_recovery_state_request(
                RecoveryStateRequestMessage{tradep2p::room_id_from_hex(room_text)}));
        std::cout << "recovery request sent; response will print when it arrives\n";
        return true;
    }
    if (command == "/recognize") {
        std::string room_text;
        std::string suite_text;
        std::string extra;
        if (!(stream >> room_text)) {
            throw std::invalid_argument("usage: /recognize ROOM_ID [ml-dsa-65|ed25519]");
        }
        std::uint16_t suite_id = tradep2p::kRecognitionSuiteMlDsa65V1;
        if (stream >> suite_text) {
            if (suite_text == "ed25519") {
                suite_id = tradep2p::kRecognitionSuiteEd25519V1;
            } else if (suite_text == "ml-dsa-65") {
                suite_id = tradep2p::kRecognitionSuiteMlDsa65V1;
            } else {
                throw std::invalid_argument("usage: /recognize ROOM_ID [ml-dsa-65|ed25519]");
            }
            if (stream >> extra) {
                throw std::invalid_argument("usage: /recognize ROOM_ID [ml-dsa-65|ed25519]");
            }
        }
        require_unlocked_keystore(state);
        const RoomId room_id = tradep2p::room_id_from_hex(room_text);
        const std::string canonical_room = tradep2p::room_id_to_hex(room_id);
        if (!state.room_parties.contains(canonical_room)) {
            throw std::invalid_argument("not currently a party to that room");
        }
        const auto challenge =
            state.recognition_tracker.issue(state.mediator_id, room_id, 0, suite_id);
        channel.send_frame(MessageType::RecognitionChallenge,
                           tradep2p::encode_recognition_challenge(tradep2p::RecognitionChallengeMessage{
                               challenge.room_id, challenge.suite_id, challenge.nonce,
                               challenge.created_at, challenge.expires_at}));
        std::cout << "recognition challenge sent; asks only \"do you currently control this "
                     "key\" - the answer proves nothing about trustworthiness (specs.txt SS8)\n";
        return true;
    }
    if (command == "/receipts") {
        std::string room_text;
        std::string extra;
        if (!(stream >> room_text) || (stream >> extra)) {
            throw std::invalid_argument("usage: /receipts ROOM_ID");
        }
        const std::string room = tradep2p::room_id_to_hex(tradep2p::room_id_from_hex(room_text));
        const auto it = state.room_receipts.find(room);
        if (it == state.room_receipts.end() || it->second.empty()) {
            std::cout << "no receipts held for that room this session\n";
            return true;
        }
        for (const auto& issued : it->second) {
            std::cout << "  stage " << tradep2p::receipt_stage_name(issued.fields.stage)
                      << (issued.fields.completed ? " (completed)" : "") << " at "
                      << issued.fields.timestamp << "\n"
                      << "    mediator: " << hex_encode(issued.fields.mediator_public_key) << '\n'
                      << "    party A ephemeral: " << hex_encode(issued.fields.party_a_ephemeral_key) << '\n'
                      << "    party B ephemeral: " << hex_encode(issued.fields.party_b_ephemeral_key) << '\n';
        }
        if (state.mediator_receipt_key.has_value()) {
            try {
                tradep2p::verify_receipt_chain(it->second, *state.mediator_receipt_key);
                std::cout << "  chain verifies\n";
            } catch (const tradep2p::ReceiptChainError& error) {
                std::cout << "  chain does NOT verify: " << error.what() << '\n';
            }
        }
        return true;
    }
    if (command == "/disclose") {
        std::string source_room_text;
        std::string target_room_text;
        std::string extra;
        if (!(stream >> source_room_text >> target_room_text) || (stream >> extra)) {
            throw std::invalid_argument("usage: /disclose SOURCE_ROOM_ID TARGET_ROOM_ID");
        }
        const std::string source_room =
            tradep2p::room_id_to_hex(tradep2p::room_id_from_hex(source_room_text));
        const RoomId target_room_id = tradep2p::room_id_from_hex(target_room_text);
        const std::string target_room = tradep2p::room_id_to_hex(target_room_id);

        const auto chain_it = state.room_receipts.find(source_room);
        if (chain_it == state.room_receipts.end() || chain_it->second.empty()) {
            throw std::invalid_argument("no receipts held for that source room this session");
        }
        const auto keypair_it = state.room_ephemeral_keypair.find(source_room);
        if (keypair_it == state.room_ephemeral_keypair.end()) {
            throw std::invalid_argument("no ephemeral key held for that source room this session");
        }
        if (!state.room_parties.contains(target_room)) {
            throw std::invalid_argument("not currently a party to the target room");
        }
        const auto recipient_key_it = state.room_counterparty_ephemeral_key.find(target_room);
        if (recipient_key_it == state.room_counterparty_ephemeral_key.end()) {
            throw std::invalid_argument(
                "counterparty in the target room has not announced an ephemeral key yet");
        }

        tradep2p::DisclosureFields fields;
        fields.mediator_id = state.mediator_id;
        fields.room_id = target_room_id;
        fields.recipient_ephemeral_key = recipient_key_it->second;
        fields.disclosed_chain_hash = tradep2p::disclosed_chain_hash(chain_it->second);
        fields.timestamp = static_cast<std::uint64_t>(std::time(nullptr));
        {
            const auto random = tradep2p::random_bytes(fields.nonce.size());
            std::copy(random.begin(), random.end(), fields.nonce.begin());
        }
        const auto signature =
            tradep2p::sign_disclosure(keypair_it->second.private_seed, fields);

        tradep2p::ReceiptDisclosureMessage message;
        message.room_id = target_room_id;
        message.recipient_ephemeral_key = fields.recipient_ephemeral_key;
        message.disclosed_chain_hash = fields.disclosed_chain_hash;
        message.timestamp = fields.timestamp;
        message.nonce = fields.nonce;
        message.signature = signature;
        for (const auto& issued : chain_it->second) {
            tradep2p::ReceiptIssuedMessage wire;
            wire.room_id = issued.fields.room_id;
            wire.mediator_id = issued.fields.mediator_id;
            wire.stage = static_cast<std::uint8_t>(issued.fields.stage);
            wire.completed = issued.fields.completed;
            wire.terms_commitment = issued.fields.terms_commitment;
            wire.party_a_ephemeral_key = issued.fields.party_a_ephemeral_key;
            wire.party_b_ephemeral_key = issued.fields.party_b_ephemeral_key;
            wire.mediator_public_key = issued.fields.mediator_public_key;
            wire.timestamp = issued.fields.timestamp;
            wire.nonce = issued.fields.nonce;
            wire.previous_stage_hash = issued.fields.previous_stage_hash;
            wire.mediator_signature = issued.mediator_signature;
            message.chain.push_back(std::move(wire));
        }
        channel.send_frame(MessageType::ReceiptDisclosure,
                           tradep2p::encode_receipt_disclosure(message));
        std::cout << "disclosed " << chain_it->second.size() << " receipt(s) from room "
                  << source_room << " to the counterparty in room " << target_room << '\n';
        return true;
    }
    if (command == "/keystore") {
        std::string sub;
        stream >> sub;
        if (sub == "create") {
            std::string path;
            std::string passphrase;
            if (!(stream >> path >> passphrase)) {
                throw std::invalid_argument("usage: /keystore create PATH PASSPHRASE [ALIAS]");
            }
            std::string alias;
            std::getline(stream, alias);
            const auto first_non_space = alias.find_first_not_of(' ');
            alias = first_non_space == std::string::npos ? std::string{} : alias.substr(first_non_space);
            state.keystore = IdentityKeystore::create(path, passphrase, alias);
            state.keystore_path = path;
            state.journal.reset();
            state.history.reset();
            std::cout << "keystore created and unlocked at " << path << '\n';
            print_public_identity(state.keystore->public_identity());
            return true;
        }
        if (sub == "unlock") {
            std::string path;
            std::string passphrase;
            std::string extra;
            if (!(stream >> path >> passphrase) || (stream >> extra)) {
                throw std::invalid_argument("usage: /keystore unlock PATH PASSPHRASE");
            }
            state.keystore = IdentityKeystore::unlock(path, passphrase);
            state.keystore_path = path;
            // A different identity may now be loaded - any already-open
            // journal/history handle belonged to whichever keystore was
            // previously active and must not be reused across identities.
            state.journal.reset();
            state.history.reset();
            std::cout << "keystore unlocked\n";
            print_public_identity(state.keystore->public_identity());
            return true;
        }
        if (sub == "lock") {
            std::string extra;
            if (stream >> extra) {
                throw std::invalid_argument("usage: /keystore lock");
            }
            if (state.keystore.has_value()) {
                state.keystore->lock();
            }
            std::cout << "keystore locked (already-open journal/history handles from this "
                         "session, if any, remain usable until the process exits)\n";
            return true;
        }
        if (sub == "rotate") {
            std::string passphrase;
            std::string extra;
            if (!(stream >> passphrase) || (stream >> extra)) {
                throw std::invalid_argument("usage: /keystore rotate PASSPHRASE");
            }
            require_unlocked_keystore(state);
            state.keystore->rotate_service_scoped_key(passphrase);
            std::cout << "service-scoped key generation rotated to " << state.keystore->key_generation()
                      << " (master secret and the local-history journal key are unaffected)\n";
            return true;
        }
        if (sub == "destroy") {
            std::string path;
            std::string extra;
            if (!(stream >> path) || (stream >> extra)) {
                throw std::invalid_argument("usage: /keystore destroy PATH");
            }
            IdentityKeystore::destroy(path);
            if (state.keystore_path == path) {
                state.keystore.reset();
                state.keystore_path.clear();
                state.journal.reset();
                state.history.reset();
            }
            std::cout << "keystore at " << path << " destroyed (best-effort shred + unlink)\n";
            return true;
        }
        if (sub == "show-identity") {
            std::string path;
            std::string extra;
            if (stream >> path) {
                if (stream >> extra) {
                    throw std::invalid_argument("usage: /keystore show-identity [PATH]");
                }
                print_public_identity(IdentityKeystore::display_public_identity(path));
                return true;
            }
            if (!state.keystore.has_value()) {
                throw std::invalid_argument(
                    "no keystore loaded; pass a PATH or run /keystore create|unlock first");
            }
            print_public_identity(state.keystore->public_identity());
            return true;
        }
        throw std::invalid_argument("usage: /keystore create|unlock|lock|rotate|destroy|show-identity ...");
    }
    if (command == "/journal") {
        std::string sub;
        std::string extra;
        if (!(stream >> sub) || sub != "status" || (stream >> extra)) {
            throw std::invalid_argument("usage: /journal status");
        }
        print_journal_status(ensure_journal_open(state));
        return true;
    }
    if (command == "/history") {
        std::string sub;
        if (!(stream >> sub)) {
            throw std::invalid_argument("usage: /history list|show FINGERPRINT");
        }
        if (sub == "list") {
            std::string extra;
            if (stream >> extra) {
                throw std::invalid_argument("usage: /history list");
            }
            auto& history = ensure_history_open(state);
            std::cout << "counterparty history: " << history.entries().size()
                      << (history.entries().size() == 1U ? " entry\n" : " entries\n");
            for (const auto& entry : history.entries()) {
                print_history_entry(entry);
            }
            return true;
        }
        if (sub == "show") {
            std::string fingerprint_text;
            std::string extra;
            if (!(stream >> fingerprint_text) || (stream >> extra)) {
                throw std::invalid_argument("usage: /history show FINGERPRINT");
            }
            auto& history = ensure_history_open(state);
            const auto fingerprint = tradep2p::fingerprint_from_hex(fingerprint_text);
            const auto found = history.find(fingerprint, state.mediator_id);
            std::cout << "display category: "
                      << tradep2p::display_category_name(tradep2p::classify_for_display(found)) << '\n';
            if (found.has_value()) {
                print_history_entry(*found);
            } else {
                std::cout << "  (no local record for this fingerprint at this mediator)\n";
            }
            return true;
        }
        throw std::invalid_argument("usage: /history list|show FINGERPRINT");
    }
    if (command == "/block" || command == "/unblock") {
        std::string fingerprint_text;
        std::string extra;
        if (!(stream >> fingerprint_text) || (stream >> extra)) {
            throw std::invalid_argument(std::string("usage: ") + command + " FINGERPRINT");
        }
        auto& history = ensure_history_open(state);
        const auto fingerprint = tradep2p::fingerprint_from_hex(fingerprint_text);
        const auto& entry = history.set_blocked(fingerprint, state.mediator_id, command == "/block");
        std::cout << (command == "/block" ? "blocked " : "unblocked ") << fingerprint_text
                  << " (locally_blocked=" << (entry.locally_blocked ? "true" : "false") << ")\n";
        return true;
    }
    if (command == "/note") {
        std::string fingerprint_text;
        if (!(stream >> fingerprint_text)) {
            throw std::invalid_argument("usage: /note FINGERPRINT TEXT...");
        }
        std::string text;
        std::getline(stream, text);
        const auto first_non_space = text.find_first_not_of(' ');
        text = first_non_space == std::string::npos ? std::string{} : text.substr(first_non_space);
        if (text.empty()) {
            throw std::invalid_argument("usage: /note FINGERPRINT TEXT...");
        }
        auto& history = ensure_history_open(state);
        const auto fingerprint = tradep2p::fingerprint_from_hex(fingerprint_text);
        history.add_note(fingerprint, state.mediator_id, text);
        std::cout << "note recorded for " << fingerprint_text << '\n';
        return true;
    }

    throw std::invalid_argument("unknown command; use /help");
}

void run_client(SecureChannel channel, std::string mediator_id) {
    channel.set_timeout(30U);
    const Frame welcome_frame = channel.receive_frame();
    if (welcome_frame.type != MessageType::Welcome) {
        throw std::runtime_error("mediator did not send a welcome message");
    }
    const auto welcome = tradep2p::decode_welcome(welcome_frame.payload);
    std::cout << "anonymous client id: "
              << tradep2p::client_id_to_hex(welcome.client_id) << '\n';
    std::cout << "No chat. Publish with /offer, browse with /offers, take with /join.\n";
    print_client_help();

    ClientState state;
    // Local history/journal records for this session are scoped to this
    // mediator (see history.hpp's fingerprint-scoping decision) - a CLI
    // process only ever talks to one mediator at a time, so that mediator's
    // own endpoint text doubles as the mediator_id label with no separate
    // command-line argument needed.
    state.mediator_id = mediator_id;
    bool running = true;
    while (running) {
        pollfd fds[2]{};
        fds[0].fd = channel.native_handle();
        fds[0].events = POLLIN;
        fds[1].fd = STDIN_FILENO;
        fds[1].events = POLLIN;

        const bool pending = channel.has_pending_input();
        const int rc = ::poll(fds, 2, pending ? 0 : -1);
        if (rc < 0) {
            throw std::runtime_error("poll failed");
        }
        if ((fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            throw std::runtime_error("mediator connection closed");
        }
        if (pending || (fds[0].revents & POLLIN) != 0) {
            do {
                handle_server_frame(channel, channel.receive_frame(), state);
            } while (channel.has_pending_input());
        }
        if ((fds[1].revents & POLLIN) != 0) {
            std::string line;
            if (!std::getline(std::cin, line)) {
                channel.send_frame(MessageType::Disconnect, {});
                break;
            }
            try {
                running = handle_client_line(channel, state, line);
            } catch (const std::exception& error) {
                std::cout << "command error: " << error.what() << '\n';
            }
        }
    }
}

// Speaks the mediator auth control channel's plain-text line protocol (see
// mediator_auth.hpp/lobby.cpp's auth_control_loop()) over an already-
// connected raw socket - direct or via SOCKS5, the caller (main()'s
// verify-mediator/verify-mediator-tor modes) has already handled that part.
// Closes `fd` before returning either way. Returns true (PASS) only when
// the signature verifies AND the response is still within its TTL AND (if
// `expect_key_hex` is non-empty) the returned key matches it - a FAIL here
// is a legitimate negative result, not an error, so this does not throw for
// any of those three cases; it only throws for genuine protocol/connection
// failures (can't send, connection closed early, malformed response).
bool run_verify_mediator(int fd, const std::string& expect_key_hex) {
    struct FdGuard {
        int fd;
        ~FdGuard() { ::close(fd); }
    } guard{fd};

    const tradep2p::MediatorAuthNonce nonce = tradep2p::generate_mediator_auth_nonce();
    const std::string request = "AUTH " + hex_encode(nonce) + "\n";
    {
        std::size_t offset = 0;
        while (offset < request.size()) {
            const ssize_t sent =
                ::send(fd, request.data() + offset, request.size() - offset, 0);
            if (sent <= 0) {
                throw std::runtime_error("failed to send AUTH request to mediator auth port");
            }
            offset += static_cast<std::size_t>(sent);
        }
    }

    std::string line;
    char buffer[8192];
    for (;;) {
        const ssize_t received = ::recv(fd, buffer, sizeof(buffer), 0);
        if (received <= 0) {
            throw std::runtime_error(
                "connection closed before the mediator sent a response");
        }
        line.append(buffer, static_cast<std::size_t>(received));
        if (line.find('\n') != std::string::npos || line.size() > 16384U) {
            break;
        }
    }
    if (const auto newline = line.find('\n'); newline != std::string::npos) {
        line.resize(newline);
    }
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }

    std::istringstream stream(line);
    std::string status;
    stream >> status;
    if (status == "ERR") {
        std::string reason;
        std::getline(stream, reason);
        throw std::runtime_error("mediator auth port returned an error:" + reason);
    }
    if (status != "OK") {
        throw std::runtime_error("malformed response from mediator auth port");
    }

    std::string mediator_id;
    std::string public_key_hex;
    std::string created_text;
    std::string expires_text;
    std::string signature_hex;
    stream >> mediator_id >> public_key_hex >> created_text >> expires_text >> signature_hex;
    if (mediator_id.empty() || public_key_hex.empty() || created_text.empty() ||
        expires_text.empty() || signature_hex.empty()) {
        throw std::runtime_error("malformed response from mediator auth port");
    }

    std::uint64_t created_at = 0;
    std::uint64_t expires_at = 0;
    const auto created_result = std::from_chars(
        created_text.data(), created_text.data() + created_text.size(), created_at);
    const auto expires_result = std::from_chars(
        expires_text.data(), expires_text.data() + expires_text.size(), expires_at);
    if (created_result.ec != std::errc{} || expires_result.ec != std::errc{}) {
        throw std::runtime_error("malformed timestamps in mediator auth response");
    }

    const auto public_key = hex_decode<tradep2p::kMlDsa65PublicKeyLength>(public_key_hex);
    const auto signature = hex_decode<tradep2p::kMlDsa65SignatureLength>(signature_hex);

    tradep2p::MediatorAuthFields fields;
    fields.mediator_id = mediator_id;
    fields.nonce = nonce;
    fields.created_at = created_at;
    fields.expires_at = expires_at;

    const bool signature_valid = tradep2p::verify_mediator_auth(public_key, fields, signature);
    const auto now = static_cast<std::uint64_t>(std::time(nullptr));
    const bool fresh = expires_at > now;

    std::cout << "mediator_id:     " << mediator_id << '\n';
    std::cout << "auth public key: " << public_key_hex << '\n';
    std::cout << "signature:       " << (signature_valid ? "verifies" : "DOES NOT VERIFY") << '\n';
    std::cout << "freshness:       "
              << (fresh ? "within TTL"
                        : "EXPIRED (clock skew, or a replayed old response)")
              << '\n';

    bool overall = signature_valid && fresh;

    if (!expect_key_hex.empty()) {
        std::string normalized_expect = expect_key_hex;
        std::transform(normalized_expect.begin(), normalized_expect.end(),
                       normalized_expect.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        const bool matches = normalized_expect == public_key_hex;
        std::cout << "matches --expect-key: " << (matches ? "yes" : "NO") << '\n';
        overall = overall && matches;
    }

    std::cout << (overall ? "PASS" : "FAIL") << '\n';
    return overall;
}

void run_registry_heartbeat(Endpoint registry,
                            ClientTlsPolicy registry_tls,
                            RegistryNode node) {
    for (;;) {
        try {
            tradep2p::register_node_once(registry, registry_tls, node);
            std::this_thread::sleep_for(std::chrono::seconds(60));
        } catch (const std::exception& error) {
            std::cerr << "registry heartbeat failed: " << error.what() << '\n';
            std::this_thread::sleep_for(std::chrono::seconds(15));
        }
    }
}

void print_registered_nodes(const tradep2p::RegistryNodesMessage& nodes) {
    std::cout << "registered mediator nodes: " << nodes.nodes.size() << '\n';
    for (const auto& node : nodes.nodes) {
        std::cout << "  " << node.host << ':' << node.port
                  << " pin=" << tradep2p::certificate_pin_to_hex(node.certificate_pin)
                  << " ttl=" << node.remaining_ttl_seconds << "s\n";
    }
}

void print_usage(const char* program) {
    std::cerr
        << "Usage:\n"
        << "  " << program
        << " registry <bind:port> <registry-cert.pem> <registry-key.pem>\n"
        << "  " << program
        << " nodes <registry:port> <registry-cert-sha256>\n"
        << "  " << program
        << " nodes-tor <proxy:port> <registry-onion:port> <registry-cert-sha256>\n"
        << "  " << program
        << " register-node <registry:port> <registry-cert-sha256> <node:port> <node-cert-sha256>\n"
        << "  " << program
        << " sign-recognition-response <keystore> <passphrase> <mediator-id> <ed25519|ml-dsa-65> "
           "<room-id-hex> <nonce-hex> <created-at> <expires-at>\n"
        << "  " << program
        << " mediator <bind:port> <node-cert.pem> <node-key.pem>\n"
        << "  " << program
        << " mediator-registered <bind:port> <node-cert.pem> <node-key.pem> "
           "<registry:port> <registry-cert-sha256> <advertised-node:port> <node-cert-sha256>\n"
        << "  " << program
        << " client <node:port> <node-cert-sha256>\n"
        << "  " << program
        << " client-tor <proxy:port> <onion:port> <node-cert-sha256>\n"
        << "  " << program
        << " verify-mediator <host:port> [--expect-key HEX]\n"
        << "  " << program
        << " verify-mediator-tor <proxy:port> <onion:port> [--expect-key HEX]\n";
}

} // namespace

int main(int argc, char** argv) {
    try {
#ifdef SIGPIPE
        if (std::signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
            throw std::runtime_error("failed to ignore SIGPIPE");
        }
#endif
        append_log("tradep2p starting");
        if (argc < 2) {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }

        const std::string mode = argv[1];
        append_log("mode=" + mode);
        if (mode == "registry") {
            if (argc != 5) {
                throw std::invalid_argument("wrong registry argument count");
            }
            RegistryServer server(
                parse_endpoint(argv[2]),
                ServerTlsIdentity{argv[3], argv[4]});
            server.run();
        } else if (mode == "nodes") {
            if (argc != 4) {
                throw std::invalid_argument("wrong nodes argument count");
            }
            print_registered_nodes(tradep2p::list_registered_nodes(
                parse_endpoint(argv[2]), ClientTlsPolicy{argv[3]}));
        } else if (mode == "nodes-tor") {
            if (argc != 5) {
                throw std::invalid_argument("wrong nodes-tor argument count");
            }
            print_registered_nodes(tradep2p::list_registered_nodes_via_socks5(
                parse_endpoint(argv[2]), parse_endpoint(argv[3]), ClientTlsPolicy{argv[4]}));
        } else if (mode == "register-node") {
            if (argc != 6) {
                throw std::invalid_argument("wrong register-node argument count");
            }
            const Endpoint node_endpoint = parse_endpoint(argv[4]);
            RegistryNode node{
                node_endpoint.host,
                node_endpoint.port,
                tradep2p::certificate_pin_from_hex(argv[5]),
                0U};
            tradep2p::register_node_once(
                parse_endpoint(argv[2]), ClientTlsPolicy{argv[3]}, node);
            std::cout << "node registered for " << tradep2p::kRegistryTtlSeconds
                      << " seconds\n";
        } else if (mode == "sign-recognition-response") {
            // Standalone external-signer mode: opens a LOCAL keystore, signs
            // ONE incoming recognition challenge, prints the public key and
            // signature, exits. Built for docs/identity-09-hosted-webclient.md's
            // preference for an external signer over holding a raw trading
            // key inside a hosted, operator-controlled process - a hosted
            // webclient session surfaces a pending challenge's exact
            // fields (see DashboardClient::submit_recognition_response()'s
            // comment) and this command reproduces the same signed bytes
            // (recognition.cpp's encode_recognition_signed_payload) from
            // your own keystore on your own machine; only the two printed
            // hex values ever need to reach the hosted page.
            if (argc != 10) {
                throw std::invalid_argument("wrong sign-recognition-response argument count");
            }
            const std::string keystore_path = argv[2];
            const std::string passphrase = argv[3];
            const std::string mediator_id = argv[4];
            const std::string suite_text = argv[5];
            const RoomId room_id = tradep2p::room_id_from_hex(argv[6]);
            const auto nonce = hex_decode<tradep2p::kRecognitionNonceLength>(argv[7]);
            const std::string created_text = argv[8];
            const std::string expires_text = argv[9];
            std::uint64_t created_at = 0;
            std::uint64_t expires_at = 0;
            const auto created_result = std::from_chars(
                created_text.data(), created_text.data() + created_text.size(), created_at);
            if (created_result.ec != std::errc{} ||
                created_result.ptr != created_text.data() + created_text.size()) {
                throw std::invalid_argument("invalid created_at");
            }
            const auto expires_result = std::from_chars(
                expires_text.data(), expires_text.data() + expires_text.size(), expires_at);
            if (expires_result.ec != std::errc{} ||
                expires_result.ptr != expires_text.data() + expires_text.size()) {
                throw std::invalid_argument("invalid expires_at");
            }

            std::uint16_t suite_id = 0U;
            if (suite_text == "ed25519") {
                suite_id = tradep2p::kRecognitionSuiteEd25519V1;
            } else if (suite_text == "ml-dsa-65") {
                suite_id = tradep2p::kRecognitionSuiteMlDsa65V1;
            } else {
                throw std::invalid_argument("suite must be ed25519 or ml-dsa-65");
            }

            const auto keystore = tradep2p::IdentityKeystore::unlock(keystore_path, passphrase);

            tradep2p::RecognitionChallengeFields fields;
            fields.suite_id = suite_id;
            fields.protocol_version = tradep2p::kProtocolVersion;
            fields.mediator_id = mediator_id;
            fields.room_id = room_id;
            fields.nonce = nonce;
            fields.created_at = created_at;
            fields.expires_at = expires_at;

            if (suite_id == tradep2p::kRecognitionSuiteEd25519V1) {
                const auto keypair = tradep2p::derive_ed25519_keypair(
                    keystore.master_secret(), tradep2p::key_scope::kMediatorPseudonym, mediator_id);
                const auto signature = tradep2p::sign_recognition_response(keypair.private_seed, fields);
                std::cout << "public_key: " << hex_encode(keypair.public_key) << '\n';
                std::cout << "signature:  " << hex_encode(signature) << '\n';
            } else {
                const auto keypair = tradep2p::derive_mldsa65_keypair(
                    keystore.master_secret(), tradep2p::key_scope::kMediatorPseudonymMlDsa65,
                    mediator_id);
                const auto signature =
                    tradep2p::sign_recognition_response_mldsa65(keypair.private_seed, fields);
                std::cout << "public_key: " << hex_encode(keypair.public_key) << '\n';
                std::cout << "signature:  " << hex_encode(signature) << '\n';
            }
        } else if (mode == "mediator") {
            if (argc != 5) {
                throw std::invalid_argument("wrong mediator argument count");
            }
            LobbyServer server(
                parse_endpoint(argv[2]),
                ServerTlsIdentity{argv[3], argv[4]});
            server.run();
        } else if (mode == "mediator-registered") {
            if (argc != 9) {
                throw std::invalid_argument("wrong mediator-registered argument count");
            }
            const Endpoint registry = parse_endpoint(argv[5]);
            const ClientTlsPolicy registry_tls{argv[6]};
            const Endpoint advertised = parse_endpoint(argv[7]);
            const RegistryNode node{
                advertised.host,
                advertised.port,
                tradep2p::certificate_pin_from_hex(argv[8]),
                0U};
            std::thread(run_registry_heartbeat, registry, registry_tls, node).detach();

            LobbyServer server(
                parse_endpoint(argv[2]),
                ServerTlsIdentity{argv[3], argv[4]});
            server.run();
        } else if (mode == "client") {
            if (argc != 4) {
                throw std::invalid_argument("wrong client argument count");
            }
            run_client(SecureChannel::connect_direct(
                parse_endpoint(argv[2]), ClientTlsPolicy{argv[3]}), std::string(argv[2]));
        } else if (mode == "client-tor") {
            if (argc != 5) {
                throw std::invalid_argument("wrong Tor client argument count");
            }
            run_client(SecureChannel::connect_via_socks5(
                parse_endpoint(argv[2]), parse_endpoint(argv[3]),
                ClientTlsPolicy{argv[4]}), std::string(argv[3]));
        } else if (mode == "verify-mediator") {
            if (argc != 3 && argc != 5) {
                throw std::invalid_argument("wrong verify-mediator argument count");
            }
            std::string expect_key;
            if (argc == 5) {
                if (std::string_view(argv[3]) != "--expect-key") {
                    throw std::invalid_argument("expected --expect-key");
                }
                expect_key = argv[4];
            }
            const int fd = connect_raw_tcp(parse_endpoint(argv[2]));
            return run_verify_mediator(fd, expect_key) ? EXIT_SUCCESS : EXIT_FAILURE;
        } else if (mode == "verify-mediator-tor") {
            if (argc != 4 && argc != 6) {
                throw std::invalid_argument("wrong verify-mediator-tor argument count");
            }
            std::string expect_key;
            if (argc == 6) {
                if (std::string_view(argv[4]) != "--expect-key") {
                    throw std::invalid_argument("expected --expect-key");
                }
                expect_key = argv[5];
            }
            const int fd = connect_raw_via_socks5(parse_endpoint(argv[2]), parse_endpoint(argv[3]));
            return run_verify_mediator(fd, expect_key) ? EXIT_SUCCESS : EXIT_FAILURE;
        } else {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        append_log(std::string("fatal: ") + error.what());
        std::cerr << "fatal: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
