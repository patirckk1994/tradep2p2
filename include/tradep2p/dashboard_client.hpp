#pragma once

#include "tradep2p/ephemeral.hpp"
#include "tradep2p/identity.hpp"
#include "tradep2p/protocol.hpp"
#include "tradep2p/receipt.hpp"
#include "tradep2p/recognition.hpp"
#include "tradep2p/secure_channel.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace tradep2p::dashboard {

// Phase 4b (personal counterparty recognition): whether a completed/aborted
// room's recognized counterparty should be recorded as a settled or an
// incomplete encounter - see RecognitionOutcomeHandler below.
enum class RecognitionOutcome : std::uint8_t { Successful, Incomplete };

// This dashboard operator's own per-mediator pseudonym keypair, supplied by
// http_dashboard.cpp (which owns the IdentityKeystore) on demand rather than
// held inside DashboardClient - this module has no keystore/passphrase
// concept of its own and must not grow one just for this. Returning
// std::nullopt means "no keystore is currently unlocked", the same "declining
// is not evidence of anything" case main.cpp's CLI handles identically.
struct RecognitionKeyMaterial {
    Ed25519PrivateSeed private_seed;
    Ed25519PublicKey public_key{};
};
using RecognitionKeyProvider = std::function<std::optional<RecognitionKeyMaterial>()>;

// Invoked (from the worker thread - see the class comment on
// set_recognition_outcome_handler()) exactly once per room, the moment a
// room with a recognized counterparty fingerprint reaches Complete or
// Abort, so the caller can feed it into a LocalCounterpartyHistory. Never
// invoked for a room where no fingerprint was ever recognized - "no key
// presented" must not manufacture a history entry (specs.txt SS8.4).
using RecognitionOutcomeHandler =
    std::function<void(const std::array<std::uint8_t, 32>& fingerprint, RecognitionOutcome outcome)>;

std::string json_escape(const std::string& text);
std::string now_text();
std::string random_token();
const char* party_name(Party party);

struct OfferView {
    std::string room_id;
    TradeTerms terms;
};

struct RoomView {
    std::string room_id;
    std::string peer_id;
    Party party{Party::A};
    TradeTerms terms;
    std::string receive_address_a;
    std::string receive_address_b;
    FeeTerms fee;
    std::string status{"active"};
    std::string detail;
    bool has_turn{false};
    TurnMessage turn;
    // True once the CURRENT turn's sender has actually reported Sent (a
    // MessageType::Sent frame arrived for this room since the last Turn).
    // Reset to false on every new Turn. Without this, the receiving party's
    // "action" in state_json() would read as "received" (button live and
    // clickable) from the moment the round starts, not from the moment
    // there is actually anything to confirm - the sender hasn't sent yet.
    bool peer_sent_this_turn{false};

    // Phase 4b: this room's counterparty-recognition state, purely local to
    // this dashboard session (never transmitted - see recognition.hpp).
    // "none" -> no challenge issued or received yet; "challenge_sent" -> an
    // outstanding /api/recognition/challenge is awaiting a response;
    // "recognized" -> a RecognitionResponse verified and
    // recognized_fingerprint_hex is populated; "declined" -> an incoming
    // challenge could not be auto-answered because no keystore is unlocked;
    // "failed" -> a response arrived but did not verify (expired/replayed/
    // bad signature - treated as no proof, never displayed as a warning).
    std::string recognition_status{"none"};
    std::string recognized_fingerprint_hex;
    std::array<std::uint8_t, 32> recognized_fingerprint{};
    bool has_recognized_fingerprint{false};

    // Phase 5 (per-trade ephemeral identities): this room's own ephemeral
    // trade key (announced automatically, unlike phase 4b's opt-in
    // recognition - see ephemeral.hpp for why there's no privacy cost to
    // making this the default) and the counterparty's, once announced.
    std::string own_ephemeral_public_key_hex;
    std::string counterparty_ephemeral_public_key_hex;

    // Phase 6 (staged receipts): "none" -> nothing yet; "gate_open" -> a
    // ReceiptAckRequired arrived and was auto-acknowledged; "stage3" /
    // "stage4" -> the corresponding IssuedReceipt was received and its
    // chain verified so far (see DashboardClient::room_receipts_).
    std::string receipt_status{"none"};
    bool receipt_chain_verifies{false};

    // Optional (see mediator.hpp's SessionState::WaitingForFeeConfirmation):
    // true once a FeeConfirmationPending frame arrives for this room - the
    // fee leg's sender reported it sent, but the mediator operator has not
    // yet confirmed receiving it, so the room stays open with nothing left
    // for either party here to do.
    bool fee_confirmation_pending{false};

    // Crypto telemetry only (dashboard display) - never used for any trust
    // decision, which is already made by recognition.hpp's verifier before
    // any of this is recorded. Populated at issue() time (the challenge WE
    // sent) and/or on a RecognitionResponse (the counterparty's answer, kept
    // regardless of whether it verified, alongside recognition_status above
    // which is the actual trust-relevant outcome).
    bool has_recognition_challenge{false};
    std::string recognition_challenge_nonce_hex;
    std::uint64_t recognition_challenge_created_at{0};
    std::uint64_t recognition_challenge_expires_at{0};
    std::uint16_t recognition_challenge_suite_id{0};
    bool has_recognition_response{false};
    std::string recognition_response_public_key_hex;
    std::string recognition_response_signature_hex;
    // Set when THIS dashboard answered an incoming challenge (proving
    // control of its own recognition key to the counterparty).
    std::string own_recognition_response_signature_hex;
};

struct OutgoingFrame {
    MessageType type{};
    std::vector<std::uint8_t> payload;
    std::string description;
};

// A persistent anonymous protocol client connected to one mediator, driven by
// queued HTTP-originated actions. Owns one worker thread and one
// SecureChannel so concurrent HTTP handler threads never touch TLS directly.
class DashboardClient {
public:
    // `mediator_id` is the mediator's identity-layer label (e.g.
    // "host:port" exactly as the operator typed it on the command line) -
    // used as the recognition-challenge mediator identifier (recognition.hpp)
    // and must be the SAME string http_dashboard.cpp passes as this
    // process's history mediator_id, or a recognized fingerprint would be
    // recorded under one label and looked up under another.
    DashboardClient(Endpoint mediator,
                    ClientTlsPolicy tls_policy,
                    std::optional<Endpoint> socks_proxy,
                    std::string mediator_id);
    ~DashboardClient();

    DashboardClient(const DashboardClient&) = delete;
    DashboardClient& operator=(const DashboardClient&) = delete;

    void start();

    void refresh_offers();
    void create_offer(const TradeTerms& terms, const std::string& address);
    void join_offer(const std::string& room_text, const std::string& address);
    void cancel_offer(const std::string& room_text);
    void mark_sent(const std::string& room_text);
    void mark_received(const std::string& room_text);
    void abort_room(const std::string& room_text);

    // Phase 4b: issues a live recognition challenge to the counterparty in
    // `room_text`. Throws std::invalid_argument if that room is not
    // currently known/active. Does not itself require a key - only
    // ANSWERING a challenge does (see set_recognition_key_provider()); the
    // verifier side only needs to generate and send a nonce.
    void recognize(const std::string& room_text);

    // These two callbacks bridge into http_dashboard.cpp's
    // IdentityDashboardState (keystore/history), which this module
    // deliberately has no direct knowledge of - see their type comments
    // above. Must be set (if at all) before start(), and must never call
    // back into any DashboardClient method that takes state_mutex_/
    // queue_mutex_ (recognize()/mark_sent()/etc.) - both are invoked from
    // the worker thread while state_mutex_ is NOT held (see the .cpp), but
    // establishing a two-way lock dependency between this class's mutexes
    // and the caller's own would risk a deadlock the moment both are held
    // in opposite orders from two threads.
    void set_recognition_key_provider(RecognitionKeyProvider provider);
    void set_recognition_outcome_handler(RecognitionOutcomeHandler handler);

    [[nodiscard]] std::string state_json() const;

private:
    void enqueue(MessageType type,
                 std::vector<std::uint8_t> payload,
                 std::string description);
    void enqueue_turn_signal(const std::string& room_text, bool sent);
    void add_event_locked(const std::string& message);
    void set_disconnected(const std::string& reason);
    void worker_loop();
    void session_loop(SecureChannel& channel);
    void flush_outgoing(SecureChannel& channel);
    void handle_frame(const Frame& frame);

    Endpoint mediator_;
    ClientTlsPolicy tls_policy_;
    std::optional<Endpoint> socks_proxy_;
    std::string mediator_id_;
    std::atomic<bool> stop_{false};
    std::thread worker_;

    mutable std::mutex state_mutex_;
    bool connected_{false};
    std::string connection_status_{"connecting"};
    std::string client_id_;
    // Crypto telemetry: this connection's live TLS session summary (§ note
    // on TlsSessionInfo - display only, the trust decision already happened
    // inside SecureChannel::make_client() before this session even exists).
    TlsSessionInfo tls_session_;
    FeeTerms mediator_fee_;
    std::vector<OfferView> offers_;
    std::map<std::string, RoomView> rooms_;
    std::deque<std::string> events_;
    std::uint64_t revision_{0U};

    // Phase 4b state - guarded by state_mutex_ alongside rooms_ above, since
    // recognition status is per-room presentation state exactly like
    // RoomView's other fields.
    RecognitionChallengeTracker recognition_tracker_;
    RecognitionKeyProvider recognition_key_provider_;
    RecognitionOutcomeHandler recognition_outcome_handler_;
    void handle_recognition_challenge(const RecognitionChallengeMessage& message);
    void handle_recognition_response(const RecognitionResponseMessage& message);

    // Phase 5 - guarded by state_mutex_ alongside rooms_/recognition_
    // tracker_ above. Keyed by room id (hex), same as rooms_.
    std::map<std::string, Ed25519KeyPair> ephemeral_keypairs_;

    // Phase 6 - guarded by state_mutex_. mediator_receipt_key_ is this
    // session's trust-on-first-use pin (see main.cpp's identical
    // ClientState::mediator_receipt_key for the same caveat, stated once
    // there rather than duplicated here).
    std::optional<Ed25519PublicKey> mediator_receipt_key_;
    std::map<std::string, std::vector<IssuedReceipt>> room_receipts_;

    std::mutex queue_mutex_;
    std::deque<OutgoingFrame> outgoing_;
};

} // namespace tradep2p::dashboard
