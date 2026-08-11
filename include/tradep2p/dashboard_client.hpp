#pragma once

#include "tradep2p/ephemeral.hpp"
#include "tradep2p/identity.hpp"
#include "tradep2p/protocol.hpp"
#include "tradep2p/receipt.hpp"
#include "tradep2p/recognition.hpp"
#include "tradep2p/secure_channel.hpp"

#ifdef TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL
#include "tradep2p/blindsig_client.hpp"
#endif

#include <array>
#include <atomic>
#include <chrono>
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
    // Populated alongside the Ed25519 keypair above whenever a keystore is
    // unlocked - deriving it is a cheap, deterministic HKDF (see
    // key_scope::kMediatorPseudonymMlDsa65's own comment on why this is a
    // DISTINCT derivation, not the same seed reused across algorithms), so
    // there's no reason to gate it behind a second round trip. Lets the
    // auto-answer path (dashboard_client.cpp) respond under whichever suite
    // an incoming challenge actually names, the same way main.cpp's CLI
    // does, without this header growing a second provider callback.
    std::optional<MlDsa65PrivateSeed> mldsa65_private_seed;
    std::optional<MlDsa65PublicKey> mldsa65_public_key;
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

    // A challenge the COUNTERPARTY issued TO us that we have not yet
    // answered - the reverse direction from recognition_challenge above
    // (which is one WE issued to them). Populated the moment a
    // RecognitionChallenge frame arrives, regardless of whether a keystore
    // is unlocked to auto-answer it, specifically so a caller with no
    // recognition key provider set (e.g. a hosted webclient session with no
    // server-held trading key) can still surface these fields to a user who
    // wants to sign externally (their own keystore, own machine) and submit
    // just the resulting response via submit_recognition_response() below -
    // see docs/identity-09-hosted-webclient.md's preference for an external
    // signer over holding the raw key in an operator-controlled runtime.
    // Cleared the moment ANY response for this challenge is sent, auto or
    // external. Bounded by the challenge's own expires_at - the counterparty
    // (and recognition_tracker_ on their side) will reject a stale one
    // regardless of what's submitted here.
    bool has_incoming_recognition_challenge{false};
    std::string incoming_recognition_challenge_nonce_hex;
    std::uint16_t incoming_recognition_challenge_suite_id{0};
    std::uint64_t incoming_recognition_challenge_created_at{0};
    std::uint64_t incoming_recognition_challenge_expires_at{0};
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
    // registry/registry_tls/registry_proxy are all optional (default
    // nullopt): when registry is unset, this client never touches a
    // registry at all, exactly as before this parameter existed. When set,
    // it periodically polls that registry's public, unauthenticated-beyond-
    // pinning RegistryList (the same query the `nodes`/`nodes-tor` CLI
    // commands make) and surfaces the result via state_json() - a
    // read-only "what does this one registry currently see" snapshot, not
    // a live connection, and not this client's own network mesh view
    // (it has none - see specs.txt SS1.3's gossip subsection for why a
    // single registry's listing already may include gossip-relayed
    // entries tagged with their source).
    DashboardClient(Endpoint mediator,
                    ClientTlsPolicy tls_policy,
                    std::optional<Endpoint> socks_proxy,
                    std::string mediator_id,
                    std::optional<Endpoint> registry = std::nullopt,
                    std::optional<ClientTlsPolicy> registry_tls = std::nullopt,
                    std::optional<Endpoint> registry_proxy = std::nullopt);
    ~DashboardClient();

    DashboardClient(const DashboardClient&) = delete;
    DashboardClient& operator=(const DashboardClient&) = delete;

    void start();

    void refresh_offers();
    // Fire-and-forget, like refresh_offers() - sends GetCandles and returns
    // immediately. The mediator's CandleData reply (if any) lands
    // asynchronously on the worker thread and is picked up by the next
    // candles_json() call for this pair - same eventually-consistent-via-
    // polling model this whole class already uses for offers_/rooms_.
    void request_candles(const std::string& asset_a, const std::string& asset_b);
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
    // verifier side only needs to generate and send a nonce. `suite_id`
    // picks which suite the COUNTERPARTY must answer with -
    // kRecognitionSuiteMlDsa65V1 (default - post-quantum) or
    // kRecognitionSuiteEd25519V1.
    void recognize(const std::string& room_text,
                    std::uint16_t suite_id = tradep2p::kRecognitionSuiteMlDsa65V1);

    // Answers an incoming recognition challenge (RoomView's
    // has_incoming_recognition_challenge above) with an ALREADY-COMPUTED
    // response, produced entirely outside this process - e.g. a
    // `tradep2p_cli sign-recognition-response` run against the caller's own
    // local keystore. This lets a caller answer without ever handing this
    // process (or, for http_webclient.cpp, this SERVER) the private key -
    // an external signer, one of the preferences
    // docs/identity-09-hosted-webclient.md states over holding a raw key in
    // an operator-controlled runtime. `nonce` must be exactly
    // sizeof(RecognitionNonce) bytes and must match the currently pending
    // challenge for this room, or this throws std::invalid_argument (e.g.
    // stale/already-answered/wrong room) - this method does not itself
    // verify the signature; an invalid one simply fails to verify on
    // whichever counterparty receives it, same as always.
    void submit_recognition_response(const std::string& room_text, std::uint16_t suite_id,
                                     std::vector<std::uint8_t> nonce,
                                     std::vector<std::uint8_t> public_key,
                                     std::vector<std::uint8_t> signature);

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
    // Whatever CandleData this session currently has cached for this pair
    // (see candles_ below) - `{"ok":true,"ticks":[]}` if request_candles()
    // hasn't been called yet, or its reply hasn't landed yet. Never blocks
    // on a fresh reply; a caller wanting up-to-date data should call
    // request_candles() first and expect the freshest data on a LATER call
    // to this, once the worker thread has processed the reply.
    [[nodiscard]] std::string candles_json(const std::string& asset_a,
                                           const std::string& asset_b) const;

#ifdef TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL
    // Experimental, unreviewed cryptography - specs.txt SS9.3a. Mirrors
    // main.cpp's CLI `/blindsig` command surface exactly (same lazy
    // construction, same TRADEP2P_BLINDSIG_PROVER_PATH-gated availability)
    // so the dashboard and CLI paths stay behaviorally identical rather
    // than growing a second, subtly different client implementation.
    // Must be called (if at all) before start(), same timing requirement
    // as set_recognition_key_provider() above - constructs the session
    // with this->enqueue() as its send_frame callback, so nothing may race
    // frames onto the wire before the worker thread exists to flush them.
    void enable_blindsig(std::string prover_path);
    // Throws std::runtime_error if enable_blindsig() was never called (no
    // TRADEP2P_BLINDSIG_PROVER_PATH configured for this dashboard process).
    void request_blindsig_info();
    void submit_blindsig_request(std::string message);
    // `{"ok":true,"enabled":false}` if enable_blindsig() was never called.
    // Otherwise stage/error/credential fields mirroring the CLI's
    // `/blindsig status` output, in the same shape as state_json() above.
    [[nodiscard]] std::string blindsig_state_json() const;
#endif

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
    void registry_poll_loop();

    Endpoint mediator_;
    ClientTlsPolicy tls_policy_;
    std::optional<Endpoint> socks_proxy_;
    std::string mediator_id_;
    std::atomic<bool> stop_{false};
    std::thread worker_;

    // Optional registry visibility (see the constructor's comment) - a
    // second, independent background thread from worker_ above, since
    // polling a registry has nothing to do with this client's own mediator
    // connection and must not be gated on it being up. registry_.has_value()
    // is this feature's on/off switch, checked once in start().
    std::optional<Endpoint> registry_;
    std::optional<ClientTlsPolicy> registry_tls_;
    std::optional<Endpoint> registry_proxy_;
    std::atomic<bool> registry_poll_running_{false};
    std::thread registry_poll_thread_;

    mutable std::mutex state_mutex_;
    bool connected_{false};
    std::string connection_status_{"connecting"};
    std::string client_id_;
    // Network telemetry - set() on every successful connect, reset() on
    // disconnect (see set_disconnected()); state_json() uses it to report
    // the current session's uptime. Cumulative across reconnects: the
    // frame/byte counters below, which live outside state_mutex_ since
    // they're only ever incremented, never read-modify-written together
    // with the rest of this locked state.
    std::optional<std::chrono::steady_clock::time_point> connected_since_;
    // Registry visibility snapshot - last successful/attempted poll only,
    // overwritten wholesale each cycle (registry_poll_loop() owns the write
    // side, state_json() the read side, both under state_mutex_). Empty
    // registry_nodes_ with an empty registry_poll_error_ just means no poll
    // has completed yet, not that the registry is empty.
    std::vector<RegistryNode> registry_nodes_;
    std::string registry_poll_error_;
    std::optional<std::chrono::steady_clock::time_point> registry_polled_at_;
    // Crypto telemetry: this connection's live TLS session summary (§ note
    // on TlsSessionInfo - display only, the trust decision already happened
    // inside SecureChannel::make_client() before this session even exists).
    TlsSessionInfo tls_session_;
    FeeTerms mediator_fee_;
    std::vector<OfferView> offers_;
    std::map<std::string, RoomView> rooms_;
    // The mediator's most recently received CandleData per pair, keyed
    // "base/quote" (same key shape as lobby.cpp's price_history_) - see
    // request_candles()/candles_json(). Guarded by state_mutex_ alongside
    // offers_/rooms_ above.
    std::map<std::string, CandleDataMessage> candles_;
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
    // The ML-DSA-65 half of the same per-room ephemeral identity above - see
    // main.cpp's identical ClientState::room_ephemeral_keypair_mldsa65 for
    // why both halves are needed (hybrid receipt-ack/disclosure signing).
    std::map<std::string, MlDsa65KeyPair> ephemeral_keypairs_mldsa65_;

    // Phase 6 - guarded by state_mutex_. mediator_receipt_key_ is this
    // session's trust-on-first-use pin (see main.cpp's identical
    // ClientState::mediator_receipt_key for the same caveat, stated once
    // there rather than duplicated here).
    std::optional<Ed25519PublicKey> mediator_receipt_key_;
    std::optional<MlDsa65PublicKey> mediator_receipt_key_mldsa65_;
    std::map<std::string, std::vector<IssuedReceipt>> room_receipts_;

#ifdef TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL
    // Not guarded by state_mutex_ - BlindSigClientSession is internally
    // thread-safe (its own state_mutex_/atomics), and this member is only
    // ever written once, from enable_blindsig() before start() runs (same
    // single-writer-before-start discipline as recognition_key_provider_
    // above).
    std::optional<blindsig::BlindSigClientSession> blindsig_session_;
#endif

    std::mutex queue_mutex_;
    std::deque<OutgoingFrame> outgoing_;

    // Network telemetry: cumulative since process start, across reconnects.
    // Every send_frame()/receive_frame() call this client makes is counted
    // at its call site (worker_loop's welcome + initial ListOffers,
    // session_loop's receive loop, flush_outgoing's send loop) - plain
    // atomics rather than state_mutex_ since these are increment-only and
    // read together with connected_since_ (under state_mutex_) only for
    // display in state_json(), never modified as part of any of the locked
    // state transitions above.
    std::atomic<std::uint64_t> frames_sent_total_{0U};
    std::atomic<std::uint64_t> frames_received_total_{0U};
    std::atomic<std::uint64_t> payload_bytes_sent_total_{0U};
    std::atomic<std::uint64_t> payload_bytes_received_total_{0U};
    std::atomic<std::uint64_t> connection_count_{0U};
};

} // namespace tradep2p::dashboard
