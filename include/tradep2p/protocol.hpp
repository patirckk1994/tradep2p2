#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace tradep2p {

constexpr std::uint16_t kProtocolVersion = 5;
// Wire size of SecureChannel's per-frame header (4-byte magic, 2-byte
// version, 2-byte type, 8-byte sequence, 4-byte length - see
// SecureChannel::send_frame/receive_frame). Named here so anything counting
// on-wire overhead (e.g. dashboard traffic telemetry) references the same
// constant the framing code itself uses, rather than duplicating the literal.
constexpr std::size_t kFrameHeaderSize = 20;
// Raised from 4096: an ML-DSA-65 (post-quantum) recognition response needs
// a 1952-byte public key + a 3309-byte signature (>5.2KB) alone, which the
// old cap couldn't fit. Confirmed safe to raise: the receive-side buffer is
// already a std::vector sized dynamically off the wire length field (no
// fixed-size buffer anywhere), the length field itself is a u32 with far
// more headroom than either value, and no other hardcoded 4096 duplicates
// this constant elsewhere in the codebase.
//
// Raised again, 8192->131072: receipts/disclosure went hybrid Ed25519+
// ML-DSA-65 (both signatures mandatory, see receipt.hpp/disclosure.hpp) -
// a single ReceiptIssuedMessage now embeds three ML-DSA-65 public keys
// (mediator + both parties' ephemeral) plus one ML-DSA-65 signature,
// ~9.5KB, and ReceiptDisclosureMessage inlines up to kDisclosureMaxChainEntries
// (8) full ReceiptIssuedMessage entries plus its own ML-DSA-65 signature -
// worst case comfortably under 80KB. 131072 leaves generous headroom above
// that measured worst case. Same "safe to raise" reasoning as above still
// applies unchanged (vector-backed, u32 length field).
constexpr std::size_t kMaxFramePayload = 131072;
constexpr std::size_t kMaxAssetCodeLength = 16;
constexpr std::size_t kMaxAddressLength = 256;
constexpr std::size_t kMaxReasonLength = 128;
constexpr std::size_t kMaxNodeHostLength = 96;
constexpr std::size_t kMaxPeerListEntries = 128;
// Caps a single registry's own DIRECT registrations only (registry.cpp's
// entries_) - deliberately small and unchanged by gossip federation, since
// this is what keeps a registry a personally-curated list rather than
// scale-up infrastructure. Gossip-learned entries live in a separate,
// separately-bounded pool (registry.cpp's gossip_entries_,
// kMaxGossipCachedNodes) so peering can never crowd out an operator's own
// registration capacity.
constexpr std::size_t kMaxRegistryNodes = 16;
// Caps a single registry's gossip-learned cache (registry.cpp's
// gossip_entries_) - separate from, and independent of, kMaxRegistryNodes
// above. Single-hop gossip only (a registry never re-shares what it
// learned from a peer), so this bounds "sum of your configured peers' own
// direct registrations", not the whole network.
constexpr std::size_t kMaxGossipCachedNodes = 128;
// Caps a single RegistryNodesMessage wire encoding - distinct from either
// cap above since a listing response can merge BOTH pools
// (registry.cpp's snapshot()). kMaxRegistryNodes + kMaxGossipCachedNodes
// with headroom; kMaxFramePayload (131072 bytes) comfortably fits this
// many nodes even at each field's maximum length (verified: worst case
// ~266 bytes/node, this cap's worth is ~43KB).
constexpr std::size_t kMaxRegistryNodesInList = 160;
constexpr std::size_t kMaxOfferPageEntries = 32;
// Bounds both the mediator's retained per-pair price history (lobby.cpp)
// and a single CandleData response - chosen so the largest possible
// response (two kMaxAssetCodeLength-ish asset strings plus this many
// 24-byte ticks) comfortably fits under kMaxFramePayload with no pagination
// needed, unlike the offer list (which is unbounded and so needs a cursor).
constexpr std::size_t kMaxCandleTicksPerPair = 300;
constexpr std::uint32_t kMaxRounds = 1000;
constexpr std::uint32_t kRegistryTtlSeconds = 300;

using RoomId = std::array<std::uint8_t, 32>;
using ClientId = std::array<std::uint8_t, 16>;
using InviteId = std::array<std::uint8_t, 16>;
using CertificatePin = std::array<std::uint8_t, 32>;

enum class Party : std::uint8_t {
    A = 0,
    B = 1,
};

enum class MessageType : std::uint16_t {
    Welcome = 1,
    ListPeers = 2,
    PeerList = 3,
    InviteTrade = 4,
    InviteCreated = 5,
    InviteReceived = 6,
    AcceptInvite = 7,
    DeclineInvite = 8,
    InviteDeclined = 9,
    TradeReady = 10,
    Turn = 11,
    Sent = 12,
    Received = 13,
    Complete = 14,
    Abort = 15,
    Error = 16,
    Disconnect = 17,
    RegistryRegister = 18,
    RegistryRegistered = 19,
    RegistryList = 20,
    RegistryNodes = 21,
    CreateOffer = 22,
    OfferCreated = 23,
    ListOffers = 24,
    OfferList = 25,
    JoinOffer = 26,
    CancelOffer = 27,
    OfferCancelled = 28,
    // Phase 3 (local journal + crash recovery, see
    // docs/identity-03-journal-recovery.md): a client that remembers a room
    // id from its own signed journal asks the mediator what it currently
    // has on file for that room, e.g. after a reconnect or after the
    // mediator itself restarted. Authorized purely by knowledge of the
    // 32-byte random room id - the same bearer-credential trust level every
    // other room operation already relies on (a room id is never listed
    // anywhere once an offer becomes a room) - deliberately NOT gated by
    // the stricter "current TLS connection's ClientId must match a stored
    // party" check that Sent/Received/Abort use via find_room_for(), since
    // that check is exactly what a mediator restart or client reconnect
    // invalidates: a fresh connection always gets a fresh, unrelated
    // ClientId, so the original parties could never satisfy it again.
    RecoveryStateRequest = 29,
    RecoveryStateResponse = 30,
    // Phase 4b (personal counterparty recognition, see
    // docs/identity-04b-counterparty-recognition.md): a live,
    // mediator-relayed challenge/response so a client can prove control of
    // its per-mediator pseudonym key to the OTHER party in the same room,
    // right now, over the room's own live connection. Relayed the same way
    // Sent/Received already are - one party sends, the mediator forwards it
    // to the other party in the room via Client::enqueue() - the mediator
    // never signs, verifies, or interprets the contents beyond relaying
    // them; verification happens only on each client. See recognition.hpp
    // for the canonical signed-payload structure and the verifier-side
    // single-use/expiry tracking that actually enforces "fresh, not
    // replayed".
    RecognitionChallenge = 31,
    RecognitionResponse = 32,
    // Phase 5 (per-trade ephemeral identities, see
    // docs/identity-05-ephemeral-trade-identity.md): announces a room's
    // freshly-generated, never-derived ephemeral signing key to the OTHER
    // party in the room. Relayed by the mediator exactly like Sent/Received/
    // RecognitionChallenge - see lobby.cpp's handle_room_relay(). Carries no
    // signature of its own (there is nothing to sign yet - the key was just
    // generated); ephemeral.hpp's signed TradeMessageContext envelope is
    // what later statements sign, once both parties hold each other's
    // announced key.
    TradeEphemeralKey = 33,
    // Phase 6 (mediator-signed staged receipts, see
    // docs/identity-06-receipts.md): a party's signed acknowledgement of
    // the "penultimate obligations complete" stage, sent to the mediator
    // (NOT relayed - unlike RecognitionChallenge/TradeEphemeralKey, the
    // mediator itself is a required participant here, since it must
    // collect both parties' acks before countersigning). ReceiptIssued is
    // the mediator's countersigned result, sent to BOTH parties once ready
    // (stage 3), or automatically once a room reaches Complete (stage 4,
    // mediator-only-signed - see receipt.hpp's file comment for why that
    // one needs no separate ack round trip).
    ReceiptAck = 34,
    ReceiptIssued = 35,
    // Sent by the mediator to BOTH parties the moment
    // SessionState::WaitingForFinalReceiptAck is entered (mediator.hpp) -
    // the explicit signal that no Turn is coming next and a ReceiptAck is
    // required from both sides before the trade's final tranche becomes
    // sendable. Without this, a client would have no way to distinguish
    // "the gate just opened" from "the mediator has gone silent" - see
    // lobby.cpp's handle_sent()/handle_received().
    ReceiptAckRequired = 36,
    // Phase 8 (selective private receipt disclosure, see
    // docs/identity-08-selective-disclosure.md): a holder showing a
    // specific prior receipt chain to the OTHER party in the CURRENT room,
    // relayed exactly like RecognitionChallenge/TradeEphemeralKey (see
    // lobby.cpp's handle_room_relay()) - the mediator never inspects or
    // interprets it beyond relaying. All verification (disclosure.hpp)
    // happens only on the recipient client.
    ReceiptDisclosure = 37,
    // Optional (see mediator.hpp's SessionState::WaitingForFeeConfirmation):
    // sent to both parties the moment the fee leg's sender reports it sent,
    // when the mediator operator has required an explicit confirmation
    // instead of trusting that report alone. Carries no new information
    // beyond "nothing to do right now, an operator action is pending" -
    // parallels ReceiptAckRequired's role for the receipt-ack gate. Only
    // ever sent by the mediator; a client never sends this type.
    FeeConfirmationPending = 38,
    // A client's request for the mediator's retained price history for one
    // asset pair - see lobby.cpp's price_history_/handle_get_candles(). Not
    // room-scoped and not admin-gated: this is public market data, the same
    // trust level as ListOffers/OfferList, just for completed trades
    // instead of open ones.
    GetCandles = 39,
    CandleData = 40,
    // Experimental post-quantum blind-signature primitive (specs.txt
    // SS9.3a) - compiled in only under TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL
    // (off by default; this repo's first compile-time feature gate). These
    // four tags are reserved unconditionally here (so the enum's numbering
    // never depends on build flags), but the message structs and codec live
    // entirely in the gated blindsig_wire.hpp/cpp, not here - a build
    // without the flag has no dispatch() case for these at all, and
    // lobby.cpp's existing default case already rejects unhandled types
    // safely. See blindsig_wire.hpp for the actual struct definitions.
    BlindSigInfoRequest = 41,
    BlindSigInfoResponse = 42,
    BlindSigRequestChunk = 43,
    BlindSigResponse = 44,
    // Parallel q=7933 experimental blind-signature path. Like the q12289
    // tags above, these numeric values are reserved unconditionally so
    // frame numbering never depends on whether TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL
    // was defined for a particular build. See blindsig_wire_q7933.hpp for
    // the actual structs/codecs.
    Q7933BlindSigInfoRequest = 45,
    Q7933BlindSigInfoResponse = 46,
    Q7933BlindSigRequestChunk = 47,
    Q7933BlindSigResponse = 48,
    Q7933BlindSigTicketPoll = 49,
};

struct Frame {
    MessageType type{};
    std::uint64_t sequence{};
    std::vector<std::uint8_t> payload;
};

struct TradeTerms {
    std::uint16_t version{kProtocolVersion};
    std::string asset_a;
    std::string asset_b;
    std::uint64_t total_a{};
    std::uint64_t total_b{};
    std::uint32_t rounds{};
    Party first_sender{Party::A};
};

struct CreateRoomMessage {
    TradeTerms terms;
    std::string receive_address_a;
};

struct JoinRoomMessage {
    RoomId room_id{};
    std::string receive_address_b;
};

// A mediator-wide fee the operator charges on every settled trade. An empty
// asset/address with amount 0 means the mediator charges no fee. The fee is
// never held or verified by the mediator; it is settled as an ordinary final
// transfer, acknowledged the same way any other round is.
struct FeeTerms {
    std::string asset;
    std::uint64_t amount{};
    std::string address;
};

struct WelcomeMessage {
    ClientId client_id{};
    FeeTerms fee;
};

struct CreateOfferMessage {
    TradeTerms terms;
    std::string receive_address_a;
};

struct OfferCreatedMessage {
    RoomId room_id{};
};

struct OfferSummary {
    RoomId room_id{};
    TradeTerms terms;
};

// Offer pages use a stable lexical room-id cursor instead of an unordered-map
// offset. A deleted cursor still works: the server resumes at the first ID
// lexically greater than after_room_id.
struct ListOffersMessage {
    bool has_cursor{false};
    RoomId after_room_id{};
    std::uint16_t limit{static_cast<std::uint16_t>(kMaxOfferPageEntries)};
};

struct OfferListMessage {
    std::vector<OfferSummary> offers;
    bool has_more{false};
    RoomId next_cursor{};
};

struct GetCandlesMessage {
    std::string asset_a;
    std::string asset_b;
};

// One completed trade's implied price, as raw integer amounts rather than
// a computed ratio - no floating point crosses the wire. base_amount/
// quote_amount are already oriented to CandleDataMessage's base_asset/
// quote_asset (see lobby.cpp's canonical_pair()), so price = quote_amount
// / base_amount regardless of which asset the original room called
// asset_a vs asset_b.
struct TradeTick {
    std::uint64_t timestamp{};
    std::uint64_t base_amount{};
    std::uint64_t quote_amount{};
};

// The mediator decides base/quote (lexicographically smaller asset code is
// base) so that a room's asset_a/asset_b order never splits one real pair
// into two series. Oldest tick first. Bounded to kMaxCandleTicksPerPair -
// unlike OfferListMessage this never paginates, since that bound already
// guarantees the whole series fits in one frame.
struct CandleDataMessage {
    std::string base_asset;
    std::string quote_asset;
    std::vector<TradeTick> ticks;
};

struct JoinOfferMessage {
    RoomId room_id{};
    std::string receive_address_b;
};

struct CancelOfferMessage {
    RoomId room_id{};
};

struct OfferCancelledMessage {
    RoomId room_id{};
};

struct PeerListMessage {
    std::vector<ClientId> peers;
};

struct InviteTradeMessage {
    ClientId target{};
    TradeTerms terms;
    std::string receive_address_a;
};

struct InviteCreatedMessage {
    InviteId invite_id{};
    ClientId target{};
};

struct InviteReceivedMessage {
    InviteId invite_id{};
    ClientId sender{};
    TradeTerms terms;
    std::string receive_address_a;
};

struct AcceptInviteMessage {
    InviteId invite_id{};
    std::string receive_address_b;
};

struct DeclineInviteMessage {
    InviteId invite_id{};
};

struct InviteDeclinedMessage {
    InviteId invite_id{};
};

struct TradeReadyMessage {
    RoomId room_id{};
    Party assigned_party{Party::A};
    ClientId peer_id{};
    TradeTerms terms;
    std::string receive_address_a;
    std::string receive_address_b;
    FeeTerms fee;
};

struct TurnMessage {
    RoomId room_id{};
    std::uint32_t round_index{};
    Party sender{Party::A};
    std::string asset;
    std::uint64_t amount{};
    std::string destination;
    // Authoritative, set only by MediatorSession::current_turn() - whether
    // this leg is the mediator fee rather than a real trade tranche. Needed
    // now that the fee's position is configurable (see FeePosition in
    // mediator.hpp): it can legitimately reuse a round_index that also
    // belongs to a real round (0, or rounds-1), so "round_index >= rounds"
    // is no longer a valid way to infer this client-side - see
    // dashboard_client.cpp's is_fee_turn, the one place that used to guess.
    bool is_fee{false};
};

struct RoundSignalMessage {
    RoomId room_id{};
    std::uint32_t round_index{};
    Party sender{Party::A};
};

struct CompleteMessage {
    RoomId room_id{};
};

struct AbortMessage {
    RoomId room_id{};
    std::string reason;
};

struct ErrorMessage {
    std::string reason;
};

struct RegistryNode {
    std::string host;
    std::uint16_t port{};
    CertificatePin certificate_pin{};
    std::uint32_t remaining_ttl_seconds{};
    // Empty for a node this registry holding the listing registered
    // directly; otherwise the peer registry's own "host:port" this entry
    // was learned from via single-hop gossip (registry.cpp's
    // gossip_entries_) - lets a caller tell "this registry personally
    // vetted this mediator" from "this registry is relaying it from a
    // peer it chose to trust". Only meaningful (and only encoded/decoded)
    // in a RegistryNodesMessage listing, never in a RegistryRegisterMessage
    // - a registrant never sets this itself.
    std::string source_registry;
};

struct RegistryRegisterMessage {
    RegistryNode node;
};

struct RegistryRegisteredMessage {
    std::uint32_t ttl_seconds{};
};

struct RegistryNodesMessage {
    std::vector<RegistryNode> nodes;
};

// --- Phase 3: recovery protocol (see docs/identity-03-journal-recovery.md) ---

// Sent by a client that wants to know what the mediator currently has on
// file for `room_id` - typically after that client's own signed local
// journal shows a room that may still be in flight (e.g. after the
// client's own process restarted, or after reconnecting following a
// disconnect). Carries nothing beyond the room id: knowledge of the id is
// the only "credential" this protocol has ever required for a room.
struct RecoveryStateRequestMessage {
    RoomId room_id{};
};

// The mediator's truthful answer. `found` is the headline field: false
// means the mediator has no persisted or in-memory record of this room at
// all (either it never existed, or it ran to completion/abort and was
// pruned - see room_persistence.hpp for why completed rooms are pruned
// rather than kept forever). When `found` is true, `state`/`round_index`/
// `leg_index` describe the mediator's last confirmed progress.
//
// `state` mirrors tradep2p::SessionState (mediator.hpp) numerically, but is
// carried here as a raw byte rather than that enum type: protocol.hpp must
// not depend on mediator.hpp (mediator.hpp already depends on
// protocol.hpp), so this struct cannot name SessionState directly. Callers
// on both sides cast explicitly.
//
// `party_a_connected`/`party_b_connected` reflect whether a live connection
// is *currently* bound to that room slot's original ClientId - for a room
// reconstructed from disk after a mediator restart, both are always false,
// truthfully, since a fresh TLS connection is never assigned the same
// random ClientId as a pre-restart one. This phase does not implement
// re-binding a new connection to a recovered room's party slot (see the
// phase report for why); RecoveryStateResponse is a read-only status
// query, not a resume/rejoin operation.
struct RecoveryStateResponseMessage {
    RoomId room_id{};
    bool found{false};
    TradeTerms terms;
    FeeTerms fee;
    std::uint8_t state{0};
    std::uint32_t round_index{0};
    std::uint8_t leg_index{0};
    bool party_a_connected{false};
    bool party_b_connected{false};
    std::string reason;
};

// --- Phase 4b: counterparty recognition relay (see
// docs/identity-04b-counterparty-recognition.md) ---
//
// Wire shapes only. protocol.hpp deliberately does not depend on
// identity.hpp (the reverse dependency already exists - identity.hpp is a
// lower layer), so the public key / signature fields here are raw
// fixed-size byte arrays, matching how every other identity-shaped field in
// this file (ClientId, CertificatePin, ...) is already represented rather
// than pulling in identity.hpp's Ed25519PublicKey/Ed25519Signature types.
// recognition.hpp is the module that gives these bytes cryptographic
// meaning (canonical signed-payload construction, sign/verify, single-use
// nonce tracking); this file only frames and bounds-checks them.
constexpr std::size_t kRecognitionNonceLength = 32;
// Maximum allowed length for RecognitionResponseMessage's variable-length
// key/signature fields (see below) - bounds decode_recognition_response()
// so a malformed/oversized field is rejected before allocating, the same
// role short_string()'s `maximum` argument plays elsewhere in this file.
// Sized to the larger of the two suites this codebase supports today
// (Ed25519: 32/64 bytes; ML-DSA-65, identity.hpp's kMlDsa65PublicKeyLength/
// kMlDsa65SignatureLength: 1952/3309 bytes) - a future suite with larger
// keys/signatures would need this raised too.
constexpr std::size_t kRecognitionMaxPublicKeyLength = 1952;  // ML-DSA-65
constexpr std::size_t kRecognitionMaxSignatureLength = 3309;  // ML-DSA-65

using RecognitionNonce = std::array<std::uint8_t, kRecognitionNonceLength>;

// Sent by the verifier (the party who wants proof of key control) to the
// mediator, which relays it unmodified to the OTHER party in `room_id`. The
// mediator identifier and protocol version are deliberately NOT carried on
// the wire here: both parties are already connected to the same mediator
// (they learned its identity out of band, via certificate pinning, before
// this room existed), so both sides supply the same mediator identifier
// string independently when building the canonical signed payload - see
// recognition.hpp's RecognitionChallengeFields. Putting it on the wire
// would add nothing a malicious mediator couldn't already fake by relaying
// whatever string it likes.
struct RecognitionChallengeMessage {
    RoomId room_id{};
    std::uint16_t suite_id{1};
    RecognitionNonce nonce{};
    std::uint64_t created_at{0};
    std::uint64_t expires_at{0};
};

// The prover's answer, relayed back to whichever party issued the
// challenge. `nonce` echoes the challenge being answered, since the
// mediator relays many rooms and the verifier may have more than one
// outstanding challenge; the verifier's own RecognitionChallengeTracker (see
// recognition.hpp) is the sole authority on whether this nonce is still
// outstanding, unexpired, and being answered in the right room - a
// mismatch on any of those is rejected identically, without revealing which
// check failed first.
//
// `suite_id` and variable-length `prover_public_key`/`signature` (instead of
// this struct's earlier fixed 32/64-byte Ed25519-only arrays) exist so a
// prover can answer with either suite the challenge's own suite_id named -
// see recognition.hpp for the suite_id values and recognition.cpp for the
// sign/verify branch on it. This is a breaking wire-format change: both
// sides of a connection must be rebuilt together, matching kMaxFramePayload's
// bump above (same commit, same reason).
struct RecognitionResponseMessage {
    RoomId room_id{};
    RecognitionNonce nonce{};
    std::uint16_t suite_id{1};
    std::vector<std::uint8_t> prover_public_key;
    std::vector<std::uint8_t> signature;
};

// --- Phase 5: ephemeral trade identity announcement (see
// docs/identity-05-ephemeral-trade-identity.md) ---
constexpr std::size_t kTradeEphemeralPublicKeyLength = 32; // Ed25519
// A room's ephemeral identity is dual-algorithm from generation (see
// ephemeral.hpp's generate_ephemeral_trade_keypair_mldsa65()) so
// receipt.hpp's ack signing and disclosure.hpp's envelope signing can
// hybrid-sign with both halves of the same per-room identity - the
// ML-DSA-65 half must be announced on the wire right alongside the
// existing Ed25519 one, or a counterparty (and later, per receipt.hpp's
// ReceiptFields, any future disclosure recipient) would have no way to
// learn it.
constexpr std::size_t kTradeEphemeralPublicKeyLengthMlDsa65 = 1952; // ML-DSA-65

struct TradeEphemeralKeyMessage {
    RoomId room_id{};
    std::array<std::uint8_t, kTradeEphemeralPublicKeyLength> ephemeral_public_key{};
    std::array<std::uint8_t, kTradeEphemeralPublicKeyLengthMlDsa65> ephemeral_public_key_mldsa65{};
};

// --- Phase 6: staged receipts (see docs/identity-06-receipts.md) ---
//
// Raw fixed-size byte arrays for the same reason RecognitionChallengeMessage
// uses them rather than identity.hpp's Ed25519PublicKey/Ed25519Signature
// types - protocol.hpp does not depend on identity.hpp. receipt.hpp is the
// module that gives these bytes cryptographic meaning.
constexpr std::size_t kReceiptPublicKeyLength = 32;   // Ed25519
constexpr std::size_t kReceiptSignatureLength = 64;   // Ed25519
// Receipts/acks/disclosure are all hybrid (both signatures mandatory, see
// receipt.hpp's file-wide hybrid note) - every wire message carrying a
// receipt-family key or signature below carries both algorithms
// unconditionally, no suite_id branching needed on the wire (unlike
// recognition's either/or, which is why those fields there are
// length-prefixed and variable while these stay plain fixed arrays).
constexpr std::size_t kReceiptPublicKeyLengthMlDsa65 = 1952;  // ML-DSA-65
constexpr std::size_t kReceiptSignatureLengthMlDsa65 = 3309;  // ML-DSA-65
constexpr std::size_t kReceiptTermsCommitmentLength = 32; // SHA-256
constexpr std::size_t kReceiptWireNonceLength = 16;
constexpr std::size_t kReceiptWireMediatorIdLength = 256; // matches receipt.hpp's kReceiptMaxMediatorIdLength

struct ReceiptAckMessage {
    RoomId room_id{};
    std::uint8_t stage{0};
    std::uint64_t timestamp{0};
    std::array<std::uint8_t, kReceiptSignatureLength> signature{};
    std::array<std::uint8_t, kReceiptSignatureLengthMlDsa65> signature_mldsa65{};
};

struct ReceiptAckRequiredMessage {
    RoomId room_id{};
};

// See MessageType::FeeConfirmationPending.
struct FeeConfirmationPendingMessage {
    RoomId room_id{};
};

struct ReceiptIssuedMessage {
    RoomId room_id{};
    // The mediator identifier this receipt was actually signed under (the
    // client-supplied "host:port"-shaped label - see receipt.hpp). Carried
    // explicitly, unlike every other phase's identity-layer messages,
    // because a receipt can legitimately be shown OUTSIDE the room/
    // connection it was issued on (phase 8's selective disclosure) - the
    // recipient in that case was never connected to the ORIGINAL mediator
    // and has no other way to learn what string it was signed under, so
    // omitting it (as e.g. RecognitionChallengeMessage does, relying on
    // both sides already sharing one live mediator connection) would make
    // a disclosed receipt's signature permanently unverifiable.
    std::string mediator_id;
    std::uint8_t stage{0};
    bool completed{false};
    std::array<std::uint8_t, kReceiptTermsCommitmentLength> terms_commitment{};
    std::array<std::uint8_t, kReceiptPublicKeyLength> party_a_ephemeral_key{};
    std::array<std::uint8_t, kReceiptPublicKeyLength> party_b_ephemeral_key{};
    std::array<std::uint8_t, kReceiptPublicKeyLengthMlDsa65> party_a_ephemeral_key_mldsa65{};
    std::array<std::uint8_t, kReceiptPublicKeyLengthMlDsa65> party_b_ephemeral_key_mldsa65{};
    std::array<std::uint8_t, kReceiptPublicKeyLength> mediator_public_key{};
    std::array<std::uint8_t, kReceiptPublicKeyLengthMlDsa65> mediator_public_key_mldsa65{};
    std::uint64_t timestamp{0};
    std::array<std::uint8_t, kReceiptWireNonceLength> nonce{};
    std::array<std::uint8_t, kReceiptTermsCommitmentLength> previous_stage_hash{};
    std::array<std::uint8_t, kReceiptSignatureLength> mediator_signature{};
    std::array<std::uint8_t, kReceiptSignatureLengthMlDsa65> mediator_signature_mldsa65{};
};

// --- Phase 8: selective private receipt disclosure (see
// docs/identity-08-selective-disclosure.md) ---
constexpr std::size_t kDisclosureMaxChainEntries = 8; // matches disclosure.hpp's kDisclosureMaxChainLength

struct ReceiptDisclosureMessage {
    RoomId room_id{}; // current negotiation
    std::array<std::uint8_t, kReceiptPublicKeyLength> recipient_ephemeral_key{};
    std::array<std::uint8_t, kReceiptTermsCommitmentLength> disclosed_chain_hash{};
    std::uint64_t timestamp{0};
    std::array<std::uint8_t, 16> nonce{};
    std::array<std::uint8_t, kReceiptSignatureLength> signature{};
    std::array<std::uint8_t, kReceiptSignatureLengthMlDsa65> signature_mldsa65{};
    std::vector<ReceiptIssuedMessage> chain;
};

void validate_terms(const TradeTerms& terms);
void validate_fee_terms(const FeeTerms& fee);
void validate_address(std::string_view address);
void validate_reason(std::string_view text);
void validate_room_id(const RoomId& room_id);
void validate_client_id(const ClientId& client_id);
void validate_invite_id(const InviteId& invite_id);
void validate_certificate_pin(const CertificatePin& pin);
void validate_registry_node(const RegistryNode& node, bool require_ttl);
void validate_message_type(MessageType type);

[[nodiscard]] std::uint64_t tranche_amount(std::uint64_t total,
                                           std::uint32_t rounds,
                                           std::uint32_t round_index);
[[nodiscard]] Party other_party(Party party);

[[nodiscard]] std::string room_id_to_hex(const RoomId& id);
[[nodiscard]] RoomId room_id_from_hex(std::string_view text);
[[nodiscard]] std::string client_id_to_hex(const ClientId& id);
[[nodiscard]] ClientId client_id_from_hex(std::string_view text);
[[nodiscard]] std::string invite_id_to_hex(const InviteId& id);
[[nodiscard]] InviteId invite_id_from_hex(std::string_view text);
[[nodiscard]] std::string certificate_pin_to_hex(const CertificatePin& pin);
[[nodiscard]] CertificatePin certificate_pin_from_hex(std::string_view text);

[[nodiscard]] std::vector<std::uint8_t> encode_terms(const TradeTerms& terms);
[[nodiscard]] TradeTerms decode_terms(std::span<const std::uint8_t> bytes);


[[nodiscard]] std::vector<std::uint8_t> encode_create_offer(const CreateOfferMessage& message);
[[nodiscard]] CreateOfferMessage decode_create_offer(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_offer_created(const OfferCreatedMessage& message);
[[nodiscard]] OfferCreatedMessage decode_offer_created(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_list_offers(const ListOffersMessage& message);
[[nodiscard]] ListOffersMessage decode_list_offers(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_offer_list(const OfferListMessage& message);
[[nodiscard]] OfferListMessage decode_offer_list(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_get_candles(const GetCandlesMessage& message);
[[nodiscard]] GetCandlesMessage decode_get_candles(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_candle_data(const CandleDataMessage& message);
[[nodiscard]] CandleDataMessage decode_candle_data(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_join_offer(const JoinOfferMessage& message);
[[nodiscard]] JoinOfferMessage decode_join_offer(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_cancel_offer(const CancelOfferMessage& message);
[[nodiscard]] CancelOfferMessage decode_cancel_offer(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_offer_cancelled(const OfferCancelledMessage& message);
[[nodiscard]] OfferCancelledMessage decode_offer_cancelled(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_welcome(const WelcomeMessage& message);
[[nodiscard]] WelcomeMessage decode_welcome(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_peer_list(const PeerListMessage& message);
[[nodiscard]] PeerListMessage decode_peer_list(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_invite_trade(const InviteTradeMessage& message);
[[nodiscard]] InviteTradeMessage decode_invite_trade(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_invite_created(const InviteCreatedMessage& message);
[[nodiscard]] InviteCreatedMessage decode_invite_created(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_invite_received(const InviteReceivedMessage& message);
[[nodiscard]] InviteReceivedMessage decode_invite_received(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_accept_invite(const AcceptInviteMessage& message);
[[nodiscard]] AcceptInviteMessage decode_accept_invite(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_decline_invite(const DeclineInviteMessage& message);
[[nodiscard]] DeclineInviteMessage decode_decline_invite(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_invite_declined(const InviteDeclinedMessage& message);
[[nodiscard]] InviteDeclinedMessage decode_invite_declined(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_trade_ready(const TradeReadyMessage& message);
[[nodiscard]] TradeReadyMessage decode_trade_ready(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_turn(const TurnMessage& message);
[[nodiscard]] TurnMessage decode_turn(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_round_signal(const RoundSignalMessage& message);
[[nodiscard]] RoundSignalMessage decode_round_signal(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_complete(const CompleteMessage& message);
[[nodiscard]] CompleteMessage decode_complete(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_abort(const AbortMessage& message);
[[nodiscard]] AbortMessage decode_abort(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_error(const ErrorMessage& message);
[[nodiscard]] ErrorMessage decode_error(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_registry_register(const RegistryRegisterMessage& message);
[[nodiscard]] RegistryRegisterMessage decode_registry_register(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_registry_registered(const RegistryRegisteredMessage& message);
[[nodiscard]] RegistryRegisteredMessage decode_registry_registered(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_registry_nodes(const RegistryNodesMessage& message);
[[nodiscard]] RegistryNodesMessage decode_registry_nodes(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_recovery_state_request(const RecoveryStateRequestMessage& message);
[[nodiscard]] RecoveryStateRequestMessage decode_recovery_state_request(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_recovery_state_response(const RecoveryStateResponseMessage& message);
[[nodiscard]] RecoveryStateResponseMessage decode_recovery_state_response(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_recognition_challenge(const RecognitionChallengeMessage& message);
[[nodiscard]] RecognitionChallengeMessage decode_recognition_challenge(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_recognition_response(const RecognitionResponseMessage& message);
[[nodiscard]] RecognitionResponseMessage decode_recognition_response(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_trade_ephemeral_key(const TradeEphemeralKeyMessage& message);
[[nodiscard]] TradeEphemeralKeyMessage decode_trade_ephemeral_key(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_receipt_ack(const ReceiptAckMessage& message);
[[nodiscard]] ReceiptAckMessage decode_receipt_ack(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_receipt_issued(const ReceiptIssuedMessage& message);
[[nodiscard]] ReceiptIssuedMessage decode_receipt_issued(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_receipt_ack_required(const ReceiptAckRequiredMessage& message);
[[nodiscard]] ReceiptAckRequiredMessage decode_receipt_ack_required(std::span<const std::uint8_t> bytes);
[[nodiscard]] std::vector<std::uint8_t> encode_fee_confirmation_pending(const FeeConfirmationPendingMessage& message);
[[nodiscard]] FeeConfirmationPendingMessage decode_fee_confirmation_pending(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::vector<std::uint8_t> encode_receipt_disclosure(const ReceiptDisclosureMessage& message);
[[nodiscard]] ReceiptDisclosureMessage decode_receipt_disclosure(std::span<const std::uint8_t> bytes);

} // namespace tradep2p
