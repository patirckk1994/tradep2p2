#pragma once

// Phase 5 of the optional identity system: per-trade ephemeral identities.
// See docs/identity-05-ephemeral-trade-identity.md and specs.txt SS5 (key
// architecture) for the design this implements.
//
// WHAT THIS BUYS, AND WHAT IT DOESN'T (state this everywhere, per the phase
// spec - it is the easiest claim in this module to oversell):
//   - Ephemeral trade keys make a client's activity UNLINKABLE ACROSS
//     ROOMS to anyone reading the public offer book or comparing room
//     contents across trades - including another client, or a mediator the
//     user did NOT connect this room through.
//   - Ephemeral trade keys do NOT hide anything from the mediator this
//     room's connection is actually made through. The mediator sees which
//     TLS connection (and therefore which ClientId) joined which room in
//     real time, regardless of what key signs messages inside it. Any
//     documentation or UI copy implying otherwise is overselling and must
//     be fixed, not the code (specs.txt SS13.2 makes the identical point
//     about the mediator's traffic-timing visibility).
//
// KEY GENERATION: always tradep2p::generate_ed25519_keypair() - freshly
// random, NEVER derived from the master secret (identity.hpp's key_scope
// table deliberately has no "trade" label; see its own comment). A key
// derived from the master secret would be mutually linkable by anyone who
// later learned the derivation path, which defeats the entire purpose of
// this phase. generate_ephemeral_trade_keypair() below is a thin,
// self-documenting wrapper that exists purely so call sites read as
// intentional rather than "some random key generation call".
//
// THE SIGNED ENVELOPE: TradeMessageContext binds everything the phase spec
// asks for - protocol version, suite id (specs.txt SS11's "add this
// cheaply now" convention, matching recognition.hpp), mediator identifier
// (so a room id collision across two DIFFERENT mediators, astronomically
// unlikely on its own since room ids are random 32-byte values, still
// cannot cross-replay even in principle), room id, round, message type,
// a hash of the underlying message payload (never the raw payload itself -
// keeps the signed envelope's size fixed regardless of message size),
// the sender's own ephemeral public key (so a captured signature cannot be
// re-attributed to a different key/room by omission), the intended
// recipient's ClientId, and a timestamp. Canonical, fixed-field,
// unambiguous encoding (encode_trade_message_context()) - no raw struct
// signing, matching every other signed-object convention in this codebase.
//
// "TRADE IDENTIFIER" vs ROOM IDENTIFIER: the phase spec's field list names
// both separately, inherited from journal.hpp's pre-room trade_id (a
// client-local id assigned before the mediator hands out a room id). By the
// time an ephemeral key is announced and messages are signed, the room
// already exists - this codebase has no broader "trade" grouping across
// multiple rooms - so TradeMessageContext deliberately does NOT carry a
// separate trade_id field; room_id already serves as the unique identifier
// this envelope needs. Documented here explicitly rather than left as a
// silent field-list mismatch against the phase spec.
//
// SCOPE OF THIS PHASE (read before assuming more is wired than is):
// this module provides the announcement message (TradeEphemeralKey, relayed
// by the mediator the same way Sent/Received/RecognitionChallenge already
// are - see lobby.cpp's handle_room_relay()) and the sign/verify primitives,
// wired into the CLI/dashboard so every room automatically announces and
// exchanges ephemeral keys and locally signs its own outgoing round
// activity (printed/held in-memory for this session). It deliberately does
// NOT change the wire shape of TurnMessage/RoundSignalMessage themselves
// (no protocol version bump to the core settlement path) and does NOT yet
// persist ephemeral keys or signed statements to disk - specs.txt SS5
// already names this as a known follow-on ("the ephemeral key for any
// in-flight room must be persisted alongside journal state once that phase
// lands"), meaning phase 6 (receipts), not this one: phase 6 is what turns
// a locally-signed statement into something worth persisting and showing to
// a counterparty.

#include "tradep2p/identity.hpp"
#include "tradep2p/protocol.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tradep2p {

constexpr std::uint16_t kTradeMessageSuiteEd25519V1 = 0x0001;
inline constexpr std::string_view kTradeMessageDomainLabel = "TRADEP2P_TRADE_MESSAGE_V1";
constexpr std::size_t kTradeMessageMaxMediatorIdLength = 256;

// The fields bound into the signed envelope - see encode_trade_message_
// context() for the exact wire encoding. `mediator_id` is supplied locally
// by the signer/verifier from their own knowledge of which mediator they
// connected to (same convention as recognition.hpp's RecognitionChallenge
// Fields - never carried on the wire for the same reason: both parties in
// a room are already connected to the identical mediator, so putting it on
// the wire would add nothing a malicious mediator couldn't already fake by
// relaying whatever string it likes).
struct TradeMessageContext {
    std::uint16_t suite_id{kTradeMessageSuiteEd25519V1};
    std::uint16_t protocol_version{kProtocolVersion};
    std::string mediator_id;
    RoomId room_id{};
    std::uint32_t round{0};
    MessageType message_type{MessageType::Sent};
    std::array<std::uint8_t, 32> payload_hash{};
    Ed25519PublicKey sender_ephemeral_public_key{};
    ClientId recipient{};
    std::uint64_t timestamp{0};
};

// Canonical, length-prefixed (for the one variable-length field,
// mediator_id), domain-separated serialization of `context` - the exact
// bytes signed and verified. Throws std::invalid_argument if mediator_id
// exceeds kTradeMessageMaxMediatorIdLength.
[[nodiscard]] std::vector<std::uint8_t> encode_trade_message_context(const TradeMessageContext& context);

// Freshly random keypair via generate_ed25519_keypair() - see this file's
// header comment for why this must never be derived from the master
// secret. Call this, and only this, for a room's ephemeral trade identity.
[[nodiscard]] Ed25519KeyPair generate_ephemeral_trade_keypair();

// The ML-DSA-65 sibling of the room's ephemeral identity above - generated
// alongside it (never derived from the master secret either, same reasoning
// applies unchanged), so receipt.hpp's ack signing and disclosure.hpp's
// envelope signing can hybrid-sign with both halves of the SAME per-room
// identity. This is a separate keypair value, not a combined struct,
// matching every other dual-algorithm identity in this codebase (the
// mediator's receipt and auth keys are likewise two independent KeyPair
// values, never merged into one type).
[[nodiscard]] MlDsa65KeyPair generate_ephemeral_trade_keypair_mldsa65();

[[nodiscard]] Ed25519Signature sign_trade_message(const Ed25519PrivateSeed& sender_ephemeral_private_seed,
                                                   const TradeMessageContext& context);

[[nodiscard]] bool verify_trade_message(const Ed25519PublicKey& sender_ephemeral_public_key,
                                        const TradeMessageContext& context,
                                        const Ed25519Signature& signature);

// sha256 of an already-encoded wire payload (e.g. encode_round_signal()'s
// output) - the payload_hash convention this envelope binds to, so the
// signed envelope's size never depends on the underlying message's size.
[[nodiscard]] std::array<std::uint8_t, 32> trade_payload_hash(std::span<const std::uint8_t> encoded_payload);

} // namespace tradep2p
