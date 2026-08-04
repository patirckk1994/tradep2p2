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
constexpr std::size_t kMaxFramePayload = 4096;
constexpr std::size_t kMaxAssetCodeLength = 16;
constexpr std::size_t kMaxAddressLength = 256;
constexpr std::size_t kMaxReasonLength = 128;
constexpr std::size_t kMaxNodeHostLength = 96;
constexpr std::size_t kMaxPeerListEntries = 128;
constexpr std::size_t kMaxRegistryNodes = 16;
constexpr std::size_t kMaxOfferPageEntries = 32;
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

struct WelcomeMessage {
    ClientId client_id{};
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
};

struct TurnMessage {
    RoomId room_id{};
    std::uint32_t round_index{};
    Party sender{Party::A};
    std::string asset;
    std::uint64_t amount{};
    std::string destination;
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

void validate_terms(const TradeTerms& terms);
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

} // namespace tradep2p
