#include "tradep2p/protocol.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace tradep2p {
namespace {

class Writer {
public:
    void u8(std::uint8_t value) { out_.push_back(value); }

    void u16(std::uint16_t value) {
        out_.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
        out_.push_back(static_cast<std::uint8_t>(value & 0xffU));
    }

    void u32(std::uint32_t value) {
        for (int shift = 24; shift >= 0; shift -= 8) {
            out_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
        }
    }

    void u64(std::uint64_t value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            out_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
        }
    }

    template <std::size_t N>
    void fixed_id(const std::array<std::uint8_t, N>& value) {
        out_.insert(out_.end(), value.begin(), value.end());
    }

    void short_string(std::string_view value, std::size_t maximum) {
        if (value.size() > maximum ||
            value.size() > std::numeric_limits<std::uint16_t>::max()) {
            throw std::invalid_argument("string exceeds protocol limit");
        }
        u16(static_cast<std::uint16_t>(value.size()));
        out_.insert(out_.end(), value.begin(), value.end());
    }

    // Same u16-length-prefix pattern as short_string(), for variable-length
    // binary data instead of text - added for RecognitionResponseMessage's
    // suite-dependent key/signature fields, reusable for any future
    // variable-length binary field.
    void bytes(std::span<const std::uint8_t> value, std::size_t maximum) {
        if (value.size() > maximum ||
            value.size() > std::numeric_limits<std::uint16_t>::max()) {
            throw std::invalid_argument("byte field exceeds protocol limit");
        }
        u16(static_cast<std::uint16_t>(value.size()));
        out_.insert(out_.end(), value.begin(), value.end());
    }

    [[nodiscard]] std::vector<std::uint8_t> take() { return std::move(out_); }

private:
    std::vector<std::uint8_t> out_;
};

class Reader {
public:
    explicit Reader(std::span<const std::uint8_t> input) : input_(input) {}

    [[nodiscard]] std::uint8_t u8() {
        require(1U);
        return input_[position_++];
    }

    [[nodiscard]] std::uint16_t u16() {
        require(2U);
        const auto result = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(input_[position_]) << 8U) |
            static_cast<std::uint16_t>(input_[position_ + 1U]));
        position_ += 2U;
        return result;
    }

    [[nodiscard]] std::uint32_t u32() {
        require(4U);
        std::uint32_t result = 0U;
        for (int i = 0; i < 4; ++i) {
            result = (result << 8U) | input_[position_++];
        }
        return result;
    }

    [[nodiscard]] std::uint64_t u64() {
        require(8U);
        std::uint64_t result = 0U;
        for (int i = 0; i < 8; ++i) {
            result = (result << 8U) | input_[position_++];
        }
        return result;
    }

    template <std::size_t N>
    [[nodiscard]] std::array<std::uint8_t, N> fixed_id() {
        require(N);
        std::array<std::uint8_t, N> result{};
        std::copy_n(input_.begin() + static_cast<std::ptrdiff_t>(position_),
                    N, result.begin());
        position_ += N;
        return result;
    }

    [[nodiscard]] std::string short_string(std::size_t maximum) {
        const auto length = static_cast<std::size_t>(u16());
        if (length > maximum) {
            throw std::runtime_error("encoded string exceeds protocol limit");
        }
        require(length);
        std::string result(
            reinterpret_cast<const char*>(input_.data() + position_), length);
        position_ += length;
        return result;
    }

    // Mirrors short_string() above, for variable-length binary data.
    [[nodiscard]] std::vector<std::uint8_t> bytes(std::size_t maximum) {
        const auto length = static_cast<std::size_t>(u16());
        if (length > maximum) {
            throw std::runtime_error("encoded byte field exceeds protocol limit");
        }
        require(length);
        std::vector<std::uint8_t> result(
            input_.begin() + static_cast<std::ptrdiff_t>(position_),
            input_.begin() + static_cast<std::ptrdiff_t>(position_ + length));
        position_ += length;
        return result;
    }

    void require_finished() const {
        if (position_ != input_.size()) {
            throw std::runtime_error("trailing bytes in message");
        }
    }

private:
    void require(std::size_t count) const {
        if (position_ > input_.size() || count > input_.size() - position_) {
            throw std::runtime_error("truncated message");
        }
    }

    std::span<const std::uint8_t> input_;
    std::size_t position_{0U};
};

void validate_party(Party party) {
    if (party != Party::A && party != Party::B) {
        throw std::invalid_argument("invalid party");
    }
}

void validate_asset(std::string_view asset) {
    if (asset.empty() || asset.size() > kMaxAssetCodeLength) {
        throw std::invalid_argument("invalid asset code length");
    }
    for (const unsigned char c : asset) {
        if (std::isalnum(c) == 0 && c != '.' && c != '_' && c != '-') {
            throw std::invalid_argument("invalid asset code character");
        }
    }
}

void validate_printable(std::string_view value,
                        std::size_t maximum,
                        bool allow_spaces,
                        const char* label) {
    if (value.empty() || value.size() > maximum) {
        throw std::invalid_argument(std::string("invalid ") + label + " length");
    }
    for (const unsigned char c : value) {
        const bool printable = c >= 0x21U && c <= 0x7eU;
        if (!printable && !(allow_spaces && c == 0x20U)) {
            throw std::invalid_argument(std::string("invalid ") + label + " character");
        }
    }
}

template <std::size_t N>
void validate_nonzero_id(const std::array<std::uint8_t, N>& id,
                         const char* label) {
    const bool zero = std::all_of(id.begin(), id.end(),
                                  [](std::uint8_t byte) { return byte == 0U; });
    if (zero) {
        throw std::invalid_argument(std::string(label) + " must not be zero");
    }
}

[[nodiscard]] int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

template <std::size_t N>
[[nodiscard]] std::string id_to_hex(const std::array<std::uint8_t, N>& id,
                                    const char* label) {
    validate_nonzero_id(id, label);
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (const std::uint8_t byte : id) {
        stream << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return stream.str();
}

template <std::size_t N>
[[nodiscard]] std::array<std::uint8_t, N> id_from_hex(std::string_view text,
                                                      const char* label) {
    if (text.size() != N * 2U) {
        throw std::invalid_argument(std::string(label) + " has wrong length");
    }
    std::array<std::uint8_t, N> result{};
    for (std::size_t i = 0U; i < N; ++i) {
        const int high = hex_value(text[i * 2U]);
        const int low = hex_value(text[i * 2U + 1U]);
        if (high < 0 || low < 0) {
            throw std::invalid_argument(std::string(label) + " is not hexadecimal");
        }
        result[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    validate_nonzero_id(result, label);
    return result;
}

void append_terms(Writer& writer, const TradeTerms& terms) {
    validate_terms(terms);
    writer.u16(terms.version);
    writer.short_string(terms.asset_a, kMaxAssetCodeLength);
    writer.short_string(terms.asset_b, kMaxAssetCodeLength);
    writer.u64(terms.total_a);
    writer.u64(terms.total_b);
    writer.u32(terms.rounds);
    writer.u8(static_cast<std::uint8_t>(terms.first_sender));
}

[[nodiscard]] TradeTerms read_terms(Reader& reader) {
    TradeTerms terms;
    terms.version = reader.u16();
    terms.asset_a = reader.short_string(kMaxAssetCodeLength);
    terms.asset_b = reader.short_string(kMaxAssetCodeLength);
    terms.total_a = reader.u64();
    terms.total_b = reader.u64();
    terms.rounds = reader.u32();
    terms.first_sender = static_cast<Party>(reader.u8());
    validate_terms(terms);
    return terms;
}

void append_fee_terms(Writer& writer, const FeeTerms& fee) {
    validate_fee_terms(fee);
    writer.short_string(fee.asset, kMaxAssetCodeLength);
    writer.u64(fee.amount);
    writer.short_string(fee.address, kMaxAddressLength);
}

[[nodiscard]] FeeTerms read_fee_terms(Reader& reader) {
    FeeTerms fee;
    fee.asset = reader.short_string(kMaxAssetCodeLength);
    fee.amount = reader.u64();
    fee.address = reader.short_string(kMaxAddressLength);
    validate_fee_terms(fee);
    return fee;
}

void append_registry_node(Writer& writer,
                          const RegistryNode& node,
                          bool include_ttl) {
    validate_registry_node(node, include_ttl);
    writer.short_string(node.host, kMaxNodeHostLength);
    writer.u16(node.port);
    writer.fixed_id(node.certificate_pin);
    if (include_ttl) {
        writer.u32(node.remaining_ttl_seconds);
    }
}

[[nodiscard]] RegistryNode read_registry_node(Reader& reader, bool include_ttl) {
    RegistryNode node;
    node.host = reader.short_string(kMaxNodeHostLength);
    node.port = reader.u16();
    node.certificate_pin = reader.fixed_id<32U>();
    node.remaining_ttl_seconds = include_ttl ? reader.u32() : 0U;
    validate_registry_node(node, include_ttl);
    return node;
}

} // namespace

void validate_terms(const TradeTerms& terms) {
    if (terms.version != kProtocolVersion) {
        throw std::invalid_argument("unsupported trade terms version");
    }
    validate_asset(terms.asset_a);
    validate_asset(terms.asset_b);
    if (terms.asset_a == terms.asset_b) {
        throw std::invalid_argument("assets must differ");
    }
    if (terms.total_a == 0U || terms.total_b == 0U) {
        throw std::invalid_argument("trade totals must be positive");
    }
    if (terms.rounds == 0U || terms.rounds > kMaxRounds) {
        throw std::invalid_argument("invalid round count");
    }
    if (terms.rounds > terms.total_a || terms.rounds > terms.total_b) {
        throw std::invalid_argument("each round must contain a positive integer amount");
    }
    validate_party(terms.first_sender);
}

void validate_fee_terms(const FeeTerms& fee) {
    if (fee.amount == 0U) {
        if (!fee.asset.empty() || !fee.address.empty()) {
            throw std::invalid_argument(
                "fee asset and address must be empty when the fee amount is zero");
        }
        return;
    }
    validate_asset(fee.asset);
    validate_address(fee.address);
}

void validate_address(std::string_view address) {
    validate_printable(address, kMaxAddressLength, false, "address");
}

void validate_reason(std::string_view text) {
    validate_printable(text, kMaxReasonLength, true, "reason");
}

void validate_room_id(const RoomId& room_id) {
    validate_nonzero_id(room_id, "room id");
}

void validate_client_id(const ClientId& client_id) {
    validate_nonzero_id(client_id, "client id");
}

void validate_invite_id(const InviteId& invite_id) {
    validate_nonzero_id(invite_id, "invite id");
}

void validate_certificate_pin(const CertificatePin& pin) {
    validate_nonzero_id(pin, "certificate pin");
}

void validate_registry_node(const RegistryNode& node, bool require_ttl) {
    validate_printable(node.host, kMaxNodeHostLength, false, "node host");
    if (node.port == 0U) {
        throw std::invalid_argument("invalid node port");
    }
    validate_certificate_pin(node.certificate_pin);
    if (require_ttl &&
        (node.remaining_ttl_seconds == 0U ||
         node.remaining_ttl_seconds > kRegistryTtlSeconds)) {
        throw std::invalid_argument("invalid registry TTL");
    }
}

void validate_message_type(MessageType type) {
    const auto value = static_cast<std::uint16_t>(type);
    if (value < static_cast<std::uint16_t>(MessageType::Welcome) ||
        value > static_cast<std::uint16_t>(MessageType::FeeConfirmationPending)) {
        throw std::invalid_argument("unknown message type");
    }
}

std::uint64_t tranche_amount(std::uint64_t total,
                             std::uint32_t rounds,
                             std::uint32_t round_index) {
    if (total == 0U || rounds == 0U || round_index >= rounds || rounds > total) {
        throw std::invalid_argument("invalid tranche inputs");
    }
    const std::uint64_t base = total / rounds;
    const std::uint64_t remainder = total % rounds;
    return base + (round_index < remainder ? 1U : 0U);
}

Party other_party(Party party) {
    validate_party(party);
    return party == Party::A ? Party::B : Party::A;
}

std::string room_id_to_hex(const RoomId& id) { return id_to_hex(id, "room id"); }
RoomId room_id_from_hex(std::string_view text) { return id_from_hex<32U>(text, "room id"); }
std::string client_id_to_hex(const ClientId& id) { return id_to_hex(id, "client id"); }
ClientId client_id_from_hex(std::string_view text) { return id_from_hex<16U>(text, "client id"); }
std::string invite_id_to_hex(const InviteId& id) { return id_to_hex(id, "invite id"); }
InviteId invite_id_from_hex(std::string_view text) { return id_from_hex<16U>(text, "invite id"); }
std::string certificate_pin_to_hex(const CertificatePin& pin) { return id_to_hex(pin, "certificate pin"); }
CertificatePin certificate_pin_from_hex(std::string_view text) { return id_from_hex<32U>(text, "certificate pin"); }

std::vector<std::uint8_t> encode_terms(const TradeTerms& terms) {
    Writer writer;
    append_terms(writer, terms);
    return writer.take();
}

TradeTerms decode_terms(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    TradeTerms terms = read_terms(reader);
    reader.require_finished();
    return terms;
}


std::vector<std::uint8_t> encode_create_offer(const CreateOfferMessage& message) {
    validate_terms(message.terms);
    validate_address(message.receive_address_a);
    Writer writer;
    append_terms(writer, message.terms);
    writer.short_string(message.receive_address_a, kMaxAddressLength);
    return writer.take();
}

CreateOfferMessage decode_create_offer(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    CreateOfferMessage message;
    message.terms = read_terms(reader);
    message.receive_address_a = reader.short_string(kMaxAddressLength);
    validate_address(message.receive_address_a);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_offer_created(const OfferCreatedMessage& message) {
    validate_room_id(message.room_id);
    Writer writer;
    writer.fixed_id(message.room_id);
    return writer.take();
}

OfferCreatedMessage decode_offer_created(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    OfferCreatedMessage message{reader.fixed_id<32U>()};
    validate_room_id(message.room_id);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_list_offers(const ListOffersMessage& message) {
    if (message.limit == 0U || message.limit > kMaxOfferPageEntries) {
        throw std::invalid_argument("invalid offer page size");
    }
    if (message.has_cursor) {
        validate_room_id(message.after_room_id);
    }

    Writer writer;
    writer.u8(message.has_cursor ? 1U : 0U);
    if (message.has_cursor) {
        writer.fixed_id(message.after_room_id);
    }
    writer.u16(message.limit);
    return writer.take();
}

ListOffersMessage decode_list_offers(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    ListOffersMessage message;
    const auto cursor_flag = reader.u8();
    if (cursor_flag > 1U) {
        throw std::runtime_error("invalid offer cursor flag");
    }
    message.has_cursor = cursor_flag == 1U;
    if (message.has_cursor) {
        message.after_room_id = reader.fixed_id<32U>();
        validate_room_id(message.after_room_id);
    }
    message.limit = reader.u16();
    if (message.limit == 0U || message.limit > kMaxOfferPageEntries) {
        throw std::runtime_error("invalid offer page size");
    }
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_offer_list(const OfferListMessage& message) {
    if (message.offers.size() > kMaxOfferPageEntries) {
        throw std::invalid_argument("offer page exceeds protocol limit");
    }
    if (message.has_more) {
        validate_room_id(message.next_cursor);
        if (message.offers.empty() ||
            message.next_cursor != message.offers.back().room_id) {
            throw std::invalid_argument("invalid next offer cursor");
        }
    }

    Writer writer;
    writer.u8(message.has_more ? 1U : 0U);
    if (message.has_more) {
        writer.fixed_id(message.next_cursor);
    }
    writer.u16(static_cast<std::uint16_t>(message.offers.size()));
    for (const auto& offer : message.offers) {
        validate_room_id(offer.room_id);
        validate_terms(offer.terms);
        writer.fixed_id(offer.room_id);
        append_terms(writer, offer.terms);
    }
    return writer.take();
}

OfferListMessage decode_offer_list(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    OfferListMessage message;
    const auto more_flag = reader.u8();
    if (more_flag > 1U) {
        throw std::runtime_error("invalid offer-page continuation flag");
    }
    message.has_more = more_flag == 1U;
    if (message.has_more) {
        message.next_cursor = reader.fixed_id<32U>();
        validate_room_id(message.next_cursor);
    }

    const auto count = static_cast<std::size_t>(reader.u16());
    if (count > kMaxOfferPageEntries) {
        throw std::runtime_error("offer page exceeds protocol limit");
    }
    message.offers.reserve(count);
    for (std::size_t i = 0U; i < count; ++i) {
        OfferSummary offer;
        offer.room_id = reader.fixed_id<32U>();
        offer.terms = read_terms(reader);
        validate_room_id(offer.room_id);
        message.offers.push_back(std::move(offer));
    }
    if (message.has_more &&
        (message.offers.empty() || message.next_cursor != message.offers.back().room_id)) {
        throw std::runtime_error("invalid next offer cursor");
    }
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_join_offer(const JoinOfferMessage& message) {
    validate_room_id(message.room_id);
    validate_address(message.receive_address_b);
    Writer writer;
    writer.fixed_id(message.room_id);
    writer.short_string(message.receive_address_b, kMaxAddressLength);
    return writer.take();
}

JoinOfferMessage decode_join_offer(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    JoinOfferMessage message;
    message.room_id = reader.fixed_id<32U>();
    message.receive_address_b = reader.short_string(kMaxAddressLength);
    validate_room_id(message.room_id);
    validate_address(message.receive_address_b);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_cancel_offer(const CancelOfferMessage& message) {
    validate_room_id(message.room_id);
    Writer writer;
    writer.fixed_id(message.room_id);
    return writer.take();
}

CancelOfferMessage decode_cancel_offer(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    CancelOfferMessage message{reader.fixed_id<32U>()};
    validate_room_id(message.room_id);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_offer_cancelled(const OfferCancelledMessage& message) {
    validate_room_id(message.room_id);
    Writer writer;
    writer.fixed_id(message.room_id);
    return writer.take();
}

OfferCancelledMessage decode_offer_cancelled(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    OfferCancelledMessage message{reader.fixed_id<32U>()};
    validate_room_id(message.room_id);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_welcome(const WelcomeMessage& message) {
    validate_client_id(message.client_id);
    Writer writer;
    writer.fixed_id(message.client_id);
    append_fee_terms(writer, message.fee);
    return writer.take();
}

WelcomeMessage decode_welcome(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    WelcomeMessage message;
    message.client_id = reader.fixed_id<16U>();
    message.fee = read_fee_terms(reader);
    validate_client_id(message.client_id);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_peer_list(const PeerListMessage& message) {
    if (message.peers.size() > kMaxPeerListEntries) {
        throw std::invalid_argument("peer list exceeds protocol limit");
    }
    Writer writer;
    writer.u16(static_cast<std::uint16_t>(message.peers.size()));
    for (const auto& peer : message.peers) {
        validate_client_id(peer);
        writer.fixed_id(peer);
    }
    return writer.take();
}

PeerListMessage decode_peer_list(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    const auto count = static_cast<std::size_t>(reader.u16());
    if (count > kMaxPeerListEntries) {
        throw std::runtime_error("peer list exceeds protocol limit");
    }
    PeerListMessage message;
    message.peers.reserve(count);
    for (std::size_t i = 0U; i < count; ++i) {
        auto peer = reader.fixed_id<16U>();
        validate_client_id(peer);
        message.peers.push_back(peer);
    }
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_invite_trade(const InviteTradeMessage& message) {
    validate_client_id(message.target);
    validate_terms(message.terms);
    validate_address(message.receive_address_a);
    Writer writer;
    writer.fixed_id(message.target);
    append_terms(writer, message.terms);
    writer.short_string(message.receive_address_a, kMaxAddressLength);
    return writer.take();
}

InviteTradeMessage decode_invite_trade(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    InviteTradeMessage message;
    message.target = reader.fixed_id<16U>();
    message.terms = read_terms(reader);
    message.receive_address_a = reader.short_string(kMaxAddressLength);
    validate_client_id(message.target);
    validate_address(message.receive_address_a);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_invite_created(const InviteCreatedMessage& message) {
    validate_invite_id(message.invite_id);
    validate_client_id(message.target);
    Writer writer;
    writer.fixed_id(message.invite_id);
    writer.fixed_id(message.target);
    return writer.take();
}

InviteCreatedMessage decode_invite_created(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    InviteCreatedMessage message;
    message.invite_id = reader.fixed_id<16U>();
    message.target = reader.fixed_id<16U>();
    validate_invite_id(message.invite_id);
    validate_client_id(message.target);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_invite_received(const InviteReceivedMessage& message) {
    validate_invite_id(message.invite_id);
    validate_client_id(message.sender);
    validate_terms(message.terms);
    validate_address(message.receive_address_a);
    Writer writer;
    writer.fixed_id(message.invite_id);
    writer.fixed_id(message.sender);
    append_terms(writer, message.terms);
    writer.short_string(message.receive_address_a, kMaxAddressLength);
    return writer.take();
}

InviteReceivedMessage decode_invite_received(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    InviteReceivedMessage message;
    message.invite_id = reader.fixed_id<16U>();
    message.sender = reader.fixed_id<16U>();
    message.terms = read_terms(reader);
    message.receive_address_a = reader.short_string(kMaxAddressLength);
    validate_invite_id(message.invite_id);
    validate_client_id(message.sender);
    validate_address(message.receive_address_a);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_accept_invite(const AcceptInviteMessage& message) {
    validate_invite_id(message.invite_id);
    validate_address(message.receive_address_b);
    Writer writer;
    writer.fixed_id(message.invite_id);
    writer.short_string(message.receive_address_b, kMaxAddressLength);
    return writer.take();
}

AcceptInviteMessage decode_accept_invite(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    AcceptInviteMessage message;
    message.invite_id = reader.fixed_id<16U>();
    message.receive_address_b = reader.short_string(kMaxAddressLength);
    validate_invite_id(message.invite_id);
    validate_address(message.receive_address_b);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_decline_invite(const DeclineInviteMessage& message) {
    validate_invite_id(message.invite_id);
    Writer writer;
    writer.fixed_id(message.invite_id);
    return writer.take();
}

DeclineInviteMessage decode_decline_invite(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    DeclineInviteMessage message{reader.fixed_id<16U>()};
    validate_invite_id(message.invite_id);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_invite_declined(const InviteDeclinedMessage& message) {
    validate_invite_id(message.invite_id);
    Writer writer;
    writer.fixed_id(message.invite_id);
    return writer.take();
}

InviteDeclinedMessage decode_invite_declined(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    InviteDeclinedMessage message{reader.fixed_id<16U>()};
    validate_invite_id(message.invite_id);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_trade_ready(const TradeReadyMessage& message) {
    validate_room_id(message.room_id);
    validate_party(message.assigned_party);
    validate_client_id(message.peer_id);
    validate_terms(message.terms);
    validate_address(message.receive_address_a);
    validate_address(message.receive_address_b);
    Writer writer;
    writer.fixed_id(message.room_id);
    writer.u8(static_cast<std::uint8_t>(message.assigned_party));
    writer.fixed_id(message.peer_id);
    append_terms(writer, message.terms);
    writer.short_string(message.receive_address_a, kMaxAddressLength);
    writer.short_string(message.receive_address_b, kMaxAddressLength);
    append_fee_terms(writer, message.fee);
    return writer.take();
}

TradeReadyMessage decode_trade_ready(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    TradeReadyMessage message;
    message.room_id = reader.fixed_id<32U>();
    message.assigned_party = static_cast<Party>(reader.u8());
    message.peer_id = reader.fixed_id<16U>();
    message.terms = read_terms(reader);
    message.receive_address_a = reader.short_string(kMaxAddressLength);
    message.receive_address_b = reader.short_string(kMaxAddressLength);
    message.fee = read_fee_terms(reader);
    validate_room_id(message.room_id);
    validate_party(message.assigned_party);
    validate_client_id(message.peer_id);
    validate_address(message.receive_address_a);
    validate_address(message.receive_address_b);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_turn(const TurnMessage& message) {
    validate_room_id(message.room_id);
    validate_party(message.sender);
    validate_asset(message.asset);
    validate_address(message.destination);
    if (message.amount == 0U) {
        throw std::invalid_argument("turn amount must be positive");
    }
    Writer writer;
    writer.fixed_id(message.room_id);
    writer.u32(message.round_index);
    writer.u8(static_cast<std::uint8_t>(message.sender));
    writer.short_string(message.asset, kMaxAssetCodeLength);
    writer.u64(message.amount);
    writer.short_string(message.destination, kMaxAddressLength);
    writer.u8(message.is_fee ? 1U : 0U);
    return writer.take();
}

TurnMessage decode_turn(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    TurnMessage message;
    message.room_id = reader.fixed_id<32U>();
    message.round_index = reader.u32();
    message.sender = static_cast<Party>(reader.u8());
    message.asset = reader.short_string(kMaxAssetCodeLength);
    message.amount = reader.u64();
    message.destination = reader.short_string(kMaxAddressLength);
    message.is_fee = reader.u8() != 0U;
    validate_room_id(message.room_id);
    validate_party(message.sender);
    validate_asset(message.asset);
    validate_address(message.destination);
    if (message.amount == 0U) {
        throw std::invalid_argument("turn amount must be positive");
    }
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_round_signal(const RoundSignalMessage& message) {
    validate_room_id(message.room_id);
    validate_party(message.sender);
    Writer writer;
    writer.fixed_id(message.room_id);
    writer.u32(message.round_index);
    writer.u8(static_cast<std::uint8_t>(message.sender));
    return writer.take();
}

RoundSignalMessage decode_round_signal(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    RoundSignalMessage message;
    message.room_id = reader.fixed_id<32U>();
    message.round_index = reader.u32();
    message.sender = static_cast<Party>(reader.u8());
    validate_room_id(message.room_id);
    validate_party(message.sender);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_complete(const CompleteMessage& message) {
    validate_room_id(message.room_id);
    Writer writer;
    writer.fixed_id(message.room_id);
    return writer.take();
}

CompleteMessage decode_complete(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    CompleteMessage message{reader.fixed_id<32U>()};
    validate_room_id(message.room_id);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_abort(const AbortMessage& message) {
    validate_room_id(message.room_id);
    validate_reason(message.reason);
    Writer writer;
    writer.fixed_id(message.room_id);
    writer.short_string(message.reason, kMaxReasonLength);
    return writer.take();
}

AbortMessage decode_abort(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    AbortMessage message;
    message.room_id = reader.fixed_id<32U>();
    message.reason = reader.short_string(kMaxReasonLength);
    validate_room_id(message.room_id);
    validate_reason(message.reason);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_error(const ErrorMessage& message) {
    validate_reason(message.reason);
    Writer writer;
    writer.short_string(message.reason, kMaxReasonLength);
    return writer.take();
}

ErrorMessage decode_error(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    ErrorMessage message{reader.short_string(kMaxReasonLength)};
    validate_reason(message.reason);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_registry_register(const RegistryRegisterMessage& message) {
    Writer writer;
    append_registry_node(writer, message.node, false);
    return writer.take();
}

RegistryRegisterMessage decode_registry_register(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    RegistryRegisterMessage message{read_registry_node(reader, false)};
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_registry_registered(const RegistryRegisteredMessage& message) {
    if (message.ttl_seconds == 0U || message.ttl_seconds > kRegistryTtlSeconds) {
        throw std::invalid_argument("invalid registry TTL");
    }
    Writer writer;
    writer.u32(message.ttl_seconds);
    return writer.take();
}

RegistryRegisteredMessage decode_registry_registered(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    RegistryRegisteredMessage message{reader.u32()};
    if (message.ttl_seconds == 0U || message.ttl_seconds > kRegistryTtlSeconds) {
        throw std::runtime_error("invalid registry TTL");
    }
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_registry_nodes(const RegistryNodesMessage& message) {
    if (message.nodes.size() > kMaxRegistryNodes) {
        throw std::invalid_argument("registry node list exceeds protocol limit");
    }
    Writer writer;
    writer.u16(static_cast<std::uint16_t>(message.nodes.size()));
    for (const auto& node : message.nodes) {
        append_registry_node(writer, node, true);
    }
    return writer.take();
}

RegistryNodesMessage decode_registry_nodes(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    const auto count = static_cast<std::size_t>(reader.u16());
    if (count > kMaxRegistryNodes) {
        throw std::runtime_error("registry node list exceeds protocol limit");
    }
    RegistryNodesMessage message;
    message.nodes.reserve(count);
    for (std::size_t i = 0U; i < count; ++i) {
        message.nodes.push_back(read_registry_node(reader, true));
    }
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_recovery_state_request(const RecoveryStateRequestMessage& message) {
    validate_room_id(message.room_id);
    Writer writer;
    writer.fixed_id(message.room_id);
    return writer.take();
}

RecoveryStateRequestMessage decode_recovery_state_request(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    RecoveryStateRequestMessage message{reader.fixed_id<32U>()};
    validate_room_id(message.room_id);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_recovery_state_response(const RecoveryStateResponseMessage& message) {
    validate_room_id(message.room_id);
    if (message.leg_index > 1U) {
        throw std::invalid_argument("invalid recovery response leg index");
    }
    if (!message.reason.empty()) {
        validate_reason(message.reason);
    }

    Writer writer;
    writer.fixed_id(message.room_id);
    writer.u8(message.found ? 1U : 0U);
    if (message.found) {
        append_terms(writer, message.terms);
        append_fee_terms(writer, message.fee);
        writer.u8(message.state);
        writer.u32(message.round_index);
        writer.u8(message.leg_index);
        writer.u8(message.party_a_connected ? 1U : 0U);
        writer.u8(message.party_b_connected ? 1U : 0U);
    }
    writer.short_string(message.reason, kMaxReasonLength);
    return writer.take();
}

RecoveryStateResponseMessage decode_recovery_state_response(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    RecoveryStateResponseMessage message;
    message.room_id = reader.fixed_id<32U>();
    validate_room_id(message.room_id);

    const auto found_flag = reader.u8();
    if (found_flag > 1U) {
        throw std::runtime_error("invalid recovery response found flag");
    }
    message.found = found_flag == 1U;
    if (message.found) {
        message.terms = read_terms(reader);
        message.fee = read_fee_terms(reader);
        message.state = reader.u8();
        message.round_index = reader.u32();
        message.leg_index = reader.u8();
        if (message.leg_index > 1U) {
            throw std::runtime_error("invalid recovery response leg index");
        }
        const auto party_a_flag = reader.u8();
        const auto party_b_flag = reader.u8();
        if (party_a_flag > 1U || party_b_flag > 1U) {
            throw std::runtime_error("invalid recovery response connection flag");
        }
        message.party_a_connected = party_a_flag == 1U;
        message.party_b_connected = party_b_flag == 1U;
    }
    message.reason = reader.short_string(kMaxReasonLength);
    if (!message.reason.empty()) {
        validate_reason(message.reason);
    }
    reader.require_finished();
    return message;
}

// --- Phase 4b: counterparty recognition relay ---
//
// These functions frame and bounds-check the wire bytes only; they do not
// know what suite_id=1 means cryptographically or whether a signature
// verifies - that is recognition.hpp's job. All this layer enforces is "the
// bytes are well-formed and every fixed-size field is exactly the length
// this protocol version defines", the same posture every other encode/
// decode pair in this file already has toward its own message type.

std::vector<std::uint8_t> encode_recognition_challenge(const RecognitionChallengeMessage& message) {
    validate_room_id(message.room_id);
    if (message.expires_at <= message.created_at) {
        throw std::invalid_argument("recognition challenge expiry must be after its creation time");
    }
    Writer writer;
    writer.fixed_id(message.room_id);
    writer.u16(message.suite_id);
    writer.fixed_id(message.nonce);
    writer.u64(message.created_at);
    writer.u64(message.expires_at);
    return writer.take();
}

RecognitionChallengeMessage decode_recognition_challenge(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    RecognitionChallengeMessage message;
    message.room_id = reader.fixed_id<32U>();
    validate_room_id(message.room_id);
    message.suite_id = reader.u16();
    message.nonce = reader.fixed_id<kRecognitionNonceLength>();
    message.created_at = reader.u64();
    message.expires_at = reader.u64();
    reader.require_finished();
    if (message.expires_at <= message.created_at) {
        throw std::runtime_error("recognition challenge expiry must be after its creation time");
    }
    return message;
}

std::vector<std::uint8_t> encode_recognition_response(const RecognitionResponseMessage& message) {
    validate_room_id(message.room_id);
    Writer writer;
    writer.fixed_id(message.room_id);
    writer.fixed_id(message.nonce);
    writer.u16(message.suite_id);
    writer.bytes(message.prover_public_key, kRecognitionMaxPublicKeyLength);
    writer.bytes(message.signature, kRecognitionMaxSignatureLength);
    return writer.take();
}

RecognitionResponseMessage decode_recognition_response(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    RecognitionResponseMessage message;
    message.room_id = reader.fixed_id<32U>();
    validate_room_id(message.room_id);
    message.nonce = reader.fixed_id<kRecognitionNonceLength>();
    message.suite_id = reader.u16();
    message.prover_public_key = reader.bytes(kRecognitionMaxPublicKeyLength);
    message.signature = reader.bytes(kRecognitionMaxSignatureLength);
    reader.require_finished();
    return message;
}

// --- Phase 5: ephemeral trade identity announcement ---

std::vector<std::uint8_t> encode_trade_ephemeral_key(const TradeEphemeralKeyMessage& message) {
    validate_room_id(message.room_id);
    Writer writer;
    writer.fixed_id(message.room_id);
    writer.fixed_id(message.ephemeral_public_key);
    return writer.take();
}

TradeEphemeralKeyMessage decode_trade_ephemeral_key(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    TradeEphemeralKeyMessage message;
    message.room_id = reader.fixed_id<32U>();
    validate_room_id(message.room_id);
    message.ephemeral_public_key = reader.fixed_id<kTradeEphemeralPublicKeyLength>();
    reader.require_finished();
    return message;
}

// --- Phase 6: staged receipts ---

std::vector<std::uint8_t> encode_receipt_ack(const ReceiptAckMessage& message) {
    validate_room_id(message.room_id);
    Writer writer;
    writer.fixed_id(message.room_id);
    writer.u8(message.stage);
    writer.u64(message.timestamp);
    writer.fixed_id(message.signature);
    return writer.take();
}

ReceiptAckMessage decode_receipt_ack(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    ReceiptAckMessage message;
    message.room_id = reader.fixed_id<32U>();
    validate_room_id(message.room_id);
    message.stage = reader.u8();
    message.timestamp = reader.u64();
    message.signature = reader.fixed_id<kReceiptSignatureLength>();
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_receipt_issued(const ReceiptIssuedMessage& message) {
    validate_room_id(message.room_id);
    Writer writer;
    writer.fixed_id(message.room_id);
    writer.short_string(message.mediator_id, kReceiptWireMediatorIdLength);
    writer.u8(message.stage);
    writer.u8(message.completed ? 1U : 0U);
    writer.fixed_id(message.terms_commitment);
    writer.fixed_id(message.party_a_ephemeral_key);
    writer.fixed_id(message.party_b_ephemeral_key);
    writer.fixed_id(message.mediator_public_key);
    writer.u64(message.timestamp);
    writer.fixed_id(message.nonce);
    writer.fixed_id(message.previous_stage_hash);
    writer.fixed_id(message.mediator_signature);
    return writer.take();
}

ReceiptIssuedMessage decode_receipt_issued(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    ReceiptIssuedMessage message;
    message.room_id = reader.fixed_id<32U>();
    validate_room_id(message.room_id);
    message.mediator_id = reader.short_string(kReceiptWireMediatorIdLength);
    message.stage = reader.u8();
    const auto completed_flag = reader.u8();
    if (completed_flag > 1U) {
        throw std::runtime_error("invalid receipt completed flag");
    }
    message.completed = completed_flag == 1U;
    message.terms_commitment = reader.fixed_id<kReceiptTermsCommitmentLength>();
    message.party_a_ephemeral_key = reader.fixed_id<kReceiptPublicKeyLength>();
    message.party_b_ephemeral_key = reader.fixed_id<kReceiptPublicKeyLength>();
    message.mediator_public_key = reader.fixed_id<kReceiptPublicKeyLength>();
    message.timestamp = reader.u64();
    message.nonce = reader.fixed_id<kReceiptWireNonceLength>();
    message.previous_stage_hash = reader.fixed_id<kReceiptTermsCommitmentLength>();
    message.mediator_signature = reader.fixed_id<kReceiptSignatureLength>();
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_receipt_ack_required(const ReceiptAckRequiredMessage& message) {
    validate_room_id(message.room_id);
    Writer writer;
    writer.fixed_id(message.room_id);
    return writer.take();
}

ReceiptAckRequiredMessage decode_receipt_ack_required(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    ReceiptAckRequiredMessage message;
    message.room_id = reader.fixed_id<32U>();
    validate_room_id(message.room_id);
    reader.require_finished();
    return message;
}

std::vector<std::uint8_t> encode_fee_confirmation_pending(const FeeConfirmationPendingMessage& message) {
    validate_room_id(message.room_id);
    Writer writer;
    writer.fixed_id(message.room_id);
    return writer.take();
}

FeeConfirmationPendingMessage decode_fee_confirmation_pending(std::span<const std::uint8_t> bytes) {
    Reader reader(bytes);
    FeeConfirmationPendingMessage message;
    message.room_id = reader.fixed_id<32U>();
    validate_room_id(message.room_id);
    reader.require_finished();
    return message;
}

// --- Phase 8: selective private receipt disclosure ---

std::vector<std::uint8_t> encode_receipt_disclosure(const ReceiptDisclosureMessage& message) {
    validate_room_id(message.room_id);
    if (message.chain.size() > kDisclosureMaxChainEntries) {
        throw std::invalid_argument("disclosed receipt chain exceeds the maximum allowed length");
    }
    Writer writer;
    writer.fixed_id(message.room_id);
    writer.fixed_id(message.recipient_ephemeral_key);
    writer.fixed_id(message.disclosed_chain_hash);
    writer.u64(message.timestamp);
    writer.fixed_id(message.nonce);
    writer.fixed_id(message.signature);
    if (message.chain.size() > std::numeric_limits<std::uint8_t>::max()) {
        throw std::invalid_argument("disclosed receipt chain has too many entries to encode");
    }
    writer.u8(static_cast<std::uint8_t>(message.chain.size()));
    for (const auto& entry : message.chain) {
        const std::vector<std::uint8_t> entry_bytes = encode_receipt_issued(entry);
        writer.short_string(
            std::string(reinterpret_cast<const char*>(entry_bytes.data()), entry_bytes.size()),
            kMaxFramePayload);
    }
    auto result = writer.take();
    if (result.size() > kMaxFramePayload) {
        throw std::invalid_argument("encoded receipt disclosure exceeds the frame payload limit");
    }
    return result;
}

ReceiptDisclosureMessage decode_receipt_disclosure(std::span<const std::uint8_t> bytes) {
    if (bytes.size() > kMaxFramePayload) {
        throw std::runtime_error("receipt disclosure payload exceeds the frame payload limit");
    }
    Reader reader(bytes);
    ReceiptDisclosureMessage message;
    message.room_id = reader.fixed_id<32U>();
    validate_room_id(message.room_id);
    message.recipient_ephemeral_key = reader.fixed_id<kReceiptPublicKeyLength>();
    message.disclosed_chain_hash = reader.fixed_id<kReceiptTermsCommitmentLength>();
    message.timestamp = reader.u64();
    message.nonce = reader.fixed_id<16U>();
    message.signature = reader.fixed_id<kReceiptSignatureLength>();
    const auto count = reader.u8();
    if (count > kDisclosureMaxChainEntries) {
        throw std::runtime_error("disclosed receipt chain exceeds the maximum allowed length");
    }
    message.chain.reserve(count);
    for (std::uint8_t i = 0U; i < count; ++i) {
        const std::string entry_bytes = reader.short_string(kMaxFramePayload);
        message.chain.push_back(decode_receipt_issued(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(entry_bytes.data()), entry_bytes.size())));
    }
    reader.require_finished();
    return message;
}

} // namespace tradep2p
