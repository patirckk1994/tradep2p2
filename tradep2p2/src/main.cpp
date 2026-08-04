#include "tradep2p/lobby.hpp"
#include "tradep2p/protocol.hpp"
#include "tradep2p/registry.hpp"
#include "tradep2p/secure_channel.hpp"

#include <poll.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <csignal>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
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
using tradep2p::JoinOfferMessage;
using tradep2p::Endpoint;
using tradep2p::Frame;
using tradep2p::LobbyServer;
using tradep2p::MessageType;
using tradep2p::Party;
using tradep2p::RegistryNode;
using tradep2p::RegistryServer;
using tradep2p::RoomId;
using tradep2p::RoundSignalMessage;
using tradep2p::SecureChannel;
using tradep2p::ServerTlsIdentity;
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
        << "  /help\n"
        << "  /quit\n";
}

struct ClientState {
    std::unordered_map<std::string, Party> room_parties;
    std::unordered_map<std::string, TurnMessage> current_turns;
};

void handle_server_frame(const Frame& frame, ClientState& state) {
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
        std::cout << "\nroom ready: " << room << '\n'
                  << "  your party: " << party_name(message.assigned_party) << '\n'
                  << "  peer: " << tradep2p::client_id_to_hex(message.peer_id) << '\n'
                  << "  trade: " << message.terms.total_a << ' '
                  << message.terms.asset_a << " <-> "
                  << message.terms.total_b << ' ' << message.terms.asset_b << '\n'
                  << "  rounds: " << message.terms.rounds << '\n'
                  << "  party A receive address: " << message.receive_address_a << '\n'
                  << "  party B receive address: " << message.receive_address_b << '\n';
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
        std::cout << "room complete: " << room << '\n';
        break;
    }
    case MessageType::Abort: {
        const auto message = tradep2p::decode_abort(frame.payload);
        const std::string room = tradep2p::room_id_to_hex(message.room_id);
        state.room_parties.erase(room);
        state.current_turns.erase(room);
        std::cout << "room aborted: " << room << " - " << message.reason << '\n';
        break;
    }
    case MessageType::Error: {
        const auto message = tradep2p::decode_error(frame.payload);
        std::cout << "server rejected request: " << message.reason << '\n';
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
        channel.send_frame(
            command == "/sent" ? MessageType::Sent : MessageType::Received,
            tradep2p::encode_round_signal(signal));
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

    throw std::invalid_argument("unknown command; use /help");
}

void run_client(SecureChannel channel) {
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
                handle_server_frame(channel.receive_frame(), state);
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

void print_usage(const char* program) {
    std::cerr
        << "Usage:\n"
        << "  " << program
        << " registry <bind:port> <registry-cert.pem> <registry-key.pem>\n"
        << "  " << program
        << " nodes <registry:port> <registry-cert-sha256>\n"
        << "  " << program
        << " register-node <registry:port> <registry-cert-sha256> <node:port> <node-cert-sha256>\n"
        << "  " << program
        << " mediator <bind:port> <node-cert.pem> <node-key.pem>\n"
        << "  " << program
        << " mediator-registered <bind:port> <node-cert.pem> <node-key.pem> "
           "<registry:port> <registry-cert-sha256> <advertised-node:port> <node-cert-sha256>\n"
        << "  " << program
        << " client <node:port> <node-cert-sha256>\n"
        << "  " << program
        << " client-tor <proxy:port> <onion:port> <node-cert-sha256>\n";
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
            const auto nodes = tradep2p::list_registered_nodes(
                parse_endpoint(argv[2]), ClientTlsPolicy{argv[3]});
            std::cout << "registered mediator nodes: " << nodes.nodes.size() << '\n';
            for (const auto& node : nodes.nodes) {
                std::cout << "  " << node.host << ':' << node.port
                          << " pin=" << tradep2p::certificate_pin_to_hex(node.certificate_pin)
                          << " ttl=" << node.remaining_ttl_seconds << "s\n";
            }
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
                parse_endpoint(argv[2]), ClientTlsPolicy{argv[3]}));
        } else if (mode == "client-tor") {
            if (argc != 5) {
                throw std::invalid_argument("wrong Tor client argument count");
            }
            run_client(SecureChannel::connect_via_socks5(
                parse_endpoint(argv[2]), parse_endpoint(argv[3]),
                ClientTlsPolicy{argv[4]}));
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
