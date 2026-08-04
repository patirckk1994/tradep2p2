#include "tradep2p/mediator.hpp"
#include "tradep2p/protocol.hpp"

#include <cstdint>
#include <iostream>
#include <stdexcept>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

tradep2p::RoomId room_fixture() {
    tradep2p::RoomId room{};
    room[0] = 0x42U;
    return room;
}


tradep2p::CertificatePin pin_fixture() {
    tradep2p::CertificatePin pin{};
    pin[0] = 0x77U;
    return pin;
}

tradep2p::TradeTerms terms_fixture() {
    tradep2p::TradeTerms terms;
    terms.asset_a = "BTC";
    terms.asset_b = "QRL";
    terms.total_a = 10U;
    terms.total_b = 23U;
    terms.rounds = 3U;
    terms.first_sender = tradep2p::Party::A;
    return terms;
}

void test_integer_tranches() {
    std::uint64_t sum = 0U;
    for (std::uint32_t i = 0U; i < 3U; ++i) {
        sum += tradep2p::tranche_amount(10U, 3U, i);
    }
    require(sum == 10U, "tranches must sum exactly to total");
    require(tradep2p::tranche_amount(10U, 3U, 0U) == 4U,
            "first tranche should receive remainder");
}

void test_offer_and_address_serialization() {
    const tradep2p::CreateOfferMessage original{
        terms_fixture(), "qrl-receive-address-A"};
    const auto decoded = tradep2p::decode_create_offer(
        tradep2p::encode_create_offer(original));
    require(decoded.receive_address_a == original.receive_address_a,
            "offer address serialization failed");
    require(decoded.terms.total_b == original.terms.total_b,
            "offer terms serialization failed");

    tradep2p::ListOffersMessage request;
    request.has_cursor = true;
    request.after_room_id = room_fixture();
    request.limit = 17U;
    const auto decoded_request = tradep2p::decode_list_offers(
        tradep2p::encode_list_offers(request));
    require(decoded_request.has_cursor, "offer cursor flag failed");
    require(decoded_request.after_room_id == room_fixture(),
            "offer request cursor failed");
    require(decoded_request.limit == 17U, "offer request limit failed");

    tradep2p::OfferListMessage list;
    list.offers.push_back(tradep2p::OfferSummary{room_fixture(), terms_fixture()});
    list.has_more = true;
    list.next_cursor = room_fixture();
    const auto decoded_list = tradep2p::decode_offer_list(
        tradep2p::encode_offer_list(list));
    require(decoded_list.offers.size() == 1U, "offer list count failed");
    require(decoded_list.offers[0].room_id == room_fixture(),
            "offer room id serialization failed");
    require(decoded_list.has_more && decoded_list.next_cursor == room_fixture(),
            "offer continuation cursor failed");
}


void test_registry_serialization() {
    tradep2p::RegistryNodesMessage original;
    original.nodes.push_back(tradep2p::RegistryNode{
        "node.example", 7443U, pin_fixture(), 120U});
    const auto decoded = tradep2p::decode_registry_nodes(
        tradep2p::encode_registry_nodes(original));
    require(decoded.nodes.size() == 1U, "registry node count failed");
    require(decoded.nodes[0].host == "node.example", "registry host failed");
    require(decoded.nodes[0].certificate_pin == pin_fixture(),
            "registry pin failed");
}

void acknowledge_current_turn(tradep2p::MediatorSession& session) {
    const auto turn = session.current_turn();
    const tradep2p::RoundSignalMessage signal{
        turn.room_id, turn.round_index, turn.sender};
    session.sender_reported_sent(turn.sender, signal);
    session.receiver_reported_received(
        tradep2p::other_party(turn.sender), signal);
}

void test_mediator_flow() {
    tradep2p::MediatorSession session(
        {terms_fixture(), "address-for-party-a"}, room_fixture());
    session.join({session.id(), "address-for-party-b"});

    auto turn = session.current_turn();
    require(turn.sender == tradep2p::Party::A,
            "party A should send first");
    require(turn.asset == "BTC" && turn.amount == 4U,
            "first tranche is incorrect");
    require(turn.destination == "address-for-party-b",
            "party A destination is incorrect");

    while (session.state() != tradep2p::SessionState::Complete) {
        acknowledge_current_turn(session);
    }
    require(session.round_index() == 3U,
            "all rounds must complete exactly once");
}

} // namespace

int main() {
    try {
        test_integer_tranches();
        test_offer_and_address_serialization();
        test_registry_serialization();
        test_mediator_flow();
        std::cout << "unit tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "test failure: " << error.what() << '\n';
        return 1;
    }
}
