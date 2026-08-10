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

void test_candle_serialization() {
    tradep2p::GetCandlesMessage request;
    request.asset_a = "BTC";
    request.asset_b = "QRL";
    const auto decoded_request = tradep2p::decode_get_candles(
        tradep2p::encode_get_candles(request));
    require(decoded_request.asset_a == "BTC" && decoded_request.asset_b == "QRL",
            "candle request asset serialization failed");

    tradep2p::CandleDataMessage data;
    data.base_asset = "BTC";
    data.quote_asset = "QRL";
    data.ticks.push_back(tradep2p::TradeTick{1000U, 10U, 230U});
    data.ticks.push_back(tradep2p::TradeTick{2000U, 5U, 120U});
    const auto decoded_data = tradep2p::decode_candle_data(
        tradep2p::encode_candle_data(data));
    require(decoded_data.base_asset == "BTC" && decoded_data.quote_asset == "QRL",
            "candle data pair serialization failed");
    require(decoded_data.ticks.size() == 2U, "candle tick count failed");
    require(decoded_data.ticks[0].timestamp == 1000U &&
                decoded_data.ticks[0].base_amount == 10U &&
                decoded_data.ticks[0].quote_amount == 230U,
            "candle tick fields failed");
    require(decoded_data.ticks[1].timestamp == 2000U, "second candle tick failed");

    bool threw = false;
    try {
        tradep2p::CandleDataMessage zero;
        zero.base_asset = "BTC";
        zero.quote_asset = "QRL";
        zero.ticks.push_back(tradep2p::TradeTick{1000U, 0U, 230U});
        (void)tradep2p::encode_candle_data(zero);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "a zero-amount candle tick must be rejected");
}

void test_registry_serialization() {
    tradep2p::RegistryNodesMessage original;
    original.nodes.push_back(tradep2p::RegistryNode{
        "node.example", 7443U, pin_fixture(), 120U, ""});
    original.nodes.push_back(tradep2p::RegistryNode{
        "gossiped.example", 7444U, pin_fixture(), 90U, "peer-registry.example:7555"});
    const auto decoded = tradep2p::decode_registry_nodes(
        tradep2p::encode_registry_nodes(original));
    require(decoded.nodes.size() == 2U, "registry node count failed");
    require(decoded.nodes[0].host == "node.example", "registry host failed");
    require(decoded.nodes[0].certificate_pin == pin_fixture(),
            "registry pin failed");
    require(decoded.nodes[0].source_registry.empty(),
            "a direct registration must round-trip an empty source_registry");
    require(decoded.nodes[1].source_registry == "peer-registry.example:7555",
            "a gossip-learned node must round-trip its source_registry");

    // source_registry only ever means something in a listing - a
    // RegistryRegisterMessage (registration request) must reject a
    // registrant trying to set it themselves.
    bool threw = false;
    try {
        tradep2p::RegistryNode node{"node.example", 7443U, pin_fixture(), 0U, "spoofed.example:1"};
        (void)tradep2p::encode_registry_register(tradep2p::RegistryRegisterMessage{node});
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "a registration request must reject a non-empty source_registry");
}

void acknowledge_current_turn(tradep2p::MediatorSession& session) {
    // Phase 6 (docs/identity-06-receipts.md, "the withholding fix"): the
    // leg immediately before the trade's actual final tranche is gated
    // behind SessionState::WaitingForFinalReceiptAck - see mediator.hpp.
    // Callers of this helper drive a room by repeatedly calling it until a
    // target state is reached; transparently passing both parties'
    // acknowledgement through the gate here keeps every existing call site
    // below black-box correct without needing to know about the gate
    // itself - see tests/receipt_tests.cpp for tests that exercise the gate
    // directly (including what happens when only one party acks).
    if (session.state() == tradep2p::SessionState::WaitingForFinalReceiptAck) {
        session.acknowledge_final_receipt(tradep2p::Party::A);
        session.acknowledge_final_receipt(tradep2p::Party::B);
        return;
    }
    const auto turn = session.current_turn();
    const tradep2p::RoundSignalMessage signal{
        turn.room_id, turn.round_index, turn.sender};
    session.sender_reported_sent(turn.sender, signal);
    session.receiver_reported_received(
        tradep2p::other_party(turn.sender), signal);
}

void test_mediator_flow() {
    tradep2p::MediatorSession session(
        {terms_fixture(), "address-for-party-a"}, room_fixture(),
        tradep2p::FeeTerms{});
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

void test_mediator_fee_flow() {
    const tradep2p::FeeTerms fee{"BTC", 7U, "mediator-fee-address"};
    tradep2p::MediatorSession session(
        {terms_fixture(), "address-for-party-a"}, room_fixture(), fee);
    session.join({session.id(), "address-for-party-b"});

    while (session.state() != tradep2p::SessionState::WaitingForFeeSent) {
        acknowledge_current_turn(session);
    }

    const auto fee_turn = session.current_turn();
    require(fee_turn.sender == tradep2p::Party::A,
            "the offer creator must settle the mediator fee");
    require(fee_turn.asset == fee.asset && fee_turn.amount == fee.amount &&
                fee_turn.destination == fee.address,
            "fee turn does not match configured fee terms");

    const tradep2p::RoundSignalMessage fee_signal{
        fee_turn.room_id, fee_turn.round_index, fee_turn.sender};
    session.sender_reported_sent(tradep2p::Party::A, fee_signal);
    require(session.state() == tradep2p::SessionState::Complete,
            "reporting the fee as sent should complete the room directly");
}

void test_mediator_fee_before_first_round() {
    const tradep2p::FeeTerms fee{"BTC", 7U, "mediator-fee-address"};
    tradep2p::MediatorSession session(
        {terms_fixture(), "address-for-party-a"}, room_fixture(), fee,
        /*require_fee_confirmation=*/false, tradep2p::FeePosition::BeforeFirstRound);
    session.join({session.id(), "address-for-party-b"});

    require(session.state() == tradep2p::SessionState::WaitingForFeeSent,
            "fee should be due immediately after join for BeforeFirstRound");
    const auto fee_turn = session.current_turn();
    require(fee_turn.is_fee, "fee turn must be marked is_fee");
    require(fee_turn.asset == fee.asset && fee_turn.amount == fee.amount &&
                fee_turn.destination == fee.address,
            "fee turn does not match configured fee terms");
    require(fee_turn.round_index == 0U, "fee before the first round sits at round_index 0");

    const tradep2p::RoundSignalMessage fee_signal{
        fee_turn.room_id, fee_turn.round_index, fee_turn.sender};
    session.sender_reported_sent(tradep2p::Party::A, fee_signal);
    require(session.state() == tradep2p::SessionState::WaitingForSent,
            "paying an early fee must resume real trading, not complete the room");

    while (session.state() != tradep2p::SessionState::Complete) {
        if (session.state() != tradep2p::SessionState::WaitingForFinalReceiptAck) {
            require(!session.current_turn().is_fee, "no second fee turn should ever appear");
        }
        acknowledge_current_turn(session);
    }
    require(session.round_index() == 3U, "all rounds must still complete exactly once");
}

void test_mediator_fee_before_last_round() {
    const tradep2p::FeeTerms fee{"BTC", 7U, "mediator-fee-address"};
    tradep2p::MediatorSession session(
        {terms_fixture(), "address-for-party-a"}, room_fixture(), fee,
        /*require_fee_confirmation=*/false, tradep2p::FeePosition::BeforeLastRound);
    session.join({session.id(), "address-for-party-b"});
    require(session.state() == tradep2p::SessionState::WaitingForSent,
            "3-round trade must not owe the fee before round 0 for BeforeLastRound");

    // Drive rounds 0 and 1 (indices 0,1) normally - the fee must not appear yet.
    while (session.round_index() < 2U) {
        const auto turn = session.current_turn();
        require(!turn.is_fee, "fee must not appear before the last round");
        acknowledge_current_turn(session);
    }

    require(session.state() == tradep2p::SessionState::WaitingForFeeSent,
            "fee must be due exactly when the last round (index 2) is about to start");
    const auto fee_turn = session.current_turn();
    require(fee_turn.is_fee, "fee turn must be marked is_fee");
    require(fee_turn.round_index == 2U, "fee before the last round sits at that round's index");

    const tradep2p::RoundSignalMessage fee_signal{
        fee_turn.room_id, fee_turn.round_index, fee_turn.sender};
    session.sender_reported_sent(tradep2p::Party::A, fee_signal);
    require(session.state() == tradep2p::SessionState::WaitingForSent,
            "paying the fee before the last round must resume trading for that round");

    while (session.state() != tradep2p::SessionState::Complete) {
        if (session.state() != tradep2p::SessionState::WaitingForFinalReceiptAck) {
            require(!session.current_turn().is_fee, "no second fee turn should ever appear");
        }
        acknowledge_current_turn(session);
    }
    require(session.round_index() == 3U, "all rounds must still complete exactly once");
}

void test_mediator_fee_before_last_round_single_round_matches_before_first() {
    tradep2p::TradeTerms terms = terms_fixture();
    terms.rounds = 1U;
    const tradep2p::FeeTerms fee{"BTC", 7U, "mediator-fee-address"};
    tradep2p::MediatorSession session(
        {terms, "address-for-party-a"}, room_fixture(), fee,
        /*require_fee_confirmation=*/false, tradep2p::FeePosition::BeforeLastRound);
    session.join({session.id(), "address-for-party-b"});
    require(session.state() == tradep2p::SessionState::WaitingForFeeSent,
            "with only one round, BeforeLastRound must degenerate to before that round");
}

void test_mediator_fee_confirmation_with_early_position() {
    const tradep2p::FeeTerms fee{"BTC", 7U, "mediator-fee-address"};
    tradep2p::MediatorSession session(
        {terms_fixture(), "address-for-party-a"}, room_fixture(), fee,
        /*require_fee_confirmation=*/true, tradep2p::FeePosition::BeforeFirstRound);
    session.join({session.id(), "address-for-party-b"});

    const auto fee_turn = session.current_turn();
    const tradep2p::RoundSignalMessage fee_signal{
        fee_turn.room_id, fee_turn.round_index, fee_turn.sender};
    session.sender_reported_sent(tradep2p::Party::A, fee_signal);
    require(session.state() == tradep2p::SessionState::WaitingForFeeConfirmation,
            "an early fee with confirmation required must still park for confirmation");

    session.confirm_fee_received();
    require(session.state() == tradep2p::SessionState::WaitingForSent,
            "confirming an early fee must resume trading, not complete the room");

    while (session.state() != tradep2p::SessionState::Complete) {
        acknowledge_current_turn(session);
    }
    require(session.round_index() == 3U, "all rounds must still complete exactly once");
}

} // namespace

int main() {
    try {
        test_integer_tranches();
        test_offer_and_address_serialization();
        test_candle_serialization();
        test_registry_serialization();
        test_mediator_flow();
        test_mediator_fee_flow();
        test_mediator_fee_before_first_round();
        test_mediator_fee_before_last_round();
        test_mediator_fee_before_last_round_single_round_matches_before_first();
        test_mediator_fee_confirmation_with_early_position();
        std::cout << "unit tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "test failure: " << error.what() << '\n';
        return 1;
    }
}
