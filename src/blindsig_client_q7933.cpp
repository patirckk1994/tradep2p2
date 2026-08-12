#include "tradep2p/blindsig_client_q7933.hpp"

#include "tradep2p/blindsig_subprocess.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>

#include <unistd.h>

namespace tradep2p::blindsig {
namespace {

constexpr std::size_t kChunkPayloadSize = 65536;

std::string u16_array_to_hex(const std::array<std::uint16_t, kQ7933RingDegree>& v) {
    std::string out;
    out.reserve(v.size() * 4);
    char buf[5];
    for (auto x : v) {
        std::snprintf(buf, sizeof buf, "%04x", x);
        out += buf;
    }
    return out;
}

template <typename T, std::size_t N>
std::array<T, N> json_to_array(const nlohmann::json& j) {
    if (!j.is_array() || j.size() != N) {
        throw std::runtime_error("q7933 blindsig client: expected a JSON array of length " +
                                 std::to_string(N));
    }
    std::array<T, N> out{};
    for (std::size_t i = 0; i < N; ++i) {
        out[i] = j.at(i).get<T>();
    }
    return out;
}

nlohmann::json array_to_json(const std::array<std::uint16_t, kQ7933RingDegree>& v) {
    return nlohmann::json(std::vector<std::uint16_t>(v.begin(), v.end()));
}

template <typename T, std::size_t N>
nlohmann::json signed_array_to_json(const std::array<T, N>& v) {
    return nlohmann::json(std::vector<T>(v.begin(), v.end()));
}

std::string make_temp_path(const char* label) {
    std::string path = std::string("/tmp/tradep2p-q7933-blindsig-") + label + "-XXXXXX";
    const int fd = ::mkstemp(path.data());
    if (fd < 0) {
        throw std::runtime_error(std::string("failed to create temp file: ") + std::strerror(errno));
    }
    ::close(fd);
    return path;
}

std::vector<std::uint8_t> read_file_bytes(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        throw std::runtime_error("failed to open " + path);
    }
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in),
                                     std::istreambuf_iterator<char>());
}

} // namespace

Q7933BlindSigClientSession::Q7933BlindSigClientSession(
    std::string prover_path, std::function<void(MessageType, std::vector<std::uint8_t>)> send_frame)
    : prover_path_(std::move(prover_path)), send_frame_(std::move(send_frame)) {}

Q7933BlindSigClientSession::~Q7933BlindSigClientSession() {
    if (worker_.joinable()) {
        worker_.join();
    }
}

void Q7933BlindSigClientSession::request_info() {
    stage_.store(Q7933BlindSigClientStage::kAwaitingInfo);
    send_frame_(MessageType::Q7933BlindSigInfoRequest, {});
}

void Q7933BlindSigClientSession::on_info_response(const Q7933BlindSigInfoResponse& info) {
    if (!info.enabled) {
        fail("this mediator does not have the experimental q7933 blind-signature feature enabled");
        return;
    }
    t_ = info.t;
    b_ = info.b;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        last_error_.clear();
    }
    stage_.store(Q7933BlindSigClientStage::kIdle);
}

void Q7933BlindSigClientSession::start_request(std::string message) {
    if (stage_.load() != Q7933BlindSigClientStage::kIdle) {
        throw std::logic_error(
            "q7933 blindsig client session: start_request() called outside kIdle");
    }
    if (worker_.joinable()) {
        worker_.join();
    }
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        credential_.reset();
        pending_ticket_id_.reset();
        last_error_.clear();
    }
    stage_.store(Q7933BlindSigClientStage::kBlindingAndProvingNizk1);
    worker_ = std::thread(&Q7933BlindSigClientSession::run_blind_and_prove_nizk1, this,
                          std::move(message));
}

void Q7933BlindSigClientSession::run_blind_and_prove_nizk1(std::string message) {
    try {
        const std::string b_hex = u16_array_to_hex(b_);
        const auto blind_result = run_blindsig_prover(
            prover_path_, {"user-blind", "--b-hex", b_hex, "--mu", message}, "",
            std::chrono::seconds(30));
        const std::string blind_stdout = require_sidecar_stdout(blind_result);
        const auto blind_json = nlohmann::json::parse(blind_stdout);
        if (!blind_json.value("ok", false)) {
            fail("user-blind failed: " + blind_json.value("error", std::string("unknown")));
            return;
        }

        mu_ = message;
        rho_hex_ = blind_json.at("public").at("rho_hex").get<std::string>();
        r_json_ = blind_json.at("private").at("r").dump();

        const std::string pi1_path = make_temp_path("pi1");
        const auto prove_result = run_blindsig_prover(
            prover_path_, {"user-prove-nizk1", "--pi1-out", pi1_path}, blind_stdout,
            std::chrono::minutes(15));
        const std::string prove_stdout = require_sidecar_stdout(prove_result);
        const auto prove_json = nlohmann::json::parse(prove_stdout);
        if (!prove_json.value("ok", false)) {
            fail("user-prove-nizk1 failed: " + prove_json.value("error", std::string("unknown")));
            return;
        }
        pi1_path_ = pi1_path;

        Q7933BlindSigAssembledRequest assembled{};
        assembled.c = json_to_array<std::uint16_t, kQ7933RingDegree>(blind_json.at("public").at("c"));
        assembled.b = json_to_array<std::uint16_t, kQ7933RingDegree>(blind_json.at("public").at("b"));
        assembled.enc_a =
            json_to_array<std::uint16_t, kQ7933RingDegree>(blind_json.at("public").at("enc_a"));
        assembled.enc_pk =
            json_to_array<std::uint16_t, kQ7933RingDegree>(blind_json.at("public").at("enc_pk"));
        assembled.ct1_r =
            json_to_array<std::uint16_t, kQ7933RingDegree>(blind_json.at("public").at("ct1_r"));
        assembled.ct2_r =
            json_to_array<std::uint16_t, kQ7933RingDegree>(blind_json.at("public").at("ct2_r"));
        assembled.ct1_mu =
            json_to_array<std::uint16_t, kQ7933RingDegree>(blind_json.at("public").at("ct1_mu"));
        assembled.ct2_mu =
            json_to_array<std::uint16_t, kQ7933RingDegree>(blind_json.at("public").at("ct2_mu"));
        assembled.pi1_receipt = read_file_bytes(pi1_path);

        send_chunked(encode_q7933_blindsig_assembled_request(assembled));
        stage_.store(Q7933BlindSigClientStage::kAwaitingInitialResponse);
    } catch (const std::exception& e) {
        fail(std::string("blind/prove-nizk1 step failed: ") + e.what());
    }
}

void Q7933BlindSigClientSession::send_chunked(const std::vector<std::uint8_t>& assembled_bytes) {
    const auto total_length = static_cast<std::uint32_t>(assembled_bytes.size());
    const std::uint32_t total_chunks =
        static_cast<std::uint32_t>((assembled_bytes.size() + kChunkPayloadSize - 1) / kChunkPayloadSize);
    for (std::uint32_t i = 0; i < total_chunks; ++i) {
        const std::size_t offset = static_cast<std::size_t>(i) * kChunkPayloadSize;
        const std::size_t length = std::min(kChunkPayloadSize, assembled_bytes.size() - offset);
        BlindSigRequestChunk chunk;
        chunk.total_length = total_length;
        chunk.chunk_index = i;
        chunk.total_chunks = total_chunks;
        chunk.data.assign(assembled_bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                          assembled_bytes.begin() + static_cast<std::ptrdiff_t>(offset + length));
        send_frame_(MessageType::Q7933BlindSigRequestChunk, encode_blindsig_request_chunk(chunk));
    }
}

void Q7933BlindSigClientSession::poll_ticket() {
    std::optional<TicketId> ticket_id;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        ticket_id = pending_ticket_id_;
    }
    if (!ticket_id.has_value()) {
        throw std::logic_error("no pending q7933 blind-signature ticket to poll");
    }
    stage_.store(Q7933BlindSigClientStage::kAwaitingPolledSignature);
    send_frame_(MessageType::Q7933BlindSigTicketPoll,
                encode_q7933_blindsig_ticket_poll(Q7933BlindSigTicketPoll{*ticket_id}));
}

void Q7933BlindSigClientSession::on_signer_response(const Q7933BlindSigResponse& response) {
    const auto current = stage_.load();
    const bool initial_response = current == Q7933BlindSigClientStage::kAwaitingInitialResponse;
    const bool poll_response = current == Q7933BlindSigClientStage::kAwaitingPolledSignature ||
                               current == Q7933BlindSigClientStage::kAwaitingOperatorApproval;
    if (!initial_response && !poll_response) {
        fail("received an unexpected q7933 blind-signature response (out of sequence)");
        return;
    }
    if (response.status == Q7933BlindSigResponse::Status::Pending) {
        {
            std::lock_guard<std::mutex> lock(state_mutex_);
            pending_ticket_id_ = response.ticket_id;
            last_error_.clear();
        }
        stage_.store(Q7933BlindSigClientStage::kAwaitingOperatorApproval);
        return;
    }
    if (response.status != Q7933BlindSigResponse::Status::Ok) {
        fail(response.reason.empty() ? "q7933 signer rejected the request" : response.reason);
        return;
    }
    if (worker_.joinable()) {
        worker_.join();
    }
    stage_.store(Q7933BlindSigClientStage::kFinalizingAndProvingNizk2);
    worker_ = std::thread(&Q7933BlindSigClientSession::run_finalize_and_verify, this, response);
}

void Q7933BlindSigClientSession::run_finalize_and_verify(Q7933BlindSigResponse response) {
    try {
        nlohmann::json finalize_request;
        finalize_request["t"] = array_to_json(t_);
        finalize_request["b"] = array_to_json(b_);
        finalize_request["rho_hex"] = rho_hex_;
        finalize_request["mu"] = mu_;
        finalize_request["r"] = nlohmann::json::parse(r_json_);
        finalize_request["s0"] = signed_array_to_json(response.s0);
        finalize_request["s1"] = signed_array_to_json(response.s1);

        const std::string pi2_path = make_temp_path("pi2");
        const auto finalize_result = run_blindsig_prover(
            prover_path_, {"user-finalize-prove-nizk2", "--pi2-out", pi2_path},
            finalize_request.dump(), std::chrono::minutes(15));
        const std::string finalize_stdout = require_sidecar_stdout(finalize_result);
        const auto finalize_json = nlohmann::json::parse(finalize_stdout);
        if (!finalize_json.value("ok", false)) {
            fail("user-finalize-prove-nizk2 failed: " + finalize_json.value("error", std::string("unknown")));
            return;
        }

        stage_.store(Q7933BlindSigClientStage::kVerifyingOwnSignature);

        nlohmann::json verify_request;
        verify_request["t"] = array_to_json(t_);
        verify_request["b"] = array_to_json(b_);
        verify_request["rho_hex"] = rho_hex_;
        verify_request["mu"] = mu_;

        const auto verify_result = run_blindsig_prover(
            prover_path_, {"verify-signature", "--pi2-in", pi2_path}, verify_request.dump(),
            std::chrono::seconds(30));
        const std::string verify_stdout = require_sidecar_stdout(verify_result);
        const auto verify_json = nlohmann::json::parse(verify_stdout);
        if (!verify_json.value("ok", false) || !verify_json.value("verified", false)) {
            fail("produced a q7933 signature that failed its own verification - this should never happen, investigate");
            return;
        }

        {
            std::lock_guard<std::mutex> lock(state_mutex_);
            credential_ = Q7933BlindSigCredential{rho_hex_, pi2_path, mu_};
            pending_ticket_id_.reset();
        }
        stage_.store(Q7933BlindSigClientStage::kReady);
    } catch (const std::exception& e) {
        fail(std::string("finalize/verify step failed: ") + e.what());
    }
}

void Q7933BlindSigClientSession::fail(const std::string& reason) {
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        last_error_ = reason;
    }
    stage_.store(Q7933BlindSigClientStage::kFailed);
}

std::string Q7933BlindSigClientSession::last_error() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return last_error_;
}

std::optional<Q7933BlindSigCredential> Q7933BlindSigClientSession::credential() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return credential_;
}

std::optional<TicketId> Q7933BlindSigClientSession::pending_ticket_id() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return pending_ticket_id_;
}

} // namespace tradep2p::blindsig
