#include "tradep2p/blindsig_client.hpp"

#include "tradep2p/blindsig_subprocess.hpp"

#include <nlohmann/json.hpp>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>

#include <unistd.h>

namespace tradep2p::blindsig {
namespace {

constexpr std::size_t kChunkPayloadSize = 65536; // well under kMaxFramePayload (131072) with headroom

std::vector<std::uint8_t> hex_to_bytes(const std::string& s) {
    if (s.size() % 2 != 0) {
        throw std::runtime_error("blindsig client: odd-length hex string");
    }
    std::vector<std::uint8_t> out(s.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(std::stoul(s.substr(i * 2, 2), nullptr, 16));
    }
    return out;
}

std::string u16_array_to_hex(const std::array<std::uint16_t, kRingDegree>& v) {
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
        throw std::runtime_error("blindsig client: expected a JSON array of length " + std::to_string(N));
    }
    std::array<T, N> out{};
    for (std::size_t i = 0; i < N; ++i) {
        out[i] = j.at(i).get<T>();
    }
    return out;
}

nlohmann::json array_to_json(const std::array<std::uint16_t, kRingDegree>& v) {
    return nlohmann::json(std::vector<std::uint16_t>(v.begin(), v.end()));
}

std::string make_temp_path(const char* label) {
    std::string path = std::string("/tmp/tradep2p-blindsig-") + label + "-XXXXXX";
    const int fd = ::mkstemp(path.data());
    if (fd < 0) {
        throw std::runtime_error(std::string("failed to create temp file: ") + std::strerror(errno));
    }
    ::close(fd); // subcommands write to this path themselves; we only need a unique reserved name
    return path;
}

std::vector<std::uint8_t> read_file_bytes(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        throw std::runtime_error("failed to open " + path);
    }
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

} // namespace

BlindSigClientSession::BlindSigClientSession(
    std::string prover_path, std::function<void(MessageType, std::vector<std::uint8_t>)> send_frame)
    : prover_path_(std::move(prover_path)), send_frame_(std::move(send_frame)) {}

BlindSigClientSession::~BlindSigClientSession() {
    if (worker_.joinable()) {
        worker_.join();
    }
}

void BlindSigClientSession::request_info() {
    stage_.store(BlindSigClientStage::kAwaitingInfo);
    send_frame_(MessageType::BlindSigInfoRequest, {});
}

void BlindSigClientSession::on_info_response(const BlindSigInfoResponse& info) {
    if (!info.enabled) {
        fail("this mediator does not have the experimental blind-signature feature enabled");
        return;
    }
    h_ = info.h;
    b_ = info.b;
    stage_.store(BlindSigClientStage::kIdle);
}

void BlindSigClientSession::start_request(std::string message) {
    if (stage_.load() != BlindSigClientStage::kIdle) {
        throw std::logic_error(
            "blindsig client session: start_request() called outside kIdle (call request_info() and wait for "
            "on_info_response() first, and only one request may be in flight per session)");
    }
    if (worker_.joinable()) {
        worker_.join();
    }
    stage_.store(BlindSigClientStage::kBlindingAndProvingNizk1);
    worker_ = std::thread(&BlindSigClientSession::run_blind_and_prove_nizk1, this, std::move(message));
}

void BlindSigClientSession::run_blind_and_prove_nizk1(std::string message) {
    try {
        const std::string b_hex = u16_array_to_hex(b_);
        const auto blind_result = run_blindsig_prover(
            prover_path_, {"user-blind", "--b-hex", b_hex, "--mu", message}, "", std::chrono::seconds(30));
        const std::string blind_stdout = require_sidecar_stdout(blind_result);
        const auto blind_json = nlohmann::json::parse(blind_stdout);
        if (!blind_json.value("ok", false)) {
            fail("user-blind failed: " + blind_json.value("error", std::string("unknown")));
            return;
        }

        mu_ = message;
        rho_hex_ = blind_json.at("public").at("rho_hex").get<std::string>();
        r_json_ = blind_json.at("private").at("r").dump();

        // user-prove-nizk1 expects exactly the {"public":...,"private":...}
        // shape user-blind already produced - passed straight through
        // (the extra "ok" field is ignored by the Rust side's serde
        // deserialization).
        const std::string pi1_path = make_temp_path("pi1");
        const auto prove_result = run_blindsig_prover(prover_path_, {"user-prove-nizk1", "--pi1-out", pi1_path},
                                                       blind_stdout, std::chrono::minutes(10));
        const std::string prove_stdout = require_sidecar_stdout(prove_result);
        const auto prove_json = nlohmann::json::parse(prove_stdout);
        if (!prove_json.value("ok", false)) {
            fail("user-prove-nizk1 failed: " + prove_json.value("error", std::string("unknown")));
            return;
        }
        pi1_path_ = pi1_path;

        BlindSigAssembledRequest assembled{};
        assembled.c = json_to_array<std::uint16_t, kRingDegree>(blind_json.at("public").at("c"));
        assembled.rho = json_to_array<std::uint8_t, 32>(
            nlohmann::json(hex_to_bytes(rho_hex_)));
        assembled.enc_a = json_to_array<std::uint16_t, kRingDegree>(blind_json.at("public").at("enc_a"));
        assembled.enc_pk = json_to_array<std::uint16_t, kRingDegree>(blind_json.at("public").at("enc_pk"));
        assembled.ct1_r = json_to_array<std::uint16_t, kRingDegree>(blind_json.at("public").at("ct1_r"));
        assembled.ct2_r = json_to_array<std::uint16_t, kRingDegree>(blind_json.at("public").at("ct2_r"));
        assembled.ct1_mu = json_to_array<std::uint16_t, kRingDegree>(blind_json.at("public").at("ct1_mu"));
        assembled.ct2_mu = json_to_array<std::uint16_t, kRingDegree>(blind_json.at("public").at("ct2_mu"));
        assembled.pi1_receipt = read_file_bytes(pi1_path);

        send_chunked(encode_blindsig_assembled_request(assembled));
        stage_.store(BlindSigClientStage::kAwaitingSignerResponse);
    } catch (const std::exception& e) {
        fail(std::string("blind/prove-nizk1 step failed: ") + e.what());
    }
}

void BlindSigClientSession::send_chunked(const std::vector<std::uint8_t>& assembled_bytes) {
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
        send_frame_(MessageType::BlindSigRequestChunk, encode_blindsig_request_chunk(chunk));
    }
}

void BlindSigClientSession::on_signer_response(const BlindSigResponse& response) {
    if (stage_.load() != BlindSigClientStage::kAwaitingSignerResponse) {
        fail("received an unexpected blind-signature response (out of sequence)");
        return;
    }
    if (response.status != BlindSigResponse::Status::Ok) {
        fail(response.reason.empty() ? "signer rejected the request" : response.reason);
        return;
    }
    if (worker_.joinable()) {
        worker_.join();
    }
    stage_.store(BlindSigClientStage::kFinalizingAndProvingNizk2);
    worker_ = std::thread(&BlindSigClientSession::run_finalize_and_verify, this, response);
}

void BlindSigClientSession::run_finalize_and_verify(BlindSigResponse response) {
    try {
        nlohmann::json finalize_request;
        finalize_request["h"] = array_to_json(h_);
        finalize_request["b"] = array_to_json(b_);
        finalize_request["rho_hex"] = rho_hex_;
        finalize_request["mu"] = mu_;
        finalize_request["r"] = nlohmann::json::parse(r_json_);
        finalize_request["s"] = nlohmann::json(std::vector<std::int16_t>(response.s.begin(), response.s.end()));

        const std::string pi2_path = make_temp_path("pi2");
        const auto finalize_result =
            run_blindsig_prover(prover_path_, {"user-finalize-prove-nizk2", "--pi2-out", pi2_path},
                                finalize_request.dump(), std::chrono::minutes(10));
        const std::string finalize_stdout = require_sidecar_stdout(finalize_result);
        const auto finalize_json = nlohmann::json::parse(finalize_stdout);
        if (!finalize_json.value("ok", false)) {
            fail("user-finalize-prove-nizk2 failed: " + finalize_json.value("error", std::string("unknown")));
            return;
        }

        stage_.store(BlindSigClientStage::kVerifyingOwnSignature);

        nlohmann::json verify_request;
        verify_request["h"] = array_to_json(h_);
        verify_request["b"] = array_to_json(b_);
        verify_request["rho_hex"] = rho_hex_;
        verify_request["mu"] = mu_;

        const auto verify_result = run_blindsig_prover(prover_path_, {"verify-signature", "--pi2-in", pi2_path},
                                                        verify_request.dump(), std::chrono::seconds(30));
        const std::string verify_stdout = require_sidecar_stdout(verify_result);
        const auto verify_json = nlohmann::json::parse(verify_stdout);
        if (!verify_json.value("ok", false) || !verify_json.value("verified", false)) {
            // This should never happen - a proof this session itself just
            // produced failing its own verification indicates a real bug,
            // not a normal rejection - see the codebase's established
            // "should never happen" phrasing for exactly this class of
            // self-consistency failure elsewhere (blindsig-prover's own
            // receipt.verify() calls right after proving).
            fail("produced a signature that failed its own verification - this should never happen, investigate");
            return;
        }

        {
            std::lock_guard<std::mutex> lock(state_mutex_);
            credential_ = BlindSigCredential{rho_hex_, pi2_path, mu_};
        }
        stage_.store(BlindSigClientStage::kReady);
    } catch (const std::exception& e) {
        fail(std::string("finalize/verify step failed: ") + e.what());
    }
}

void BlindSigClientSession::fail(const std::string& reason) {
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        last_error_ = reason;
    }
    stage_.store(BlindSigClientStage::kFailed);
}

std::string BlindSigClientSession::last_error() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return last_error_;
}

std::optional<BlindSigCredential> BlindSigClientSession::credential() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return credential_;
}

} // namespace tradep2p::blindsig
