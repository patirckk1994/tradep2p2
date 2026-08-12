#pragma once

#include "tradep2p/blindsig_ticket_store_q7933.hpp"
#include "tradep2p/blindsig_wire_q7933.hpp"
#include "tradep2p/protocol.hpp"

#include <atomic>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

namespace tradep2p::blindsig {

enum class Q7933BlindSigClientStage : std::uint8_t {
    kIdle,
    kAwaitingInfo,
    kBlindingAndProvingNizk1,
    kAwaitingInitialResponse,
    kAwaitingOperatorApproval,
    kAwaitingPolledSignature,
    kFinalizingAndProvingNizk2,
    kVerifyingOwnSignature,
    kReady,
    kFailed,
};

struct Q7933BlindSigCredential {
    std::string rho_hex;
    std::string pi2_path;
    std::string mu;
};

class Q7933BlindSigClientSession {
public:
    Q7933BlindSigClientSession(
        std::string prover_path,
        std::function<void(MessageType, std::vector<std::uint8_t>)> send_frame);
    ~Q7933BlindSigClientSession();

    Q7933BlindSigClientSession(const Q7933BlindSigClientSession&) = delete;
    Q7933BlindSigClientSession& operator=(const Q7933BlindSigClientSession&) = delete;

    void request_info();
    void on_info_response(const Q7933BlindSigInfoResponse& info);
    void start_request(std::string message);
    void poll_ticket();
    void on_signer_response(const Q7933BlindSigResponse& response);

    [[nodiscard]] Q7933BlindSigClientStage stage() const { return stage_.load(); }
    [[nodiscard]] std::string last_error() const;
    [[nodiscard]] std::optional<Q7933BlindSigCredential> credential() const;
    [[nodiscard]] std::optional<TicketId> pending_ticket_id() const;

private:
    void run_blind_and_prove_nizk1(std::string message);
    void run_finalize_and_verify(Q7933BlindSigResponse response);
    void send_chunked(const std::vector<std::uint8_t>& assembled_bytes);
    void fail(const std::string& reason);

    std::string prover_path_;
    std::function<void(MessageType, std::vector<std::uint8_t>)> send_frame_;

    std::atomic<Q7933BlindSigClientStage> stage_{Q7933BlindSigClientStage::kIdle};

    mutable std::mutex state_mutex_;
    std::string last_error_;
    std::optional<Q7933BlindSigCredential> credential_;
    std::optional<TicketId> pending_ticket_id_;

    std::array<std::uint16_t, kQ7933RingDegree> t_{};
    std::array<std::uint16_t, kQ7933RingDegree> b_{};

    std::string mu_;
    std::string r_json_;
    std::string rho_hex_;
    std::string pi1_path_;

    std::thread worker_;
};

} // namespace tradep2p::blindsig
