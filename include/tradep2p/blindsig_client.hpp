#pragma once

// The client (user) side of the experimental blind-signature primitive:
// orchestrates the sidecar through the slow steps (blind -> prove NIZK1
// -> [signer round trip] -> finalize/prove NIZK2 -> verify) and hands
// wire frames to an injected send callback.
//
// Deliberately decoupled from DashboardClient/SecureChannel the same way
// BlindSigSigner is decoupled from LobbyServer::Impl::Client - this class
// owns no socket and no channel; whatever embeds it (dashboard_client.cpp
// or main.cpp's CLI REPL - still pending, see specs.txt SS9.3a) is
// responsible for calling on_info_response()/on_signer_response() when
// the corresponding frames arrive, and for actually writing whatever
// send_frame_ is called with onto the wire. This keeps this class
// buildable and testable in complete isolation from the rest of the
// networking stack.
//
// Every slow step (proving NIZK1, proving NIZK2) runs on this session's
// own background thread - none of the public methods below block the
// caller waiting for a zkVM proof.

#include "tradep2p/blindsig_wire.hpp"
#include "tradep2p/protocol.hpp" // MessageType

#include <atomic>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

namespace tradep2p::blindsig {

enum class BlindSigClientStage : std::uint8_t {
    kIdle,
    kAwaitingInfo,
    kBlindingAndProvingNizk1,
    kAwaitingSignerResponse,
    kFinalizingAndProvingNizk2,
    kVerifyingOwnSignature,
    kReady,
    kFailed,
};

struct BlindSigCredential {
    std::string rho_hex;
    std::string pi2_path; // where the NIZK2 receipt was written - the actual portable artifact is (rho, this file)
    std::string mu;
};

class BlindSigClientSession {
public:
    // `prover_path` is this CLIENT's own local blindsig-prover binary
    // (may be a different build/machine than the signer's - nothing
    // about the protocol requires them to match, only the guest ELF
    // hashes baked into both need to agree, which is a build-reproducibility
    // property outside this class's scope). `send_frame` is called
    // (from this session's background thread) whenever a frame needs to
    // go out - the embedder is responsible for actually writing it to
    // the wire.
    BlindSigClientSession(std::string prover_path,
                          std::function<void(MessageType, std::vector<std::uint8_t>)> send_frame);
    ~BlindSigClientSession();

    BlindSigClientSession(const BlindSigClientSession&) = delete;
    BlindSigClientSession& operator=(const BlindSigClientSession&) = delete;

    // Sends BlindSigInfoRequest, transitions to kAwaitingInfo.
    void request_info();

    // Call when a BlindSigInfoResponse frame arrives.
    void on_info_response(const BlindSigInfoResponse& info);

    // Starts blinding `message` and proving NIZK1 on a background thread
    // (~100-200s); once done, chunks and sends the assembled request via
    // send_frame, transitioning to kAwaitingSignerResponse. Requires a
    // prior successful on_info_response(). Throws std::logic_error if
    // called from any stage other than kIdle (after a fresh
    // request_info()/on_info_response()) - one request at a time per
    // session, matching the wire protocol's own one-in-flight-per-
    // connection scope limitation (see blindsig_wire.hpp).
    void start_request(std::string message);

    // Call when a BlindSigResponse frame arrives. If Status::Ok, starts
    // finalizing (proving NIZK2, ~100s) and then self-verifying on a
    // background thread; transitions to kReady on success. Any other
    // status transitions to kFailed with last_error() explaining why.
    void on_signer_response(const BlindSigResponse& response);

    [[nodiscard]] BlindSigClientStage stage() const { return stage_.load(); }
    [[nodiscard]] std::string last_error() const;
    [[nodiscard]] std::optional<BlindSigCredential> credential() const;

private:
    void run_blind_and_prove_nizk1(std::string message);
    void run_finalize_and_verify(BlindSigResponse response);
    void send_chunked(const std::vector<std::uint8_t>& assembled_bytes);
    void fail(const std::string& reason);

    std::string prover_path_;
    std::function<void(MessageType, std::vector<std::uint8_t>)> send_frame_;

    std::atomic<BlindSigClientStage> stage_{BlindSigClientStage::kIdle};

    mutable std::mutex state_mutex_;
    std::string last_error_;
    std::optional<BlindSigCredential> credential_;

    // Populated by on_info_response(), read by the background threads.
    std::array<std::uint16_t, kRingDegree> h_{};
    std::array<std::uint16_t, kRingDegree> b_{};

    // Populated by run_blind_and_prove_nizk1(), read by
    // run_finalize_and_verify() once the signer responds.
    std::string mu_;
    std::string r_json_; // the private witness fields (r, mu, coins_hex) as JSON, from user-blind's "private" object
    std::string rho_hex_;
    std::string pi1_path_;

    std::thread worker_;
};

} // namespace tradep2p::blindsig
