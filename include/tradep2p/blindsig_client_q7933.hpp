#pragma once

#include "tradep2p/blindsig_ticket_store_q7933.hpp"
#include "tradep2p/blindsig_wire_q7933.hpp"
#include "tradep2p/protocol.hpp"
#include "tradep2p/q7933_credential.hpp"

#include <atomic>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

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
    // Populated only for the replay-protected credential issuance path.
    // This object contains the hidden client-generated serial and therefore
    // must remain local; it is never copied into the clear issuance metadata.
    std::optional<q7933_credential::CredentialPayload> credential_payload;
};

// Produced only after `c` exists, because the party proof must be bound to
// the exact blinded target being authorized. DashboardClient supplies the
// callback that has access to the completed room's receipt and private
// ephemeral key; Q7933BlindSigClientSession never owns those keys itself.
struct Q7933CredentialIssuanceAuthorization {
    std::vector<std::uint8_t> completion_receipt;
    std::array<std::uint8_t, kReceiptSignatureLength> signature{};
    std::array<std::uint8_t, kReceiptSignatureLengthMlDsa65> signature_mldsa65{};
};

using Q7933CredentialAuthorizationProvider = std::function<Q7933CredentialIssuanceAuthorization(
    const std::array<std::uint16_t, kQ7933RingDegree>& blinded_target)>;

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

    // Raw research primitive. No room/party issuance uniqueness is attached.
    void start_request(std::string message);

    // Credential-layer path. Generates a fresh hidden 32-byte serial and
    // constructs the domain-separated credential payload used as blinded
    // `mu`. `authorization_provider` is invoked later on the worker thread,
    // after NIZK1's blinded target c has been computed; it must return the
    // completed stage-4 receipt plus a hybrid party proof bound to that c.
    void start_credential_request(
        const RoomId& completed_room_id,
        std::uint32_t credential_epoch,
        Q7933CredentialAuthorizationProvider authorization_provider);

    void poll_ticket();
    void on_signer_response(const Q7933BlindSigResponse& response);

    [[nodiscard]] Q7933BlindSigClientStage stage() const { return stage_.load(); }
    [[nodiscard]] std::string last_error() const;
    [[nodiscard]] std::optional<Q7933BlindSigCredential> credential() const;
    [[nodiscard]] std::optional<TicketId> pending_ticket_id() const;

private:
    void start_request_internal(
        std::string message,
        bool credential_issuance,
        RoomId issuance_room_id,
        std::uint32_t credential_epoch,
        std::optional<q7933_credential::CredentialPayload> credential_payload,
        Q7933CredentialAuthorizationProvider authorization_provider);
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

    bool credential_issuance_{false};
    RoomId issuance_room_id_{};
    std::uint32_t credential_epoch_{0U};
    std::optional<q7933_credential::CredentialPayload> credential_payload_;
    Q7933CredentialAuthorizationProvider credential_authorization_provider_;

    std::thread worker_;
};

} // namespace tradep2p::blindsig
