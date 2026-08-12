#include "tradep2p/blindsig_service_q7933.hpp"

#include "tradep2p/protocol.hpp"

#include <limits>
#include <stdexcept>
#include <utility>

namespace tradep2p::blindsig {
namespace {

std::string bounded_reason(std::string reason) {
    if (reason.size() > kMaxReasonLength) {
        reason.resize(kMaxReasonLength);
    }
    return reason;
}

Q7933BlindSigResponse poll_error(std::string reason) {
    Q7933BlindSigResponse response;
    response.status = Q7933BlindSigResponse::Status::Error;
    response.reason = bounded_reason(std::move(reason));
    return response;
}

} // namespace

Q7933BlindSigService::Q7933BlindSigService(Q7933Keystore keystore,
                                           std::string ticket_directory,
                                           std::string prover_path,
                                           std::size_t queue_capacity,
                                           std::size_t worker_count) {
    if (!keystore.is_unlocked()) {
        throw std::invalid_argument("q7933 service requires an unlocked keystore");
    }
    if (ticket_directory.empty()) {
        throw std::invalid_argument("q7933 service ticket directory must not be empty");
    }
    if (prover_path.empty()) {
        throw std::invalid_argument("q7933 service prover path must not be empty");
    }
    if (queue_capacity == 0U) {
        throw std::invalid_argument("q7933 service queue capacity must be positive");
    }

    // Build everything into locals first. If tree construction, store setup,
    // or worker startup throws, these locals unwind in dependency-safe order
    // and Q7933NTRUSigner/TrapdoorKey cleanse their secret coefficients.
    auto signer = std::make_unique<Q7933NTRUSigner>(keystore.trapdoor(), keystore.b());
    if (signer->public_key().t != keystore.public_key().t) {
        throw std::runtime_error(
            "q7933 service derived public key does not match unlocked keystore");
    }

    auto ticket_store = std::make_unique<Q7933TicketStore>(std::move(ticket_directory));
    auto verifier = std::make_unique<Q7933BlindSigSigner>(
        *signer, *ticket_store, std::move(prover_path), queue_capacity, worker_count);

    // The service now owns its own cleansable copy of the trapdoor. Drop the
    // keystore's duplicate immediately rather than retaining two live copies.
    keystore.lock();

    signer_ = std::move(signer);
    ticket_store_ = std::move(ticket_store);
    verifier_ = std::move(verifier);
}

Q7933BlindSigInfoResponse Q7933BlindSigService::info() const {
    return verifier_->info();
}

void Q7933BlindSigService::submit(Q7933BlindSigAssembledRequest request,
                                  Q7933BlindSigReplyCallback reply) {
    verifier_->submit(std::move(request), std::move(reply));
}

void Q7933BlindSigService::signature_to_wire(const blns7933::Signature& signature,
                                             Q7933BlindSigResponse& response) {
    if (signature.s0.size() != kQ7933RingDegree ||
        signature.s1.size() != kQ7933RingDegree) {
        throw std::runtime_error("stored q7933 signature has wrong degree");
    }

    constexpr std::int64_t kMin = std::numeric_limits<std::int16_t>::min();
    constexpr std::int64_t kMax = std::numeric_limits<std::int16_t>::max();
    for (std::size_t i = 0U; i < kQ7933RingDegree; ++i) {
        if (signature.s0[i] < kMin || signature.s0[i] > kMax ||
            signature.s1[i] < kMin || signature.s1[i] > kMax) {
            throw std::runtime_error("stored q7933 signature does not fit wire coefficient width");
        }
        response.s0[i] = static_cast<std::int16_t>(signature.s0[i]);
        response.s1[i] = static_cast<std::int16_t>(signature.s1[i]);
    }
}

Q7933TicketPollResult Q7933BlindSigService::poll(const TicketId& ticket_id) const {
    Q7933TicketPollResult result;
    try {
        const auto ticket = ticket_store_->find(ticket_id);
        if (!ticket.has_value()) {
            result.response.status = Q7933BlindSigResponse::Status::Rejected;
            result.response.reason = "unknown or already-consumed q7933 blind-signature ticket";
            return result;
        }

        if (ticket->status == TicketStatus::kPending) {
            result.response.status = Q7933BlindSigResponse::Status::Pending;
            result.response.ticket_id = ticket_id;
            return result;
        }

        if (ticket->status != TicketStatus::kSigned || !ticket->signature.has_value()) {
            result.response = poll_error("q7933 ticket store contains an invalid signed state");
            return result;
        }

        result.response.status = Q7933BlindSigResponse::Status::Ok;
        signature_to_wire(*ticket->signature, result.response);
        result.consume_after_delivery = true;
        return result;
    } catch (const std::exception& error) {
        result.response = poll_error(
            std::string("q7933 ticket poll failed: ") + error.what());
        return result;
    } catch (...) {
        result.response = poll_error("q7933 ticket poll failed: unknown exception");
        return result;
    }
}

void Q7933BlindSigService::consume_ticket(const TicketId& ticket_id) noexcept {
    ticket_store_->remove(ticket_id);
}

const std::string& Q7933BlindSigService::ticket_directory() const noexcept {
    return ticket_store_->directory();
}

} // namespace tradep2p::blindsig
