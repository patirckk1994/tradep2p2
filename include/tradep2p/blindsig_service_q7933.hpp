#pragma once

// Mediator-facing ownership facade for the q=7933 deferred blind-signature
// path. This keeps lobby.cpp out of the NTRU/tree/ticket-store ownership
// details: one long-lived object owns the secret signing backend, durable
// ticket store, and NIZK1 verifier queue, and exposes only the operations the
// wire/admin layers need.
//
// Submission still NEVER signs inline. A verified NIZK1 request becomes a
// durable Pending ticket. Operator-approved signing is intentionally not
// exposed here yet; Phase 5 will add that narrow admin operation explicitly.

#include "tradep2p/blindsig_keystore_q7933.hpp"
#include "tradep2p/blindsig_ntru_q7933.hpp"
#include "tradep2p/blindsig_signer_q7933.hpp"
#include "tradep2p/blindsig_ticket_store_q7933.hpp"
#include "tradep2p/blindsig_wire_q7933.hpp"

#include <cstddef>
#include <memory>
#include <string>

namespace tradep2p::blindsig {

struct Q7933TicketPollResult {
    Q7933BlindSigResponse response;
    // True only for a signed ticket. The transport owner should call
    // consume_ticket() only after it has accepted the response for delivery.
    bool consume_after_delivery{false};
};

class Q7933BlindSigService {
public:
    Q7933BlindSigService(Q7933Keystore keystore,
                         std::string ticket_directory,
                         std::string prover_path,
                         std::size_t queue_capacity,
                         std::size_t worker_count = 1U);
    ~Q7933BlindSigService() = default;

    Q7933BlindSigService(const Q7933BlindSigService&) = delete;
    Q7933BlindSigService& operator=(const Q7933BlindSigService&) = delete;
    Q7933BlindSigService(Q7933BlindSigService&&) = delete;
    Q7933BlindSigService& operator=(Q7933BlindSigService&&) = delete;

    [[nodiscard]] Q7933BlindSigInfoResponse info() const;

    void submit(Q7933BlindSigAssembledRequest request,
                Q7933BlindSigReplyCallback reply);

    [[nodiscard]] Q7933TicketPollResult poll(const TicketId& ticket_id) const;

    // Idempotent durability cleanup, deliberately separate from poll():
    // callers can enqueue/send the signed response first and only then
    // consume the ticket, avoiding deletion before the delivery path has at
    // least accepted the reply.
    void consume_ticket(const TicketId& ticket_id) noexcept;

    [[nodiscard]] const std::string& ticket_directory() const noexcept;

private:
    static void signature_to_wire(const blns7933::Signature& signature,
                                  Q7933BlindSigResponse& response);

    // Declaration order is intentional: destruction runs in reverse, so the
    // verifier queue dies first, then the store, then the secret backend.
    std::unique_ptr<Q7933NTRUSigner> signer_;
    std::unique_ptr<Q7933TicketStore> ticket_store_;
    std::unique_ptr<Q7933BlindSigSigner> verifier_;
};

} // namespace tradep2p::blindsig
