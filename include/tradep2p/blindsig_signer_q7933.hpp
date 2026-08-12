#pragma once

// q=7933 mediator-side NIZK1 verification queue.
//
// This is deliberately separate from BlindSigSigner (the q=12289/FALCON
// backend). The q=7933 protocol is deferred/operator-approved: after NIZK1
// verifies, this class stores the blinded target in Q7933TicketStore and
// replies Pending+ticket_id. It NEVER signs inline; the later admin/operator
// path is the only place that may call Q7933NTRUSigner::sign_target().
//
// The constructor receives the long-lived Q7933NTRUSigner only to copy its
// immutable public t/B into info_. It does not retain the signing backend and
// therefore cannot accidentally turn a request worker into an approval path.
// Q7933TicketStore must outlive this object.

#include "tradep2p/blindsig_ntru_q7933.hpp"
#include "tradep2p/blindsig_ticket_store_q7933.hpp"
#include "tradep2p/blindsig_wire_q7933.hpp"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace tradep2p::blindsig {

using Q7933BlindSigReplyCallback = std::function<void(const Q7933BlindSigResponse&)>;

class Q7933BlindSigSigner {
public:
    Q7933BlindSigSigner(const Q7933NTRUSigner& signer,
                        Q7933TicketStore& ticket_store,
                        std::string prover_path,
                        std::size_t queue_capacity,
                        std::size_t worker_count = 1U);
    ~Q7933BlindSigSigner();

    Q7933BlindSigSigner(const Q7933BlindSigSigner&) = delete;
    Q7933BlindSigSigner& operator=(const Q7933BlindSigSigner&) = delete;
    Q7933BlindSigSigner(Q7933BlindSigSigner&&) = delete;
    Q7933BlindSigSigner& operator=(Q7933BlindSigSigner&&) = delete;

    // Non-blocking. If the bounded queue is full, invokes `reply` inline
    // with Status::Busy and does not enqueue work.
    void submit(Q7933BlindSigAssembledRequest request,
                Q7933BlindSigReplyCallback reply);

    [[nodiscard]] Q7933BlindSigInfoResponse info() const { return info_; }

private:
    struct Job {
        Q7933BlindSigAssembledRequest request;
        Q7933BlindSigReplyCallback reply;
    };

    void worker_loop();
    [[nodiscard]] Q7933BlindSigResponse process_job(
        const Q7933BlindSigAssembledRequest& request) noexcept;

    Q7933TicketStore& ticket_store_;
    std::string prover_path_;
    std::size_t queue_capacity_;
    Q7933BlindSigInfoResponse info_;

    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::deque<Job> queue_;
    std::atomic<bool> running_{true};
    std::vector<std::thread> workers_;

    // Q7933TicketStore is disk-is-truth and intentionally has no in-memory
    // mutex. Serialize submit() calls here so worker_count>1 cannot race the
    // store's capacity check and over-admit tickets.
    std::mutex ticket_submit_mutex_;
};

} // namespace tradep2p::blindsig
