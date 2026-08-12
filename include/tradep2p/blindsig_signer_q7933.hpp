#pragma once

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
    Q7933BlindSigSigner(Q7933NTRUSigner& signer,
                        Q7933TicketStore& ticket_store,
                        std::string prover_path,
                        std::size_t queue_capacity,
                        std::size_t worker_count = 1);
    ~Q7933BlindSigSigner();

    Q7933BlindSigSigner(const Q7933BlindSigSigner&) = delete;
    Q7933BlindSigSigner& operator=(const Q7933BlindSigSigner&) = delete;
    Q7933BlindSigSigner(Q7933BlindSigSigner&&) = delete;
    Q7933BlindSigSigner& operator=(Q7933BlindSigSigner&&) = delete;

    void submit(Q7933BlindSigAssembledRequest request, Q7933BlindSigReplyCallback reply);
    [[nodiscard]] Q7933BlindSigInfoResponse info() const { return info_; }

private:
    struct Job {
        Q7933BlindSigAssembledRequest request;
        Q7933BlindSigReplyCallback reply;
    };

    void worker_loop();
    [[nodiscard]] Q7933BlindSigResponse process_job(const Q7933BlindSigAssembledRequest& request) noexcept;

    Q7933NTRUSigner* signer_;
    Q7933TicketStore* ticket_store_;
    std::string prover_path_;
    std::size_t queue_capacity_;
    Q7933BlindSigInfoResponse info_;

    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::deque<Job> queue_;
    std::atomic<bool> running_{true};
    std::vector<std::thread> workers_;
};

} // namespace tradep2p::blindsig
