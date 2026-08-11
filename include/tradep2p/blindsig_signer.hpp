#pragma once

// The mediator (signer) side of the experimental blind-signature
// primitive: a bounded job queue + worker thread(s), matching
// snapshot_loop()/fee_plugin_loop()'s established background-thread
// shape (lobby.cpp) and the per-client outgoing-frame queue's own
// mutex+deque pattern.
//
// Deliberately decoupled from LobbyServer::Impl::Client (a private nested
// type, not exposed via any header) - submit() takes a plain callback
// instead of a client handle, so this module has zero dependency on
// lobby.cpp's internals. The actual lobby.cpp integration point wraps a
// std::shared_ptr<Client> in a lambda that calls client->enqueue(...).
//
// Per-job cost is small even though NIZK1 PROVING is slow (~200s): that
// proving happens entirely on the client's own machine, before
// submission. This signer only ever verifies an already-produced receipt
// (a fast STARK-verification operation, not proving) and does one
// falcon_sign_dyn() call (fast, not the zkVM). The bounded queue below is
// defensive - this is the first code path in this codebase's history
// that shells out to an external process - not a response to slow jobs.

#include "tradep2p/blindsig_falcon.hpp"
#include "tradep2p/blindsig_keystore.hpp"
#include "tradep2p/blindsig_wire.hpp"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace tradep2p::blindsig {

using BlindSigReplyCallback = std::function<void(const BlindSigResponse&)>;

class BlindSigSigner {
public:
    // `keystore` must already be unlocked - this signer holds it for its
    // entire lifetime and uses trapdoor()/public_key()/b() from it on
    // every job. `prover_path` is the blindsig-prover binary invoked for
    // signer-verify-nizk1. `queue_capacity` bounds concurrent in-flight
    // jobs (default-sized by the caller, see lobby.cpp's
    // configured_blindsig_queue_size()). `worker_count` is deliberately
    // small (1-2) - see file comment on why this doesn't need to be large
    // to keep up.
    BlindSigSigner(BlindSigKeystore keystore, std::string prover_path, std::size_t queue_capacity,
                   std::size_t worker_count = 1);
    ~BlindSigSigner();

    BlindSigSigner(const BlindSigSigner&) = delete;
    BlindSigSigner& operator=(const BlindSigSigner&) = delete;
    BlindSigSigner(BlindSigSigner&&) = delete;
    BlindSigSigner& operator=(BlindSigSigner&&) = delete;

    // Non-blocking: enqueues the job and returns immediately, or - if the
    // queue is already at capacity - invokes `reply` synchronously,
    // inline, with Status::Busy (no work needed for that case, so there
    // is no reason to hand it to a worker thread). Never blocks on the
    // calling (client-connection) thread waiting for a worker.
    void submit(BlindSigAssembledRequest request, BlindSigReplyCallback reply);

    // This mediator's published (h, B) - immutable for this signer's
    // entire lifetime (derived once from the keystore at construction),
    // so safe to call from any thread with no locking.
    [[nodiscard]] BlindSigInfoResponse info() const { return info_; }

private:
    struct Job {
        BlindSigAssembledRequest request;
        BlindSigReplyCallback reply;
    };

    void worker_loop();
    // The actual verify-then-sign logic for one job. Never throws - any
    // internal failure (subprocess failure, malformed sidecar output)
    // becomes a Status::Error response, never an unhandled exception
    // reaching worker_loop()'s caller.
    [[nodiscard]] BlindSigResponse process_job(const BlindSigAssembledRequest& request) noexcept;

    BlindSigKeystore keystore_;
    std::string prover_path_;
    std::size_t queue_capacity_;
    BlindSigInfoResponse info_;

    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::deque<Job> queue_;
    std::atomic<bool> running_{true};
    std::vector<std::thread> workers_;
};

} // namespace tradep2p::blindsig
