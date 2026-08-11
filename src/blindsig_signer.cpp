#include "tradep2p/blindsig_signer.hpp"

#include "tradep2p/blindsig_subprocess.hpp"

#include <nlohmann/json.hpp>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <stdexcept>

#include <unistd.h>

namespace tradep2p::blindsig {
namespace {

nlohmann::json u16_array_to_json(const std::array<std::uint16_t, kRingDegree>& v) {
    return nlohmann::json(std::vector<std::uint16_t>(v.begin(), v.end()));
}

// Writes `bytes` to a fresh, uniquely-named temp file and returns its
// path - signer-verify-nizk1 reads the receipt from a file, not stdin
// (receipts run into the megabytes; stdin is reserved for the small
// expected-fields JSON). Throws std::runtime_error on failure.
std::string write_temp_receipt(std::span<const std::uint8_t> bytes) {
    std::string path = "/tmp/tradep2p-blindsig-verify-XXXXXX";
    const int fd = ::mkstemp(path.data());
    if (fd < 0) {
        throw std::runtime_error(std::string("failed to create temp file for receipt: ") + std::strerror(errno));
    }
    std::size_t written = 0U;
    while (written < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.data() + written, bytes.size() - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            ::close(fd);
            ::unlink(path.c_str());
            throw std::runtime_error(std::string("failed to write temp receipt file: ") + std::strerror(errno));
        }
        written += static_cast<std::size_t>(n);
    }
    ::close(fd);
    return path;
}

struct TempFileGuard {
    std::string path;
    ~TempFileGuard() {
        if (!path.empty()) {
            ::unlink(path.c_str());
        }
    }
};

} // namespace

BlindSigSigner::BlindSigSigner(BlindSigKeystore keystore, std::string prover_path, std::size_t queue_capacity,
                               std::size_t worker_count)
    : keystore_(std::move(keystore)), prover_path_(std::move(prover_path)), queue_capacity_(queue_capacity) {
    info_.enabled = true;
    info_.h = keystore_.public_key().h;
    info_.b = keystore_.b();

    workers_.reserve(worker_count == 0 ? 1 : worker_count);
    for (std::size_t i = 0; i < (worker_count == 0 ? 1 : worker_count); ++i) {
        workers_.emplace_back(&BlindSigSigner::worker_loop, this);
    }
}

BlindSigSigner::~BlindSigSigner() {
    running_.store(false);
    queue_cv_.notify_all();
    for (auto& t : workers_) {
        if (t.joinable()) {
            t.join();
        }
    }
}

void BlindSigSigner::submit(BlindSigAssembledRequest request, BlindSigReplyCallback reply) {
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        if (queue_.size() >= queue_capacity_) {
            lock.unlock();
            BlindSigResponse busy;
            busy.status = BlindSigResponse::Status::Busy;
            busy.reason = "blind-signature signer is at capacity, try again shortly";
            reply(busy);
            return;
        }
        queue_.push_back(Job{std::move(request), std::move(reply)});
    }
    queue_cv_.notify_one();
}

void BlindSigSigner::worker_loop() {
    while (true) {
        Job job;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this] { return !queue_.empty() || !running_.load(); });
            if (queue_.empty()) {
                if (!running_.load()) {
                    return;
                }
                continue;
            }
            job = std::move(queue_.front());
            queue_.pop_front();
        }
        // process_job() is noexcept - a bad job can never take this
        // thread down, matching fee_plugin_loop()'s catch-and-log
        // discipline (see that function's own comment in lobby.cpp).
        const BlindSigResponse response = process_job(job.request);
        job.reply(response);
    }
}

BlindSigResponse BlindSigSigner::process_job(const BlindSigAssembledRequest& request) noexcept {
    try {
        const std::string receipt_path = write_temp_receipt(request.pi1_receipt);
        TempFileGuard guard{receipt_path};

        // The critical correctness property: `b` here comes from THIS
        // signer's OWN keystore, never from the client's request (which
        // doesn't even carry a `b` field - see BlindSigAssembledRequest).
        // A verified:true result therefore can only mean the receipt
        // committed to THIS signer's own B, not one the client merely
        // claims - a client cannot get a valid proof for one (c,B) and
        // submit a different one to be signed.
        nlohmann::json expected;
        expected["b"] = u16_array_to_json(keystore_.b());
        expected["c"] = u16_array_to_json(request.c);
        expected["enc_a"] = u16_array_to_json(request.enc_a);
        expected["enc_pk"] = u16_array_to_json(request.enc_pk);
        expected["ct1_r"] = u16_array_to_json(request.ct1_r);
        expected["ct2_r"] = u16_array_to_json(request.ct2_r);
        expected["ct1_mu"] = u16_array_to_json(request.ct1_mu);
        expected["ct2_mu"] = u16_array_to_json(request.ct2_mu);

        const auto verify_result = run_blindsig_prover(
            prover_path_, {"signer-verify-nizk1", "--pi1-in", receipt_path}, expected.dump(),
            std::chrono::seconds(30));
        const std::string stdout_text = require_sidecar_stdout(verify_result);
        const auto parsed = nlohmann::json::parse(stdout_text);

        if (!parsed.value("ok", false)) {
            BlindSigResponse response;
            response.status = BlindSigResponse::Status::Error;
            response.reason = "signer-verify-nizk1 tool error: " + parsed.value("error", std::string("unknown"));
            return response;
        }
        if (!parsed.value("verified", false)) {
            BlindSigResponse response;
            response.status = BlindSigResponse::Status::Rejected;
            response.reason = parsed.value("reason", std::string("NIZK1 did not verify"));
            return response;
        }

        // NIZK1 verified against THIS signer's own published values -
        // safe to sign. This is the fast operation (real Gaussian
        // preimage sampling, not a zkVM proof) - see file comment.
        const auto sig = falcon_sign_dyn(keystore_.trapdoor(), request.c);

        BlindSigResponse response;
        response.status = BlindSigResponse::Status::Ok;
        response.s = sig;
        return response;
    } catch (const std::exception& e) {
        BlindSigResponse response;
        response.status = BlindSigResponse::Status::Error;
        response.reason = std::string("internal error: ") + e.what();
        return response;
    } catch (...) {
        BlindSigResponse response;
        response.status = BlindSigResponse::Status::Error;
        response.reason = "internal error: unknown exception";
        return response;
    }
}

} // namespace tradep2p::blindsig
