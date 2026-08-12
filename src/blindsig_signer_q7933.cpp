#include "tradep2p/blindsig_signer_q7933.hpp"

#include "tradep2p/blindsig_subprocess.hpp"

#include <nlohmann/json.hpp>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <span>
#include <stdexcept>

#include <unistd.h>

namespace tradep2p::blindsig {
namespace {

using tradep2p::blns7933::PolyQ;

nlohmann::json poly_to_json(const PolyQ& value) {
    return nlohmann::json(std::vector<std::int64_t>(value.begin(), value.end()));
}

template <typename T, std::size_t N>
std::array<T, N> poly_to_array(const PolyQ& value, const char* field_name) {
    if (value.size() != N) {
        throw std::runtime_error(std::string(field_name) + " has unexpected degree");
    }
    std::array<T, N> result{};
    for (std::size_t index = 0; index < N; ++index) {
        const auto coefficient = value[index];
        if (coefficient < static_cast<std::int64_t>(std::numeric_limits<T>::min()) ||
            coefficient > static_cast<std::int64_t>(std::numeric_limits<T>::max())) {
            throw std::runtime_error(std::string(field_name) + " coefficient exceeds wire range");
        }
        result[index] = static_cast<T>(coefficient);
    }
    return result;
}

PolyQ array_to_poly(const std::array<std::uint16_t, kQ7933RingDegree>& value) {
    PolyQ result;
    result.reserve(value.size());
    for (const auto coefficient : value) {
        result.push_back(static_cast<std::int64_t>(coefficient));
    }
    return result;
}

std::string write_temp_receipt(std::span<const std::uint8_t> bytes) {
    std::string path = "/tmp/tradep2p-q7933-verify-XXXXXX";
    const int fd = ::mkstemp(path.data());
    if (fd < 0) {
        throw std::runtime_error(std::string("failed to create temp file for q7933 receipt: ") +
                                 std::strerror(errno));
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
            throw std::runtime_error(std::string("failed to write q7933 temp receipt file: ") +
                                     std::strerror(errno));
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

Q7933BlindSigSigner::Q7933BlindSigSigner(Q7933NTRUSigner& signer,
                                         Q7933TicketStore& ticket_store,
                                         std::string prover_path,
                                         std::size_t queue_capacity,
                                         std::size_t worker_count)
    : signer_(&signer),
      ticket_store_(&ticket_store),
      prover_path_(std::move(prover_path)),
      queue_capacity_(queue_capacity) {
    info_.enabled = true;
    info_.t = poly_to_array<std::uint16_t, kQ7933RingDegree>(signer_->public_key().t, "q7933 public key t");
    info_.b = poly_to_array<std::uint16_t, kQ7933RingDegree>(signer_->b(), "q7933 blinding element b");

    workers_.reserve(worker_count == 0 ? 1 : worker_count);
    for (std::size_t index = 0; index < (worker_count == 0 ? 1 : worker_count); ++index) {
        workers_.emplace_back(&Q7933BlindSigSigner::worker_loop, this);
    }
}

Q7933BlindSigSigner::~Q7933BlindSigSigner() {
    running_.store(false);
    queue_cv_.notify_all();
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

void Q7933BlindSigSigner::submit(Q7933BlindSigAssembledRequest request,
                                 Q7933BlindSigReplyCallback reply) {
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        if (queue_.size() >= queue_capacity_) {
            lock.unlock();
            Q7933BlindSigResponse busy;
            busy.status = Q7933BlindSigResponse::Status::Busy;
            busy.reason = "q7933 blind-signature signer is at capacity, try again shortly";
            reply(busy);
            return;
        }
        queue_.push_back(Job{std::move(request), std::move(reply)});
    }
    queue_cv_.notify_one();
}

void Q7933BlindSigSigner::worker_loop() {
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
        const Q7933BlindSigResponse response = process_job(job.request);
        job.reply(response);
    }
}

Q7933BlindSigResponse Q7933BlindSigSigner::process_job(
    const Q7933BlindSigAssembledRequest& request) noexcept {
    try {
        const std::string receipt_path = write_temp_receipt(request.pi1_receipt);
        TempFileGuard guard{receipt_path};

        nlohmann::json expected;
        expected["b"] = poly_to_json(signer_->b());
        expected["c"] = poly_to_json(array_to_poly(request.c));
        expected["enc_a"] = poly_to_json(array_to_poly(request.enc_a));
        expected["enc_pk"] = poly_to_json(array_to_poly(request.enc_pk));
        expected["ct1_r"] = poly_to_json(array_to_poly(request.ct1_r));
        expected["ct2_r"] = poly_to_json(array_to_poly(request.ct2_r));
        expected["ct1_mu"] = poly_to_json(array_to_poly(request.ct1_mu));
        expected["ct2_mu"] = poly_to_json(array_to_poly(request.ct2_mu));

        const auto verify_result = run_blindsig_prover(
            prover_path_, {"signer-verify-nizk1", "--pi1-in", receipt_path}, expected.dump(),
            std::chrono::seconds(30));
        const std::string stdout_text = require_sidecar_stdout(verify_result);
        const auto parsed = nlohmann::json::parse(stdout_text);

        if (!parsed.value("ok", false)) {
            Q7933BlindSigResponse response;
            response.status = Q7933BlindSigResponse::Status::Error;
            response.reason = "signer-verify-nizk1 tool error: " +
                              parsed.value("error", std::string("unknown"));
            return response;
        }
        if (!parsed.value("verified", false)) {
            Q7933BlindSigResponse response;
            response.status = Q7933BlindSigResponse::Status::Rejected;
            response.reason = parsed.value("reason", std::string("NIZK1 did not verify"));
            return response;
        }

        Q7933BlindSigResponse response;
        response.status = Q7933BlindSigResponse::Status::Pending;
        response.ticket_id = ticket_store_->submit(array_to_poly(request.c));
        return response;
    } catch (const Q7933TicketStoreFullError& error) {
        Q7933BlindSigResponse response;
        response.status = Q7933BlindSigResponse::Status::Busy;
        response.reason = error.what();
        return response;
    } catch (const std::exception& error) {
        Q7933BlindSigResponse response;
        response.status = Q7933BlindSigResponse::Status::Error;
        response.reason = std::string("internal error: ") + error.what();
        return response;
    } catch (...) {
        Q7933BlindSigResponse response;
        response.status = Q7933BlindSigResponse::Status::Error;
        response.reason = "internal error: unknown exception";
        return response;
    }
}

} // namespace tradep2p::blindsig
