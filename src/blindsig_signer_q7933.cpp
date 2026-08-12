#include "tradep2p/blindsig_signer_q7933.hpp"

#include "tradep2p/blindsig_subprocess.hpp"
#include "tradep2p/protocol.hpp"

#include <nlohmann/json.hpp>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>

#include <unistd.h>

namespace tradep2p::blindsig {
namespace {

constexpr std::int64_t kQ7933Modulus = blns7933::Parameters::modulus;

std::string bounded_reason(std::string text) {
    if (text.size() > kMaxReasonLength) {
        text.resize(kMaxReasonLength);
    }
    return text;
}

nlohmann::json u16_array_to_json(
    const std::array<std::uint16_t, kQ7933RingDegree>& value) {
    return nlohmann::json(std::vector<std::uint16_t>(value.begin(), value.end()));
}

std::array<std::uint16_t, kQ7933RingDegree> poly_to_wire(
    const blns7933::PolyQ& value, const char* field_name) {
    if (value.size() != kQ7933RingDegree) {
        throw std::invalid_argument(std::string("q7933 signer: ") + field_name +
                                    " has wrong degree");
    }
    std::array<std::uint16_t, kQ7933RingDegree> out{};
    for (std::size_t i = 0U; i < value.size(); ++i) {
        if (value[i] < 0 || value[i] >= kQ7933Modulus) {
            throw std::invalid_argument(std::string("q7933 signer: ") + field_name +
                                        " contains a non-canonical coefficient");
        }
        out[i] = static_cast<std::uint16_t>(value[i]);
    }
    return out;
}

blns7933::PolyQ wire_to_poly(
    const std::array<std::uint16_t, kQ7933RingDegree>& value) {
    blns7933::PolyQ out;
    out.reserve(value.size());
    for (const auto coeff : value) {
        out.push_back(static_cast<std::int64_t>(coeff));
    }
    return out;
}

std::optional<std::string> first_noncanonical_field(
    const Q7933BlindSigAssembledRequest& request) {
    const auto check = [](const auto& value, const char* name) -> std::optional<std::string> {
        for (std::size_t i = 0U; i < value.size(); ++i) {
            if (static_cast<std::int64_t>(value[i]) >= kQ7933Modulus) {
                return std::string(name) + " contains a non-canonical q=7933 coefficient";
            }
        }
        return std::nullopt;
    };

    if (auto reason = check(request.b, "b")) return reason;
    if (auto reason = check(request.c, "c")) return reason;
    if (auto reason = check(request.enc_a, "enc_a")) return reason;
    if (auto reason = check(request.enc_pk, "enc_pk")) return reason;
    if (auto reason = check(request.ct1_r, "ct1_r")) return reason;
    if (auto reason = check(request.ct2_r, "ct2_r")) return reason;
    if (auto reason = check(request.ct1_mu, "ct1_mu")) return reason;
    if (auto reason = check(request.ct2_mu, "ct2_mu")) return reason;
    return std::nullopt;
}

// signer-verify-nizk1 consumes the receipt from a file because receipts are
// megabytes; stdin remains the small expected-fields JSON object.
std::string write_temp_receipt(std::span<const std::uint8_t> bytes) {
    std::string path = "/tmp/tradep2p-blindsig-q7933-verify-XXXXXX";
    const int fd = ::mkstemp(path.data());
    if (fd < 0) {
        throw std::runtime_error(std::string("failed to create q7933 receipt temp file: ") +
                                 std::strerror(errno));
    }

    std::size_t written = 0U;
    while (written < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.data() + written, bytes.size() - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            const int saved_errno = errno;
            ::close(fd);
            ::unlink(path.c_str());
            throw std::runtime_error(std::string("failed to write q7933 receipt temp file: ") +
                                     std::strerror(saved_errno));
        }
        written += static_cast<std::size_t>(n);
    }
    if (::close(fd) != 0) {
        const int saved_errno = errno;
        ::unlink(path.c_str());
        throw std::runtime_error(std::string("failed to close q7933 receipt temp file: ") +
                                 std::strerror(saved_errno));
    }
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

Q7933BlindSigResponse error_response(std::string reason) {
    Q7933BlindSigResponse response;
    response.status = Q7933BlindSigResponse::Status::Error;
    response.reason = bounded_reason(std::move(reason));
    return response;
}

Q7933BlindSigResponse rejected_response(std::string reason) {
    Q7933BlindSigResponse response;
    response.status = Q7933BlindSigResponse::Status::Rejected;
    response.reason = bounded_reason(std::move(reason));
    return response;
}

} // namespace

Q7933BlindSigSigner::Q7933BlindSigSigner(const Q7933NTRUSigner& signer,
                                         Q7933TicketStore& ticket_store,
                                         std::string prover_path,
                                         std::size_t queue_capacity,
                                         std::size_t worker_count)
    : ticket_store_(ticket_store),
      prover_path_(std::move(prover_path)),
      queue_capacity_(queue_capacity) {
    if (prover_path_.empty()) {
        throw std::invalid_argument("q7933 signer: prover path must not be empty");
    }
    if (queue_capacity_ == 0U) {
        throw std::invalid_argument("q7933 signer: queue capacity must be positive");
    }
    if (signer.degree() != kQ7933RingDegree || signer.modulus() != kQ7933Modulus) {
        throw std::invalid_argument("q7933 signer: backend is not the production d=512,q=7933 instance");
    }

    info_.enabled = true;
    info_.t = poly_to_wire(signer.public_key().t, "public key t");
    info_.b = poly_to_wire(signer.b(), "B");

    const std::size_t actual_worker_count = worker_count == 0U ? 1U : worker_count;
    workers_.reserve(actual_worker_count);
    try {
        for (std::size_t i = 0U; i < actual_worker_count; ++i) {
            workers_.emplace_back(&Q7933BlindSigSigner::worker_loop, this);
        }
    } catch (...) {
        running_.store(false);
        queue_cv_.notify_all();
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        throw;
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
    if (!reply) {
        throw std::invalid_argument("q7933 signer: reply callback must not be empty");
    }

    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        if (queue_.size() >= queue_capacity_) {
            lock.unlock();
            Q7933BlindSigResponse response;
            response.status = Q7933BlindSigResponse::Status::Busy;
            response.reason = "q7933 blind-signature verifier is at capacity; try again later";
            reply(response);
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
        // A callback is integration glue (normally Client::enqueue + wire
        // encoding), not trusted worker logic. Do not let an exception from
        // it permanently kill this verifier thread.
        try {
            job.reply(response);
        } catch (...) {
        }
    }
}

Q7933BlindSigResponse Q7933BlindSigSigner::process_job(
    const Q7933BlindSigAssembledRequest& request) noexcept {
    try {
        if (request.pi1_receipt.empty()) {
            return rejected_response("NIZK1 receipt is empty");
        }
        if (const auto reason = first_noncanonical_field(request)) {
            return rejected_response(*reason);
        }
        if (request.b != info_.b) {
            return rejected_response("request B does not match this mediator's published B");
        }

        const std::string receipt_path = write_temp_receipt(request.pi1_receipt);
        TempFileGuard guard{receipt_path};

        // Security-critical: expected `b` comes from THIS mediator's copied
        // public info, never from the client's request. request.b was checked
        // equal above only as a wire-consistency fast path; the sidecar still
        // verifies the receipt against our own value independently.
        nlohmann::json expected;
        expected["b"] = u16_array_to_json(info_.b);
        expected["c"] = u16_array_to_json(request.c);
        expected["enc_a"] = u16_array_to_json(request.enc_a);
        expected["enc_pk"] = u16_array_to_json(request.enc_pk);
        expected["ct1_r"] = u16_array_to_json(request.ct1_r);
        expected["ct2_r"] = u16_array_to_json(request.ct2_r);
        expected["ct1_mu"] = u16_array_to_json(request.ct1_mu);
        expected["ct2_mu"] = u16_array_to_json(request.ct2_mu);

        const SidecarResult verify_result = run_blindsig_prover(
            prover_path_, {"signer-verify-nizk1", "--pi1-in", receipt_path},
            expected.dump(), std::chrono::seconds(30));
        const std::string stdout_text = require_sidecar_stdout(verify_result);
        const auto parsed = nlohmann::json::parse(stdout_text);

        if (!parsed.value("ok", false)) {
            return error_response("signer-verify-nizk1 tool error: " +
                                  parsed.value("error", std::string("unknown")));
        }
        if (!parsed.value("verified", false)) {
            return rejected_response(parsed.value("reason", std::string("NIZK1 did not verify")));
        }

        TicketId ticket_id{};
        try {
            std::lock_guard<std::mutex> lock(ticket_submit_mutex_);
            ticket_id = ticket_store_.submit(wire_to_poly(request.c));
        } catch (const Q7933TicketStoreFullError& e) {
            Q7933BlindSigResponse response;
            response.status = Q7933BlindSigResponse::Status::Busy;
            response.reason = bounded_reason(e.what());
            return response;
        }

        Q7933BlindSigResponse response;
        response.status = Q7933BlindSigResponse::Status::Pending;
        response.ticket_id = ticket_id;
        return response;
    } catch (const std::exception& e) {
        return error_response(std::string("internal q7933 blind-signature error: ") + e.what());
    } catch (...) {
        return error_response("internal q7933 blind-signature error: unknown exception");
    }
}

} // namespace tradep2p::blindsig
