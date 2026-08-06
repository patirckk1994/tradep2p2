#include "tradep2p/login.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <stdexcept>

namespace tradep2p {
namespace {

class Writer {
public:
    void u16(std::uint16_t value) {
        out_.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
        out_.push_back(static_cast<std::uint8_t>(value & 0xffU));
    }
    void u64(std::uint64_t value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            out_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
        }
    }
    void bytes(std::span<const std::uint8_t> value) {
        out_.insert(out_.end(), value.begin(), value.end());
    }
    void length_prefixed(std::string_view value, std::size_t maximum) {
        if (value.size() > maximum || value.size() > std::numeric_limits<std::uint16_t>::max()) {
            throw std::invalid_argument("login field exceeds protocol limit");
        }
        u16(static_cast<std::uint16_t>(value.size()));
        out_.insert(out_.end(), value.begin(), value.end());
    }
    [[nodiscard]] std::vector<std::uint8_t> take() { return std::move(out_); }

private:
    std::vector<std::uint8_t> out_;
};

std::uint64_t now_unix_seconds() {
    return static_cast<std::uint64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
}

} // namespace

std::vector<std::uint8_t> encode_login_challenge_signed_payload(const LoginChallengeFields& fields) {
    if (fields.service_id.size() > kLoginMaxFieldLength ||
        fields.server_identity.size() > kLoginMaxFieldLength ||
        fields.username.size() > kLoginMaxFieldLength) {
        throw std::invalid_argument("login challenge field exceeds maximum length");
    }
    Writer writer;
    writer.length_prefixed(kLoginChallengeDomainLabel, kLoginChallengeDomainLabel.size());
    writer.u16(fields.protocol_version);
    writer.u16(fields.suite_id);
    writer.length_prefixed(fields.service_id, kLoginMaxFieldLength);
    writer.length_prefixed(fields.server_identity, kLoginMaxFieldLength);
    writer.length_prefixed(fields.username, kLoginMaxFieldLength);
    writer.bytes(fields.session_id);
    writer.bytes(fields.nonce);
    writer.u64(fields.created_at);
    writer.u64(fields.expires_at);
    return writer.take();
}

LoginNonce generate_login_nonce() {
    LoginNonce nonce{};
    const std::vector<std::uint8_t> raw = random_bytes(nonce.size());
    std::copy(raw.begin(), raw.end(), nonce.begin());
    return nonce;
}

LoginSessionId generate_login_session_id() {
    LoginSessionId id{};
    const std::vector<std::uint8_t> raw = random_bytes(id.size());
    std::copy(raw.begin(), raw.end(), id.begin());
    return id;
}

Ed25519Signature sign_login_response(const Ed25519PrivateSeed& login_private_seed,
                                     const LoginChallengeFields& fields) {
    return ed25519_sign(login_private_seed, encode_login_challenge_signed_payload(fields));
}

bool verify_login_response(const Ed25519PublicKey& login_public_key, const LoginChallengeFields& fields,
                           const Ed25519Signature& signature) {
    return ed25519_verify(login_public_key, encode_login_challenge_signed_payload(fields), signature);
}

LoginChallengeFields LoginChallengeTracker::issue(const std::string& service_id,
                                                  const std::string& server_identity,
                                                  const std::string& username, std::uint64_t now) {
    if (outstanding_.size() >= kLoginMaxOutstandingChallenges) {
        throw std::invalid_argument("too many outstanding login challenges");
    }
    if (now == 0U) {
        now = now_unix_seconds();
    }
    LoginChallengeFields fields;
    fields.service_id = service_id;
    fields.server_identity = server_identity;
    fields.username = username;
    fields.session_id = generate_login_session_id();
    fields.nonce = generate_login_nonce();
    fields.created_at = now;
    fields.expires_at = now + kLoginChallengeTtlSeconds;
    outstanding_.push_back(fields);
    return fields;
}

std::optional<LoginChallengeFields> LoginChallengeTracker::peek(const LoginSessionId& session_id,
                                                                 std::uint64_t now) const {
    if (now == 0U) {
        now = now_unix_seconds();
    }
    const auto it = std::find_if(outstanding_.begin(), outstanding_.end(),
                                  [&](const LoginChallengeFields& fields) {
                                      return fields.session_id == session_id;
                                  });
    if (it == outstanding_.end() || now > it->expires_at) {
        return std::nullopt;
    }
    return *it;
}

void LoginChallengeTracker::consume(const LoginSessionId& session_id) {
    outstanding_.erase(
        std::remove_if(outstanding_.begin(), outstanding_.end(),
                        [&](const LoginChallengeFields& fields) {
                            return fields.session_id == session_id;
                        }),
        outstanding_.end());
}

void LoginChallengeTracker::expire_stale(std::uint64_t now) {
    if (now == 0U) {
        now = now_unix_seconds();
    }
    outstanding_.erase(
        std::remove_if(outstanding_.begin(), outstanding_.end(),
                        [now](const LoginChallengeFields& fields) { return now > fields.expires_at; }),
        outstanding_.end());
}

} // namespace tradep2p
