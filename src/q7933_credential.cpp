#include "tradep2p/q7933_credential.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <random>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace tradep2p::q7933_credential {

CredentialSerial generate_serial() {
    CredentialSerial serial{};
    if (RAND_bytes(serial.data(), static_cast<int>(serial.size())) != 1) {
        throw std::runtime_error("q7933_credential: failed to generate random serial");
    }
    return serial;
}

std::vector<std::uint8_t> IssuanceContext::encode() const {
    std::vector<std::uint8_t> out;
    out.reserve(1 + 1 + 4 + 32 + 1); // version + issuer_scope + epoch + room_id + party

    out.push_back(version);
    out.push_back(issuer_scope);
    out.push_back(static_cast<std::uint8_t>((epoch >> 24) & 0xff));
    out.push_back(static_cast<std::uint8_t>((epoch >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((epoch >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(epoch & 0xff));
    out.insert(out.end(), room_id.begin(), room_id.end());
    out.push_back(party);

    return out;
}

IssuanceContext IssuanceContext::decode(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 39) { // 1 + 1 + 4 + 32 + 1
        throw std::runtime_error(
            "q7933_credential: IssuanceContext too short, expected >=39 bytes, got " +
            std::to_string(bytes.size()));
    }

    IssuanceContext out;
    std::size_t pos = 0;

    out.version = bytes[pos++];
    out.issuer_scope = bytes[pos++];

    out.epoch = (static_cast<std::uint32_t>(bytes[pos]) << 24) |
                (static_cast<std::uint32_t>(bytes[pos + 1]) << 16) |
                (static_cast<std::uint32_t>(bytes[pos + 2]) << 8) | static_cast<std::uint32_t>(bytes[pos + 3]);
    pos += 4;

    std::copy(bytes.begin() + pos, bytes.begin() + pos + 32, out.room_id.begin());
    pos += 32;

    out.party = bytes[pos];

    return out;
}

Nullifier derive_nullifier(
    const CredentialSerial& serial,
    std::uint8_t issuer_scope,
    std::uint32_t epoch,
    std::span<const std::uint8_t> presentation_scope) {
    // Domain-separated nullifier: H("TRADEP2P-Q7933-CREDENTIAL-NULLIFIER-v1" || ...)
    const char* domain = "TRADEP2P-Q7933-CREDENTIAL-NULLIFIER-v1";
    const size_t domain_len = std::strlen(domain);

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw std::runtime_error("q7933_credential: EVP_MD_CTX_new failed");
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: EVP_DigestInit_ex failed");
    }

    // Hash the domain string
    if (EVP_DigestUpdate(mdctx, domain, domain_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: EVP_DigestUpdate (domain) failed");
    }

    // Hash issuer_scope (1 byte)
    if (EVP_DigestUpdate(mdctx, &issuer_scope, 1) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: EVP_DigestUpdate (issuer_scope) failed");
    }

    // Hash epoch (4 bytes, big-endian)
    std::uint8_t epoch_bytes[4];
    epoch_bytes[0] = static_cast<std::uint8_t>((epoch >> 24) & 0xff);
    epoch_bytes[1] = static_cast<std::uint8_t>((epoch >> 16) & 0xff);
    epoch_bytes[2] = static_cast<std::uint8_t>((epoch >> 8) & 0xff);
    epoch_bytes[3] = static_cast<std::uint8_t>(epoch & 0xff);
    if (EVP_DigestUpdate(mdctx, epoch_bytes, 4) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: EVP_DigestUpdate (epoch) failed");
    }

    // Hash presentation_scope (including its length prefix for domain separation)
    if (presentation_scope.size() > std::numeric_limits<std::uint32_t>::max()) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: presentation_scope too large");
    }
    std::uint32_t scope_len = static_cast<std::uint32_t>(presentation_scope.size());
    std::uint8_t scope_len_bytes[4];
    scope_len_bytes[0] = static_cast<std::uint8_t>((scope_len >> 24) & 0xff);
    scope_len_bytes[1] = static_cast<std::uint8_t>((scope_len >> 16) & 0xff);
    scope_len_bytes[2] = static_cast<std::uint8_t>((scope_len >> 8) & 0xff);
    scope_len_bytes[3] = static_cast<std::uint8_t>(scope_len & 0xff);
    if (EVP_DigestUpdate(mdctx, scope_len_bytes, 4) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: EVP_DigestUpdate (scope length) failed");
    }
    if (!presentation_scope.empty() && EVP_DigestUpdate(mdctx, presentation_scope.data(), presentation_scope.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: EVP_DigestUpdate (scope) failed");
    }

    // Hash serial
    if (EVP_DigestUpdate(mdctx, serial.data(), static_cast<int>(serial.size())) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: EVP_DigestUpdate (serial) failed");
    }

    Nullifier out{};
    unsigned int out_len = 0;
    if (EVP_DigestFinal_ex(mdctx, out.data(), &out_len) != 1 || out_len != out.size()) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("q7933_credential: EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(mdctx);
    return out;
}

Nullifier derive_nullifier_empty() {
    CredentialSerial empty_serial{};
    return derive_nullifier(empty_serial, 0, 0, {});
}

std::vector<std::uint8_t> CredentialPayload::encode() const {
    std::vector<std::uint8_t> out;

    // Fixed header: version (1) + issuer_scope (1) + epoch (4) + serial (32)
    out.push_back(version);
    out.push_back(issuer_scope);
    out.push_back(static_cast<std::uint8_t>((epoch >> 24) & 0xff));
    out.push_back(static_cast<std::uint8_t>((epoch >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((epoch >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(epoch & 0xff));
    out.insert(out.end(), serial.begin(), serial.end());

    // Reserved fields as a length-prefixed blob (0 length for v1).
    if (reserved.size() > std::numeric_limits<std::uint16_t>::max()) {
        throw std::runtime_error("q7933_credential: reserved field too large");
    }
    std::uint16_t reserved_len = static_cast<std::uint16_t>(reserved.size());
    out.push_back(static_cast<std::uint8_t>((reserved_len >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(reserved_len & 0xff));
    out.insert(out.end(), reserved.begin(), reserved.end());

    return out;
}

CredentialPayload CredentialPayload::decode(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 40) { // 1 + 1 + 4 + 32 + 2 (minimum with empty reserved)
        throw std::runtime_error(
            "q7933_credential: CredentialPayload too short, expected >=40 bytes, got " +
            std::to_string(bytes.size()));
    }

    CredentialPayload out;
    std::size_t pos = 0;

    out.version = bytes[pos++];
    out.issuer_scope = bytes[pos++];

    out.epoch = (static_cast<std::uint32_t>(bytes[pos]) << 24) |
                (static_cast<std::uint32_t>(bytes[pos + 1]) << 16) |
                (static_cast<std::uint32_t>(bytes[pos + 2]) << 8) | static_cast<std::uint32_t>(bytes[pos + 3]);
    pos += 4;

    std::copy(bytes.begin() + pos, bytes.begin() + pos + 32, out.serial.begin());
    pos += 32;

    if (pos + 2 > bytes.size()) {
        throw std::runtime_error("q7933_credential: CredentialPayload truncated at reserved length");
    }

    std::uint16_t reserved_len = (static_cast<std::uint16_t>(bytes[pos]) << 8) |
                                  static_cast<std::uint16_t>(bytes[pos + 1]);
    pos += 2;

    if (pos + reserved_len != bytes.size()) {
        throw std::runtime_error(
            "q7933_credential: CredentialPayload size mismatch, expected " + std::to_string(pos + reserved_len) +
            " bytes, got " + std::to_string(bytes.size()));
    }

    if (reserved_len > 0) {
        out.reserved.insert(out.reserved.end(), bytes.begin() + pos,
                           bytes.begin() + pos + reserved_len);
    }

    return out;
}

std::vector<std::uint8_t> encode_credential_for_blind(const CredentialPayload& payload) {
    // Domain-separated encoding for use in the blinded commitment.
    // Format: "TRADEP2P-Q7933-CREDENTIAL-FOR-BLIND-v1" || payload.encode()
    const char* domain = "TRADEP2P-Q7933-CREDENTIAL-FOR-BLIND-v1";
    const size_t domain_len = std::strlen(domain);

    std::vector<std::uint8_t> out;
    out.reserve(domain_len + 40); // estimate

    out.insert(out.end(), domain, domain + domain_len);

    auto payload_bytes = payload.encode();
    out.insert(out.end(), payload_bytes.begin(), payload_bytes.end());

    return out;
}

} // namespace tradep2p::q7933_credential
