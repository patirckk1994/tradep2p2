#include "tradep2p/q7933_presentation.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace tradep2p::q7933_credential {

std::vector<std::uint8_t> PresentationContext::encode() const {
    std::vector<std::uint8_t> out;

    // Encode as: room_id_len (4) || room_id || verifier_len (4) || verifier ||
    //            challenge_len (4) || challenge
    // Each length is a u32, big-endian.

    auto encode_u32 = [](std::vector<std::uint8_t>& v, std::uint32_t val) {
        v.push_back(static_cast<std::uint8_t>((val >> 24) & 0xff));
        v.push_back(static_cast<std::uint8_t>((val >> 16) & 0xff));
        v.push_back(static_cast<std::uint8_t>((val >> 8) & 0xff));
        v.push_back(static_cast<std::uint8_t>(val & 0xff));
    };

    encode_u32(out, static_cast<std::uint32_t>(room_id.size()));
    out.insert(out.end(), room_id.begin(), room_id.end());

    encode_u32(out, static_cast<std::uint32_t>(verifier_identity.size()));
    out.insert(out.end(), verifier_identity.begin(), verifier_identity.end());

    encode_u32(out, static_cast<std::uint32_t>(challenge.size()));
    out.insert(out.end(), challenge.begin(), challenge.end());

    return out;
}

bool verify_nullifier(
    const CredentialSerial& serial,
    const Nullifier& claimed_nullifier,
    std::uint8_t issuer_scope,
    std::uint32_t epoch,
    const PresentationContext& context) {
    // Re-derive what the nullifier SHOULD be, then compare.
    auto scope_bytes = encode_presentation_context(context);
    auto expected_nullifier = derive_nullifier(serial, issuer_scope, epoch, scope_bytes);

    // Constant-time comparison to avoid timing attacks.
    bool matches = true;
    for (std::size_t i = 0; i < claimed_nullifier.size(); ++i) {
        if (claimed_nullifier[i] != expected_nullifier[i]) {
            matches = false;
        }
    }
    return matches;
}

std::vector<std::uint8_t> encode_presentation_context(const PresentationContext& context) {
    return context.encode();
}

} // namespace tradep2p::q7933_credential
