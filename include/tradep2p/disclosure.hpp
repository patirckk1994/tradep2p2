#pragma once

// Phase 8 of the optional identity system: selective private receipt
// disclosure. See docs/identity-08-selective-disclosure.md and specs.txt
// SS9.2 for the design this implements.
//
// SCOPE DECISION, PER THE PHASE SPEC'S OWN INSTRUCTION TO RESOLVE THIS
// EXPLICITLY: this phase implements ONLY explicit disclosure of specific
// receipts to a specific chosen counterparty during a specific
// negotiation - "show this receipt to this party, right now, and only
// them." It does NOT implement:
//   - Blind-signed completion tokens (linkability fix) - the phase doc
//     itself says to check before assuming the primitives exist, and
//     specs.txt SS9.3/SS11 already establish, in detail, that they don't:
//     no pairing-friendly curve support for BBS+, and naive blind Schnorr
//     over Ed25519 is unsafe under concurrent sessions (the ROS attack).
//     Remains documented future work, exactly as SS9.3 already states.
//   - Bond anchoring (Sybil-resistance fix) - explicitly deferred by its
//     own phase-8 spec text ("offered here as an option with its costs
//     stated, not a solution" - specs.txt SS12) unless small enough to fit
//     reviewably; a real bond/slashing/balance-check design is not that.
// Building either of these into THIS phase would be presenting a
// linkability fix as a Sybil fix or vice versa, which docs/identity-08-
// selective-disclosure.md explicitly calls out as the mistake to avoid
// ("do not present one fix as solving both"). This phase's realistic,
// implementable deliverable is disclosure - see below.
//
// WHAT DISCLOSURE ACTUALLY PROVES, AND WHAT IT DOESN'T: showing a receipt
// chain to a new counterparty proves "the holder was a genuine party to a
// mediator-attested trade with this shape, at this stage." It does NOT
// prove the holder is trustworthy (specs.txt SS12: keys are free, and nothing
// here changes that), and if the disclosed chain was issued by a DIFFERENT
// mediator than the one relaying this disclosure, the recipient has no
// independent way to confirm that mediator's public key (embedded in the
// receipt itself) is genuine rather than self-asserted - the identical,
// already-documented registry-trust gap (specs.txt SS1.3), surfacing again
// here rather than a new one. Never presented as more than that.
//
// THE BINDING THAT MAKES THIS "SELECTIVE" RATHER THAN "PUBLIC": the
// disclosure envelope is signed with the ORIGINAL per-room ephemeral key
// that actually appears inside the disclosed chain (party_a_ephemeral_key
// or party_b_ephemeral_key of the receipts being shown) - not the
// discloser's key for the current room, which is a DIFFERENT, unlinkable
// key by phase 5's own design. Signing with the original key is what
// proves "I was genuinely a party to this receipt", not merely someone who
// obtained a copy of it. The envelope then binds the CURRENT negotiation's
// room id and the intended RECIPIENT's CURRENT ephemeral key, so a
// disclosure shown to party X in room A cannot be replayed by X to party Y
// in room B, and cannot be replayed by an interceptor whose own current
// ephemeral key doesn't match the bound recipient key - even though the
// signing key itself is old, the binding fields are fresh to this exact
// exchange.

#include "tradep2p/identity.hpp"
#include "tradep2p/protocol.hpp"
#include "tradep2p/receipt.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tradep2p {

constexpr std::uint16_t kDisclosureSuiteEd25519V1 = 0x0001;
inline constexpr std::string_view kDisclosureDomainLabel = "TRADEP2P_RECEIPT_DISCLOSURE_V1";
constexpr std::size_t kDisclosureMaxMediatorIdLength = 256;
constexpr std::size_t kDisclosureMaxChainLength = 8;

struct DisclosureFields {
    std::uint16_t suite_id{kDisclosureSuiteEd25519V1};
    std::uint16_t protocol_version{1};
    std::string mediator_id;
    RoomId room_id{}; // the CURRENT negotiation, not the disclosed chain's original room
    Ed25519PublicKey recipient_ephemeral_key{}; // recipient's key for THIS room - see file comment
    std::array<std::uint8_t, 32> disclosed_chain_hash{};
    std::uint64_t timestamp{0};
    std::array<std::uint8_t, 16> nonce{};
};

[[nodiscard]] std::vector<std::uint8_t> encode_disclosure_signed_payload(const DisclosureFields& fields);

// sha256 over the concatenation of each receipt's receipt_chain_link_hash()
// in chain order - what disclosed_chain_hash binds to, so the envelope and
// the specific receipt bytes accompanying it cannot be separated and
// recombined with a different chain.
[[nodiscard]] std::array<std::uint8_t, 32> disclosed_chain_hash(const std::vector<IssuedReceipt>& chain);

// Signed with the ORIGINAL room's ephemeral key (matching
// party_a_ephemeral_key/party_b_ephemeral_key inside the chain being
// disclosed) - see file comment for why this, not the discloser's current
// room's key.
[[nodiscard]] Ed25519Signature sign_disclosure(const Ed25519PrivateSeed& original_ephemeral_private_seed,
                                               const DisclosureFields& fields);
[[nodiscard]] bool verify_disclosure(const Ed25519PublicKey& original_ephemeral_public_key,
                                     const DisclosureFields& fields, const Ed25519Signature& signature);

// Everything a RECIPIENT needs to check about an incoming disclosure,
// bundled into one call so no caller has to remember every sub-check.
// Tries the signature against BOTH party_a_ephemeral_key and
// party_b_ephemeral_key from the chain (whichever party actually disclosed
// it), since a genuine disclosure is valid under exactly one of the two.
// Returns a human-readable failure reason on any violation (bad chain,
// wrong chain hash, bad envelope signature under either chain key,
// envelope not bound to `expected_recipient_key` or `expected_room_id`) or
// std::nullopt if everything checks out. Does NOT check whether the
// receipt chain's EMBEDDED mediator_public_key is one the recipient
// independently trusts - see this file's header comment on why that is a
// separate, honestly unsolved trust question the caller must handle itself
// (e.g. by comparing against a TOFU-pinned key if it happens to be the
// same mediator this negotiation is also on).
[[nodiscard]] std::optional<std::string> verify_disclosure_bundle(
    const std::vector<IssuedReceipt>& chain, const DisclosureFields& fields,
    const Ed25519Signature& signature, const RoomId& expected_room_id,
    const Ed25519PublicKey& expected_recipient_key);

} // namespace tradep2p
