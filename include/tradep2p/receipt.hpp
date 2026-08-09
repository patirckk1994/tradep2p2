#pragma once

// Phase 6 of the optional identity system: mediator-signed staged receipts.
// See docs/identity-06-receipts.md and specs.txt SS9.1 for the design this
// implements.
//
// WHAT A RECEIPT IS, AND ISN'T (state this everywhere - it is the single
// easiest confusion to introduce, per the phase spec):
//   - The local journal (journal.hpp) proves what THIS client recorded
//     about itself. Nobody else can rely on it; it has no value to a
//     counterparty.
//   - A receipt (this file) is evidence SIGNED BY A THIRD PARTY (the
//     mediator, countersigning both parties' own acknowledgements) - it
//     carries weight to someone who was not present for the trade. Never
//     conflate the two in code, docs, or UI.
//   - A bare assertion of the form "key X traded successfully" is
//     prohibited by design: every IssuedReceipt is bound to a specific
//     room, a specific terms commitment, and (for stage 3) both parties'
//     own signed acknowledgements - it is not a mediator-only claim.
//
// STAGES (docs/identity-06-receipts.md):
//   1. TermsAccepted
//   2. RoundAcknowledged
//   3. PenultimateObligationsComplete - "all obligations except final
//      settlement completed"
//   4. SettlementCompleted
//
// WHAT THIS PHASE ACTUALLY WIRES UP LIVE (read before assuming more than
// is implemented - "report unresolved limitations honestly" per every
// phase doc in this series):
//   - Stage 3 is issued for EVERY room, via the two-party-ack +
//     mediator-countersignature path (MessageType::ReceiptAck /
//     ReceiptIssued, lobby.cpp), gating the room's actual final tranche -
//     see mediator.hpp's SessionState::WaitingForFinalReceiptAck. THIS is
//     the withholding fix: refusing to ack costs the refuser their own
//     final leg too, exactly like an ordinary defection.
//   - Stage 4 is issued automatically, mediator-only-signed (no two-party
//     ack round trip - the mediator already independently observed both
//     legs' completion through the existing Sent/Received flow, which is
//     the actual completion condition; see verify_receipt_completion_
//     condition() below for the check that a stage-4 receipt is never
//     issued before that condition is true).
//   - Stages 1 and 2 are fully implemented and tested at the receipt/
//     verification level (encode/sign/verify/chain), matching the phase
//     spec's field list and ordering rules, but are NOT YET triggered by
//     the live wire protocol - the mediator does not currently issue them.
//     This is a deliberate, stated scope boundary: stage 3 is what the
//     withholding fix actually needs, and stage 4 is what "the trade
//     completed" needs; issuing 1/2 live as well is a natural follow-on,
//     not a hard requirement of this phase.
//   - Pagination (RECEIPT_REQUEST/RECEIPT_PAGE) is NOT implemented. A
//     room's receipt chain in this phase is at most two IssuedReceipts
//     (stage 3, stage 4), both individually well under the 4096-byte frame
//     cap, and both are pushed to each party in real time as they are
//     issued - there is currently no unbounded "give me everything"
//     request that could ever need paging. This is stated honestly as
//     deferred, not silently skipped: a future phase adding bulk/
//     historical receipt retrieval (e.g. after a reconnect) is exactly
//     where real pagination would earn its keep, and receipt.hpp's
//     canonical, versioned, chained format is designed so that adding it
//     later does not require reissuing anything already signed.
//
// SELF-TRADE / REPUTATION-FARMING NOTE (docs/identity-06-receipts.md
// "Reputation constraints"): keys are free, and two self-created identities
// completing rooms with each other would mint a spotless mutual history
// from nothing. This codebase already structurally prevents the naive case
// at the point a room forms: LobbyServer::Impl::handle_join_offer() rejects
// "cannot join your own offer" and handle_accept()'s invite flow requires
// InviteTradeMessage::target != the inviting ClientId (see lobby.cpp) -
// both keyed on the CURRENT CONNECTION'S ClientId, which the mediator
// cannot be tricked into reusing for both sides of one room. What this does
// NOT catch, and cannot catch without compromising the anonymity model this
// whole architecture exists to protect: the SAME OPERATOR running two
// separate client processes/connections (and therefore two distinct
// ClientIds and two distinct ephemeral keys) to wash-trade with themselves.
// Detecting that would require the mediator to correlate connections by
// something like source IP or timing - exactly the traffic-analysis
// capability specs.txt SS4/SS13.2 already documents this system does not
// and should not give the mediator. This is not a gap unique to receipts;
// it is specs.txt SS12's "no Sybil resistance, and says so plainly" stated
// again at the point where it becomes concrete. Nothing in this phase
// implies otherwise.
//
// TWO-PARTY ACK + MEDIATOR COUNTERSIGNATURE: for stage 3, each party signs
// a ReceiptAckFields envelope with the SAME per-room ephemeral key it
// announced via phase 5's TradeEphemeralKey message (the mediator verifies
// the ack's signature against the ephemeral key it already cached from that
// announcement - see lobby.cpp - never against a key embedded in the ack
// itself, which would let a party ack under an unannounced key). Only once
// BOTH parties' acks verify does the mediator build and countersign the
// stage-3 IssuedReceipt. A hostile mediator therefore cannot fabricate a
// stage-3 receipt neither party actually produced.

#include "tradep2p/identity.hpp"
#include "tradep2p/protocol.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tradep2p {

constexpr std::uint16_t kReceiptSuiteEd25519V1 = 0x0001;
// The only suite issued by any production code today - see specs.txt SS11:
// "Mediator receipt-signing keys should be hybrid Ed25519+ML-DSA from their
// first shipped version." Hybrid means BOTH signatures are mandatory, not a
// switchable choice the way recognition.hpp's suite_id is - receipts and
// disclosure must stay unforgeable even if just one of the two schemes is
// later broken, so there is no lone-Ed25519 or lone-ML-DSA-65 issuance path
// to fall back to. kReceiptSuiteEd25519V1 above is kept only as a historical
// constant/domain-separation value for tests exercising the Ed25519-only
// primitives in isolation.
constexpr std::uint16_t kReceiptSuiteEd25519MlDsa65HybridV1 = 0x0002;
inline constexpr std::string_view kReceiptAckDomainLabel = "TRADEP2P_RECEIPT_ACK_V1";
inline constexpr std::string_view kReceiptDomainLabel = "TRADEP2P_RECEIPT_V1";
constexpr std::size_t kReceiptMaxMediatorIdLength = 256;
constexpr std::size_t kReceiptNonceLength = 16;

enum class ReceiptStage : std::uint8_t {
    TermsAccepted = 1,
    RoundAcknowledged = 2,
    PenultimateObligationsComplete = 3,
    SettlementCompleted = 4,
};

[[nodiscard]] const char* receipt_stage_name(ReceiptStage stage);

// --- Stage-ack (party-signed, two-party-ack half) ---------------------

// What each PARTY signs with its per-room ephemeral key (phase 5) to
// acknowledge one stage. `mediator_id` and `terms_commitment` are supplied
// locally by the signer/verifier, same convention as recognition.hpp/
// ephemeral.hpp - never carried redundantly on the wire beyond what's
// needed to reconstruct these bytes (see protocol.hpp's ReceiptAckMessage).
struct ReceiptAckFields {
    std::uint16_t suite_id{kReceiptSuiteEd25519MlDsa65HybridV1};
    std::uint16_t protocol_version{kProtocolVersion};
    std::string mediator_id;
    RoomId room_id{};
    ReceiptStage stage{ReceiptStage::PenultimateObligationsComplete};
    std::array<std::uint8_t, 32> terms_commitment{};
    std::uint64_t timestamp{0};
};

[[nodiscard]] std::vector<std::uint8_t> encode_receipt_ack_signed_payload(
    const ReceiptAckFields& fields);
[[nodiscard]] Ed25519Signature sign_receipt_ack(const Ed25519PrivateSeed& ephemeral_private_seed,
                                                 const ReceiptAckFields& fields);
[[nodiscard]] bool verify_receipt_ack(const Ed25519PublicKey& ephemeral_public_key,
                                      const ReceiptAckFields& fields,
                                      const Ed25519Signature& signature);
[[nodiscard]] MlDsa65Signature sign_receipt_ack_mldsa65(const MlDsa65PrivateSeed& ephemeral_private_seed,
                                                        const ReceiptAckFields& fields);
[[nodiscard]] bool verify_receipt_ack_mldsa65(const MlDsa65PublicKey& ephemeral_public_key,
                                              const ReceiptAckFields& fields,
                                              const MlDsa65Signature& signature);
// Both signatures must verify - see the file-wide hybrid note above.
[[nodiscard]] bool verify_receipt_ack_hybrid(const Ed25519PublicKey& ephemeral_public_key,
                                             const MlDsa65PublicKey& ephemeral_public_key_mldsa65,
                                             const ReceiptAckFields& fields,
                                             const Ed25519Signature& signature,
                                             const MlDsa65Signature& signature_mldsa65);

// --- The receipt itself (mediator-signed) ------------------------------

struct ReceiptFields {
    std::uint16_t suite_id{kReceiptSuiteEd25519MlDsa65HybridV1};
    std::uint16_t protocol_version{kProtocolVersion};
    std::string mediator_id;
    RoomId room_id{};
    std::array<std::uint8_t, 32> terms_commitment{};
    Ed25519PublicKey party_a_ephemeral_key{};
    Ed25519PublicKey party_b_ephemeral_key{};
    // Each party's ML-DSA-65 ephemeral counterpart (see ephemeral.hpp - a
    // room's ephemeral identity is dual-algorithm from generation). Carried
    // here, not just the mediator's own hybrid keys above, because
    // disclosure.hpp's verify_disclosure_bundle() needs BOTH of a party's
    // ephemeral public keys to hybrid-verify a disclosure envelope signed
    // long after this room closed - a future recipient who was never
    // connected to this room has no other way to learn them.
    MlDsa65PublicKey party_a_ephemeral_key_mldsa65{};
    MlDsa65PublicKey party_b_ephemeral_key_mldsa65{};
    Ed25519PublicKey mediator_public_key{};
    MlDsa65PublicKey mediator_public_key_mldsa65{};
    ReceiptStage stage{ReceiptStage::PenultimateObligationsComplete};
    bool completed{false};
    std::uint64_t timestamp{0};
    std::array<std::uint8_t, kReceiptNonceLength> nonce{};
    // sha256(encode_receipt_signed_payload(previous) ‖ previous.signature ‖
    // previous.signature_mldsa65) of the chain's prior stage, or all-zero
    // for the first receipt in a room's chain - see receipt_chain_link_hash()
    // below.
    std::array<std::uint8_t, 32> previous_stage_hash{};
};

[[nodiscard]] std::vector<std::uint8_t> encode_receipt_signed_payload(const ReceiptFields& fields);
[[nodiscard]] Ed25519Signature sign_receipt(const Ed25519PrivateSeed& mediator_private_seed,
                                            const ReceiptFields& fields);
[[nodiscard]] bool verify_receipt(const Ed25519PublicKey& mediator_public_key,
                                  const ReceiptFields& fields, const Ed25519Signature& signature);
[[nodiscard]] MlDsa65Signature sign_receipt_mldsa65(const MlDsa65PrivateSeed& mediator_private_seed,
                                                    const ReceiptFields& fields);
[[nodiscard]] bool verify_receipt_mldsa65(const MlDsa65PublicKey& mediator_public_key,
                                          const ReceiptFields& fields,
                                          const MlDsa65Signature& signature);
// Both signatures must verify - see the file-wide hybrid note above. This is
// the function every receipt verifier (verify_receipt_chain below, and every
// client call site) should actually call; the lone-algorithm functions above
// exist mainly so tests can exercise each primitive in isolation.
[[nodiscard]] bool verify_receipt_hybrid(const Ed25519PublicKey& mediator_public_key,
                                         const MlDsa65PublicKey& mediator_public_key_mldsa65,
                                         const ReceiptFields& fields,
                                         const Ed25519Signature& signature,
                                         const MlDsa65Signature& signature_mldsa65);

// A receipt's chain-link hash - what the NEXT receipt in the same room's
// chain must carry as its own previous_stage_hash. Binds the signed fields
// and BOTH of the mediator's signatures over them, so a later receipt cannot
// be re-parented onto a same-fields-different-signature forgery under either
// algorithm.
[[nodiscard]] std::array<std::uint8_t, 32> receipt_chain_link_hash(
    const ReceiptFields& fields, const Ed25519Signature& mediator_signature,
    const MlDsa65Signature& mediator_signature_mldsa65);

struct IssuedReceipt {
    ReceiptFields fields;
    Ed25519Signature mediator_signature{};
    MlDsa65Signature mediator_signature_mldsa65{};
};

// Thrown by verify_receipt_chain() - a single type covering every violation
// class (bad signature, broken link, non-monotonic stage, inconsistent
// room/terms/party-key across the chain) since, like keystore.hpp's
// authentication error, a caller should treat "this chain does not verify"
// uniformly rather than branch on which specific check failed.
class ReceiptChainError : public std::runtime_error {
public:
    explicit ReceiptChainError(const std::string& message) : std::runtime_error(message) {}
};

// Verifies a full ordered chain of receipts for ONE room: every entry's
// mediator signatures (BOTH Ed25519 and ML-DSA-65) verify under
// `mediator_public_key`/`mediator_public_key_mldsa65`; stages strictly
// increase from one entry to the next; room_id, terms_commitment, and both
// parties' ephemeral keys are identical across every entry (a receipt chain
// describes one room, never a mix); each entry's previous_stage_hash
// matches receipt_chain_link_hash() of the prior entry (all-zero required
// for the first). Throws ReceiptChainError on any violation; returns
// normally (no return value - the caller already holds `chain`) if the
// whole chain is internally consistent and genuinely mediator-signed.
void verify_receipt_chain(const std::vector<IssuedReceipt>& chain,
                          const Ed25519PublicKey& mediator_public_key,
                          const MlDsa65PublicKey& mediator_public_key_mldsa65);

// "Don't let it be issued optimistically" (docs/identity-06-receipts.md) is
// enforced STRUCTURALLY, not by a separate checking function: lobby.cpp
// only ever constructs a ReceiptStage::SettlementCompleted ReceiptFields
// from inside the exact branch where it has already established
// `room->session.state() == SessionState::Complete` via the ordinary
// Sent/Received flow (see handle_sent()/handle_received()) - there is no
// code path that builds a stage-4 ReceiptFields any other way. See
// tests/receipt_tests.cpp for a test that exercises this end-to-end
// through MediatorSession directly, confirming a stage-4 receipt is only
// ever reachable after the real completion condition holds.

[[nodiscard]] Ed25519KeyPair generate_mediator_receipt_keypair();

} // namespace tradep2p
