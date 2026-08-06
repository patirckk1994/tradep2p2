#pragma once

// Phase 7 of the optional identity system: service-scoped challenge-response
// login. See docs/identity-07-login.md and specs.txt SS5 (key_scope::kLogin,
// "one per service") for the design this implements.
//
// SCOPE DECISION (docs/identity-07-login.md asks this to be resolved
// explicitly, not left to default to whichever was easier to bolt on):
// this phase extends `tradep2p-webclient`'s existing account system
// (AccountStore/SessionManager, src/http_webclient.cpp) with an
// alternative to password login - it does NOT add a login concept to the
// mediator protocol. Reasoning: the mediator has no account system today,
// by design - every client is an anonymous per-connection ClientId, and
// nothing in specs.txt's threat model wants that to change. Adding a
// mediator-facing login would introduce exactly the "public lifelong
// identifier" specs.txt SS3's constraints forbid. The web client, in
// contrast, already has a real account/password system with a real
// password-storage-compromise risk to mitigate - that is this phase's
// actual, bounded motivation, and identity.hpp's key_scope::kLogin ("one
// per service") already names the scope this targets: a service (like the
// hosted web client), not the anonymous trade protocol.
//
// THE HONEST CEILING (docs/identity-07-login.md, carried into phase 9):
// this protects against STORED-CREDENTIAL compromise - a leaked account
// file, a database dump, credential stuffing from password reuse
// elsewhere. It does NOT protect against a hostile or compromised
// tradep2p-webclient OPERATOR, who controls the JavaScript served to the
// browser and can always ship a build that exfiltrates whatever key the
// browser holds. Never described as more than that anywhere this module's
// output is surfaced.
//
// WHAT THIS FILE PROVIDES: the canonical signed challenge/response
// primitives and the server-side (verifier) single-use/expiring tracker.
// The actual HTTP routes, account-file migration, and rate limiting live
// in src/http_webclient.cpp, since they are specific to that one binary's
// trust boundary, matching this codebase's convention (protocol.hpp knows
// nothing about lobby.cpp's connection handling either).
//
// BROWSER-SIDE KEY GENERATION IS EXPLICITLY NOT THIS PHASE'S JOB: per
// docs/identity-07-login.md and docs/identity-09-hosted-webclient.md, that
// is phase 9's job, gated on choosing (and this repo currently having no
// dependency for) a real in-browser Ed25519 signing mechanism - WebAuthn,
// an external signer, a browser extension, or a local companion service
// are all preferred over raw browser-JS custody per phase 9's own ordering.
// This phase's server-side routes accept an already-generated public key
// (hex) and an already-produced signature (hex) from whatever the caller
// used to make them - a native client, a CLI helper, or (once phase 9
// lands) a browser using one of the above mechanisms.
//
// TLS CHANNEL BINDING - DELIBERATELY NOT USED HERE, WITH REASONING (same
// posture as recognition.hpp's identical omission): docs/identity-07-
// login.md asks for "TLS channel binding or TLS exporter value where
// available". tradep2p-webclient's own file comment documents that it is
// "meant to sit behind a TLS-terminating reverse proxy" - meaning this
// process itself typically speaks PLAIN HTTP; there is no TLS session at
// this layer to export a binding value from, so one is not fabricated.
// "Bind it to the current session where possible" (per the same spec
// sentence) is instead satisfied at the layer that DOES exist here: each
// challenge carries a fresh, server-chosen, single-use LoginSessionId that
// the response must echo, which the tracker below enforces - the
// HTTP-application-layer equivalent of the same anti-replay property.

#include "tradep2p/identity.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace tradep2p {

constexpr std::uint16_t kLoginSuiteEd25519V1 = 0x0001;
constexpr std::uint16_t kLoginProtocolVersion = 1;
inline constexpr std::string_view kLoginChallengeDomainLabel = "TRADEP2P_LOGIN_CHALLENGE_V1";
constexpr std::size_t kLoginNonceLength = 32;
constexpr std::size_t kLoginSessionIdLength = 16;
constexpr std::size_t kLoginMaxFieldLength = 256;
constexpr std::uint64_t kLoginChallengeTtlSeconds = 120;
constexpr std::size_t kLoginMaxOutstandingChallenges = 4096;

using LoginNonce = std::array<std::uint8_t, kLoginNonceLength>;
using LoginSessionId = std::array<std::uint8_t, kLoginSessionIdLength>;

// The fields bound into the signed challenge/response. `username` is not
// in the phase spec's literal field list but is included deliberately: it
// is what prevents a confusion attack where a challenge issued for account
// X gets checked against account Y's enrolled key (both are looked up by
// the SAME LoginSessionId in the tracker, but binding the account into the
// signed bytes themselves means a mismatch is caught by signature
// verification too, not only by the tracker's own bookkeeping - defense in
// depth, matching this codebase's "never sign an ambiguous context"
// discipline elsewhere).
struct LoginChallengeFields {
    std::uint16_t suite_id{kLoginSuiteEd25519V1};
    std::uint16_t protocol_version{kLoginProtocolVersion};
    std::string service_id;
    std::string server_identity;
    std::string username;
    LoginSessionId session_id{};
    LoginNonce nonce{};
    std::uint64_t created_at{0};
    std::uint64_t expires_at{0};
};

[[nodiscard]] std::vector<std::uint8_t> encode_login_challenge_signed_payload(
    const LoginChallengeFields& fields);

[[nodiscard]] LoginNonce generate_login_nonce();
[[nodiscard]] LoginSessionId generate_login_session_id();

[[nodiscard]] Ed25519Signature sign_login_response(const Ed25519PrivateSeed& login_private_seed,
                                                    const LoginChallengeFields& fields);
[[nodiscard]] bool verify_login_response(const Ed25519PublicKey& login_public_key,
                                         const LoginChallengeFields& fields,
                                         const Ed25519Signature& signature);

// ---------------------------------------------------------------------------
// LoginChallengeTracker - server-side (verifier), single-use, expiring.
// Mirrors recognition.hpp's RecognitionChallengeTracker shape exactly (this
// codebase's established pattern for "issue a fresh nonce, verify it's
// still outstanding and unexpired, consume it once").
// ---------------------------------------------------------------------------
class LoginChallengeTracker {
public:
    // Issues a fresh challenge for `username` (which may not exist, or may
    // have no enrolled login key - see http_webclient.cpp's account-
    // enumeration-resistance handling; this tracker itself does not care
    // whether the account is real). Throws std::invalid_argument if this
    // would exceed kLoginMaxOutstandingChallenges.
    [[nodiscard]] LoginChallengeFields issue(const std::string& service_id,
                                             const std::string& server_identity,
                                             const std::string& username, std::uint64_t now = 0);

    // Looks up (without consuming) the outstanding challenge for
    // `session_id`, if any and unexpired - used by the caller to know which
    // fields/username to verify a response against before deciding whether
    // to consume it.
    [[nodiscard]] std::optional<LoginChallengeFields> peek(const LoginSessionId& session_id,
                                                            std::uint64_t now = 0) const;

    // Removes `session_id` from the outstanding set unconditionally (called
    // once after a verify attempt - successful or not - so a captured
    // response can never be retried against the same challenge).
    void consume(const LoginSessionId& session_id);

    void expire_stale(std::uint64_t now = 0);
    [[nodiscard]] std::size_t outstanding_count() const noexcept { return outstanding_.size(); }

private:
    std::vector<LoginChallengeFields> outstanding_;
};

} // namespace tradep2p
