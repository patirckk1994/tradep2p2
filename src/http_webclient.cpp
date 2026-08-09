// Public multi-session web client: the "website has its own client to the
// exchange." Unlike tradep2p-dashboard (one process, one anonymous client,
// loopback only), this binary can be exposed publicly and serves many
// browser sessions from one process. Each session is a local convenience
// account (username/password) that owns its own persistent anonymous
// connection to the mediator. The account system has nothing to do with the
// mediator protocol, which stays fully anonymous; it only lets a visitor
// create and later terminate a session on this page.
//
// cpp-httplib hardcodes an 8KB cap specifically for
// application/x-www-form-urlencoded bodies (CPPHTTPLIB_FORM_URL_ENCODED_
// PAYLOAD_MAX_LENGTH, checked at parse time - unlike the general payload
// cap, there is no set_*() to raise this at runtime, only this compile-time
// override). /api/recognition/answer-external's public_key+signature form
// fields alone are ~10.5KB of hex for ML-DSA-65 (1952-byte key, 3309-byte
// signature) - discovered by hitting a real 413 in live testing, not
// theoretical. Must be defined before including httplib.h.
#define CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH 32768
#include <httplib.h>

#include "tradep2p/dashboard_client.hpp"
#include "tradep2p/history.hpp"
#include "tradep2p/keystore.hpp"
#include "tradep2p/login.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <sys/stat.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

using tradep2p::ClientTlsPolicy;
using tradep2p::Endpoint;
using tradep2p::Party;
using tradep2p::TradeTerms;
using tradep2p::dashboard::DashboardClient;
using tradep2p::dashboard::json_escape;
using tradep2p::dashboard::now_text;
using tradep2p::dashboard::random_token;

constexpr const char* kSessionCookie = "tp2p_session";
// Double-submit cookie used only to defend /api/register and /api/login
// against CSRF before any session exists to hold a synchronizer token in.
constexpr const char* kPreAuthCookie = "tp2p_csrf";
constexpr const char* kPreAuthHeader = "X-TradeP2P-PreAuth";
// OWASP's current minimum recommendation for PBKDF2-HMAC-SHA256.
constexpr int kPbkdf2Iterations = 600000;
constexpr std::size_t kSaltLength = 16U;
constexpr std::size_t kHashLength = 32U;

std::uint16_t parse_port(const std::string& value) {
    std::size_t used = 0U;
    const auto parsed = std::stoul(value, &used, 10);
    if (used != value.size() || parsed == 0U || parsed > 65535U) {
        throw std::invalid_argument("invalid port");
    }
    return static_cast<std::uint16_t>(parsed);
}

Endpoint parse_endpoint(const std::string& text) {
    if (!text.empty() && text.front() == '[') {
        const auto close = text.find(']');
        if (close == std::string::npos || close + 2U >= text.size() ||
            text[close + 1U] != ':') {
            throw std::invalid_argument("endpoint must be [ipv6]:port");
        }
        return Endpoint{text.substr(1U, close - 1U),
                        parse_port(text.substr(close + 2U))};
    }
    const auto separator = text.rfind(':');
    if (separator == std::string::npos || separator == 0U ||
        separator + 1U >= text.size()) {
        throw std::invalid_argument("endpoint must be host:port");
    }
    return Endpoint{text.substr(0U, separator),
                    parse_port(text.substr(separator + 1U))};
}

std::uint64_t parse_u64(const std::string& value, const char* name) {
    if (value.empty()) {
        throw std::invalid_argument(std::string("missing ") + name);
    }
    std::uint64_t parsed = 0U;
    const char* begin = value.data();
    const char* end = begin + value.size();
    const auto [ptr, error] = std::from_chars(begin, end, parsed, 10);
    if (error != std::errc{} || ptr != end || parsed == 0U) {
        throw std::invalid_argument(std::string("invalid ") + name);
    }
    return parsed;
}

std::uint32_t parse_u32(const std::string& value, const char* name) {
    const auto parsed = parse_u64(value, name);
    if (parsed > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument(std::string(name) + " is too large");
    }
    return static_cast<std::uint32_t>(parsed);
}

std::string required_param(const httplib::Request& request, const char* name) {
    if (!request.has_param(name)) {
        throw std::invalid_argument(std::string("missing form field: ") + name);
    }
    const std::string value = request.get_param_value(name);
    if (value.empty()) {
        throw std::invalid_argument(std::string("empty form field: ") + name);
    }
    return value;
}

void validate_username(const std::string& username) {
    if (username.size() < 3U || username.size() > 32U) {
        throw std::invalid_argument("username must be 3 to 32 characters");
    }
    if (std::isalpha(static_cast<unsigned char>(username.front())) == 0) {
        throw std::invalid_argument("username must start with a letter");
    }
    for (const char ch : username) {
        const auto value = static_cast<unsigned char>(ch);
        if (std::isalnum(value) == 0 && ch != '_' && ch != '-') {
            throw std::invalid_argument(
                "username may only contain letters, digits, '-' and '_'");
        }
    }
}

void validate_password(const std::string& password) {
    if (password.size() < 8U) {
        throw std::invalid_argument("password must be at least 8 characters");
    }
    if (password.size() > 256U) {
        throw std::invalid_argument("password is too long");
    }
}

std::optional<std::string> read_cookie(const httplib::Request& request,
                                       const std::string& name) {
    const std::string header = request.get_header_value("Cookie");
    std::size_t position = 0U;
    while (position < header.size()) {
        const auto semicolon = header.find(';', position);
        const std::string part = header.substr(
            position, semicolon == std::string::npos ? std::string::npos
                                                      : semicolon - position);
        const auto start = part.find_first_not_of(' ');
        if (start != std::string::npos) {
            const std::string trimmed = part.substr(start);
            const auto equals = trimmed.find('=');
            if (equals != std::string::npos && trimmed.substr(0, equals) == name) {
                return trimmed.substr(equals + 1U);
            }
        }
        if (semicolon == std::string::npos) {
            break;
        }
        position = semicolon + 1U;
    }
    return std::nullopt;
}

// Only meaningfully enforced when a browser sends Origin, which it does for
// the cross-site requests this guards against (login/registration CSRF).
bool same_origin(const httplib::Request& request) {
    const std::string origin = request.get_header_value("Origin");
    if (origin.empty()) {
        return true;
    }
    const auto scheme_end = origin.find("://");
    if (scheme_end == std::string::npos) {
        return false;
    }
    return origin.substr(scheme_end + 3U) == request.get_header_value("Host");
}

// json_escape() is for JSON string literals and does not escape '<', '>' or
// '&'; anything placed into HTML body content (as opposed to a JSON payload
// or a JS string literal) must go through this instead.
std::string html_escape(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (const char ch : text) {
        switch (ch) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&#39;"; break;
        default: out += ch;
        }
    }
    return out;
}

std::string to_hex(const std::vector<std::uint8_t>& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string text;
    text.reserve(bytes.size() * 2U);
    for (const auto byte : bytes) {
        text.push_back(digits[(byte >> 4U) & 0x0fU]);
        text.push_back(digits[byte & 0x0fU]);
    }
    return text;
}

template <std::size_t N>
std::string to_hex(const std::array<std::uint8_t, N>& bytes) {
    return to_hex(std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
}

std::vector<std::uint8_t> from_hex(const std::string& raw_text) {
    // Originally written for AccountStore's own on-disk hex fields only
    // (hence trimming wasn't needed - that text never came from a human);
    // now also used to parse pasted hex from a browser form (recognition
    // public_key/signature/nonce - see /api/recognition/answer-external),
    // where a copy-paste picking up a trailing newline or stray space is a
    // completely ordinary mistake to make, not corruption.
    const auto first = raw_text.find_first_not_of(" \t\r\n");
    const auto last = raw_text.find_last_not_of(" \t\r\n");
    const std::string text =
        first == std::string::npos ? std::string{} : raw_text.substr(first, last - first + 1U);
    if (text.size() % 2U != 0U || text.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
        throw std::invalid_argument("expected a hex string with an even number of characters");
    }
    std::vector<std::uint8_t> bytes(text.size() / 2U);
    for (std::size_t index = 0U; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::uint8_t>(
            std::stoul(text.substr(index * 2U, 2U), nullptr, 16));
    }
    return bytes;
}

// An enrolled login key's suite plus its raw public-key bytes - length
// depends on suite_id (32 for kLoginSuiteEd25519V1, 1952 for
// kLoginSuiteMlDsa65V1). Kept as raw bytes rather than a fixed-size typed
// array so the account store doesn't need a second field type per suite;
// login.hpp's own suite-specific verify functions are the only place that
// interprets these bytes cryptographically.
struct EnrolledLoginKey {
    std::uint16_t suite_id{};
    std::vector<std::uint8_t> bytes;
};

std::size_t expected_login_key_length(std::uint16_t suite_id) {
    if (suite_id == tradep2p::kLoginSuiteEd25519V1) {
        return tradep2p::kEd25519PublicKeyLength;
    }
    if (suite_id == tradep2p::kLoginSuiteMlDsa65V1) {
        return tradep2p::kMlDsa65PublicKeyLength;
    }
    return 0U; // unknown suite - never a valid length, rejected by callers
}

std::size_t expected_login_signature_length(std::uint16_t suite_id) {
    if (suite_id == tradep2p::kLoginSuiteEd25519V1) {
        return tradep2p::kEd25519SignatureLength;
    }
    if (suite_id == tradep2p::kLoginSuiteMlDsa65V1) {
        return tradep2p::kMlDsa65SignatureLength;
    }
    return 0U;
}

std::string login_suite_name(std::uint16_t suite_id) {
    if (suite_id == tradep2p::kLoginSuiteEd25519V1) {
        return "ed25519";
    }
    if (suite_id == tradep2p::kLoginSuiteMlDsa65V1) {
        return "ml-dsa-65";
    }
    return "unknown";
}

struct Account {
    std::string username;
    std::vector<std::uint8_t> salt;
    std::vector<std::uint8_t> hash;
    std::string created_at;
    // Phase 7 (service-scoped challenge-response login, see
    // include/tradep2p/login.hpp): absent means password-only, exactly the
    // pre-phase-7 shape - migration requires this, so every existing
    // account keeps working unmodified with no server-side action needed.
    // Present means the account has OPTED IN to also (not instead of - see
    // AccountStore::verify()/login_key(), password auth is never disabled
    // by enrolling a key) accepting challenge-response login with this key.
    std::optional<EnrolledLoginKey> login_key;
};

// A local convenience-account store for this web client only. It has no
// relationship to the anonymous mediator protocol: it exists so a visitor's
// browser session can be re-attached after a reload, not to identify anyone
// to a peer or to the mediator.
class AccountStore {
public:
    explicit AccountStore(std::string path) : path_(std::move(path)) { load(); }

    bool exists(const std::string& username) {
        std::scoped_lock lock(mutex_);
        return accounts_.find(username) != accounts_.end();
    }

    void create(const std::string& username, const std::string& password) {
        std::vector<std::uint8_t> salt(kSaltLength);
        if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
            throw std::runtime_error("RAND_bytes failed while creating an account");
        }
        Account account{username, salt, derive(password, salt), now_text(), std::nullopt};
        std::scoped_lock lock(mutex_);
        if (accounts_.find(username) != accounts_.end()) {
            throw std::runtime_error("that username is already registered");
        }
        append_locked(account);
        accounts_.emplace(username, std::move(account));
    }

    bool verify(const std::string& username, const std::string& password) {
        std::scoped_lock lock(mutex_);
        const auto it = accounts_.find(username);
        if (it == accounts_.end()) {
            // Pay the same PBKDF2 cost as a real lookup even for an unknown
            // username, so response timing cannot be used to enumerate which
            // usernames are registered.
            static const std::vector<std::uint8_t> dummy_salt(kSaltLength, 0U);
            (void)derive(password, dummy_salt);
            return false;
        }
        const auto candidate = derive(password, it->second.salt);
        return candidate.size() == it->second.hash.size() &&
               CRYPTO_memcmp(candidate.data(), it->second.hash.data(),
                            candidate.size()) == 0;
    }

    // Phase 7: binds `key` to an EXISTING account, enrolling it for
    // challenge-response login going forward - the explicit, no-access-lost
    // migration path (docs/identity-07-login.md). Throws std::runtime_error
    // if the account does not exist; callers (the /api/account/enroll-key
    // route) require an already-authenticated session before calling this,
    // so "does the caller actually own this account" is established before
    // this function is ever reached, not by this function itself.
    void set_login_key(const std::string& username, std::uint16_t suite_id,
                       const std::vector<std::uint8_t>& key_bytes) {
        std::scoped_lock lock(mutex_);
        const auto it = accounts_.find(username);
        if (it == accounts_.end()) {
            throw std::runtime_error("unknown account");
        }
        it->second.login_key = EnrolledLoginKey{suite_id, key_bytes};
        append_locked(it->second);
    }

    // std::nullopt for an unknown username OR a known one with no enrolled
    // key - callers must not distinguish the two in any response they send
    // back to a caller who hasn't already authenticated (account
    // enumeration - see the /api/login/key/* routes).
    std::optional<EnrolledLoginKey> login_key(const std::string& username) {
        std::scoped_lock lock(mutex_);
        const auto it = accounts_.find(username);
        if (it == accounts_.end() || !it->second.login_key.has_value()) {
            return std::nullopt;
        }
        return it->second.login_key;
    }

    // Admin-only listing: username, creation time, and whether a login key
    // is enrolled - deliberately never the salt or password hash. Sorted by
    // created_at so the newest registration is easy to find.
    std::vector<std::pair<std::string, std::string>> list_summary() {
        std::scoped_lock lock(mutex_);
        std::vector<std::pair<std::string, std::string>> out;
        out.reserve(accounts_.size());
        for (const auto& [username, account] : accounts_) {
            out.emplace_back(username, account.created_at);
        }
        std::sort(out.begin(), out.end(),
                 [](const auto& left, const auto& right) { return left.second < right.second; });
        return out;
    }

private:
    static std::vector<std::uint8_t> derive(const std::string& password,
                                             const std::vector<std::uint8_t>& salt) {
        std::vector<std::uint8_t> out(kHashLength);
        if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                              salt.data(), static_cast<int>(salt.size()),
                              kPbkdf2Iterations, EVP_sha256(),
                              static_cast<int>(out.size()), out.data()) != 1) {
            throw std::runtime_error("password hashing failed");
        }
        return out;
    }

    void load() {
        std::ifstream input(path_);
        if (!input.is_open()) {
            return;
        }
        std::string line;
        while (std::getline(input, line)) {
            if (line.empty() || line.front() == '#') {
                continue;
            }
            std::istringstream stream(line);
            std::string username, salt_hex, hash_hex, created_at, login_key_hex, suite_text;
            if (!std::getline(stream, username, '\t') ||
                !std::getline(stream, salt_hex, '\t') ||
                !std::getline(stream, hash_hex, '\t') ||
                !std::getline(stream, created_at, '\t')) {
                continue;
            }
            // Phase 7's trailing 5th field (login key hex), optional for
            // backward compatibility: a pre-phase-7 record has no 5th
            // field at all, so this getline() simply finds nothing left
            // and leaves login_key_hex empty - treated identically to an
            // account that exists but never enrolled a key. Every account
            // record is re-appended in full on every mutation (see
            // append_locked()/set_login_key()), and this loop lets a LATER
            // line for the same username overwrite an earlier one, so the
            // most recent record always wins.
            std::getline(stream, login_key_hex, '\t');
            // Phase "Phase 2 post-quantum" trailing 6th field (suite id, as
            // decimal text), same optional-trailing-field convention as the
            // 5th field above: a pre-this-change record has no 6th field at
            // all, so a present-but-suite-less key must have been enrolled
            // before any suite but Ed25519 existed - defaulting to
            // kLoginSuiteEd25519V1 here is therefore exact, not a guess.
            std::getline(stream, suite_text);
            Account account{username, from_hex(salt_hex), from_hex(hash_hex), created_at,
                            std::nullopt};
            if (!login_key_hex.empty()) {
                // A malformed trailing field (non-numeric suite id, wrong
                // length for the suite, unknown suite id) is treated as "no
                // key enrolled" rather than aborting the whole load -
                // password auth for this and every other account must keep
                // working regardless.
                std::uint16_t suite_id = tradep2p::kLoginSuiteEd25519V1;
                bool suite_valid = true;
                if (!suite_text.empty()) {
                    try {
                        std::size_t consumed = 0;
                        const unsigned long parsed = std::stoul(suite_text, &consumed);
                        suite_valid = consumed == suite_text.size() &&
                                     parsed <= std::numeric_limits<std::uint16_t>::max();
                        suite_id = static_cast<std::uint16_t>(parsed);
                    } catch (const std::exception&) {
                        suite_valid = false;
                    }
                }
                const auto raw = from_hex(login_key_hex);
                if (suite_valid && raw.size() == expected_login_key_length(suite_id)) {
                    account.login_key = EnrolledLoginKey{suite_id, raw};
                }
            }
            accounts_[username] = std::move(account);
        }
    }

    void append_locked(const Account& account) {
        const std::filesystem::path file_path(path_);
        if (file_path.has_parent_path()) {
            std::filesystem::create_directories(file_path.parent_path());
        }
        std::ofstream output(path_, std::ios::app);
        if (!output.is_open()) {
            throw std::runtime_error("failed to open the account store for writing");
        }
        output << account.username << '\t' << to_hex(account.salt) << '\t'
               << to_hex(account.hash) << '\t' << account.created_at << '\t'
               << (account.login_key.has_value() ? to_hex(account.login_key->bytes) : std::string{})
               << '\t'
               << (account.login_key.has_value() ? std::to_string(account.login_key->suite_id)
                                                  : std::string{})
               << '\n';
        output.close();
        // The file holds password salts and hashes; keep it readable only by
        // whoever runs this process, regardless of the process umask.
        ::chmod(path_.c_str(), S_IRUSR | S_IWUSR);
    }

    std::string path_;
    std::mutex mutex_;
    std::unordered_map<std::string, Account> accounts_;
};

// Phase 7 (docs/identity-07-login.md: "rate-limit authentication
// attempts"). A simple per-username sliding-window limiter, applied to
// BOTH the existing password path and the new key-based path - both are
// "authentication attempts" against the same account. Deliberately
// per-username, not per-IP: this binary expects to sit behind a reverse
// proxy (see the file's top comment), and trusting a client-supplied or
// proxy-supplied source IP at this layer without a verified proxy
// allowlist would be easy to spoof. This does not stop a distributed
// attacker trying many DIFFERENT usernames at once - that is a
// reverse-proxy/WAF concern outside this binary's trust boundary - but it
// does stop credential stuffing or online guessing against one account,
// which is the concrete risk this phase's login mechanism exists to
// reduce. Rate-limiting applies identically whether or not the username
// is real, so it adds no new account-enumeration signal.
class AuthRateLimiter {
public:
    [[nodiscard]] bool allowed(const std::string& username) {
        std::scoped_lock lock(mutex_);
        prune_locked(username);
        const auto it = failures_.find(username);
        return it == failures_.end() || it->second.size() < kMaxAttempts;
    }

    void record_failure(const std::string& username) {
        std::scoped_lock lock(mutex_);
        prune_locked(username);
        failures_[username].push_back(std::chrono::steady_clock::now());
    }

    void record_success(const std::string& username) {
        std::scoped_lock lock(mutex_);
        failures_.erase(username);
    }

private:
    void prune_locked(const std::string& username) {
        const auto it = failures_.find(username);
        if (it == failures_.end()) {
            return;
        }
        const auto cutoff = std::chrono::steady_clock::now() - kWindow;
        auto& attempts = it->second;
        attempts.erase(std::remove_if(attempts.begin(), attempts.end(),
                                      [cutoff](const auto& when) { return when < cutoff; }),
                       attempts.end());
        if (attempts.empty()) {
            failures_.erase(it);
        }
    }

    static constexpr std::size_t kMaxAttempts = 5U;
    static constexpr std::chrono::seconds kWindow{60};

    std::mutex mutex_;
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> failures_;
};

struct WebSession {
    std::string username;
    std::string csrf_token;
    std::shared_ptr<DashboardClient> client;
    std::chrono::steady_clock::time_point last_seen;
    // Phase 9 (docs/identity-09-hosted-webclient.md): a per-account trading
    // identity, absent until the user explicitly enables it (see
    // SessionManager::keystore_enable() - never created automatically at
    // registration or login). Protected by the account's own login
    // password, re-verified via AccountStore::verify() on every use rather
    // than cached - see keystore_enable()'s comment for why a second,
    // separate passphrase would not buy back anything real in this
    // already-hosted trust model. Unlocked into memory only while this
    // session is active; dropped on logout/idle-reap same as the rest of
    // WebSession, or explicitly via /api/keystore/lock.
    std::optional<tradep2p::IdentityKeystore> keystore;
    std::string keystore_path;
    std::optional<tradep2p::LocalCounterpartyHistory> history;
};

struct SessionHandle {
    std::string username;
    std::string csrf_token;
    std::shared_ptr<DashboardClient> client;
};

struct KeystoreStatus {
    bool loaded = false;
    bool unlocked = false;
    std::string alias;
    std::string identity_id_hex;
    std::string public_key_hex;
    std::string public_key_mldsa65_hex; // empty unless unlocked - never cached on disk
    std::uint64_t created_at = 0U;
    std::uint32_t key_generation = 0U;
    std::string path;
};

// One running mediator connection per logged-in account. Logging in again
// from another tab or browser re-attaches the same session instead of
// opening a second connection, matching a "create once, terminate on logout"
// session model.
class SessionManager {
public:
    SessionManager(Endpoint mediator, ClientTlsPolicy tls,
                  std::optional<Endpoint> proxy, std::size_t max_sessions,
                  std::chrono::minutes idle_timeout, std::string mediator_id,
                  std::string keystore_dir)
        : mediator_(std::move(mediator)),
          tls_(std::move(tls)),
          proxy_(std::move(proxy)),
          max_sessions_(max_sessions),
          idle_timeout_(idle_timeout),
          mediator_id_(std::move(mediator_id)),
          keystore_dir_(std::move(keystore_dir)) {}

    std::string login(const std::string& username) {
        std::scoped_lock lock(mutex_);
        const auto active_it = active_by_user_.find(username);
        if (active_it != active_by_user_.end()) {
            const auto session_it = sessions_.find(active_it->second);
            if (session_it != sessions_.end()) {
                session_it->second.last_seen = std::chrono::steady_clock::now();
                return active_it->second;
            }
            active_by_user_.erase(active_it);
        }
        if (sessions_.size() >= max_sessions_) {
            throw std::runtime_error(
                "this web client is at capacity, please try again shortly");
        }
        auto client = std::make_shared<DashboardClient>(mediator_, tls_, proxy_, mediator_id_);
        const std::string token = random_token();

        // Phase 9 wiring: bridges DashboardClient's worker thread (which
        // knows nothing about per-account keystores) to this session's own
        // WebSession entry in sessions_ - mirrors http_dashboard.cpp's
        // identical single-operator wiring, just keyed by session token
        // instead of one global state struct, since this process serves
        // many concurrent accounts. Looks the session up fresh on every
        // call (not a captured reference) since a session can be logged
        // out or its keystore locked at any time between callback
        // registration and an actual challenge arriving. Must be set
        // before client->start() so no early RecognitionChallenge/Response
        // frame can race an unset callback.
        client->set_recognition_key_provider(
            [this, token]() -> std::optional<tradep2p::dashboard::RecognitionKeyMaterial> {
                std::scoped_lock callback_lock(mutex_);
                const auto it = sessions_.find(token);
                if (it == sessions_.end() || !it->second.keystore.has_value() ||
                    !it->second.keystore->is_unlocked()) {
                    return std::nullopt;
                }
                auto keypair = tradep2p::derive_ed25519_keypair(
                    it->second.keystore->master_secret(),
                    tradep2p::key_scope::kMediatorPseudonym, mediator_id_);
                auto mldsa65_keypair = tradep2p::derive_mldsa65_keypair(
                    it->second.keystore->master_secret(),
                    tradep2p::key_scope::kMediatorPseudonymMlDsa65, mediator_id_);
                tradep2p::dashboard::RecognitionKeyMaterial material;
                material.private_seed = std::move(keypair.private_seed);
                material.public_key = keypair.public_key;
                material.mldsa65_private_seed = std::move(mldsa65_keypair.private_seed);
                material.mldsa65_public_key = mldsa65_keypair.public_key;
                return material;
            });
        client->set_recognition_outcome_handler(
            [this, token](const std::array<std::uint8_t, 32>& fingerprint,
                          tradep2p::dashboard::RecognitionOutcome outcome) {
                std::scoped_lock callback_lock(mutex_);
                const auto it = sessions_.find(token);
                if (it == sessions_.end() || !it->second.keystore.has_value() ||
                    !it->second.keystore->is_unlocked()) {
                    return;
                }
                auto& history = ensure_history_open_locked(it->second);
                const tradep2p::CounterpartyFingerprint counterparty_fingerprint = fingerprint;
                history.record_encounter(
                    counterparty_fingerprint, mediator_id_,
                    outcome == tradep2p::dashboard::RecognitionOutcome::Successful
                        ? tradep2p::LocalOutcome::Successful
                        : tradep2p::LocalOutcome::Incomplete);
            });
        client->start();

        sessions_.emplace(
            token, WebSession{username, random_token(), std::move(client),
                              std::chrono::steady_clock::now(), std::nullopt,
                              std::string{}, std::nullopt});
        active_by_user_[username] = token;
        return token;
    }

    std::string keystore_path_for(const std::string& username) const {
        return keystore_dir_ + "/" + username + ".keystore";
    }

    // Creates a trading identity for this account if none exists yet, or
    // unlocks the existing one - protected by the account's own login
    // password (re-verified by the caller via AccountStore::verify() before
    // this is called; see this file's /api/keystore/enable route). A second,
    // separate keystore passphrase was deliberately not added: this hosted
    // model already accepts the operator seeing session activity (see the
    // honest-disclosure copy on the login page), so a second secret would
    // not buy back any real protection, only friction.
    void keystore_enable(const std::string& token, const std::string& password) {
        std::scoped_lock lock(mutex_);
        const auto it = sessions_.find(token);
        if (it == sessions_.end()) {
            throw std::runtime_error("session not found");
        }
        const std::string path = keystore_path_for(it->second.username);
        if (std::filesystem::exists(path)) {
            it->second.keystore = tradep2p::IdentityKeystore::unlock(path, password);
        } else {
            it->second.keystore =
                tradep2p::IdentityKeystore::create(path, password, it->second.username);
        }
        it->second.keystore_path = path;
        it->second.history.reset();
    }

    void keystore_lock(const std::string& token) {
        std::scoped_lock lock(mutex_);
        const auto it = sessions_.find(token);
        if (it == sessions_.end()) {
            return;
        }
        if (it->second.keystore.has_value()) {
            it->second.keystore->lock();
        }
    }

    [[nodiscard]] std::optional<KeystoreStatus> keystore_status(const std::string& token) {
        std::scoped_lock lock(mutex_);
        const auto it = sessions_.find(token);
        if (it == sessions_.end()) {
            return std::nullopt;
        }
        KeystoreStatus status;
        const std::string path = keystore_path_for(it->second.username);
        status.path = path;
        status.loaded = it->second.keystore.has_value() || std::filesystem::exists(path);
        if (it->second.keystore.has_value()) {
            status.unlocked = it->second.keystore->is_unlocked();
            const auto identity = it->second.keystore->public_identity();
            status.alias = identity.alias;
            status.identity_id_hex = to_hex(identity.identity_id);
            status.public_key_hex = to_hex(identity.identity_public_key);
            if (status.unlocked) {
                status.public_key_mldsa65_hex =
                    to_hex(it->second.keystore->identity_public_key_mldsa65());
            }
            status.created_at = identity.created_at;
            status.key_generation = identity.key_generation;
        }
        return status;
    }

    // Streams the raw on-disk keystore FILE bytes - already encrypted at
    // rest per keystore.hpp's format, never decrypted here. Does not
    // require the keystore to currently be unlocked in this session, only
    // that the file exists; the caller (the /api/keystore/export route)
    // re-verifies the account password before calling this regardless.
    [[nodiscard]] std::vector<std::uint8_t> keystore_export_bytes(const std::string& token) {
        std::string path;
        {
            std::scoped_lock lock(mutex_);
            const auto it = sessions_.find(token);
            if (it == sessions_.end()) {
                throw std::runtime_error("session not found");
            }
            path = keystore_path_for(it->second.username);
        }
        std::ifstream input(path, std::ios::binary);
        if (!input.is_open()) {
            throw std::runtime_error("no trading identity exists for this account yet");
        }
        return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(input),
                                         std::istreambuf_iterator<char>());
    }

    [[nodiscard]] std::string history_list_json(const std::string& token) {
        std::scoped_lock lock(mutex_);
        const auto it = sessions_.find(token);
        if (it == sessions_.end() || !it->second.keystore.has_value() ||
            !it->second.keystore->is_unlocked()) {
            return "{\"ok\":true,\"unlocked\":false,\"entries\":[]}";
        }
        auto& history = ensure_history_open_locked(it->second);
        std::ostringstream json;
        json << "{\"ok\":true,\"unlocked\":true,\"entries\":[";
        bool first_entry = true;
        for (const auto& entry : history.entries()) {
            if (!first_entry) {
                json << ',';
            }
            first_entry = false;
            json << "{\"fingerprint\":\"" << json_escape(tradep2p::fingerprint_to_hex(entry.fingerprint))
                 << "\",\"mediator_id\":\"" << json_escape(entry.mediator_id) << "\""
                 << ",\"first_seen\":" << entry.first_seen << ",\"last_seen\":" << entry.last_seen
                 << ",\"encounter_count\":" << entry.encounter_count
                 << ",\"locally_blocked\":" << (entry.locally_blocked ? "true" : "false")
                 << ",\"confidence\":\"" << tradep2p::confidence_level_name(entry.confidence) << "\""
                 << ",\"display_category\":\""
                 << tradep2p::display_category_name(tradep2p::classify_for_display(entry)) << "\""
                 << ",\"notes\":[";
            bool first_note = true;
            for (const auto& note : entry.notes) {
                if (!first_note) {
                    json << ',';
                }
                first_note = false;
                json << "{\"recorded_at\":" << note.recorded_at << ",\"text\":\""
                     << json_escape(note.text) << "\"}";
            }
            json << "],\"evidence_count\":" << entry.evidence_hashes.size() << "}";
        }
        json << "]}";
        return json.str();
    }

    void history_set_blocked(const std::string& token, const std::string& fingerprint_hex,
                             bool blocked) {
        std::scoped_lock lock(mutex_);
        const auto it = sessions_.find(token);
        if (it == sessions_.end()) {
            throw std::runtime_error("session not found");
        }
        auto& history = ensure_history_open_locked(it->second);
        history.set_blocked(tradep2p::fingerprint_from_hex(fingerprint_hex), mediator_id_, blocked);
    }

    void history_add_note(const std::string& token, const std::string& fingerprint_hex,
                          const std::string& text) {
        std::scoped_lock lock(mutex_);
        const auto it = sessions_.find(token);
        if (it == sessions_.end()) {
            throw std::runtime_error("session not found");
        }
        auto& history = ensure_history_open_locked(it->second);
        history.add_note(tradep2p::fingerprint_from_hex(fingerprint_hex), mediator_id_, text);
    }

    void logout(const std::string& token) {
        std::scoped_lock lock(mutex_);
        const auto it = sessions_.find(token);
        if (it == sessions_.end()) {
            return;
        }
        active_by_user_.erase(it->second.username);
        sessions_.erase(it);
    }

    std::optional<SessionHandle> touch(const std::string& token) {
        std::scoped_lock lock(mutex_);
        const auto it = sessions_.find(token);
        if (it == sessions_.end()) {
            return std::nullopt;
        }
        it->second.last_seen = std::chrono::steady_clock::now();
        return SessionHandle{it->second.username, it->second.csrf_token,
                             it->second.client};
    }

    void reap_idle() {
        const auto now = std::chrono::steady_clock::now();
        std::scoped_lock lock(mutex_);
        for (auto it = sessions_.begin(); it != sessions_.end();) {
            if (now - it->second.last_seen > idle_timeout_) {
                active_by_user_.erase(it->second.username);
                it = sessions_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    // PRECONDITION: mutex_ already held. Deliberately checks
    // keystore->is_unlocked() every time this is reached (every caller
    // already checked it too), not merely "was a history handle already
    // opened earlier" - see http_dashboard.cpp's identical helper for the
    // "Lock should stop rendering history immediately" reasoning this
    // mirrors.
    static tradep2p::LocalCounterpartyHistory& ensure_history_open_locked(WebSession& session) {
        if (!session.keystore.has_value() || !session.keystore->is_unlocked()) {
            throw std::invalid_argument("no unlocked trading identity; enable one first");
        }
        if (!session.history.has_value()) {
            session.history = tradep2p::LocalCounterpartyHistory::open(
                session.keystore_path + ".history", *session.keystore);
        }
        return *session.history;
    }

    Endpoint mediator_;
    ClientTlsPolicy tls_;
    std::optional<Endpoint> proxy_;
    std::size_t max_sessions_;
    std::chrono::minutes idle_timeout_;
    std::string mediator_id_;
    std::string keystore_dir_;

    std::mutex mutex_;
    std::unordered_map<std::string, WebSession> sessions_;
    std::unordered_map<std::string, std::string> active_by_user_;
};

void set_json_result(httplib::Response& response, bool ok,
                     const std::string& message, int status = 200) {
    response.status = status;
    response.set_content(
        std::string("{\"ok\":") + (ok ? "true" : "false") +
            (ok ? ",\"message\":\"" : ",\"error\":\"") + json_escape(message) +
            "\"}",
        "application/json; charset=utf-8");
}

constexpr const char* kPrivacyNotice =
    "Privacy is not guaranteed. This is a convenience web client hosted on a "
    "shared server. The operator of this page can observe your account "
    "activity, session timing and source IP address, even though the trade "
    "protocol itself stays anonymous to the mediator. Your username and "
    "password are only a local key for this browser session &mdash; they are "
    "not part of the TradeP2P protocol and are not sent to any mediator. For "
    "stronger privacy guarantees, run the CLI or dashboard client yourself, "
    "ideally over Tor.";

// Same pyramid-with-a-closed-eye mark as the marketing site's
// assets/img/favicon.svg, inlined as a data URI since this process serves
// no static files - kept in sync deliberately, used for both the favicon
// link and the header logo below so there is exactly one copy of the
// encoded SVG. Closed, not all-seeing: the mediator doesn't watch trades
// either.
std::string logo_data_uri() {
    return "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' "
           "viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='10' "
           "fill='%23060605'/%3E%3Crect x='1.5' y='1.5' width='61' "
           "height='61' rx='9' fill='none' stroke='%232a2a28' "
           "stroke-width='1.4'/%3E%3Cpath d='M32 11 L56 53 H8 Z' fill='none' "
           "stroke='%235b8fe6' stroke-width='2.2' "
           "stroke-linejoin='round'/%3E%3Cpath d='M23.5 26.5 H40.5' "
           "stroke='%235b8fe6' stroke-width='1.6' stroke-linecap='round'/%3E"
           "%3Cpath d='M21 36 Q32 41 43 36' fill='none' stroke='%238fb4f2' "
           "stroke-width='2.2' stroke-linecap='round'/%3E%3Cpath d='M26 38 "
           "L24.3 42' stroke='%238fb4f2' stroke-width='1.6' "
           "stroke-linecap='round'/%3E%3Cpath d='M32 39.4 L32 43.6' "
           "stroke='%238fb4f2' stroke-width='1.6' stroke-linecap='round'/%3E"
           "%3Cpath d='M38 38 L39.7 42' stroke='%238fb4f2' stroke-width='1.6' "
           "stroke-linecap='round'/%3E%3C/svg%3E";
}

// Matches htdocs/assets/css/style.css so this page reads as part of the
// same site once reverse-proxied under the marketing site's domain.
// Same dark "black-figure pottery" design system as the marketing site's
// assets/css/style.css and this project's own tradep2p-dashboard (restyled
// earlier this session) - shared palette/fonts/meander motif duplicated
// here rather than linked, since this binary serves everything standalone
// with no access to external asset files. .wide/.two-col below are this
// page's own data-density needs, same reasoning as the dashboard's wider
// .grid versus the marketing site's narrow prose .shell.
std::string page_head(const std::string& title, const std::string& home_url) {
    std::string html = R"HTML(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0c0c0a">
<link rel="icon" type="image/svg+xml" href="__LOGO_URI__">
<title>__TITLE__</title>
<style>
:root{--bg:#0c0c0a;--bg-deep:#060605;--panel:#17160f;--panel-2:#201f16;--line:#4a453a;--line-soft:#322f27;--text:#f2efe4;--muted:#a39d89;--accent:#5b8fe6;--accent-soft:#16233d;--amber:#d9a441;--danger:#d9635c;--sans:Verdana,Geneva,Arial,"Helvetica Neue",Helvetica,sans-serif;--mono:"Courier New",Courier,ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;--serif:Cambria,Georgia,"Times New Roman",Times,serif;--meander:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='14'%3E%3Cpath d='M0 12 L0 2 L8 2 L8 7 L16 7 L16 2 L24 2' fill='none' stroke='%235b8fe6' stroke-width='2.2'/%3E%3C/svg%3E")}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 var(--sans)}
a{color:var(--accent)}
code{font-family:var(--mono)}
h1,h2,h3{font-family:var(--serif);letter-spacing:.01em}
.site-header{position:relative;border-bottom:3px double var(--line);background:var(--panel)}
.site-header::after{content:"";display:block;height:12px;background-image:var(--meander);background-repeat:repeat-x;background-position:center;opacity:.8}
.nav-shell{min-height:56px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:10px 0}
.brand{display:inline-flex;align-items:center;gap:10px;text-decoration:none}
.brand-mark{display:block;width:32px;height:32px;flex:none;border-radius:6px}
.brand-copy{display:grid;line-height:1.15}
.brand-copy strong{font:700 15px var(--mono);color:var(--text)}
.brand-copy small{color:var(--muted);font-size:11px;letter-spacing:.03em;margin-top:2px}
.header-links{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.header-links .muted{font-size:12px}
.header-links a{font:700 12px var(--mono);text-transform:uppercase;letter-spacing:.03em;text-decoration:none}
.wrap{width:min(900px,calc(100% - 24px));margin:24px auto 60px}
.wide{width:min(1300px,calc(100% - 24px))}
.panel{border:1px solid var(--line);background:var(--panel);padding:20px;margin-bottom:16px;min-width:0}
.panel h2{margin:0 0 14px;color:var(--accent);font-size:1.05rem}
.panel h3{margin:0 0 10px;color:var(--text);font-size:.95rem}
.warning{border:1px solid var(--amber);background:#241a08;color:#e8c98a;padding:14px 16px;margin-bottom:18px;line-height:1.6}
.warning b{color:var(--amber)}
.disclosure{border:1px solid var(--accent);background:var(--accent-soft);color:var(--text);padding:14px 16px;margin-bottom:18px;line-height:1.6;font-size:.92rem}
.disclosure strong{color:var(--accent)}
h1{font-size:1.35rem;margin:0 0 6px}
.muted{color:var(--muted)}
label{display:grid;gap:5px;color:var(--muted);margin-bottom:12px;font-size:13px}
input,button{font:inherit;border:1px solid var(--line)}
input{width:100%;padding:9px 10px;background:var(--bg-deep);color:var(--text);min-width:0}
button{padding:8px 12px;background:var(--panel-2);color:var(--text);cursor:pointer}
button:hover{border-color:var(--accent)}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.primary:hover{background:#7fa8ee}
button.danger{background:#3a1c14;border-color:var(--danger);color:#f3c9c2}
button:disabled{opacity:.45;cursor:not-allowed}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:14px;min-width:0}
.two-col>div{min-width:0}
.notice{margin:10px 0 0;color:var(--amber)}
.error{color:var(--danger)}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{padding:9px 8px;border-bottom:1px solid var(--line-soft);text-align:left}
th{color:var(--muted);font:700 11px var(--mono);text-transform:uppercase;letter-spacing:.03em;white-space:nowrap}
td{font-size:13px}
.room{border:1px solid var(--line);background:var(--panel-2);padding:14px;margin-bottom:10px;min-width:0}
.mono-break{word-break:break-all;font-family:var(--mono);font-size:.85em}
.turn{margin-top:10px;padding:10px;border-left:3px solid var(--amber);background:var(--bg-deep)}
.events{max-height:260px;overflow:auto;margin:0;padding-left:20px;font-size:13px}
.events li{margin:5px 0;color:var(--text)}
.status{display:inline-block;padding:.25rem .6rem;border:1px solid var(--line);font:700 11px var(--mono);text-transform:uppercase;letter-spacing:.03em;background:var(--panel-2)}
.status.connected,.status.active,.status.complete{border-color:var(--accent);color:var(--accent);background:var(--accent-soft)}
.status.connecting{border-color:var(--amber);color:var(--amber);background:#241a08}
.status.disconnected,.status.aborted{border-color:var(--danger);color:var(--danger);background:#2a1512}
.topline{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.topline h2{margin:0}
button.copy{padding:2px 7px;font-size:.8rem;background:transparent;border-color:var(--line);color:var(--muted)}
button.copy:hover{color:var(--accent);border-color:var(--accent)}
.hexrow{display:flex;align-items:center;gap:6px;min-width:0}
.hexrow .mono-break{flex:1;min-width:0}
details.crypto{margin-top:10px;border-top:1px dashed var(--line);padding-top:8px}
details.crypto summary{cursor:pointer;color:var(--accent);font-size:.85rem}
details.crypto .field{margin:6px 0}
details.crypto .field b{display:block;color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.03em;margin-bottom:2px}
.receipt-card{background:var(--bg-deep);border:1px solid var(--line);padding:9px;margin-top:6px}
.pq{color:var(--accent)}
.classical{color:var(--amber)}
.server-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
.metric{background:var(--bg-deep);border:1px solid var(--line);padding:10px;min-width:0}
.metric b{display:block;color:var(--accent);font:700 11px var(--mono);text-transform:uppercase}
.danger-zone{border:1px dashed var(--danger);padding:12px;margin-top:10px}
@media(max-width:760px){.two-col{grid-template-columns:1fr}}
</style>
</head>
<body>
<header class="site-header">
  <div class="wrap wide nav-shell">
    <a class="brand" href="/">
      <img class="brand-mark" src="__LOGO_URI__" width="32" height="32" alt="">
      <span class="brand-copy"><strong>TRADEP2P</strong><small>hosted web client</small></span>
    </a>
    <div class="header-links">
      <span class="muted">hosted session &middot; not the mediator itself</span>
__HOME_LINK__
    </div>
  </div>
</header>
)HTML";

    const auto replace_all = [&](const std::string& needle, const std::string& replacement) {
        std::size_t position = 0U;
        while ((position = html.find(needle, position)) != std::string::npos) {
            html.replace(position, needle.size(), replacement);
            position += replacement.size();
        }
    };
    replace_all("__LOGO_URI__", logo_data_uri());
    replace_all("__TITLE__", title);
    replace_all("__HOME_LINK__",
                home_url.empty() ? std::string{}
                                 : ("<a href=\"" + html_escape(home_url) + "\">&larr; main site</a>"));
    return html;
}

std::string landing_html(const std::string& preauth_token, const std::string& home_url) {
    std::string html = page_head("TradeP2P Web Client", home_url) + R"HTML(<div class="wrap">
<div class="warning"><b>&#9888; Privacy warning.</b> __PRIVACY_NOTICE__</div>
<div class="disclosure">
<strong>The honest ceiling, stated plainly (protocol_spec.md &sect;9.6, normative):</strong>
this account system - password login, and the optional key-based login below -
protects only against compromise of stored credentials: a leaked account
database, credential stuffing from a password you reused elsewhere. It does
<strong>not</strong>, and cannot, protect against this server's own operator, who
controls every byte of code this page ever sends your browser and could ship
a version that reads your key the moment you use it. That is true no matter
how the signing happens client-side - it is not a bug this page can fix with
more JavaScript. If you need protection from this server's operator, use the
native CLI or <code>tradep2p-dashboard</code> instead, ideally over Tor - see
the <a href="documentation.php">documentation</a>.
</div>
<h1>TradeP2P web client</h1>
<p class="muted">Create a session to publish offers, join trades and settle fractional rounds from your browser.</p>
<div id="notice" class="notice"></div>
<div class="two-col">
<section class="panel">
<h2>Log in</h2>
<form id="login-form">
<label>Username<input name="username" maxlength="32" required autocomplete="username"></label>
<label>Password<input name="password" type="password" maxlength="256" required autocomplete="current-password"></label>
<button class="primary" type="submit">Log in</button>
</form>
</section>
<section class="panel">
<h2>Register</h2>
<form id="register-form">
<label>Username (3-32 letters/digits/-/_)<input name="username" maxlength="32" required autocomplete="username"></label>
<label>Password (8+ characters)<input name="password" type="password" maxlength="256" required autocomplete="new-password"></label>
<button class="primary" type="submit">Create session</button>
</form>
</section>
</div>
<section class="panel">
<h2>Log in with a key</h2>
<p class="muted">For an account that has enrolled a login key (see "Account" once
logged in). Same ceiling as above: this protects against a leaked password
database or credential stuffing, <strong>not</strong> against this server's own
operator. Signing happens OUTSIDE this browser page (a native client or other
external tool you trust) - this page never generates or holds this login key's
private seed.</p>
<form id="key-challenge-form">
<label>Username<input name="username" id="key-username" maxlength="32" required autocomplete="username"></label>
<button type="submit">Request login challenge</button>
</form>
<div id="key-challenge-box" style="display:none">
<p class="muted">Sign these exact bytes with your enrolled key's private seed,
using the same external tool that generated it, then paste the resulting
signature below. Expires <span id="key-expires"></span> (unix seconds).</p>
<table class="mono-break"><tbody>
<tr><td>suite</td><td id="key-suite"></td></tr>
<tr><td>service_id</td><td id="key-service"></td></tr>
<tr><td>server_identity</td><td id="key-server"></td></tr>
<tr><td>session_id</td><td id="key-session"></td></tr>
<tr><td>nonce</td><td id="key-nonce"></td></tr>
<tr><td>created_at</td><td id="key-created"></td></tr>
</tbody></table>
<form id="key-verify-form">
<label>Signature (hex - 128 chars for Ed25519, 6618 for ML-DSA-65)<input name="signature" id="key-signature" maxlength="6618" required></label>
<button class="primary" type="submit">Log in</button>
</form>
</div>
</section>
<p class="muted">This account exists only on this server, only to let you resume
a session. It is not a protocol identity and is never shown to your trade
counterparty or the mediator. A key badge or key-based login here means only
"controlled the same enrolled key" - never trusted, verified, or safe
(protocol_spec.md &sect;9.6). A separate, optional trading identity - used for
counterparty recognition in the mediator protocol itself, entirely distinct
from this login account - can be enabled after logging in; see "Trading
identity" once you're in.</p>
</div>
<script>
const PREAUTH_TOKEN="__PREAUTH_TOKEN__";
function notice(t,bad){const n=document.getElementById('notice');n.textContent=t;n.className=bad?'notice error':'notice'}
async function submitForm(form,path){const d=Object.fromEntries(new FormData(form));const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','__PREAUTH_HEADER__':PREAUTH_TOKEN},body:new URLSearchParams(d)});const body=await r.json().catch(()=>({ok:false,error:'invalid response'}));if(!r.ok||!body.ok)throw new Error(body.error||('HTTP '+r.status));location.reload()}
document.getElementById('login-form').onsubmit=async(e)=>{e.preventDefault();try{await submitForm(e.target,'/api/login')}catch(err){notice(err.message,true)}};
document.getElementById('register-form').onsubmit=async(e)=>{e.preventDefault();try{await submitForm(e.target,'/api/register')}catch(err){notice(err.message,true)}};
let pendingSessionId=null;
document.getElementById('key-challenge-form').onsubmit=async(e)=>{e.preventDefault();try{const username=document.getElementById('key-username').value;const r=await fetch('/api/login/key/challenge',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','__PREAUTH_HEADER__':PREAUTH_TOKEN},body:new URLSearchParams({username})});const body=await r.json();if(!r.ok||!body.ok)throw new Error(body.error||('HTTP '+r.status));pendingSessionId=body.session_id;document.getElementById('key-suite').textContent=body.suite;document.getElementById('key-service').textContent=body.service_id;document.getElementById('key-server').textContent=body.server_identity;document.getElementById('key-session').textContent=body.session_id;document.getElementById('key-nonce').textContent=body.nonce;document.getElementById('key-created').textContent=body.created_at;document.getElementById('key-expires').textContent=body.expires_at;document.getElementById('key-challenge-box').style.display='block'}catch(err){notice(err.message,true)}};
document.getElementById('key-verify-form').onsubmit=async(e)=>{e.preventDefault();try{const username=document.getElementById('key-username').value;const signature=document.getElementById('key-signature').value;const r=await fetch('/api/login/key/verify',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','__PREAUTH_HEADER__':PREAUTH_TOKEN},body:new URLSearchParams({username,session_id:pendingSessionId,signature})});const body=await r.json();if(!r.ok||!body.ok)throw new Error(body.error||('HTTP '+r.status));location.reload()}catch(err){notice(err.message,true)}};
</script>
</body>
</html>)HTML";

    const auto replace_all = [&](const std::string& needle, const std::string& replacement) {
        std::size_t position = 0U;
        while ((position = html.find(needle, position)) != std::string::npos) {
            html.replace(position, needle.size(), replacement);
            position += replacement.size();
        }
    };
    replace_all("__PRIVACY_NOTICE__", kPrivacyNotice);
    replace_all("__PREAUTH_TOKEN__", preauth_token);
    replace_all("__PREAUTH_HEADER__", kPreAuthHeader);
    return html;
}

std::string app_html(const std::string& username, const std::string& csrf_token,
                      const std::string& home_url) {
    std::string html = page_head("TradeP2P Web Client", home_url) + R"HTML(<div class="wrap wide">
<div class="warning"><b>&#9888; Privacy warning.</b> __PRIVACY_NOTICE__</div>
<div class="panel topline">
<div><div class="muted">TRADEP2P WEB CLIENT</div><h1>Session: __USERNAME__</h1>
<div id="identity" class="muted">connecting&hellip;</div></div>
<div class="row"><span id="connection" class="status connecting">connecting</span>
<button class="danger" id="logout">Log out</button></div>
</div>
<div id="notice" class="notice"></div>
<section class="panel">
<h2>Trading identity</h2>
<p class="muted">A separate, optional identity used only for counterparty
recognition in the mediator protocol itself - distinct from your login
account above, and from the protocol's own anonymity (the mediator never
sees this). Protected by your account password; not created automatically.
See the crypto detail under each room once you have one.</p>
<div id="identity-status" class="muted">loading trading identity status&hellip;</div>
<form id="keystore-form" class="row">
<label style="flex:1;min-width:200px">Account password<input name="ks_password" type="password" required autocomplete="current-password"></label>
<div class="row" style="align-items:flex-end;padding-bottom:12px">
<button type="button" id="ks-enable" class="primary">Enable / unlock</button>
<button type="button" id="ks-lock">Lock</button>
</div>
</form>
<div class="danger-zone">
<button type="button" id="ks-export-reveal">Export encrypted keystore&hellip;</button>
<form id="ks-export-form" style="display:none;margin-top:10px" >
<p class="muted"><b>This downloads your trading identity's encrypted keystore
file.</b> Anyone who gets both this file and your account password can act as
this identity. Use this to move to running the native CLI or
tradep2p-dashboard yourself instead of staying hosted - the file is portable,
unmodified, to either.</p>
<label>Account password (again)<input name="ks_export_password" type="password" required autocomplete="current-password"></label>
<label style="display:flex;align-items:center;gap:8px;flex-direction:row"><input type="checkbox" name="ks_export_confirm" required style="width:auto">I understand this exports my encrypted keystore file</label>
<button type="submit" class="danger">Download keystore</button>
</form>
</div>
</section>
<div class="two-col">
<div>
<section class="panel">
<h2>Publish offer</h2>
<form id="offer-form">
<label>Sell symbol<input name="sell_asset" value="QRL" maxlength="16" required></label>
<label>Sell amount<input name="sell_amount" value="500000" inputmode="numeric" required></label>
<label>Buy symbol<input name="buy_asset" value="BTC" maxlength="16" required></label>
<label>Buy amount<input name="buy_amount" value="100000" inputmode="numeric" required></label>
<label>Settlement rounds<input name="rounds" value="2" inputmode="numeric" required></label>
<label>Your receiving address<input name="address" placeholder="receiving-address" maxlength="256" required></label>
<button class="primary" type="submit">Publish offer</button>
</form>
</section>
<section class="panel">
<h2>Take offer</h2>
<label>Your receiving address for the sold asset<input id="join-address" placeholder="receiving-address" maxlength="256"></label>
<p class="muted">Set this once, then press Join next to an open offer.</p>
</section>
<section class="panel">
<h2>Event stream</h2>
<ol id="events" class="events"><li>waiting for connection</li></ol>
</section>
</div>
<div>
<section class="panel">
<div class="topline"><h2>Open offers</h2><button id="refresh-offers">Refresh</button></div>
<div class="table-wrap"><table><thead><tr><th>Room</th><th>Sell</th><th>Buy</th><th>Rounds</th><th>Actions</th></tr></thead><tbody id="offers"><tr><td colspan="5" class="muted">waiting for offer list</td></tr></tbody></table></div>
</section>
<section class="panel">
<h2>My settlement rooms</h2>
<div id="rooms"><p class="muted">No active rooms.</p></div>
</section>
<section class="panel">
<div class="topline"><h2>Counterparty history &amp; blocklist</h2><button id="refresh-history">Refresh</button></div>
<div id="history-status" class="muted">requires an unlocked trading identity</div>
<div class="table-wrap"><table><thead><tr><th>Fingerprint</th><th>Mediator</th><th>First / last seen</th><th>Encounters</th><th>Status</th><th>Notes</th><th>Actions</th></tr></thead><tbody id="history-rows"><tr><td colspan="7" class="muted">no data yet</td></tr></tbody></table></div>
<form id="note-form" class="row">
<label style="flex:1;min-width:160px">Fingerprint (64 hex chars)<input name="note_fp" maxlength="64" placeholder="counterparty fingerprint"></label>
<label style="flex:2;min-width:200px">Note text<input name="note_text" placeholder="e.g. slow to respond but completed the trade"></label>
<div style="padding-bottom:12px"><button type="submit" class="primary">Add note</button></div>
</form>
</section>
</div>
</div>
<section class="panel">
<h2>Account: key-based login</h2>
<p class="muted">Enroll a public key to also allow challenge-response login
for this account, alongside your password (never instead of it - enrolling
never disables the password). Generate the keypair with a native tool you
trust, never in this browser page; see the "Log in with a key" panel on the
login screen for how the resulting login works.</p>
<form id="enroll-key-form">
<label>Suite<select name="suite" id="enroll-key-suite"><option value="ml-dsa-65" selected>ML-DSA-65 (post-quantum)</option><option value="ed25519">Ed25519</option></select></label>
<label>Public key (hex - 3904 characters for ML-DSA-65, 64 for Ed25519)<input name="public_key" maxlength="3904" required></label>
<button type="submit">Enroll key</button>
</form>
</section>
</div>
<script>
const TOKEN="__CSRF_TOKEN__";
const esc=(v)=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const short=(v)=>{v=String(v??'');return v.length>22?v.slice(0,10)+'…'+v.slice(-10):v};
const copyBtn=(v)=>v?`<button type="button" class="copy" data-copy="${esc(v)}" title="copy full value">&#10688;</button>`:'';
const hexField=(label,v)=>v?`<div class="field"><b>${esc(label)}</b><div class="hexrow"><span class="mono-break">${esc(v)}</span>${copyBtn(v)}</div></div>`:'';
document.body.addEventListener('click',e=>{const b=e.target.closest('[data-copy]');if(!b)return;navigator.clipboard.writeText(b.dataset.copy).then(()=>notice('copied to clipboard')).catch(()=>notice('copy failed - clipboard unavailable',true))});
function notice(text,bad){const n=document.getElementById('notice');n.textContent=text;n.className=bad?'notice error':'notice';setTimeout(()=>{if(n.textContent===text)n.textContent=''},5000)}
async function post(path,data={}){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-TradeP2P-Token':TOKEN},body:new URLSearchParams(data)});const body=await r.json().catch(()=>({ok:false,error:'invalid response'}));if(!r.ok||!body.ok)throw new Error(body.error||('HTTP '+r.status));return body}
function renderOffers(offers){const target=document.getElementById('offers');if(!offers.length){target.innerHTML='<tr><td colspan="5" class="muted">No open offers.</td></tr>';return}target.innerHTML=offers.map(o=>`<tr><td title="${esc(o.room_id)}">${esc(short(o.room_id))}</td><td>${esc(o.sell_amount)} ${esc(o.sell_asset)}</td><td>${esc(o.buy_amount)} ${esc(o.buy_asset)}</td><td>${esc(o.rounds)}</td><td><div class="row"><button data-join="${esc(o.room_id)}" class="primary">Join</button><button data-cancel="${esc(o.room_id)}" class="danger">Cancel mine</button></div></td></tr>`).join('');target.querySelectorAll('[data-join]').forEach(b=>b.onclick=async()=>{try{const address=document.getElementById('join-address').value.trim();if(!address)throw new Error('enter your receiving address first');await post('/api/offers/join',{room_id:b.dataset.join,address});notice('join request queued')}catch(e){notice(e.message,true)}});target.querySelectorAll('[data-cancel]').forEach(b=>b.onclick=async()=>{try{await post('/api/offers/cancel',{room_id:b.dataset.cancel});notice('cancel request queued')}catch(e){notice(e.message,true)}})}
const pendingTurn=new Map(),expandedDetails=new Set(),selectedSuite=new Map();
let currentMediatorId='';
function turnKey(r){return r.turn?(r.turn.round+':'+r.turn.sender+':'+r.turn.amount+':'+r.turn.asset+':'+(r.turn.is_fee?1:0)):''}
function roomCryptoDetail(r){const rc=r.recognition_challenge;const rr=r.recognition_response;const chParts=rc?[hexField('Challenge nonce (sent by us)',rc.nonce),`<div class="field"><b>Challenge suite / window</b><div class="muted">suite ${esc(rc.suite_id)} &middot; created ${esc(rc.created_at)} &middot; expires ${esc(rc.expires_at)}</div></div>`]:[];const rrParts=rr?[hexField("Counterparty's recognition public key",rr.public_key),hexField("Counterparty's recognition signature",rr.signature)]:[];const ownAnswerParts=r.own_recognition_response_signature?[hexField('Our recognition-response signature (we answered their challenge)',r.own_recognition_response_signature)]:[];const recognitionSection=(chParts.length||rrParts.length||ownAnswerParts.length)?`<div class="field"><b>Recognition</b></div>${chParts.join('')}${rrParts.join('')}${ownAnswerParts.join('')}`:'<p class="muted">No recognition challenge issued or answered in this room yet.</p>';const receipts=(r.receipts||[]).map(x=>`<div class="receipt-card"><div class="field"><b>Stage</b>${esc(x.stage)}${x.completed?' <span class="pq">(completed)</span>':''} &middot; suite ${esc(x.suite_id)} &middot; ts ${esc(x.timestamp)}</div>${hexField('Nonce',x.nonce)}${hexField('Terms commitment',x.terms_commitment)}${hexField('Party A ephemeral key',x.party_a_ephemeral_key)}${hexField('Party B ephemeral key',x.party_b_ephemeral_key)}${hexField('Mediator public key',x.mediator_public_key)}${hexField('Previous stage hash',x.previous_stage_hash)}${hexField('Mediator signature',x.mediator_signature)}${hexField('Chain-link hash',x.chain_link_hash)}</div>`).join('');const receiptsSection=`<div class="field" style="margin-top:8px"><b>Receipt chain (${(r.receipts||[]).length})</b></div>${receipts||'<p class="muted">No receipts issued yet.</p>'}`;return `<details class="crypto" data-detail-room="${esc(r.room_id)}"${expandedDetails.has(r.room_id)?' open':''}><summary>&#9656; crypto detail</summary>${recognitionSection}${receiptsSection}</details>`}
function externalAnswerPanel(r){const c=r.incoming_recognition_challenge;if(!c)return'';const suiteName=c.suite_id===2?'ml-dsa-65':'ed25519';const cmd=`tradep2p_cli sign-recognition-response YOUR_KEYSTORE_PATH YOUR_PASSPHRASE ${currentMediatorId} ${suiteName} ${r.room_id} ${c.nonce} ${c.created_at} ${c.expires_at}`;return `<div class="panel" style="margin-top:10px;padding:12px;border-style:dashed"><p class="muted">Counterparty is asking you to prove control of your trading identity (suite ${esc(suiteName)}, expires ${esc(c.expires_at)}). Answer without handing this server your key: run this on your own machine with your own keystore, then paste back the two values it prints. Replace YOUR_KEYSTORE_PATH/YOUR_PASSPHRASE first.</p><pre class="mono-break" style="white-space:pre-wrap;background:var(--bg-deep);padding:8px;border:1px solid var(--line)">${esc(cmd)}</pre><form class="row" data-answer-external="${esc(r.room_id)}" data-nonce="${esc(c.nonce)}" data-suite="${esc(suiteName)}"><label style="flex:1;min-width:200px">public_key (from the command output)<input name="public_key" required></label><label style="flex:1;min-width:200px">signature (from the command output)<input name="signature" required></label><div style="padding-bottom:12px"><button type="submit" class="primary">Submit answer</button></div></form></div>`}
function renderRooms(rooms){const target=document.getElementById('rooms');if(document.activeElement&&target.contains(document.activeElement)&&document.activeElement.tagName==='SELECT')return;if(!rooms.length){pendingTurn.clear();expandedDetails.clear();selectedSuite.clear();target.innerHTML='<p class="muted">No settlement rooms in this session.</p>';return}const liveIds=new Set(rooms.map(r=>r.room_id));for(const id of pendingTurn.keys())if(!liveIds.has(id))pendingTurn.delete(id);for(const id of expandedDetails)if(!liveIds.has(id))expandedDetails.delete(id);for(const id of selectedSuite.keys())if(!liveIds.has(id))selectedSuite.delete(id);target.innerHTML=rooms.map(r=>{const turn=r.turn?`<div class="turn"><b>${r.turn.is_fee?'Mediator fee':'Round '+esc(r.turn.round)}:</b> party ${esc(r.turn.sender)} sends <b>${esc(r.turn.amount)} ${esc(r.turn.asset)}</b><br><span class="muted mono-break">destination: ${esc(r.turn.destination)}</span></div>`:'';let primary='';if(r.status==='active'&&r.action==='sent')primary=`<button class="primary" data-sent="${esc(r.room_id)}">${r.turn&&r.turn.is_fee?'I paid the mediator fee':'I sent it'}</button>`;if(r.status==='active'&&r.action==='received')primary=`<button class="primary" data-received="${esc(r.room_id)}">I verified receipt</button>`;if(r.status==='active'&&r.turn&&r.turn.is_fee&&r.action==='none')primary=`<span class="muted">waiting for the offer creator to settle the mediator fee</span>`;const abort=r.status==='active'?`<button class="danger" data-abort="${esc(r.room_id)}">Abort room</button>`:'';const fee=r.fee_amount>0?`<div class="muted mono-break">mediator fee: ${esc(r.fee_amount)} ${esc(r.fee_asset)} &rarr; ${esc(r.fee_address)}</div>`:'';const feeConfirmationLine=r.fee_confirmation_pending?'<p class="notice">Mediator fee reported sent - waiting for the mediator operator to confirm receipt before this room completes.</p>':'';const canRecognize=r.status==='active'&&(r.recognition_status==='none'||r.recognition_status==='failed');const suiteSel=selectedSuite.get(r.room_id)||'ml-dsa-65';const recognize=canRecognize?`<select data-suite="${esc(r.room_id)}"><option value="ml-dsa-65"${suiteSel==='ml-dsa-65'?' selected':''}>ML-DSA-65 (PQ)</option><option value="ed25519"${suiteSel==='ed25519'?' selected':''}>Ed25519</option></select> <button data-recognize="${esc(r.room_id)}">Recognize counterparty</button>`:'';let recognitionLine='';if(r.recognition_status==='challenge_sent')recognitionLine='<p class="muted">recognition challenge sent - awaiting response</p>';else if(r.recognition_status==='recognized')recognitionLine=`<p class="muted">counterparty proved control of <span class="mono-break">${esc(r.recognized_fingerprint)}</span>${copyBtn(r.recognized_fingerprint)} - see History panel for prior settlement count with this key</p>`;else if(r.recognition_status==='declined')recognitionLine='<p class="muted">declined to answer counterparty\'s recognition challenge (no trading identity unlocked)</p>';else if(r.recognition_status==='failed')recognitionLine='<p class="muted">a recognition response did not verify - not evidence of anything, may retry</p>';return `<article class="room"><div class="topline"><div><b title="${esc(r.room_id)}">Room ${esc(short(r.room_id))}</b><div class="muted">party ${esc(r.party)} &middot; peer ${esc(short(r.peer_id))}</div></div><span class="status ${esc(r.status)}">${esc(r.status)}</span></div><p>${esc(r.sell_amount)} ${esc(r.sell_asset)} &harr; ${esc(r.buy_amount)} ${esc(r.buy_asset)} &middot; ${esc(r.rounds)} rounds</p><div class="muted mono-break">party A receives: ${esc(r.receive_address_a)}<br>party B receives: ${esc(r.receive_address_b)}</div>${fee}${turn}${feeConfirmationLine}${recognitionLine}${r.detail?`<p class="notice">${esc(r.detail)}</p>`:''}<div class="row">${primary}${abort}${recognize}</div>${externalAnswerPanel(r)}${roomCryptoDetail(r)}</article>`}).join('');target.querySelectorAll('[data-sent]').forEach(b=>b.onclick=()=>roomAction('/api/rooms/sent',b.dataset.sent));target.querySelectorAll('[data-received]').forEach(b=>b.onclick=()=>roomAction('/api/rooms/received',b.dataset.received));target.querySelectorAll('[data-abort]').forEach(b=>b.onclick=()=>roomAction('/api/rooms/abort',b.dataset.abort));target.querySelectorAll('select[data-suite]').forEach(s=>s.onchange=()=>{selectedSuite.set(s.dataset.suite,s.value)});target.querySelectorAll('[data-recognize]').forEach(b=>b.onclick=()=>{b.disabled=true;const sel=document.querySelector(`select[data-suite="${b.dataset.recognize}"]`);post('/api/recognition/recognize',{room_id:b.dataset.recognize,suite:sel?sel.value:'ed25519'}).catch(e=>notice(e.message,true))});target.querySelectorAll('[data-answer-external]').forEach(f=>f.onsubmit=async(e)=>{e.preventDefault();try{const d=Object.fromEntries(new FormData(f));await post('/api/recognition/answer-external',{room_id:f.dataset.answerExternal,suite:f.dataset.suite,nonce:f.dataset.nonce,public_key:d.public_key,signature:d.signature});notice('recognition challenge answered')}catch(err){notice(err.message,true)}});target.querySelectorAll('details.crypto').forEach(d=>d.addEventListener('toggle',()=>{const id=d.dataset.detailRoom;if(d.open)expandedDetails.add(id);else expandedDetails.delete(id)}))}
async function roomAction(path,room){try{await post(path,{room_id:room});notice('room action queued')}catch(e){notice(e.message,true)}}
function renderEvents(events){document.getElementById('events').innerHTML=(events.length?events:['No events yet.']).map(e=>`<li>${esc(e)}</li>`).join('')}
async function refreshIdentity(){try{const r=await fetch('/api/identity/state',{cache:'no-store'});const s=await r.json();const el=document.getElementById('identity-status');if(!s.loaded){el.innerHTML='<span class="muted">No trading identity yet. Enter your password and click Enable / unlock to create one.</span>';return}el.innerHTML=`<div class="server-grid"><div class="metric"><b>Status</b>${s.unlocked?'unlocked':'locked'}</div><div class="metric"><b>Key generation</b>${esc(s.key_generation)}</div></div><p class="muted mono-break">identity id: ${esc(s.identity_id)}<br>public key: ${esc(s.public_key)}${copyBtn(s.public_key)}</p>`}catch(e){document.getElementById('identity-status').textContent='identity status error: '+e.message}}
async function refreshHistory(){try{const r=await fetch('/api/history/list',{cache:'no-store'});const s=await r.json();const tbody=document.getElementById('history-rows');const status=document.getElementById('history-status');if(!s.unlocked){status.textContent='requires an unlocked trading identity';tbody.innerHTML='<tr><td colspan="7" class="muted">locked</td></tr>';return}status.textContent=s.entries.length+' record(s) for this mediator';tbody.innerHTML=s.entries.length?s.entries.map(en=>`<tr><td class="mono-break" title="${esc(en.fingerprint)}">${esc(short(en.fingerprint))}</td><td>${esc(en.mediator_id)}</td><td>${esc(en.first_seen)} / ${esc(en.last_seen)}</td><td>${esc(en.encounter_count)}</td><td>${en.locally_blocked?'<b class="error">BLOCKED</b>':esc(en.display_category)}</td><td>${esc(en.notes.length)}</td><td><div class="row"><button data-block="${esc(en.fingerprint)}" data-blocked="${en.locally_blocked?1:0}">${en.locally_blocked?'Unblock':'Block'}</button></div></td></tr>`).join(''):'<tr><td colspan="7" class="muted">No counterparty records yet.</td></tr>';tbody.querySelectorAll('[data-block]').forEach(b=>b.onclick=async()=>{try{const path=b.dataset.blocked==='1'?'/api/history/unblock':'/api/history/block';await post(path,{fingerprint:b.dataset.block});notice('history updated');refreshHistory()}catch(e){notice(e.message,true)}})}catch(e){document.getElementById('history-status').textContent='history error: '+e.message}}
async function refresh(){try{const r=await fetch('/api/state',{cache:'no-store'});if(r.status===401){location.reload();return}const s=await r.json();currentMediatorId=s.mediator_id||'';const c=document.getElementById('connection');c.textContent=s.connection_status;c.className='status '+(s.connected?'connected':'disconnected');const fee=s.mediator_fee_amount>0?(' &middot; mediator fee: '+esc(s.mediator_fee_amount)+' '+esc(s.mediator_fee_asset)):'';document.getElementById('identity').innerHTML=(s.client_id?'anonymous mediator client '+esc(s.client_id):'not connected to a mediator yet')+fee;renderOffers(s.offers||[]);renderRooms(s.rooms||[]);renderEvents(s.events||[])}catch(e){notice('refresh failed: '+e.message,true)}}
document.getElementById('offer-form').onsubmit=async(e)=>{e.preventDefault();try{const d=Object.fromEntries(new FormData(e.target));await post('/api/offers/create',d);notice('offer request queued')}catch(err){notice(err.message,true)}};
document.getElementById('refresh-offers').onclick=async()=>{try{await post('/api/offers/refresh');notice('offer refresh queued')}catch(e){notice(e.message,true)}};
document.getElementById('refresh-history').onclick=()=>refreshHistory();
document.getElementById('logout').onclick=async()=>{try{await post('/api/logout')}catch(e){}location.reload()};
document.getElementById('enroll-key-form').onsubmit=async(e)=>{e.preventDefault();try{const public_key=document.getElementById('enroll-key-form').public_key.value;const suite=document.getElementById('enroll-key-suite').value;await post('/api/account/enroll-key',{public_key,suite});notice('login key enrolled')}catch(err){notice(err.message,true)}};
document.getElementById('ks-enable').onclick=async()=>{try{const password=document.querySelector('#keystore-form [name=ks_password]').value;await post('/api/keystore/enable',{password});notice('trading identity ready');refreshIdentity();refreshHistory()}catch(e){notice(e.message,true)}};
document.getElementById('ks-lock').onclick=async()=>{try{await post('/api/keystore/lock');notice('trading identity locked');refreshIdentity();refreshHistory()}catch(e){notice(e.message,true)}};
document.getElementById('ks-export-reveal').onclick=()=>{document.getElementById('ks-export-form').style.display='block'};
document.getElementById('ks-export-form').onsubmit=async(e)=>{e.preventDefault();try{const d=Object.fromEntries(new FormData(e.target));if(!d.ks_export_confirm)throw new Error('confirm the checkbox first');const r=await fetch('/api/keystore/export',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-TradeP2P-Token':TOKEN},body:new URLSearchParams({password:d.ks_export_password,confirm:'yes-export-my-encrypted-keystore'})});if(!r.ok){const body=await r.json().catch(()=>({error:'export failed'}));throw new Error(body.error||('HTTP '+r.status))}const blob=await r.blob();const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='trading-identity.keystore';document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);notice('keystore exported');e.target.reset();e.target.style.display='none'}catch(err){notice(err.message,true)}};
document.getElementById('note-form').onsubmit=async(e)=>{e.preventDefault();try{const d=Object.fromEntries(new FormData(e.target));if(!d.note_fp||!d.note_text)throw new Error('fingerprint and note text are both required');await post('/api/history/note',{fingerprint:d.note_fp,text:d.note_text});notice('note added');e.target.reset();refreshHistory()}catch(err){notice(err.message,true)}};
refresh();refreshIdentity();refreshHistory();setInterval(refresh,1000);
</script>
</body>
</html>)HTML";

    const auto replace_all = [&](const std::string& needle, const std::string& replacement) {
        std::size_t position = 0U;
        while ((position = html.find(needle, position)) != std::string::npos) {
            html.replace(position, needle.size(), replacement);
            position += replacement.size();
        }
    };
    replace_all("__PRIVACY_NOTICE__", kPrivacyNotice);
    replace_all("__USERNAME__", html_escape(username));
    replace_all("__CSRF_TOKEN__", csrf_token);
    return html;
}

void print_usage(const char* program) {
    std::cerr
        << "Usage:\n"
        << "  " << program
        << " client <mediator:port> <certificate-sha256> [options]\n"
        << "  " << program
        << " client-tor <proxy:port> <onion:port> <certificate-sha256> [options]\n\n"
        << "Options:\n"
        << "  --listen HOST          HTTP bind address (default 127.0.0.1)\n"
        << "  --port PORT            HTTP port (default 8090)\n"
        << "  --accounts FILE        account store path (default "
           "logs/webclient-accounts.tsv)\n"
        << "  --keystore-dir DIR     per-account trading identity keystores, one "
           "file per account that enables one (default logs/webclient-keystores)\n"
        << "  --max-sessions N       concurrent session cap (default 64)\n"
        << "  --idle-minutes N       idle session timeout (default 30)\n"
        << "  --home-url URL         link back to the main site shown in the page "
           "header (default: none, no link shown)\n"
        << "  --admin-token TOKEN    enables GET /api/admin/accounts (username + "
           "creation time only, never salts/hashes) when the request carries a "
           "matching X-TradeP2P-Admin-Token header (default: unset, endpoint "
           "returns 404)\n\n"
        << "This binary is meant to sit behind a TLS-terminating reverse proxy "
           "before it is exposed to the public Internet.\n";
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 4) {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }

        const std::string mode = argv[1];
        std::optional<Endpoint> proxy;
        Endpoint mediator;
        ClientTlsPolicy tls;
        int option_index = 0;
        std::string mediator_id_text;

        if (mode == "client") {
            mediator = parse_endpoint(argv[2]);
            tls = ClientTlsPolicy{argv[3]};
            option_index = 4;
            mediator_id_text = argv[2];
        } else if (mode == "client-tor") {
            if (argc < 5) {
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            proxy = parse_endpoint(argv[2]);
            mediator = parse_endpoint(argv[3]);
            tls = ClientTlsPolicy{argv[4]};
            option_index = 5;
            mediator_id_text = argv[3];
        } else {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }

        std::string listen_host = "127.0.0.1";
        int http_port = 8090;
        std::string accounts_file = "logs/webclient-accounts.tsv";
        // Phase 9: one IdentityKeystore file per account that has enabled a
        // trading identity, named <username>.keystore under this directory -
        // portable, unmodified, to the native CLI/tradep2p-dashboard (see
        // /api/keystore/export). Never created automatically; see
        // SessionManager::keystore_enable().
        std::string keystore_dir = "logs/webclient-keystores";
        std::size_t max_sessions = 64U;
        std::chrono::minutes idle_timeout{30};
        // Phase 7: the "server identity or domain" bound into every signed
        // login challenge (see login.hpp's LoginChallengeFields). Defaults
        // to this process's own listen address, which is correct for a
        // direct connection but NOT what a browser actually navigated to
        // if a reverse proxy terminates TLS in front of this binary (see
        // this file's top comment) - an operator running behind a proxy
        // should set this explicitly to the public-facing domain, so a
        // signed response cannot be replayed against a differently-named
        // deployment sharing the same account file.
        std::string server_identity;
        // Shown as a link back to the main site in every page's header, if
        // set. Deliberately opt-in (empty by default): this binary is meant
        // to also work standalone, and a stale or wrong URL here is worse
        // than no link at all.
        std::string home_url;
        // Gates GET /api/admin/accounts - unset (default) disables the route
        // entirely rather than requiring an empty/guessable token.
        std::string admin_token;

        for (int index = option_index; index < argc; ++index) {
            const std::string argument = argv[index];
            if (argument == "--listen" && index + 1 < argc) {
                listen_host = argv[++index];
            } else if (argument == "--port" && index + 1 < argc) {
                http_port = static_cast<int>(parse_port(argv[++index]));
            } else if (argument == "--accounts" && index + 1 < argc) {
                accounts_file = argv[++index];
            } else if (argument == "--keystore-dir" && index + 1 < argc) {
                keystore_dir = argv[++index];
            } else if (argument == "--max-sessions" && index + 1 < argc) {
                max_sessions = parse_u32(argv[++index], "max session count");
            } else if (argument == "--idle-minutes" && index + 1 < argc) {
                idle_timeout = std::chrono::minutes(
                    parse_u32(argv[++index], "idle minute count"));
            } else if (argument == "--server-identity" && index + 1 < argc) {
                server_identity = argv[++index];
            } else if (argument == "--home-url" && index + 1 < argc) {
                home_url = argv[++index];
            } else if (argument == "--admin-token" && index + 1 < argc) {
                admin_token = argv[++index];
            } else if (argument == "--help") {
                print_usage(argv[0]);
                return EXIT_SUCCESS;
            } else {
                throw std::invalid_argument(
                    "unknown or incomplete web client option: " + argument);
            }
        }
        if (server_identity.empty()) {
            server_identity = listen_host + ":" + std::to_string(http_port);
        }
        constexpr const char* kLoginServiceId = "tradep2p-webclient";

        AccountStore accounts(accounts_file);
        SessionManager sessions(mediator, tls, proxy, max_sessions, idle_timeout, mediator_id_text,
                                keystore_dir);
        tradep2p::LoginChallengeTracker login_tracker;
        AuthRateLimiter auth_limiter;

        std::atomic<bool> stop_reaper{false};
        std::thread reaper([&] {
            while (!stop_reaper.load()) {
                std::this_thread::sleep_for(std::chrono::seconds(60));
                sessions.reap_idle();
            }
        });

        httplib::Server server;
        const auto host_allowed = [&](const httplib::Request& request) {
            if (listen_host != "127.0.0.1" && listen_host != "localhost" &&
                listen_host != "::1") {
                return true;
            }
            const std::string host = request.get_header_value("Host");
            const std::string port_text = std::to_string(http_port);
            return host == "127.0.0.1:" + port_text ||
                   host == "localhost:" + port_text ||
                   host == "[::1]:" + port_text;
        };

        const auto set_common_headers = [](httplib::Response& response) {
            response.set_header("Cache-Control", "no-store");
            response.set_header("X-Frame-Options", "DENY");
            response.set_header("Content-Security-Policy",
                                "default-src 'self'; img-src 'self' data:; "
                                "style-src 'unsafe-inline'; "
                                "script-src 'unsafe-inline'; frame-ancestors 'none'");
        };

        // A reverse proxy terminating TLS in front of this process sets
        // X-Forwarded-Proto; only then is it correct to mark cookies Secure
        // (the default bind is plain HTTP on loopback, where that flag would
        // just make the cookie stop working).
        const auto cookie_suffix = [](const httplib::Request& request) {
            return request.get_header_value("X-Forwarded-Proto") == "https"
                       ? "; Secure"
                       : "";
        };

        const auto require_preauth = [&](const httplib::Request& request) {
            const auto cookie = read_cookie(request, kPreAuthCookie);
            const std::string header = request.get_header_value(kPreAuthHeader);
            return cookie.has_value() && !cookie->empty() && cookie == header;
        };

        server.Get("/", [&](const httplib::Request& request, httplib::Response& response) {
            if (!host_allowed(request)) {
                response.status = 403;
                response.set_content("forbidden host", "text/plain; charset=utf-8");
                return;
            }
            set_common_headers(response);
            const auto cookie = read_cookie(request, kSessionCookie);
            const auto session = cookie ? sessions.touch(*cookie) : std::nullopt;
            if (session) {
                response.set_content(
                    app_html(session->username, session->csrf_token, home_url),
                    "text/html; charset=utf-8");
                return;
            }
            auto preauth = read_cookie(request, kPreAuthCookie);
            if (!preauth || preauth->empty()) {
                preauth = random_token();
                response.set_header(
                    "Set-Cookie", std::string(kPreAuthCookie) + "=" + *preauth +
                                      "; Path=/; SameSite=Strict" + cookie_suffix(request));
            }
            response.set_content(landing_html(*preauth, home_url),
                                 "text/html; charset=utf-8");
        });

        server.Post("/api/register", [&](const httplib::Request& request,
                                         httplib::Response& response) {
            if (!host_allowed(request) || !same_origin(request) ||
                !require_preauth(request)) {
                set_json_result(response, false, "forbidden", 403);
                return;
            }
            try {
                const std::string username = required_param(request, "username");
                const std::string password = required_param(request, "password");
                validate_username(username);
                validate_password(password);
                accounts.create(username, password);
                const std::string token = sessions.login(username);
                response.set_header(
                    "Set-Cookie", std::string(kSessionCookie) + "=" + token +
                                      "; Path=/; HttpOnly; SameSite=Strict" +
                                      cookie_suffix(request));
                set_json_result(response, true, "account created");
            } catch (const std::exception& error) {
                set_json_result(response, false, error.what(), 400);
            }
        });

        server.Post("/api/login", [&](const httplib::Request& request,
                                      httplib::Response& response) {
            if (!host_allowed(request) || !same_origin(request) ||
                !require_preauth(request)) {
                set_json_result(response, false, "forbidden", 403);
                return;
            }
            try {
                const std::string username = required_param(request, "username");
                const std::string password = required_param(request, "password");
                if (!auth_limiter.allowed(username)) {
                    throw std::invalid_argument("too many attempts, try again later");
                }
                if (!accounts.verify(username, password)) {
                    auth_limiter.record_failure(username);
                    throw std::invalid_argument("invalid username or password");
                }
                auth_limiter.record_success(username);
                const std::string token = sessions.login(username);
                response.set_header(
                    "Set-Cookie", std::string(kSessionCookie) + "=" + token +
                                      "; Path=/; HttpOnly; SameSite=Strict" +
                                      cookie_suffix(request));
                set_json_result(response, true, "logged in");
            } catch (const std::exception& error) {
                set_json_result(response, false, error.what(), 400);
            }
        });

        // Phase 7 (service-scoped challenge-response login, see
        // include/tradep2p/login.hpp): step 1 of key-based login. Always
        // issues a real, trackable challenge regardless of whether
        // `username` exists or has an enrolled key - the response shape is
        // identical either way, so this route alone reveals nothing about
        // account existence (see /api/login/key/verify for the matching
        // half of that property).
        server.Post("/api/login/key/challenge",
                   [&](const httplib::Request& request, httplib::Response& response) {
                       if (!host_allowed(request) || !same_origin(request) ||
                           !require_preauth(request)) {
                           set_json_result(response, false, "forbidden", 403);
                           return;
                       }
                       try {
                           const std::string username = required_param(request, "username");
                           if (!auth_limiter.allowed(username)) {
                               throw std::invalid_argument("too many attempts, try again later");
                           }
                           // The suite is whatever this account actually
                           // enrolled - never client-selectable (see
                           // kLoginSuiteMlDsa65V1's comment in login.hpp) -
                           // defaulting to the post-quantum suite for an
                           // unknown/keyless account is moot either way,
                           // since verify() below will reject those
                           // regardless of suite.
                           const auto enrolled = accounts.login_key(username);
                           const std::uint16_t suite_id =
                               enrolled.has_value() ? enrolled->suite_id : tradep2p::kLoginSuiteMlDsa65V1;
                           const auto challenge = login_tracker.issue(kLoginServiceId, server_identity,
                                                                      username, 0, suite_id);
                           std::ostringstream json;
                           json << "{\"ok\":true"
                                << ",\"session_id\":\"" << json_escape(to_hex(challenge.session_id))
                                << "\",\"nonce\":\"" << json_escape(to_hex(challenge.nonce)) << "\""
                                << ",\"service_id\":\"" << json_escape(challenge.service_id) << "\""
                                << ",\"server_identity\":\""
                                << json_escape(challenge.server_identity) << "\""
                                << ",\"suite_id\":" << challenge.suite_id
                                << ",\"suite\":\"" << json_escape(login_suite_name(challenge.suite_id)) << "\""
                                << ",\"created_at\":" << challenge.created_at
                                << ",\"expires_at\":" << challenge.expires_at << "}";
                           response.status = 200;
                           response.set_content(json.str(), "application/json; charset=utf-8");
                       } catch (const std::exception& error) {
                           set_json_result(response, false, error.what(), 400);
                       }
                   });

        // Step 2: verify the signed response and, on success, log in
        // exactly like the password path (same session/cookie mechanics).
        // A wrong signature, an unknown username, and a known username
        // with no enrolled key ALL fail identically ("invalid login") -
        // the account-enumeration-resistance property the phase spec asks
        // for. The challenge is consumed unconditionally (success or
        // failure) so it can never be retried.
        server.Post("/api/login/key/verify",
                   [&](const httplib::Request& request, httplib::Response& response) {
                       if (!host_allowed(request) || !same_origin(request) ||
                           !require_preauth(request)) {
                           set_json_result(response, false, "forbidden", 403);
                           return;
                       }
                       try {
                           const std::string username = required_param(request, "username");
                           const std::string session_id_hex = required_param(request, "session_id");
                           const std::string signature_hex = required_param(request, "signature");
                           if (!auth_limiter.allowed(username)) {
                               throw std::invalid_argument("too many attempts, try again later");
                           }

                           const auto session_id_bytes = from_hex(session_id_hex);
                           const auto signature_bytes = from_hex(signature_hex);
                           bool ok = false;
                           if (session_id_bytes.size() == tradep2p::kLoginSessionIdLength) {
                               tradep2p::LoginSessionId session_id{};
                               std::copy(session_id_bytes.begin(), session_id_bytes.end(),
                                        session_id.begin());

                               const auto challenge = login_tracker.peek(session_id);
                               login_tracker.consume(session_id); // unconditional - single-use either way
                               // A key is always fetched (or, for an
                               // unenrolled/unknown account, a fixed dummy
                               // Ed25519 key is substituted, matching the
                               // challenge route's own default suite) so
                               // that verification always does the same
                               // amount of work on the same shape of input,
                               // regardless of account state - part of the
                               // same enumeration-resistance property
                               // AccountStore::verify() already applies to
                               // the password path. The suite to verify
                               // under is likewise always the ACCOUNT's own
                               // enrolled suite, never anything derived from
                               // this request - see kLoginSuiteMlDsa65V1's
                               // comment in login.hpp.
                               const auto enrolled = accounts.login_key(username);
                               const std::uint16_t suite_id = enrolled.has_value()
                                                                   ? enrolled->suite_id
                                                                   : tradep2p::kLoginSuiteMlDsa65V1;
                               if (signature_bytes.size() == expected_login_signature_length(suite_id)) {
                                   const bool challenge_matches = challenge.has_value() &&
                                                                  challenge->username == username &&
                                                                  challenge->suite_id == suite_id &&
                                                                  enrolled.has_value();
                                   if (suite_id == tradep2p::kLoginSuiteEd25519V1) {
                                       static const tradep2p::Ed25519PublicKey kDummyKey{};
                                       tradep2p::Ed25519PublicKey key_to_check = kDummyKey;
                                       if (enrolled.has_value()) {
                                           std::copy(enrolled->bytes.begin(), enrolled->bytes.end(),
                                                    key_to_check.begin());
                                       }
                                       tradep2p::Ed25519Signature signature{};
                                       std::copy(signature_bytes.begin(), signature_bytes.end(),
                                                signature.begin());
                                       ok = challenge_matches &&
                                            tradep2p::verify_login_response(key_to_check, *challenge,
                                                                            signature);
                                   } else if (suite_id == tradep2p::kLoginSuiteMlDsa65V1) {
                                       static const tradep2p::MlDsa65PublicKey kDummyKeyMlDsa65{};
                                       tradep2p::MlDsa65PublicKey key_to_check = kDummyKeyMlDsa65;
                                       if (enrolled.has_value()) {
                                           std::copy(enrolled->bytes.begin(), enrolled->bytes.end(),
                                                    key_to_check.begin());
                                       }
                                       tradep2p::MlDsa65Signature signature{};
                                       std::copy(signature_bytes.begin(), signature_bytes.end(),
                                                signature.begin());
                                       ok = challenge_matches &&
                                            tradep2p::verify_login_response_mldsa65(key_to_check, *challenge,
                                                                                    signature);
                                   }
                               }
                           }

                           if (!ok) {
                               auth_limiter.record_failure(username);
                               throw std::invalid_argument("invalid login");
                           }
                           auth_limiter.record_success(username);
                           const std::string token = sessions.login(username);
                           response.set_header(
                               "Set-Cookie", std::string(kSessionCookie) + "=" + token +
                                                 "; Path=/; HttpOnly; SameSite=Strict" +
                                                 cookie_suffix(request));
                           set_json_result(response, true, "logged in");
                       } catch (const std::exception& error) {
                           set_json_result(response, false, error.what(), 400);
                       }
                   });

        const auto require_session = [&](const httplib::Request& request,
                                         httplib::Response& response)
            -> std::optional<SessionHandle> {
            if (!host_allowed(request)) {
                set_json_result(response, false, "forbidden host", 403);
                return std::nullopt;
            }
            const auto cookie = read_cookie(request, kSessionCookie);
            const auto session = cookie ? sessions.touch(*cookie) : std::nullopt;
            if (!session) {
                set_json_result(response, false, "no active session", 401);
                return std::nullopt;
            }
            return session;
        };

        server.Post("/api/logout", [&](const httplib::Request& request,
                                       httplib::Response& response) {
            const auto session = require_session(request, response);
            if (!session) {
                return;
            }
            const auto cookie = read_cookie(request, kSessionCookie);
            if (cookie) {
                sessions.logout(*cookie);
            }
            response.set_header("Set-Cookie", std::string(kSessionCookie) +
                                                  "=deleted; Path=/; Max-Age=0");
            set_json_result(response, true, "logged out");
        });

        // Phase 7 migration path: opts an ALREADY-LOGGED-IN account into
        // key-based login, without ever disabling its existing password -
        // "how a user opts an existing account into key-based login
        // without losing access" (docs/identity-07-login.md). Requires an
        // active session (proven ownership via whichever method the user
        // already used to log in this time - password or, once enrolled,
        // an existing key) rather than re-checking the password here, so
        // this route has no separate credential-guessing surface of its
        // own. `public_key` is caller-supplied hex (64 chars / 32 bytes) -
        // see login.hpp's file comment for why this phase does not itself
        // generate the keypair (that's phase 9's browser-side job).
        server.Post("/api/account/enroll-key",
                   [&](const httplib::Request& request, httplib::Response& response) {
                       const auto session = require_session(request, response);
                       if (!session) {
                           return;
                       }
                       try {
                           const std::string suite = request.get_param_value("suite");
                           std::uint16_t suite_id = tradep2p::kLoginSuiteMlDsa65V1;
                           if (suite == "ed25519") {
                               suite_id = tradep2p::kLoginSuiteEd25519V1;
                           } else if (!suite.empty() && suite != "ml-dsa-65") {
                               throw std::invalid_argument("unknown login suite: " + suite);
                           }
                           const std::string public_key_hex = required_param(request, "public_key");
                           const auto raw = from_hex(public_key_hex);
                           if (raw.size() != expected_login_key_length(suite_id)) {
                               throw std::invalid_argument("invalid public key length for suite " +
                                                           login_suite_name(suite_id));
                           }
                           accounts.set_login_key(session->username, suite_id, raw);
                           set_json_result(response, true,
                                          "login key enrolled (" + login_suite_name(suite_id) + ")");
                       } catch (const std::exception& error) {
                           set_json_result(response, false, error.what(), 400);
                       }
                   });

        server.Get("/api/state", [&](const httplib::Request& request,
                                     httplib::Response& response) {
            const auto session = require_session(request, response);
            if (!session) {
                return;
            }
            response.set_header("Cache-Control", "no-store");
            response.set_content(session->client->state_json(),
                                 "application/json; charset=utf-8");
        });

        // Deliberately unauthenticated-by-default (404, not 401/403, when
        // admin_token is unset) so the route's very existence isn't
        // observable without the token. Never touches AccountStore's raw
        // file - list_summary() is the only path in, and it excludes
        // salts/hashes by construction (see its definition above).
        server.Get("/api/admin/accounts", [&](const httplib::Request& request,
                                              httplib::Response& response) {
            const std::string provided = request.get_header_value("X-TradeP2P-Admin-Token");
            if (admin_token.empty() || provided.size() != admin_token.size() ||
                CRYPTO_memcmp(provided.data(), admin_token.data(), admin_token.size()) != 0) {
                response.status = 404;
                response.set_content("not found", "text/plain; charset=utf-8");
                return;
            }
            response.set_header("Cache-Control", "no-store");
            std::ostringstream out;
            out << "{\"ok\":true,\"accounts\":[";
            bool first = true;
            for (const auto& [username, created_at] : accounts.list_summary()) {
                if (!first) {
                    out << ',';
                }
                first = false;
                out << "{\"username\":\"" << json_escape(username) << "\""
                    << ",\"created_at\":\"" << json_escape(created_at) << "\"}";
            }
            out << "]}";
            response.set_content(out.str(), "application/json; charset=utf-8");
        });

        const auto action = [&](auto handler) {
            return [&, handler](const httplib::Request& request,
                                httplib::Response& response) {
                const auto session = require_session(request, response);
                if (!session) {
                    return;
                }
                if (request.get_header_value("X-TradeP2P-Token") !=
                    session->csrf_token) {
                    set_json_result(response, false, "invalid session token", 403);
                    return;
                }
                try {
                    handler(request, *session);
                    set_json_result(response, true, "queued");
                } catch (const std::exception& error) {
                    set_json_result(response, false, error.what(), 400);
                }
            };
        };

        // Like action() above, but also passes the raw session token (the
        // cookie value / sessions_ map key) through to the handler - needed
        // by every keystore/history mutation below, which must look up and
        // modify the live WebSession entry in SessionManager rather than
        // the snapshot SessionHandle that action()/require_session return.
        const auto keystore_action = [&](auto handler) {
            return [&, handler](const httplib::Request& request,
                                httplib::Response& response) {
                const auto session = require_session(request, response);
                if (!session) {
                    return;
                }
                if (request.get_header_value("X-TradeP2P-Token") !=
                    session->csrf_token) {
                    set_json_result(response, false, "invalid session token", 403);
                    return;
                }
                const auto token = read_cookie(request, kSessionCookie);
                if (!token) {
                    set_json_result(response, false, "no active session", 401);
                    return;
                }
                try {
                    handler(request, *session, *token);
                    set_json_result(response, true, "ok");
                } catch (const std::exception& error) {
                    set_json_result(response, false, error.what(), 400);
                }
            };
        };

        server.Get("/api/identity/state",
                   [&](const httplib::Request& request, httplib::Response& response) {
                       const auto session = require_session(request, response);
                       if (!session) {
                           return;
                       }
                       const auto token = read_cookie(request, kSessionCookie);
                       response.set_header("Cache-Control", "no-store");
                       const auto status = token ? sessions.keystore_status(*token) : std::nullopt;
                       if (!status.has_value() || !status->loaded) {
                           response.set_content("{\"ok\":true,\"loaded\":false}",
                                                "application/json; charset=utf-8");
                           return;
                       }
                       std::ostringstream json;
                       json << "{\"ok\":true,\"loaded\":true"
                            << ",\"unlocked\":" << (status->unlocked ? "true" : "false")
                            << ",\"path\":\"" << json_escape(status->path) << "\""
                            << ",\"alias\":\"" << json_escape(status->alias) << "\""
                            << ",\"identity_id\":\"" << json_escape(status->identity_id_hex) << "\""
                            << ",\"public_key\":\"" << json_escape(status->public_key_hex) << "\""
                            << ",\"public_key_mldsa65\":\""
                            << json_escape(status->public_key_mldsa65_hex) << "\""
                            << ",\"created_at\":" << status->created_at
                            << ",\"key_generation\":" << status->key_generation << "}";
                       response.set_content(json.str(), "application/json; charset=utf-8");
                   });

        // Creates-or-unlocks this account's trading identity keystore - an
        // explicit action (a dedicated button, not automatic at
        // registration/login) per docs/identity-09-hosted-webclient.md.
        // Re-verifies the account password via AccountStore::verify() every
        // time rather than trusting the already-authenticated session alone,
        // since this unlocks real signing key material, not just session
        // state.
        server.Post("/api/keystore/enable",
                   keystore_action([&](const httplib::Request& request,
                                       const SessionHandle& session, const std::string& token) {
                       const std::string password = required_param(request, "password");
                       if (!accounts.verify(session.username, password)) {
                           throw std::runtime_error("wrong password");
                       }
                       sessions.keystore_enable(token, password);
                   }));

        server.Post("/api/keystore/lock",
                   keystore_action([&](const httplib::Request&, const SessionHandle&,
                                       const std::string& token) {
                       sessions.keystore_lock(token);
                   }));

        // Disabled-by-default in the sense that nothing in the UI reaches
        // this route without an explicit, separately-worded confirmation
        // (see app_html()'s export flow) - per
        // docs/identity-09-hosted-webclient.md: "not a quiet export button
        // next to routine settings." Streams the keystore FILE's raw
        // encrypted bytes; this process never decrypts it for the purpose
        // of exporting it. Not wrapped in action()/set_json_result() since
        // a successful response here is a binary file, not JSON.
        server.Post("/api/keystore/export",
                   [&](const httplib::Request& request, httplib::Response& response) {
                       const auto session = require_session(request, response);
                       if (!session) {
                           return;
                       }
                       if (request.get_header_value("X-TradeP2P-Token") != session->csrf_token) {
                           response.status = 403;
                           response.set_content(
                               "{\"ok\":false,\"error\":\"invalid session token\"}",
                               "application/json; charset=utf-8");
                           return;
                       }
                       const auto token = read_cookie(request, kSessionCookie);
                       try {
                           if (!token) {
                               throw std::runtime_error("no active session");
                           }
                           const std::string password = required_param(request, "password");
                           if (request.get_param_value("confirm") !=
                               "yes-export-my-encrypted-keystore") {
                               throw std::invalid_argument("export not confirmed");
                           }
                           if (!accounts.verify(session->username, password)) {
                               throw std::runtime_error("wrong password");
                           }
                           const auto bytes = sessions.keystore_export_bytes(*token);
                           response.set_header(
                               "Content-Disposition",
                               "attachment; filename=\"" + session->username + ".keystore\"");
                           response.set_content(
                               reinterpret_cast<const char*>(bytes.data()), bytes.size(),
                               "application/octet-stream");
                       } catch (const std::exception& error) {
                           response.status = 400;
                           response.set_content(
                               std::string("{\"ok\":false,\"error\":\"") +
                                   json_escape(error.what()) + "\"}",
                               "application/json; charset=utf-8");
                       }
                   });

        server.Get("/api/history/list",
                   [&](const httplib::Request& request, httplib::Response& response) {
                       const auto session = require_session(request, response);
                       if (!session) {
                           return;
                       }
                       const auto token = read_cookie(request, kSessionCookie);
                       response.set_header("Cache-Control", "no-store");
                       response.set_content(
                           token ? sessions.history_list_json(*token)
                                 : "{\"ok\":true,\"unlocked\":false,\"entries\":[]}",
                           "application/json; charset=utf-8");
                   });

        server.Post("/api/history/block",
                   keystore_action([&](const httplib::Request& request, const SessionHandle&,
                                       const std::string& token) {
                       sessions.history_set_blocked(token, required_param(request, "fingerprint"),
                                                    true);
                   }));

        server.Post("/api/history/unblock",
                   keystore_action([&](const httplib::Request& request, const SessionHandle&,
                                       const std::string& token) {
                       sessions.history_set_blocked(token, required_param(request, "fingerprint"),
                                                    false);
                   }));

        server.Post("/api/history/note",
                   keystore_action([&](const httplib::Request& request, const SessionHandle&,
                                       const std::string& token) {
                       sessions.history_add_note(token, required_param(request, "fingerprint"),
                                                 required_param(request, "text"));
                   }));

        server.Post("/api/offers/refresh",
                   action([&](const httplib::Request&, const SessionHandle& session) {
                       session.client->refresh_offers();
                   }));

        server.Post("/api/recognition/recognize",
                   action([&](const httplib::Request& request, const SessionHandle& session) {
                       const std::string suite = request.get_param_value("suite");
                       std::uint16_t suite_id = tradep2p::kRecognitionSuiteMlDsa65V1;
                       if (suite == "ed25519") {
                           suite_id = tradep2p::kRecognitionSuiteEd25519V1;
                       } else if (!suite.empty() && suite != "ml-dsa-65") {
                           throw std::invalid_argument("unknown recognition suite: " + suite);
                       }
                       session.client->recognize(required_param(request, "room_id"), suite_id);
                   }));

        // Answers a counterparty's incoming recognition challenge with a
        // signature computed entirely OUTSIDE this process - see
        // `tradep2p_cli sign-recognition-response`'s comment and
        // DashboardClient::submit_recognition_response()'s. This session's
        // trading identity, if any, is untouched either way; a caller with
        // no keystore enabled at all can still answer a challenge this way.
        server.Post("/api/recognition/answer-external",
                   action([&](const httplib::Request& request, const SessionHandle& session) {
                       const std::string suite = request.get_param_value("suite");
                       std::uint16_t suite_id = tradep2p::kRecognitionSuiteMlDsa65V1;
                       if (suite == "ed25519") {
                           suite_id = tradep2p::kRecognitionSuiteEd25519V1;
                       } else if (!suite.empty() && suite != "ml-dsa-65") {
                           throw std::invalid_argument("unknown recognition suite: " + suite);
                       }
                       session.client->submit_recognition_response(
                           required_param(request, "room_id"), suite_id,
                           from_hex(required_param(request, "nonce")),
                           from_hex(required_param(request, "public_key")),
                           from_hex(required_param(request, "signature")));
                   }));

        server.Post("/api/offers/create", action([&](const httplib::Request& request,
                                                      const SessionHandle& session) {
                        TradeTerms terms;
                        terms.asset_a = required_param(request, "sell_asset");
                        terms.total_a = parse_u64(
                            required_param(request, "sell_amount"), "sell amount");
                        terms.asset_b = required_param(request, "buy_asset");
                        terms.total_b = parse_u64(
                            required_param(request, "buy_amount"), "buy amount");
                        terms.rounds = parse_u32(
                            required_param(request, "rounds"), "round count");
                        terms.first_sender = Party::A;
                        session.client->create_offer(
                            terms, required_param(request, "address"));
                    }));

        server.Post("/api/offers/join", action([&](const httplib::Request& request,
                                                    const SessionHandle& session) {
                        session.client->join_offer(required_param(request, "room_id"),
                                                   required_param(request, "address"));
                    }));

        server.Post("/api/offers/cancel",
                   action([&](const httplib::Request& request, const SessionHandle& session) {
                       session.client->cancel_offer(required_param(request, "room_id"));
                   }));

        server.Post("/api/rooms/sent",
                   action([&](const httplib::Request& request, const SessionHandle& session) {
                       session.client->mark_sent(required_param(request, "room_id"));
                   }));

        server.Post("/api/rooms/received",
                   action([&](const httplib::Request& request, const SessionHandle& session) {
                       session.client->mark_received(required_param(request, "room_id"));
                   }));

        server.Post("/api/rooms/abort",
                   action([&](const httplib::Request& request, const SessionHandle& session) {
                       session.client->abort_room(required_param(request, "room_id"));
                   }));

        std::cout << "TradeP2P public web client listening on http://"
                  << listen_host << ':' << http_port << "\n";
        std::cout << "Accounts stored at " << accounts_file << "\n";
        std::cout << "Put this behind a TLS-terminating reverse proxy before "
                     "exposing it publicly.\n";

        if (!server.listen(listen_host, http_port)) {
            throw std::runtime_error("failed to bind web client HTTP listener");
        }
        stop_reaper.store(true);
        reaper.join();
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "fatal: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
