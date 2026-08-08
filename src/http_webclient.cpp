// Public multi-session web client: the "website has its own client to the
// exchange." Unlike tradep2p-dashboard (one process, one anonymous client,
// loopback only), this binary can be exposed publicly and serves many
// browser sessions from one process. Each session is a local convenience
// account (username/password) that owns its own persistent anonymous
// connection to the mediator. The account system has nothing to do with the
// mediator protocol, which stays fully anonymous; it only lets a visitor
// create and later terminate a session on this page.
#include <httplib.h>

#include "tradep2p/dashboard_client.hpp"
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

std::vector<std::uint8_t> from_hex(const std::string& text) {
    if (text.size() % 2U != 0U) {
        throw std::runtime_error("corrupt account store");
    }
    std::vector<std::uint8_t> bytes(text.size() / 2U);
    for (std::size_t index = 0U; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::uint8_t>(
            std::stoul(text.substr(index * 2U, 2U), nullptr, 16));
    }
    return bytes;
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
    std::optional<tradep2p::Ed25519PublicKey> login_key;
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
    void set_login_key(const std::string& username, const tradep2p::Ed25519PublicKey& key) {
        std::scoped_lock lock(mutex_);
        const auto it = accounts_.find(username);
        if (it == accounts_.end()) {
            throw std::runtime_error("unknown account");
        }
        it->second.login_key = key;
        append_locked(it->second);
    }

    // std::nullopt for an unknown username OR a known one with no enrolled
    // key - callers must not distinguish the two in any response they send
    // back to a caller who hasn't already authenticated (account
    // enumeration - see the /api/login/key/* routes).
    std::optional<tradep2p::Ed25519PublicKey> login_key(const std::string& username) {
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
            std::string username, salt_hex, hash_hex, created_at, login_key_hex;
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
            std::getline(stream, login_key_hex);
            Account account{username, from_hex(salt_hex), from_hex(hash_hex), created_at,
                            std::nullopt};
            if (!login_key_hex.empty()) {
                const auto raw = from_hex(login_key_hex);
                account.login_key = tradep2p::parse_ed25519_public_key(raw);
                // A malformed trailing field (wrong length, all-zero) is
                // treated as "no key enrolled" rather than aborting the
                // whole load - password auth for this and every other
                // account must keep working regardless.
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
               << (account.login_key.has_value() ? to_hex(*account.login_key) : std::string{})
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
};

struct SessionHandle {
    std::string username;
    std::string csrf_token;
    std::shared_ptr<DashboardClient> client;
};

// One running mediator connection per logged-in account. Logging in again
// from another tab or browser re-attaches the same session instead of
// opening a second connection, matching a "create once, terminate on logout"
// session model.
class SessionManager {
public:
    SessionManager(Endpoint mediator, ClientTlsPolicy tls,
                  std::optional<Endpoint> proxy, std::size_t max_sessions,
                  std::chrono::minutes idle_timeout, std::string mediator_id)
        : mediator_(std::move(mediator)),
          tls_(std::move(tls)),
          proxy_(std::move(proxy)),
          max_sessions_(max_sessions),
          idle_timeout_(idle_timeout),
          mediator_id_(std::move(mediator_id)) {}

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
        // Phase 4b (counterparty recognition) wiring is deliberately NOT
        // done in this binary yet - tradep2p-webclient has no per-account
        // keystore/history concept at all (see docs/IDENTITY-PLAN.md phase
        // 9, still planned), so no RecognitionKeyProvider/
        // RecognitionOutcomeHandler is set here. Leaving both unset means
        // this session safely auto-declines any incoming
        // RecognitionChallenge (see DashboardClient::handle_frame) rather
        // than silently doing nothing - the same "no key, no proof, not
        // evidence of anything" default every other unkeyed path in this
        // architecture already has.
        auto client = std::make_shared<DashboardClient>(mediator_, tls_, proxy_, mediator_id_);
        client->start();
        const std::string token = random_token();
        sessions_.emplace(
            token, WebSession{username, random_token(), std::move(client),
                              std::chrono::steady_clock::now()});
        active_by_user_[username] = token;
        return token;
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
    Endpoint mediator_;
    ClientTlsPolicy tls_;
    std::optional<Endpoint> proxy_;
    std::size_t max_sessions_;
    std::chrono::minutes idle_timeout_;
    std::string mediator_id_;

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

// Matches htdocs/assets/css/style.css so this page reads as part of the
// same site once reverse-proxied under the marketing site's domain.
std::string page_head(const std::string& title, const std::string& home_url) {
    std::ostringstream out;
    out << "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        << "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
        << "<meta name=\"theme-color\" content=\"#f4f2ea\">\n"
        << "<title>" << title << "</title>\n<style>\n"
        << ":root{--bg:#f4f2ea;--panel:#fbfaf5;--panel2:#f1efe4;--line:#b8b09a;"
           "--text:#1a1a15;--muted:#5c5745;--link:#14508c;--accent:#2f6d3a;"
           "--accent-soft:#e4ecdf;--amber:#8a5a10;--danger:#8a2f2a}\n"
        << "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:"
           "var(--text);font:15px/1.55 Verdana,Geneva,Arial,\"Helvetica Neue\","
           "Helvetica,sans-serif}\n"
        << "a{color:var(--link)}code{font-family:\"Courier New\",Courier,"
           "monospace}\n"
        << ".site-strip{border-bottom:3px double var(--line);background:var(--"
           "panel)}\n"
        << ".site-strip .row{width:min(900px,calc(100% - 24px));margin:0 auto;"
           "min-height:44px;justify-content:space-between}\n"
        << ".site-strip a{text-decoration:none;font:700 13px \"Courier New\","
           "Courier,monospace;color:var(--text)}\n"
        << ".site-strip span{color:var(--muted);font-size:12px}\n"
        << ".wrap{width:min(900px,calc(100% - 24px));margin:24px auto 60px}\n"
        << ".wide{width:min(1300px,calc(100% - 24px))}\n"
        << ".panel{border:1px solid var(--line);background:var(--panel);"
           "padding:18px;margin-bottom:14px}\n"
        << ".warning{border:1px solid var(--amber);background:#f6ecd9;color:"
           "#5a4110;padding:14px 16px;margin-bottom:18px;line-height:1.6}\n"
        << ".warning b{color:var(--amber)}\n"
        << "h1{font-size:1.35rem;margin:0 0 6px}h2{margin:0 0 12px;color:var(--"
           "text);font-size:1.02rem}\n"
        << ".muted{color:var(--muted)}\n"
        << "label{display:grid;gap:5px;color:var(--muted);margin-bottom:12px}\n"
        << "input,button{font:inherit;border:1px solid var(--line)}\n"
        << "input{width:100%;padding:8px 9px;background:#fff;color:var(--text)}"
           "\n"
        << "button{padding:7px 13px;background:var(--panel2);color:var(--text);"
           "cursor:pointer}\n"
        << "button:hover{background:var(--accent-soft)}button.primary{"
           "background:var(--accent);border-color:var(--accent);color:#fff}"
           "button.primary:hover{background:#285c31}button.danger{border-color:"
           "var(--danger);color:var(--danger)}\n"
        << ".row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}\n"
        << ".two-col{display:grid;grid-template-columns:1fr 1fr;gap:14px}\n"
        << ".notice{margin:10px 0 0;color:var(--amber)}.error{color:var(--"
           "danger)}\n"
        << "table{width:100%;border-collapse:collapse}th,td{padding:8px 7px;"
           "border-bottom:1px solid var(--line);text-align:left;white-space:"
           "nowrap}th{color:var(--muted);font-size:.78rem}\n"
        << ".room{border:1px solid var(--line);background:var(--panel2);"
           "padding:12px;margin-bottom:10px}\n"
        << ".mono-break{word-break:break-all;font-family:\"Courier New\",Courier"
           ",monospace}.turn{margin-top:10px;padding:9px;border-left:3px solid "
           "var(--amber);background:#f6ecd9}\n"
        << ".events{max-height:260px;overflow:auto;margin:0;padding-left:20px}"
           ".events li{margin:5px 0;color:var(--text)}\n"
        << ".status{display:inline-block;padding:.2rem .55rem;border:1px solid "
           "var(--line);background:var(--panel2);font-size:.8rem}.status."
           "connected,.status.active,.status.complete{border-color:var(--"
           "accent);color:var(--accent)}.status.connecting{border-color:var(--"
           "amber);color:var(--amber)}.status.disconnected,.status.aborted{"
           "border-color:var(--danger);color:var(--danger)}\n"
        << ".topline{display:flex;align-items:center;justify-content:space-"
           "between;gap:12px;flex-wrap:wrap}\n"
        << "@media(max-width:760px){.two-col{grid-template-columns:1fr}}\n"
        << "</style>\n</head>\n<body>\n"
        << "<div class=\"site-strip\"><div class=\"row\"><a href=\"/\">TradeP2P "
           "web client</a><span>hosted session &middot; not the mediator "
           "itself</span>";
    if (!home_url.empty()) {
        out << "<a href=\"" << html_escape(home_url)
            << "\" style=\"margin-left:auto\">&larr; main site</a>";
    }
    out << "</div></div>\n";
    return out.str();
}

std::string landing_html(const std::string& preauth_token, const std::string& home_url) {
    std::ostringstream out;
    out << page_head("TradeP2P Web Client", home_url)
        << "<div class=\"wrap\">\n"
        << "<div class=\"warning\"><b>&#9888; Privacy warning.</b> " << kPrivacyNotice
        << "</div>\n"
        << "<h1>TradeP2P web client</h1>\n"
        << "<p class=\"muted\">Create a session to publish offers, join trades "
           "and settle fractional rounds from your browser.</p>\n"
        << "<div id=\"notice\" class=\"notice\"></div>\n"
        << "<div class=\"two-col\">\n"
        << "<section class=\"panel\">\n<h2>Log in</h2>\n"
        << "<form id=\"login-form\">\n"
        << "<label>Username<input name=\"username\" maxlength=\"32\" required "
           "autocomplete=\"username\"></label>\n"
        << "<label>Password<input name=\"password\" type=\"password\" "
           "maxlength=\"256\" required autocomplete=\"current-password\"></label>\n"
        << "<button class=\"primary\" type=\"submit\">Log in</button>\n"
        << "</form>\n</section>\n"
        << "<section class=\"panel\">\n<h2>Register</h2>\n"
        << "<form id=\"register-form\">\n"
        << "<label>Username (3-32 letters/digits/-/_)<input name=\"username\" "
           "maxlength=\"32\" required autocomplete=\"username\"></label>\n"
        << "<label>Password (8+ characters)<input name=\"password\" "
           "type=\"password\" maxlength=\"256\" required "
           "autocomplete=\"new-password\"></label>\n"
        << "<button class=\"primary\" type=\"submit\">Create session</button>\n"
        << "</form>\n</section>\n"
        << "</div>\n"
        << "<section class=\"panel\">\n<h2>Log in with a key</h2>\n"
        << "<p class=\"muted\">For an account that has enrolled a login key (see "
           "&quot;Account&quot; once logged in). This protects against a leaked "
           "password database or credential stuffing - "
           "<b>it does not protect against this server's own operator</b>, who "
           "controls every byte of this page; see the project's identity "
           "architecture notes (specs.txt SS13.4) before relying on it for more "
           "than that. Signing happens OUTSIDE this browser page (a native client "
           "or other external tool you trust) - this page never generates or "
           "holds your private key.</p>\n"
        << "<form id=\"key-challenge-form\">\n"
        << "<label>Username<input name=\"username\" id=\"key-username\" "
           "maxlength=\"32\" required autocomplete=\"username\"></label>\n"
        << "<button type=\"submit\">Request login challenge</button>\n"
        << "</form>\n"
        << "<div id=\"key-challenge-box\" style=\"display:none\">\n"
        << "<p class=\"muted\">Sign these exact bytes with your enrolled key's "
           "private seed, using the same external tool that generated it, then "
           "paste the resulting signature below. Expires "
           "<span id=\"key-expires\"></span> (unix seconds).</p>\n"
        << "<table class=\"mono-break\"><tbody>"
           "<tr><td>service_id</td><td id=\"key-service\"></td></tr>"
           "<tr><td>server_identity</td><td id=\"key-server\"></td></tr>"
           "<tr><td>session_id</td><td id=\"key-session\"></td></tr>"
           "<tr><td>nonce</td><td id=\"key-nonce\"></td></tr>"
           "<tr><td>created_at</td><td id=\"key-created\"></td></tr>"
           "</tbody></table>\n"
        << "<form id=\"key-verify-form\">\n"
        << "<label>Signature (128 hex characters)<input name=\"signature\" "
           "id=\"key-signature\" maxlength=\"128\" required></label>\n"
        << "<button class=\"primary\" type=\"submit\">Log in</button>\n"
        << "</form>\n</div>\n"
        << "</section>\n"
        << "<p class=\"muted\">This account exists only on this server, only to "
           "let you resume a session. It is not a protocol identity and is "
           "never shown to your trade counterparty or the mediator. A key badge "
           "or key-based login here means only \"controlled the same enrolled "
           "key\" - never trusted, verified, or safe (specs.txt SS14).</p>\n"
        << "</div>\n"
        << "<script>\n"
        << "const PREAUTH_TOKEN=\"" << preauth_token << "\";\n"
        << "function notice(t,bad){const n=document.getElementById('notice');"
           "n.textContent=t;n.className=bad?'notice error':'notice'}\n"
        << "async function submitForm(form,path){const d=Object.fromEntries(new "
           "FormData(form));const r=await "
           "fetch(path,{method:'POST',headers:{'Content-Type':'application/x-www-"
           "form-urlencoded','" << kPreAuthHeader << "':PREAUTH_TOKEN},body:new "
           "URLSearchParams(d)});const body=await "
           "r.json().catch(()=>({ok:false,error:'invalid response'}));if(!r.ok||"
           "!body.ok)throw new Error(body.error||('HTTP '+r.status));location."
           "reload()}\n"
        << "document.getElementById('login-form').onsubmit=async(e)=>{e."
           "preventDefault();try{await submitForm(e.target,'/api/login')}catch(err"
           "){notice(err.message,true)}};\n"
        << "document.getElementById('register-form').onsubmit=async(e)=>{e."
           "preventDefault();try{await submitForm(e.target,'/api/"
           "register')}catch(err){notice(err.message,true)}};\n"
        << "let pendingSessionId=null;\n"
        << "document.getElementById('key-challenge-form').onsubmit=async(e)=>{e."
           "preventDefault();try{const username=document.getElementById("
           "'key-username').value;const r=await fetch('/api/login/key/"
           "challenge',{method:'POST',headers:{'Content-Type':'application/x-"
           "www-form-urlencoded','" << kPreAuthHeader << "':PREAUTH_TOKEN},body:"
           "new URLSearchParams({username})});const body=await r.json();if(!r."
           "ok||!body.ok)throw new Error(body.error||('HTTP '+r.status));"
           "pendingSessionId=body.session_id;document.getElementById('key-"
           "service').textContent=body.service_id;document.getElementById('key-"
           "server').textContent=body.server_identity;document.getElementById("
           "'key-session').textContent=body.session_id;document.getElementById("
           "'key-nonce').textContent=body.nonce;document.getElementById('key-"
           "created').textContent=body.created_at;document.getElementById('key-"
           "expires').textContent=body.expires_at;document.getElementById('key-"
           "challenge-box').style.display='block'}catch(err){notice(err.message,"
           "true)}};\n"
        << "document.getElementById('key-verify-form').onsubmit=async(e)=>{e."
           "preventDefault();try{const username=document.getElementById("
           "'key-username').value;const signature=document.getElementById("
           "'key-signature').value;const r=await fetch('/api/login/key/verify',{"
           "method:'POST',headers:{'Content-Type':'application/x-www-form-"
           "urlencoded','" << kPreAuthHeader << "':PREAUTH_TOKEN},body:new "
           "URLSearchParams({username,session_id:pendingSessionId,signature})});"
           "const body=await r.json();if(!r.ok||!body.ok)throw new Error(body."
           "error||('HTTP '+r.status));location.reload()}catch(err){notice(err."
           "message,true)}};\n"
        << "</script>\n</body>\n</html>";
    return out.str();
}

std::string app_html(const std::string& username, const std::string& csrf_token,
                      const std::string& home_url) {
    std::ostringstream out;
    out << page_head("TradeP2P Web Client", home_url)
        << "<div class=\"wrap wide\">\n"
        << "<div class=\"warning\"><b>&#9888; Privacy warning.</b> " << kPrivacyNotice
        << "</div>\n"
        << "<div class=\"panel topline\">\n"
        << "<div><div class=\"muted\">TRADEP2P WEB CLIENT</div><h1>Session: "
        << html_escape(username) << "</h1>"
        << "<div id=\"identity\" class=\"muted\">connecting&hellip;</div></div>\n"
        << "<div class=\"row\"><span id=\"connection\" class=\"status "
           "connecting\">connecting</span>"
        << "<button class=\"danger\" id=\"logout\">Log out</button></div>\n"
        << "</div>\n"
        << "<div id=\"notice\" class=\"notice\"></div>\n"
        << "<div class=\"two-col\">\n"
        << "<div>\n"
        << "<section class=\"panel\">\n<h2>Publish offer</h2>\n"
        << "<form id=\"offer-form\">\n"
        << "<label>Sell symbol<input name=\"sell_asset\" value=\"QRL\" "
           "maxlength=\"16\" required></label>\n"
        << "<label>Sell amount<input name=\"sell_amount\" value=\"500000\" "
           "inputmode=\"numeric\" required></label>\n"
        << "<label>Buy symbol<input name=\"buy_asset\" value=\"BTC\" "
           "maxlength=\"16\" required></label>\n"
        << "<label>Buy amount<input name=\"buy_amount\" value=\"100000\" "
           "inputmode=\"numeric\" required></label>\n"
        << "<label>Settlement rounds<input name=\"rounds\" value=\"2\" "
           "inputmode=\"numeric\" required></label>\n"
        << "<label>Your receiving address<input name=\"address\" "
           "placeholder=\"receiving-address\" maxlength=\"256\" required></label>\n"
        << "<button class=\"primary\" type=\"submit\">Publish offer</button>\n"
        << "</form>\n</section>\n"
        << "<section class=\"panel\">\n<h2>Take offer</h2>\n"
        << "<label>Your receiving address for the sold asset<input "
           "id=\"join-address\" placeholder=\"receiving-address\" "
           "maxlength=\"256\"></label>\n"
        << "<p class=\"muted\">Set this once, then press Join next to an open "
           "offer.</p>\n</section>\n"
        << "<section class=\"panel\">\n<h2>Event stream</h2>\n"
        << "<ol id=\"events\" class=\"events\"><li>waiting for connection</li></ol>"
           "\n</section>\n"
        << "</div>\n<div>\n"
        << "<section class=\"panel\">\n<div class=\"topline\"><h2>Open "
           "offers</h2><button id=\"refresh-offers\">Refresh</button></div>\n"
        << "<table><thead><tr><th>Room</th><th>Sell</th><th>Buy</th><th>Rounds</"
           "th><th>Actions</th></tr></thead><tbody id=\"offers\"><tr><td "
           "colspan=\"5\" class=\"muted\">waiting for offer list</td></tr></"
           "tbody></table>\n</section>\n"
        << "<section class=\"panel\">\n<h2>My settlement rooms</h2>\n<div "
           "id=\"rooms\"><p class=\"muted\">No active rooms.</p></div>\n</section>"
           "\n"
        << "<section class=\"panel\">\n<h2>Account: key-based login</h2>\n"
        << "<p class=\"muted\">Enroll a public key to also allow challenge-"
           "response login for this account, alongside your password (never "
           "instead of it - enrolling never disables the password). Generate the "
           "keypair with a native tool you trust, never in this browser page; see "
           "the &quot;Log in with a key&quot; panel on the login screen for how "
           "the resulting login works.</p>\n"
        << "<form id=\"enroll-key-form\">\n"
        << "<label>Public key (64 hex characters)<input name=\"public_key\" "
           "maxlength=\"64\" required></label>\n"
        << "<button type=\"submit\">Enroll key</button>\n"
        << "</form>\n</section>\n"
        << "</div>\n</div>\n"
        << "</div>\n<script>\n"
        << "const TOKEN=\"" << csrf_token << "\";\n"
        << "const esc=(v)=>String(v\?\?'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<'"
           ":'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));\n"
        << "const short_=(v)=>{v=String(v\?\?'');return v.length>22?v.slice(0,10)+"
           "'\\u2026'+v.slice(-10):v};\n"
        << "function notice(text,bad){const n=document.getElementById('notice');"
           "n.textContent=text;n.className=bad?'notice error':'notice';"
           "setTimeout(()=>{if(n.textContent===text)n.textContent=''},5000)}\n"
        << "async function post(path,data={}){const "
           "r=await fetch(path,{method:'POST',headers:{'Content-Type':'"
           "application/x-www-form-urlencoded','X-TradeP2P-Token':TOKEN},body:new "
           "URLSearchParams(data)});const body=await "
           "r.json().catch(()=>({ok:false,error:'invalid response'}));if(!r.ok||!"
           "body.ok)throw new Error(body.error||('HTTP '+r.status));return body}\n"
        << "function renderOffers(offers){const "
           "target=document.getElementById('offers');if(!offers.length){target."
           "innerHTML='<tr><td colspan=\"5\" class=\"muted\">No open "
           "offers.</td></tr>';return}target.innerHTML=offers.map(o=>`<tr><td "
           "title=\"${esc(o.room_id)}\">${esc(short_(o.room_id))}</td><td>${esc(o."
           "sell_amount)} ${esc(o.sell_asset)}</td><td>${esc(o.buy_amount)} "
           "${esc(o.buy_asset)}</td><td>${esc(o.rounds)}</td><td><div "
           "class=\"row\"><button data-join=\"${esc(o.room_id)}\" "
           "class=\"primary\">Join</button><button data-cancel=\"${esc(o.room_id)}"
           "\" class=\"danger\">Cancel mine</button></div></td></tr>`).join('');"
           "target.querySelectorAll('[data-join]').forEach(b=>b.onclick=async()=>{"
           "try{const "
           "address=document.getElementById('join-address').value.trim();if(!"
           "address)throw new Error('enter your receiving address "
           "first');await post('/api/offers/join',{room_id:b.dataset.join,"
           "address});notice('join request queued')}catch(e){notice(e.message,"
           "true)}});target.querySelectorAll('[data-cancel]').forEach(b=>b."
           "onclick=async()=>{try{await "
           "post('/api/offers/cancel',{room_id:b.dataset.cancel});notice('cancel "
           "request queued')}catch(e){notice(e.message,true)}})}\n"
        << "function renderRooms(rooms){const "
           "target=document.getElementById('rooms');if(!rooms.length){target."
           "innerHTML='<p class=\"muted\">No settlement rooms in this "
           "session.</p>';return}target.innerHTML=rooms.map(r=>{const "
           "turn=r.turn?`<div class=\"turn\"><b>${r.turn.is_fee?'Mediator "
           "fee':'Round '+esc(r.turn.round)}:</b> party ${esc(r.turn.sender)} "
           "sends "
           "<b>${esc(r.turn.amount)} ${esc(r.turn.asset)}</b><br><span "
           "class=\"muted mono-break\">destination: "
           "${esc(r.turn.destination)}</span></div>`:'';let "
           "primary='';if(r.status==='active'&&r.action==='sent')primary=`<button "
           "class=\"primary\" data-sent=\"${esc(r.room_id)}\">${r.turn&&r.turn."
           "is_fee?'I paid the mediator fee':'I sent "
           "it'}</button>`;if(r.status==='active'&&r.action==='received')primary=`<"
           "button class=\"primary\" data-received=\"${esc(r.room_id)}\">I "
           "verified receipt</button>`;if(r.status==='active'&&r.turn&&r.turn."
           "is_fee&&r.action==='none')primary=`<span class=\"muted\">waiting for "
           "the offer creator to settle the mediator fee</span>`;const "
           "abort=r.status==='active'?`<button class=\"danger\" "
           "data-abort=\"${esc(r.room_id)}\">Abort room</button>`:'';const "
           "fee=r.fee_amount>0?`<div class=\"muted mono-break\">mediator fee: "
           "${esc(r.fee_amount)} ${esc(r.fee_asset)} &rarr; "
           "${esc(r.fee_address)}</div>`:'';const "
           "feeConfirmationLine=r.fee_confirmation_pending?'<p "
           "class=\"notice\">Mediator fee reported sent - waiting for the "
           "mediator operator to confirm receipt before this room "
           "completes.</p>':'';return "
           "`<article class=\"room\"><div class=\"topline\"><div><b "
           "title=\"${esc(r.room_id)}\">Room "
           "${esc(short_(r.room_id))}</b><div class=\"muted\">party "
           "${esc(r.party)} &middot; peer "
           "${esc(short_(r.peer_id))}</div></div><span class=\"status "
           "${esc(r.status)}\">${esc(r.status)}</span></div><p>${esc(r.sell_"
           "amount)} ${esc(r.sell_asset)} &harr; ${esc(r.buy_amount)} "
           "${esc(r.buy_asset)} &middot; ${esc(r.rounds)} rounds</p><div "
           "class=\"muted mono-break\">party A receives: "
           "${esc(r.receive_address_a)}<br>party B receives: "
           "${esc(r.receive_address_b)}</div>${fee}${turn}${feeConfirmationLine}${r.detail?`<p "
           "class=\"notice\">${esc(r.detail)}</p>`:''}<div "
           "class=\"row\">${primary}${abort}</div></article>`}).join('');target."
           "querySelectorAll('[data-sent]').forEach(b=>b.onclick=()=>roomAction('/"
           "api/rooms/sent',b.dataset.sent));target.querySelectorAll('[data-"
           "received]').forEach(b=>b.onclick=()=>roomAction('/api/rooms/received',"
           "b.dataset.received));target.querySelectorAll('[data-abort]').forEach("
           "b=>b.onclick=()=>roomAction('/api/rooms/abort',b.dataset.abort))}\n"
        << "async function roomAction(path,room){try{await "
           "post(path,{room_id:room});notice('room action "
           "queued')}catch(e){notice(e.message,true)}}\n"
        << "function renderEvents(events){document.getElementById('events')."
           "innerHTML=(events.length?events:['No events "
           "yet.']).map(e=>`<li>${esc(e)}</li>`).join('')}\n"
        << "async function refresh(){try{const r=await "
           "fetch('/api/state',{cache:'no-store'});if(r.status===401){location."
           "reload();return}const s=await r.json();const "
           "c=document.getElementById('connection');c.textContent=s."
           "connection_status;c.className='status "
           "'+(s.connected?'connected':'disconnected');const "
           "fee=s.mediator_fee_amount>0?(' &middot; mediator fee: "
           "'+esc(s.mediator_fee_amount)+' '+esc(s.mediator_fee_asset)):'';"
           "document.getElementById("
           "'identity').innerHTML=(s.client_id?'anonymous mediator client "
           "'+esc(s.client_id):'not connected to a "
           "mediator yet')+fee;renderOffers(s.offers||[]);renderRooms(s.rooms||[]);"
           "renderEvents(s.events||[])}catch(e){notice('refresh failed: "
           "'+e.message,true)}}\n"
        << "document.getElementById('offer-form').onsubmit=async(e)=>{e."
           "preventDefault();try{const d=Object.fromEntries(new "
           "FormData(e.target));await "
           "post('/api/offers/create',d);notice('offer request "
           "queued')}catch(err){notice(err.message,true)}};\n"
        << "document.getElementById('refresh-offers').onclick=async()=>{try{"
           "await post('/api/offers/refresh');notice('offer refresh "
           "queued')}catch(e){notice(e.message,true)}};\n"
        << "document.getElementById('logout').onclick=async()=>{try{await "
           "post('/api/logout')}catch(e){}location.reload()};\n"
        << "document.getElementById('enroll-key-form').onsubmit=async(e)=>{e."
           "preventDefault();try{const "
           "public_key=document.getElementById('enroll-key-form').public_key."
           "value;await post('/api/account/enroll-key',{public_key});notice('login "
           "key enrolled')}catch(err){notice(err.message,true)}};\n"
        << "refresh();setInterval(refresh,1000);\n"
        << "</script>\n</body>\n</html>";
    return out.str();
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
        SessionManager sessions(mediator, tls, proxy, max_sessions, idle_timeout, mediator_id_text);
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
                                "default-src 'self'; style-src 'unsafe-inline'; "
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
                           const auto challenge =
                               login_tracker.issue(kLoginServiceId, server_identity, username);
                           std::ostringstream json;
                           json << "{\"ok\":true"
                                << ",\"session_id\":\"" << json_escape(to_hex(challenge.session_id))
                                << "\",\"nonce\":\"" << json_escape(to_hex(challenge.nonce)) << "\""
                                << ",\"service_id\":\"" << json_escape(challenge.service_id) << "\""
                                << ",\"server_identity\":\""
                                << json_escape(challenge.server_identity) << "\""
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
                           if (session_id_bytes.size() == tradep2p::kLoginSessionIdLength &&
                               signature_bytes.size() == tradep2p::kEd25519SignatureLength) {
                               tradep2p::LoginSessionId session_id{};
                               std::copy(session_id_bytes.begin(), session_id_bytes.end(),
                                        session_id.begin());
                               tradep2p::Ed25519Signature signature{};
                               std::copy(signature_bytes.begin(), signature_bytes.end(),
                                        signature.begin());

                               const auto challenge = login_tracker.peek(session_id);
                               login_tracker.consume(session_id); // unconditional - single-use either way
                               // A key is always fetched (or, for an
                               // unenrolled/unknown account, a fixed dummy
                               // key is substituted) so that verification
                               // always does the same amount of work on the
                               // same shape of input, regardless of account
                               // state - part of the same enumeration-
                               // resistance property AccountStore::verify()
                               // already applies to the password path.
                               static const tradep2p::Ed25519PublicKey kDummyKey{};
                               const auto enrolled = accounts.login_key(username);
                               const auto& key_to_check = enrolled.has_value() ? *enrolled : kDummyKey;
                               ok = challenge.has_value() && challenge->username == username &&
                                    enrolled.has_value() &&
                                    tradep2p::verify_login_response(key_to_check, *challenge, signature);
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
                           const std::string public_key_hex = required_param(request, "public_key");
                           const auto raw = from_hex(public_key_hex);
                           const auto parsed = tradep2p::parse_ed25519_public_key(raw);
                           if (!parsed.has_value()) {
                               throw std::invalid_argument("invalid public key");
                           }
                           accounts.set_login_key(session->username, *parsed);
                           set_json_result(response, true, "login key enrolled");
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

        server.Post("/api/offers/refresh",
                   action([&](const httplib::Request&, const SessionHandle& session) {
                       session.client->refresh_offers();
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
