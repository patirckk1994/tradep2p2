#include <httplib.h>

#include "tradep2p/dashboard_client.hpp"
#include "tradep2p/history.hpp"
#include "tradep2p/keystore.hpp"

#include <array>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

using tradep2p::ClientTlsPolicy;
using tradep2p::Endpoint;
using tradep2p::TradeTerms;
using tradep2p::dashboard::DashboardClient;
using tradep2p::dashboard::json_escape;
using tradep2p::dashboard::random_token;

// ---------------------------------------------------------------------------
// Phase 4 CLI/dashboard wiring: a single operator's keystore and counterparty
// history, held for the lifetime of this dashboard process. Guarded by its
// own mutex, separate from DashboardClient's internal state_mutex_, since
// httplib::Server services requests from a small thread pool - see each
// route handler below for exactly what is held under this lock and for how
// long (never across the AEAD/KDF work itself is unusual, but every access
// to identity_state's fields is).
//
// Security posture, matching the CLI's identical posture in main.cpp: the
// passphrase travels as an ordinary application/x-www-form-urlencoded POST
// field to this LOOPBACK-ONLY dashboard process (see host_allowed() below,
// already enforced for every route) - it is never sent to the mediator, and
// never leaves loopback. This is the same trust model the rest of this
// dashboard already has (see the README's "do not expose it directly to the
// public Internet" guidance) - no new exposure is introduced by adding a
// passphrase field to it.
// ---------------------------------------------------------------------------
struct IdentityDashboardState {
    std::mutex mutex;
    std::optional<tradep2p::IdentityKeystore> keystore;
    std::string keystore_path;
    std::optional<tradep2p::LocalCounterpartyHistory> history;
    // This dashboard process's mediator endpoint text (e.g. "host:port"),
    // used as the implicit mediator_id for history records - a dashboard
    // process only ever talks to one mediator at a time, matching the CLI's
    // identical design choice (see history.hpp's fingerprint-scoping
    // decision for why this is per-mediator, not global).
    std::string mediator_id;
    // Security tier (specs.txt SS8): both default false, preserving today's
    // unlinkable-by-default behavior unchanged unless a user explicitly
    // opts in. persistent_identity_enabled alone means "prove my identity-
    // layer pseudonym in every room automatically" (per-mediator scoped,
    // same key recognition already used for a manual per-room click);
    // global_identity_enabled additionally means "and reuse ONE such
    // pseudonym across every mediator, not just this one" - only
    // meaningful when persistent_identity_enabled is also true, but kept as
    // an independent bool rather than an enum so the JSON/API shape stays a
    // simple pair of checkboxes matching the two-checkbox UI directly.
    bool persistent_identity_enabled{false};
    bool global_identity_enabled{false};
};

template <std::size_t N>
std::string hex_encode(const std::array<std::uint8_t, N>& bytes) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (const std::uint8_t byte : bytes) {
        stream << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return stream.str();
}

// PRECONDITION: state.mutex already held.
std::string identity_state_json_locked(const IdentityDashboardState& state) {
    const std::string tier_json =
        std::string(",\"persistent_identity_enabled\":") +
        (state.persistent_identity_enabled ? "true" : "false") +
        ",\"global_identity_enabled\":" + (state.global_identity_enabled ? "true" : "false");
    if (!state.keystore.has_value()) {
        return "{\"ok\":true,\"loaded\":false" + tier_json + "}";
    }
    const auto identity = state.keystore->public_identity();
    std::ostringstream json;
    json << "{\"ok\":true,\"loaded\":true"
         << ",\"unlocked\":" << (state.keystore->is_unlocked() ? "true" : "false")
         << ",\"path\":\"" << json_escape(state.keystore_path) << "\""
         << ",\"alias\":\"" << json_escape(identity.alias) << "\""
         << ",\"identity_id\":\"" << json_escape(hex_encode(identity.identity_id)) << "\""
         << ",\"public_key\":\"" << json_escape(hex_encode(identity.identity_public_key)) << "\""
         << ",\"public_key_mldsa65\":\""
         << (state.keystore->is_unlocked()
                 ? json_escape(hex_encode(state.keystore->identity_public_key_mldsa65()))
                 : std::string{})
         << "\""
         << ",\"created_at\":" << identity.created_at
         << ",\"key_generation\":" << identity.key_generation << tier_json << "}";
    return json.str();
}

// PRECONDITION: state.mutex already held. Throws std::invalid_argument if no
// keystore is currently unlocked - callers (the /api/history/* routes) let
// this propagate to action()'s existing try/catch, matching how every other
// validation failure in this file is already reported to the browser.
//
// Deliberately checks is_unlocked() every time, not merely "was a history
// handle already opened earlier this session" - unlike the CLI (main.cpp),
// which documents that an already-open Journal/LocalCounterpartyHistory
// handle stays usable after /keystore lock until the process exits. This is
// an intentional divergence: the dashboard's "Lock" button is a visual,
// walk-away-from-the-screen affordance, and a Lock click that left history
// entries still rendering in the browser would defeat the point of it. The
// CLI has no equivalent "someone might glance at the screen" concern in the
// same way, so it optimizes for not re-deriving keys unnecessarily instead.
tradep2p::LocalCounterpartyHistory& ensure_history_open_locked(IdentityDashboardState& state) {
    if (!state.keystore.has_value() || !state.keystore->is_unlocked()) {
        throw std::invalid_argument("no unlocked keystore; unlock or create one first");
    }
    if (!state.history.has_value()) {
        state.history = tradep2p::LocalCounterpartyHistory::open(state.keystore_path + ".history",
                                                                  *state.keystore);
    }
    return *state.history;
}

// PRECONDITION: state.mutex already held.
std::string history_list_json_locked(IdentityDashboardState& state) {
    if (!state.keystore.has_value() || !state.keystore->is_unlocked()) {
        return "{\"ok\":true,\"unlocked\":false,\"entries\":[]}";
    }
    auto& history = ensure_history_open_locked(state);
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
            json << "{\"recorded_at\":" << note.recorded_at << ",\"text\":\"" << json_escape(note.text)
                 << "\"}";
        }
        json << "],\"evidence_count\":" << entry.evidence_hashes.size() << "}";
    }
    json << "]}";
    return json.str();
}

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

#ifdef TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL
// Mirrors lobby.cpp's/main.cpp's identical helper of the same shape.
std::string env_or_empty(const char* name) {
    const char* value = std::getenv(name);
    return value == nullptr ? std::string{} : std::string(value);
}
#endif

std::string required_param(const httplib::Request& request,
                           const char* name) {
    if (!request.has_param(name)) {
        throw std::invalid_argument(std::string("missing form field: ") + name);
    }
    const std::string value = request.get_param_value(name);
    if (value.empty()) {
        throw std::invalid_argument(std::string("empty form field: ") + name);
    }
    return value;
}

std::string read_server_state(const std::string& state_file) {
    if (state_file.empty()) {
        return "{\"enabled\":false}";
    }
    std::ifstream input(state_file);
    if (!input.is_open()) {
        return "{\"enabled\":true,\"available\":false,\"error\":\"state file not available yet\"}";
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    const std::string content = buffer.str();
    if (content.empty()) {
        return "{\"enabled\":true,\"available\":false,\"error\":\"state file is empty\"}";
    }
    return content;
}

std::string dashboard_html(const std::string& token,
                           bool server_state_enabled) {
    std::string html = R"HTML(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TradeP2P Lobby Dashboard</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='10' fill='%23060605'/%3E%3Crect x='1.5' y='1.5' width='61' height='61' rx='9' fill='none' stroke='%232a2a28' stroke-width='1.4'/%3E%3Cpath d='M32 11 L56 53 H8 Z' fill='none' stroke='%235b8fe6' stroke-width='2.2' stroke-linejoin='round'/%3E%3Cpath d='M23.5 26.5 H40.5' stroke='%235b8fe6' stroke-width='1.6' stroke-linecap='round'/%3E%3Cpath d='M21 36 Q32 41 43 36' fill='none' stroke='%238fb4f2' stroke-width='2.2' stroke-linecap='round'/%3E%3Cpath d='M26 38 L24.3 42' stroke='%238fb4f2' stroke-width='1.6' stroke-linecap='round'/%3E%3Cpath d='M32 39.4 L32 43.6' stroke='%238fb4f2' stroke-width='1.6' stroke-linecap='round'/%3E%3Cpath d='M38 38 L39.7 42' stroke='%238fb4f2' stroke-width='1.6' stroke-linecap='round'/%3E%3C/svg%3E">
<style>
/* Same design language as the main UMBRA site (assets/css/style.css) -
   this page can't link that stylesheet directly (it's served standalone
   by this binary, not through the PHP site), so the shared palette/fonts/
   meander motif are duplicated here rather than approximated. Layout
   below is dashboard-specific (data-dense, wider .wrap than the site's
   880px prose .shell) since this is a working tool, not a marketing page. */
:root{--bg:#0c0c0a;--bg-deep:#060605;--panel:#17160f;--panel-2:#201f16;--line:#4a453a;--line-soft:#322f27;--text:#f2efe4;--muted:#a39d89;--accent:#5b8fe6;--accent-soft:#16233d;--amber:#d9a441;--danger:#d9635c;--sans:Verdana,Geneva,Arial,"Helvetica Neue",Helvetica,sans-serif;--mono:"Courier New",Courier,ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;--serif:Cambria,Georgia,"Times New Roman",Times,serif;--meander:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='14'%3E%3Cpath d='M0 12 L0 2 L8 2 L8 7 L16 7 L16 2 L24 2' fill='none' stroke='%235b8fe6' stroke-width='2.2'/%3E%3C/svg%3E")}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 var(--sans)}
h1,h2,h3{font-family:var(--serif);letter-spacing:.01em}
code,.mono-break,input,button{font-family:var(--mono)}
.wrap{width:min(1500px,calc(100% - 24px));margin:0 auto}
.site-header{position:relative;border-bottom:3px double var(--line);background:var(--panel);margin-bottom:0}
.site-header::after{content:"";display:block;height:12px;background-image:var(--meander);background-repeat:repeat-x;background-position:center;opacity:.8}
.nav-shell{min-height:56px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:10px 0}
.brand{display:inline-flex;align-items:center;gap:10px}
.brand-mark{display:block;flex:none}
.brand-copy{display:grid;line-height:1.15}
.brand-copy strong{font:700 15px var(--mono);color:var(--text)}
.brand-copy small{color:var(--muted);font-size:11px;letter-spacing:.03em;margin-top:2px}
.session-bar{padding:10px 0;border-bottom:1px solid var(--line-soft);background:var(--panel);margin-bottom:18px}
#identity{color:var(--muted);font-size:13px}
.notice{color:var(--amber);font-size:13px;padding:6px 0 0}
.grid{display:grid;grid-template-columns:minmax(340px,.8fr) minmax(500px,1.7fr);gap:14px;padding-bottom:60px}
/* min-width:0 on every grid/flex level below is the actual fix for the
   "squashed/overlapping panels" bug: grid items default to min-width:auto,
   which lets wide unbreakable content (a 64-hex-char fingerprint, an
   nowrap table row) force a track past its intended size instead of
   scrolling inside .table-wrap/.hexrow as intended - the overflow then
   visually bleeds into the adjacent column. */
.grid,.stack,.panel,.hexrow{min-width:0}
.stack{display:grid;gap:14px;align-content:start}
.panel{padding:20px;border:1px solid var(--line);background:var(--panel)}
.panel h2{margin:0 0 14px;color:var(--accent);font-size:1.05rem}
.panel h3{margin:0 0 10px;color:var(--text);font-size:.95rem}
.topline{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.topline h2{margin:0}
.muted{color:var(--muted)}
.status{display:inline-block;padding:.25rem .6rem;border:1px solid var(--line);font:700 11px var(--mono);text-transform:uppercase;letter-spacing:.03em;background:var(--panel-2)}
.status.connected,.status.active,.status.complete{border-color:var(--accent);color:var(--accent);background:var(--accent-soft)}
.status.connecting{border-color:var(--amber);color:var(--amber);background:#241a08}
.status.disconnected,.status.aborted{border-color:var(--danger);color:var(--danger);background:#2a1512}
label{display:grid;gap:5px;color:var(--muted);font-family:var(--sans);font-size:13px}
input,button{font-size:13px;border:1px solid var(--line)}
input{width:100%;padding:9px 10px;background:var(--bg-deep);color:var(--text);min-width:0}
button{padding:8px 12px;background:var(--panel-2);color:var(--text);cursor:pointer}
button:hover{border-color:var(--accent)}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.primary:hover{background:#7fa8ee}
button.danger{background:#3a1c14;border-color:var(--danger);color:#f3c9c2}
button:disabled{opacity:.45;cursor:not-allowed}
.tier-row{display:grid;grid-template-columns:auto 1fr;gap:10px;align-items:start;color:var(--text);font-size:13px}
.tier-row input[type=checkbox]{width:auto;margin-top:3px}
.tier-warn{color:var(--amber)}
.tier-disabled{opacity:.6}
tr.active{background:var(--accent-soft)}
.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.span2{grid-column:span 2}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{padding:9px 8px;border-bottom:1px solid var(--line-soft);text-align:left}
th{color:var(--muted);font:700 11px var(--mono);text-transform:uppercase;letter-spacing:.03em;white-space:nowrap}
td{font-size:13px;font-family:var(--sans)}
.room{border:1px solid var(--line);background:var(--panel-2);padding:14px;margin-bottom:10px}
.room-head{display:flex;justify-content:space-between;gap:10px;align-items:flex-start;flex-wrap:wrap}
.mono-break{word-break:break-all;font-size:.85em}
.turn{margin-top:10px;padding:10px;border-left:3px solid var(--amber);background:var(--bg-deep)}
.events{max-height:330px;overflow:auto;margin:0;padding-left:20px;font-size:13px;font-family:var(--sans)}
.events li{margin:5px 0;color:var(--text)}
.server-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}
.metric{background:var(--bg-deep);border:1px solid var(--line);padding:10px;min-width:0}
.metric b{display:block;color:var(--accent);font:700 11px var(--mono);text-transform:uppercase}
.error{color:var(--danger)}
@media(max-width:1000px){.grid{grid-template-columns:1fr}}
@media(max-width:620px){.form-grid,.server-grid{grid-template-columns:1fr}.span2{grid-column:auto}}
button.copy{padding:2px 7px;font-size:.8rem;background:transparent;border-color:var(--line);color:var(--muted)}button.copy:hover{color:var(--accent);border-color:var(--accent)}.hexrow{display:flex;align-items:center;gap:6px}.hexrow .mono-break{flex:1;min-width:0}details.crypto{margin-top:10px;border-top:1px dashed var(--line);padding-top:8px}details.crypto summary{cursor:pointer;color:var(--accent);font-size:.85rem;font-family:var(--sans)}details.crypto .field{margin:6px 0}details.crypto .field b{display:block;color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.03em;margin-bottom:2px;font-family:var(--sans)}.receipt-card{background:var(--bg-deep);border:1px solid var(--line);padding:9px;margin-top:6px}.pq{color:var(--accent)}.classical{color:var(--amber)}
</style>
</head>
<body>
<header class="site-header">
  <div class="wrap nav-shell">
    <div class="brand">
      <svg class="brand-mark" viewBox="0 0 64 64" width="32" height="32" aria-hidden="true">
        <rect width="64" height="64" rx="10" fill="#060605"/>
        <rect x="1.5" y="1.5" width="61" height="61" rx="9" fill="none" stroke="#2a2a28" stroke-width="1.4"/>
        <path d="M32 11 L56 53 H8 Z" fill="none" stroke="#5b8fe6" stroke-width="2.2" stroke-linejoin="round"/>
        <path d="M23.5 26.5 H40.5" stroke="#5b8fe6" stroke-width="1.6" stroke-linecap="round"/>
        <path d="M21 36 Q32 41 43 36" fill="none" stroke="#8fb4f2" stroke-width="2.2" stroke-linecap="round"/>
        <path d="M26 38 L24.3 42" stroke="#8fb4f2" stroke-width="1.6" stroke-linecap="round"/>
        <path d="M32 39.4 L32 43.6" stroke="#8fb4f2" stroke-width="1.6" stroke-linecap="round"/>
        <path d="M38 38 L39.7 42" stroke="#8fb4f2" stroke-width="1.6" stroke-linecap="round"/>
      </svg>
      <span class="brand-copy"><strong>TRADEP2P</strong><small>lobby + mediator dashboard</small></span>
    </div>
    <span id="connection" class="status connecting">connecting</span>
  </div>
</header>
<div class="session-bar">
  <div class="wrap">
    <div id="identity">anonymous client not connected yet</div>
    <div id="notice" class="notice"></div>
  </div>
</div>
<div class="wrap">
  <div class="grid">
    <div class="stack">
      <section class="panel">
        <h2>// identity / keystore</h2>
        <div id="identity-status" class="muted">loading identity status&hellip;</div>
        <form id="keystore-form" class="form-grid">
          <label class="span2">Keystore file path<input name="ks_path" placeholder="/path/to/identity.ks" required></label>
          <label class="span2">Passphrase<input name="ks_passphrase" type="password" required></label>
          <label class="span2">Alias (optional, used by Create only)<input name="ks_alias" maxlength="255"></label>
          <div class="actions span2">
            <button type="button" id="ks-create" class="primary">Create</button>
            <button type="button" id="ks-unlock" class="primary">Unlock</button>
            <button type="button" id="ks-lock">Lock</button>
            <button type="button" id="ks-rotate">Rotate service key</button>
            <button type="button" id="ks-destroy" class="danger">Destroy</button>
          </div>
        </form>
        <p class="muted">The passphrase is sent to this loopback-only dashboard process as an ordinary form field; it is never sent to the mediator.</p>
      </section>
      <section class="panel">
        <h2>// security tier</h2>
        <p class="muted">Your choice, not a recommendation either way - see specs.txt SS8. Off by
        default: nothing here is enabled unless you check it.</p>
        <div class="form-grid">
          <label class="span2 tier-row">
            <input type="checkbox" id="tier-persistent">
            <span><b>Persistent identity (reputation)</b> - lets you answer a recognition
            challenge with the same key every time (per-mediator), instead of never
            revealing one. Still manual, per room - click "Recognize counterparty" when
            you want a specific counterparty to see it, same as before. Off means
            declining every challenge automatically, indistinguishable from not having a
            keystore at all. <span class="tier-warn">Revealing this key at all correlates
            whichever rooms you use it in - that's the point, not a side effect, if
            reputation is what you want.</span></span>
          </label>
          <label class="span2 tier-row">
            <input type="checkbox" id="tier-global" disabled>
            <span><b>Global (all mediators)</b> - reuse ONE identity across every mediator you
            trade through, not just this one. <span class="tier-warn">Wider correlation than
            per-mediator alone - your reputation follows you everywhere, and so does the
            linkability.</span> Requires the checkbox above.</span>
          </label>
)HTML"
#ifdef TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL
              R"HTML(
          <label class="span2 tier-row">
            <input type="checkbox" id="blindsig-enable" disabled>
            <span><b>Blind-signature unlinkable credentials (EXPERIMENTAL, UNREVIEWED)</b> -
            see specs.txt SS9.3a. This checkbox reflects whether the dashboard process was
            started with a blind-signature prover configured
            (TRADEP2P_BLINDSIG_PROVER_PATH); it does not itself turn the feature on or off.
            <span class="tier-warn">Unreviewed post-quantum cryptography - proving a request
            takes ~100-200s and happens in the background; use the panel below once
            enabled.</span></span>
          </label>
)HTML"
#else
              R"HTML(
          <label class="span2 tier-row tier-disabled">
            <input type="checkbox" disabled>
            <span><b>Blind-signature unlinkable credentials</b> - not implemented. See
            specs.txt SS9.3 for status and why.</span>
          </label>
)HTML"
#endif
              R"HTML(
        </div>
      </section>
)HTML"
#ifdef TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL
              R"HTML(
      <section class="panel">
        <h2>// blind-signature credential (EXPERIMENTAL, UNREVIEWED)</h2>
        <p class="muted">See specs.txt SS9.3a. Only usable if this dashboard process was
        started with TRADEP2P_BLINDSIG_PROVER_PATH set. Proving is slow (~100-200s per
        request) and runs in the background; this panel polls for progress, it does not
        block.</p>
        <div id="blindsig-disabled-notice" class="muted" style="display:none">Not enabled for
        this dashboard process - set TRADEP2P_BLINDSIG_PROVER_PATH and restart it.</div>
        <div id="blindsig-panel-body" style="display:none">
          <form id="blindsig-form" class="form-grid">
            <label class="span2">Message to blind-sign<input name="blindsig_message" maxlength="512" placeholder="message"></label>
            <div class="actions span2">
              <button type="button" id="blindsig-fetch-info">Fetch mediator info</button>
              <button class="primary" type="submit">Request signature</button>
            </div>
          </form>
          <div id="blindsig-status" class="muted">stage: unknown</div>
        </div>
      </section>
)HTML"
#endif
              R"HTML(
      <section class="panel">
        <h2>// publish offer</h2>
        <form id="offer-form" class="form-grid">
          <label>Sell symbol<input name="sell_asset" value="QRL" maxlength="16" required></label>
          <label>Sell amount (integer units)<input name="sell_amount" value="500000" inputmode="numeric" required></label>
          <label>Buy symbol<input name="buy_asset" value="BTC" maxlength="16" required></label>
          <label>Buy amount (integer units)<input name="buy_amount" value="100000" inputmode="numeric" required></label>
          <label>Settlement rounds<input name="rounds" value="2" inputmode="numeric" required></label>
          <label class="span2">Your receiving address for the asset you buy<input name="address" placeholder="receiving-address" maxlength="256" required></label>
          <div class="actions span2"><button class="primary" type="submit">Publish offer</button></div>
        </form>
        <div id="publish-fee-notice" class="muted"></div>
      </section>
      <section class="panel">
        <h2>// take offer</h2>
        <label>Your receiving address for the asset offered by the seller<input id="join-address" placeholder="receiving-address" maxlength="256"></label>
        <p class="muted">Set this once, then press Join next to an open offer.</p>
        <div id="join-fee-notice" class="muted"></div>
      </section>
      <section class="panel">
        <h2>// mediator state</h2>
        <div id="server-state" class="muted">__SERVER_STATE_TEXT__</div>
      </section>
      <section class="panel">
        <h2>// cryptographic telemetry</h2>
        <p class="muted">Display only - every trust decision here already
        happened before this panel renders anything (TLS pin verification,
        signature checks, chain verification). Nothing on this page changes
        what is trusted, it just shows what was.</p>
        <div id="crypto-telemetry" class="muted">waiting for dashboard client&hellip;</div>
      </section>
      <section class="panel">
        <h2>// network telemetry</h2>
        <p class="muted">Traffic to your one connected mediator, over its one
        session, counted at this client's own framing layer - not a view of
        the wider mediator/registry mesh (this client has no such view; see
        specs.txt if that ever changes). Header overhead is exact (each
        frame's fixed-size header is a protocol constant); throughput is a
        simple average over the current session, not a live rate.</p>
        <div id="network-telemetry" class="muted">waiting for dashboard client&hellip;</div>
      </section>
      <section class="panel">
        <h2>// registry visibility</h2>
        <p class="muted">A fixed-frame snapshot of one registry's public listing, polled
        periodically (started with <code>--registry</code>) - not a live connection, and not
        this client's own view of the network mesh. "Source" empty means that registry
        vetted the mediator directly; a peer name means it was relayed via gossip
        federation (specs.txt SS1.3).</p>
        <div id="registry-visibility" class="muted">not configured (start with --registry)</div>
      </section>
      <section class="panel">
        <h2>// event stream</h2>
        <ol id="events" class="events"><li>waiting for dashboard client</li></ol>
      </section>
    </div>
    <div class="stack">
      <section class="panel">
        <div class="topline"><h2>// open lobbies / offers</h2><button id="refresh-offers">Refresh offers</button></div>
        <div class="table-wrap"><table><thead><tr><th>Room</th><th>Sell</th><th>Buy</th><th>Rounds</th><th>Actions</th></tr></thead><tbody id="offers"><tr><td colspan="5" class="muted">waiting for offer list</td></tr></tbody></table></div>
      </section>
      <section class="panel">
        <h2>// my settlement rooms</h2>
        <div id="rooms"><p class="muted">No active rooms.</p></div>
      </section>
      <section class="panel">
        <div class="topline"><h2>// counterparty history &amp; blocklist</h2><button id="refresh-history">Refresh</button></div>
        <div id="history-status" class="muted">requires an unlocked keystore</div>
        <div class="table-wrap"><table><thead><tr><th>Fingerprint</th><th>Mediator</th><th>First / last seen</th><th>Encounters</th><th>Status</th><th>Notes</th><th>Actions</th></tr></thead><tbody id="history-rows"><tr><td colspan="7" class="muted">no data yet</td></tr></tbody></table></div>
        <form id="note-form" class="form-grid">
          <label class="span2">Fingerprint (64 hex chars)<input name="note_fp" maxlength="64" placeholder="counterparty fingerprint"></label>
          <label class="span2">Note text<input name="note_text" placeholder="e.g. slow to respond but completed the trade"></label>
          <div class="actions span2"><button type="submit" class="primary">Add note (creates the record if new)</button></div>
        </form>
      </section>
    </div>
  </div>
</div>
<script>
const TOKEN="__TOKEN__";
const serverStateEnabled=__SERVER_STATE_ENABLED__;
const esc=(v)=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const short=(v)=>{v=String(v??'');return v.length>22?v.slice(0,10)+'…'+v.slice(-10):v};
const copyBtn=(v)=>v?`<button type="button" class="copy" data-copy="${esc(v)}" title="copy full value">⧉</button>`:'';
const hexField=(label,v)=>v?`<div class="field"><b>${esc(label)}</b><div class="hexrow"><span class="mono-break">${esc(v)}</span>${copyBtn(v)}</div></div>`:'';
document.body.addEventListener('click',e=>{const b=e.target.closest('[data-copy]');if(!b)return;navigator.clipboard.writeText(b.dataset.copy).then(()=>notice('copied to clipboard')).catch(()=>notice('copy failed - clipboard unavailable',true))});
let lastIdentityPublicKey='';
function notice(text,bad=false){const n=document.getElementById('notice');n.textContent=text;n.className=bad?'notice error':'notice';setTimeout(()=>{if(n.textContent===text)n.textContent=''},5000)}
async function post(path,data={}){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-TradeP2P-Token':TOKEN},body:new URLSearchParams(data)});const body=await r.json().catch(()=>({ok:false,error:'invalid dashboard response'}));if(!r.ok||!body.ok)throw new Error(body.error||('HTTP '+r.status));return body}
function renderOffers(offers){const target=document.getElementById('offers');if(!offers.length){target.innerHTML='<tr><td colspan="5" class="muted">No open offers.</td></tr>';return}target.innerHTML=offers.map(o=>`<tr><td title="${esc(o.room_id)}">${esc(short(o.room_id))}</td><td>${esc(o.sell_amount)} ${esc(o.sell_asset)}</td><td>${esc(o.buy_amount)} ${esc(o.buy_asset)}</td><td>${esc(o.rounds)}</td><td><div class="actions"><button data-join="${esc(o.room_id)}" class="primary">Join</button><button data-cancel="${esc(o.room_id)}" class="danger">Cancel mine</button></div></td></tr>`).join('');target.querySelectorAll('[data-join]').forEach(b=>b.onclick=async()=>{try{const address=document.getElementById('join-address').value.trim();if(!address)throw new Error('enter your receiving address first');await post('/api/offers/join',{room_id:b.dataset.join,address});notice('join request queued')}catch(e){notice(e.message,true)}});target.querySelectorAll('[data-cancel]').forEach(b=>b.onclick=async()=>{try{await post('/api/offers/cancel',{room_id:b.dataset.cancel});notice('cancel request queued')}catch(e){notice(e.message,true)}})}
function roomCryptoDetail(r){const rc=r.recognition_challenge;const rr=r.recognition_response;const chParts=rc?[hexField('Challenge nonce (sent by us)',rc.nonce),`<div class="field"><b>Challenge suite / window</b><div class="muted">suite ${esc(rc.suite_id)} &middot; created ${esc(rc.created_at)} &middot; expires ${esc(rc.expires_at)}</div></div>`]:[];const rrParts=rr?[hexField("Counterparty's recognition public key",rr.public_key),hexField("Counterparty's recognition signature",rr.signature)]:[];const ownAnswerParts=r.own_recognition_response_signature?[hexField('Our recognition-response signature (we answered their challenge)',r.own_recognition_response_signature)]:[];const recognitionSection=(chParts.length||rrParts.length||ownAnswerParts.length)?`<div class="field"><b>Recognition (specs.txt §8)</b></div>${chParts.join('')}${rrParts.join('')}${ownAnswerParts.join('')}`:'<p class="muted">No recognition challenge issued or answered in this room yet.</p>';const receipts=(r.receipts||[]).map(x=>`<div class="receipt-card"><div class="field"><b>Stage</b>${esc(x.stage)}${x.completed?' <span class="pq">(completed)</span>':''} &middot; suite ${esc(x.suite_id)} &middot; ts ${esc(x.timestamp)}</div>${hexField('Nonce',x.nonce)}${hexField('Terms commitment',x.terms_commitment)}${hexField('Party A ephemeral key',x.party_a_ephemeral_key)}${hexField('Party B ephemeral key',x.party_b_ephemeral_key)}${hexField('Mediator public key',x.mediator_public_key)}${hexField('Previous stage hash',x.previous_stage_hash)}${hexField('Mediator signature',x.mediator_signature)}${hexField('Chain-link hash',x.chain_link_hash)}</div>`).join('');const receiptsSection=`<div class="field" style="margin-top:8px"><b>Receipt chain (${(r.receipts||[]).length})</b></div>${receipts||'<p class="muted">No receipts issued yet.</p>'}`;return `<details class="crypto" data-detail-room="${esc(r.room_id)}"${expandedDetails.has(r.room_id)?' open':''}><summary>&#9656; crypto detail</summary>${recognitionSection}${receiptsSection}</details>`}
const expandedDetails=new Set();
const pendingTurn=new Map();
const selectedSuite=new Map();
const turnKey=(r)=>r.turn?`${r.turn.round}:${r.turn.sender}:${r.turn.is_fee}:${r.action}`:`no-turn:${r.status}`;
const waitingText='queued - waiting for the counterparty to confirm…';
const waitingHtml=`<button class="primary" disabled>${waitingText}</button>`;
function renderRooms(rooms){const target=document.getElementById('rooms');if(document.activeElement&&target.contains(document.activeElement)&&document.activeElement.tagName==='SELECT')return;if(!rooms.length){pendingTurn.clear();expandedDetails.clear();selectedSuite.clear();target.innerHTML='<p class="muted">No settlement rooms in this browser session.</p>';return}const liveIds=new Set(rooms.map(r=>r.room_id));for(const id of pendingTurn.keys())if(!liveIds.has(id))pendingTurn.delete(id);for(const id of expandedDetails)if(!liveIds.has(id))expandedDetails.delete(id);for(const id of selectedSuite.keys())if(!liveIds.has(id))selectedSuite.delete(id);target.innerHTML=rooms.map(r=>{const turn=r.turn?`<div class="turn"><b>${r.turn.is_fee?'Mediator fee':'Round '+esc(r.turn.round)}:</b> party ${esc(r.turn.sender)} sends <b>${esc(r.turn.amount)} ${esc(r.turn.asset)}</b><br><span class="muted mono-break">destination: ${esc(r.turn.destination)}</span></div>`:'';const tKey=turnKey(r);const isPending=pendingTurn.get(r.room_id)===tKey;let primary='';if(isPending){primary=waitingHtml;}else if(r.status==='active'&&r.action==='sent'){primary=`<button class="primary" data-sent="${esc(r.room_id)}" data-turnkey="${esc(tKey)}">${r.turn&&r.turn.is_fee?'I paid the mediator fee':'I sent it'}</button>`;}else if(r.status==='active'&&r.action==='received'){primary=`<button class="primary" data-received="${esc(r.room_id)}" data-turnkey="${esc(tKey)}">I verified receipt</button>`;}else if(r.status==='active'&&r.action==='awaiting_peer_send'){primary='<button class="primary" disabled>waiting for the counterparty to send this round&hellip;</button>';}else if(r.status==='active'&&r.turn&&r.turn.is_fee&&r.action==='none'){primary='<span class="muted">waiting for the offer creator to settle the mediator fee</span>';}const abort=r.status==='active'?`<button class="danger" data-abort="${esc(r.room_id)}">Abort room</button>`:'';const fee=r.fee_amount>0?`<div class="muted mono-break">mediator fee: ${esc(r.fee_amount)} ${esc(r.fee_asset)} &rarr; ${esc(r.fee_address)}</div>`:'';const canRecognize=r.status==='active'&&(r.recognition_status==='none'||r.recognition_status==='failed');const suiteSel=selectedSuite.get(r.room_id)||'ml-dsa-65';const recognize=canRecognize?`<select data-suite="${esc(r.room_id)}"><option value="ml-dsa-65"${suiteSel==='ml-dsa-65'?' selected':''}>ML-DSA-65 (PQ)</option><option value="ed25519"${suiteSel==='ed25519'?' selected':''}>Ed25519</option></select> <button data-recognize="${esc(r.room_id)}">Recognize counterparty</button>`:'';let recognitionLine='';if(r.recognition_status==='challenge_sent')recognitionLine='<p class="muted">recognition challenge sent - awaiting response</p>';else if(r.recognition_status==='recognized')recognitionLine=`<p class="muted">counterparty proved control of <span class="mono-break">${esc(r.recognized_fingerprint)}</span>${copyBtn(r.recognized_fingerprint)} - see History panel for prior settlement count with this key</p>`;else if(r.recognition_status==='declined')recognitionLine='<p class="muted">declined to answer counterparty\'s recognition challenge (no keystore unlocked)</p>';else if(r.recognition_status==='failed')recognitionLine='<p class="muted">a recognition response did not verify - not evidence of anything, may retry</p>';const ephemeralLine=r.own_ephemeral_key?`<p class="muted">ephemeral trade key: <span class="mono-break">${esc(short(r.own_ephemeral_key))}</span>${copyBtn(r.own_ephemeral_key)}${r.counterparty_ephemeral_key?` &middot; counterparty: <span class="mono-break">${esc(short(r.counterparty_ephemeral_key))}</span>${copyBtn(r.counterparty_ephemeral_key)}`:' &middot; awaiting counterparty announcement'} (unlinkable to any other room by design)</p>`:'';const receiptLine=r.receipt_status==='none'?'':`<p class="muted">receipt: ${esc(r.receipt_status)}${r.receipt_status!=='gate_open'?(r.receipt_chain_verifies?' (chain verifies)':' (chain INVALID)'):''}</p>`;const feeConfirmationLine=r.fee_confirmation_pending?'<p class="notice">Mediator fee reported sent - waiting for the mediator operator to confirm receipt before this room completes.</p>':'';return `<article class="room"><div class="room-head"><div><h3 title="${esc(r.room_id)}">Room ${esc(short(r.room_id))}${copyBtn(r.room_id)}</h3><div class="muted">party ${esc(r.party)} · peer ${esc(short(r.peer_id))}</div></div><span class="status ${esc(r.status)}">${esc(r.status)}</span></div><p>${esc(r.sell_amount)} ${esc(r.sell_asset)} ↔ ${esc(r.buy_amount)} ${esc(r.buy_asset)} · ${esc(r.rounds)} rounds</p><div class="muted mono-break">party A receives: ${esc(r.receive_address_a)}<br>party B receives: ${esc(r.receive_address_b)}</div>${fee}${turn}${ephemeralLine}${receiptLine}${feeConfirmationLine}${recognitionLine}${r.detail?`<p class="notice">${esc(r.detail)}</p>`:''}<div class="actions">${primary}${abort}${recognize}</div>${roomCryptoDetail(r)}</article>`}).join('');target.querySelectorAll('[data-sent]').forEach(b=>b.onclick=()=>{const room=b.dataset.sent;pendingTurn.set(room,b.dataset.turnkey);b.disabled=true;b.textContent=waitingText;roomAction('/api/rooms/sent',room,()=>pendingTurn.delete(room))});target.querySelectorAll('[data-received]').forEach(b=>b.onclick=()=>{const room=b.dataset.received;pendingTurn.set(room,b.dataset.turnkey);b.disabled=true;b.textContent=waitingText;roomAction('/api/rooms/received',room,()=>pendingTurn.delete(room))});target.querySelectorAll('[data-abort]').forEach(b=>b.onclick=()=>{b.disabled=true;roomAction('/api/rooms/abort',b.dataset.abort)});target.querySelectorAll('select[data-suite]').forEach(s=>s.onchange=()=>{selectedSuite.set(s.dataset.suite,s.value)});target.querySelectorAll('[data-recognize]').forEach(b=>b.onclick=()=>{b.disabled=true;const sel=document.querySelector(`select[data-suite="${b.dataset.recognize}"]`);roomAction('/api/recognition/recognize',b.dataset.recognize,null,{suite:sel?sel.value:'ed25519'})});target.querySelectorAll('details.crypto').forEach(d=>d.addEventListener('toggle',()=>{const id=d.dataset.detailRoom;if(d.open)expandedDetails.add(id);else expandedDetails.delete(id)}))}
async function roomAction(path,room,onError,extra={}){try{await post(path,{room_id:room,...extra});notice('room action queued')}catch(e){notice(e.message,true);if(onError)onError()}}
function renderEvents(events){document.getElementById('events').innerHTML=(events.length?events:['No events yet.']).map(e=>`<li>${esc(e)}</li>`).join('')}
const fmtBytes=(n)=>{n=Number(n)||0;if(n<1024)return n+' B';if(n<1024*1024)return (n/1024).toFixed(1)+' KiB';return (n/(1024*1024)).toFixed(2)+' MiB'};
const fmtDuration=(s)=>{s=Number(s)||0;if(s<60)return s+'s';const m=Math.floor(s/60),r=s%60;if(m<60)return m+'m '+r+'s';const h=Math.floor(m/60);return h+'h '+(m%60)+'m'};
function renderNetworkTelemetry(s){const target=document.getElementById('network-telemetry');const t=(s&&s.traffic)||{};const framesSent=t.frames_sent||0,framesReceived=t.frames_received||0,payloadSent=t.payload_bytes_sent||0,payloadReceived=t.payload_bytes_received||0,headerBytes=t.header_bytes||0,connCount=t.connection_count||0,connSeconds=t.connection_seconds||0;const totalWire=payloadSent+payloadReceived+headerBytes;const overheadPct=totalWire>0?((headerBytes/totalWire)*100).toFixed(1):'0.0';const avgSentRate=connSeconds>0?fmtBytes(payloadSent/connSeconds)+'/s':'n/a (just connected)';const avgReceivedRate=connSeconds>0?fmtBytes(payloadReceived/connSeconds)+'/s':'n/a (just connected)';target.innerHTML=`<div class="field"><b>Frames sent / received</b><div class="muted">${esc(framesSent)} sent &middot; ${esc(framesReceived)} received</div></div>`+`<div class="field"><b>Payload bytes sent / received</b><div class="muted">${fmtBytes(payloadSent)} sent &middot; ${fmtBytes(payloadReceived)} received</div></div>`+`<div class="field"><b>Framing overhead</b><div class="muted">${fmtBytes(headerBytes)} of ${fmtBytes(totalWire)} total (${overheadPct}%) - ${esc(framesSent+framesReceived)} frames &times; 20-byte header</div></div>`+`<div class="field"><b>Average throughput (this session)</b><div class="muted">${avgSentRate} out &middot; ${avgReceivedRate} in</div></div>`+`<div class="field"><b>Connections since launch / current session uptime</b><div class="muted">${esc(connCount)} connection${connCount===1?'':'s'} &middot; ${s&&s.connected?fmtDuration(connSeconds):'not connected'}</div></div>`}
function renderTelemetry(s){const target=document.getElementById('crypto-telemetry');if(!s||!s.connected){target.innerHTML='<span class="muted">not connected yet.</span>';return}const t=s.tls||{};const group=t.negotiated_group||'';const isHybrid=/MLKEM/i.test(group);const sig=t.peer_certificate_signature_algorithm||'';const isPqSig=/ML-DSA|SLH-DSA/i.test(sig);target.innerHTML=`<div class="field"><b>Transport - TLS version / cipher</b><div class="muted">${esc(t.protocol_version||'unknown')} &middot; ${esc(t.cipher_suite||'unknown')}</div></div>`+`<div class="field"><b>Negotiated key-exchange group</b><div class="hexrow"><span class="${isHybrid?'pq':'classical'}">${esc(group||'unknown')}</span><span class="muted">${isHybrid?'(post-quantum hybrid)':'(classical - peer or library did not offer the hybrid group)'}</span></div></div>`+`<div class="field"><b>Mediator certificate signature algorithm</b><div class="hexrow"><span class="${isPqSig?'pq':'classical'}">${esc(sig||'unknown')}</span><span class="muted">${isPqSig?'(post-quantum)':'(classical)'}</span></div></div>`+hexField('Mediator certificate SHA-256 (the pin)',t.peer_certificate_sha256)+hexField("This session's pseudonym public key (keystore)",lastIdentityPublicKey)+hexField('Mediator receipt-signing public key - Ed25519 (trust-on-first-use pin)',s.mediator_receipt_key)+hexField('Mediator receipt-signing public key - ML-DSA-65 (post-quantum, trust-on-first-use pin)',s.mediator_receipt_key_mldsa65)+'<p class="muted">Receipts are hybrid-signed: both keys above must verify. Per-room ephemeral keys, recognition proofs, and receipt chains are under each room\'s "crypto detail" toggle below.</p>'}
function sourceLabel(source){return source?`<span class="muted">via ${esc(source)}</span>`:'<span class="pq">direct</span>'}
function renderRegistryVisibility(s){const target=document.getElementById('registry-visibility');const r=(s&&s.registry)||{configured:false};if(!r.configured){target.innerHTML='<span class="muted">not configured (start with --registry)</span>';return}if(r.error){target.innerHTML=`<p class="muted">registry: <span class="mono-break">${esc(r.endpoint)}</span></p><p class="notice">poll failed: ${esc(r.error)}</p>`;return}const nodes=r.nodes||[];const rows=nodes.length?nodes.map(n=>{const endpoint=`${n.host}:${n.port}`;return `<tr${n.is_current_mediator?' class="active"':''}><td>${esc(endpoint)}${n.is_current_mediator?' <span class="pq">(this session\'s mediator)</span>':''}</td><td title="${esc(n.certificate_pin)}">${esc(short(n.certificate_pin))}${copyBtn(n.certificate_pin)}</td><td>${esc(n.remaining_ttl_seconds)}s</td><td>${sourceLabel(n.source_registry)}</td></tr>`}).join(''):'<tr><td colspan="4" class="muted">registry reports no approved mediators</td></tr>';target.innerHTML=`<p class="muted">registry: <span class="mono-break">${esc(r.endpoint)}</span> &middot; polled ${esc(r.polled_seconds_ago)}s ago</p><div class="table-wrap"><table><thead><tr><th>Host:Port</th><th>Pin</th><th>TTL</th><th>Source</th></tr></thead><tbody>${rows}</tbody></table></div>`}
async function refreshClient(){try{const r=await fetch('/api/state',{cache:'no-store'});const s=await r.json();const c=document.getElementById('connection');c.textContent=s.connection_status;c.className='status '+(s.connected?'connected':'disconnected');const hasFee=s.mediator_fee_amount>0;const fee=hasFee?(' · mediator fee: '+esc(s.mediator_fee_amount)+' '+esc(s.mediator_fee_asset)+' → '+esc(s.mediator_fee_address)):'';document.getElementById('identity').textContent=(s.client_id?'anonymous client '+s.client_id:'anonymous client not connected')+fee;document.getElementById('publish-fee-notice').textContent=hasFee?('This mediator charges a fee: '+s.mediator_fee_amount+' '+s.mediator_fee_asset+' → '+s.mediator_fee_address+' - as the offer creator, YOU pay this as an extra final step after settlement (not deducted from your trade amounts).'):'This mediator currently charges no fee.';document.getElementById('join-fee-notice').textContent=hasFee?('This mediator charges a fee: '+s.mediator_fee_amount+' '+s.mediator_fee_asset+' → '+s.mediator_fee_address+' - paid by the offer creator, not you, as an extra step after your rounds settle.'):'This mediator currently charges no fee.';renderOffers(s.offers||[]);renderRooms(s.rooms||[]);renderEvents(s.events||[]);renderTelemetry(s);renderNetworkTelemetry(s);renderRegistryVisibility(s)}catch(e){notice('dashboard refresh failed: '+e.message,true)}}
function renderServer(s){const t=document.getElementById('server-state');if(!serverStateEnabled){t.innerHTML='<span class="muted">Server snapshot disabled. Start the mediator with TRADEP2P_LOBBY_STATE_FILE and pass the same path to --server-state.</span>';return}if(s.available===false){t.innerHTML='<span class="error">'+esc(s.error||'snapshot unavailable')+'</span>';return}t.innerHTML=`<div class="server-grid"><div class="metric"><b>Clients</b>${esc(s.clients??0)}</div><div class="metric"><b>Open offers</b>${esc((s.offers||[]).length)}</div><div class="metric"><b>Active rooms</b>${esc((s.rooms||[]).length)}</div><div class="metric"><b>Pending invites</b>${esc(s.pending_invites??0)}</div></div><p class="muted">${esc(s.bind||'')} · snapshot ${esc(s.generated_at||'')}</p>`+(s.rooms||[]).map(r=>`<div class="room"><b title="${esc(r.room_id)}">${esc(short(r.room_id))}</b> · ${esc(r.state)} · round ${esc(r.round)}/${esc(r.rounds)} · ${esc(r.total_a)} ${esc(r.asset_a)} ↔ ${esc(r.total_b)} ${esc(r.asset_b)}</div>`).join('')}
async function refreshServer(){if(!serverStateEnabled)return;try{const r=await fetch('/api/server-state',{cache:'no-store'});renderServer(await r.json())}catch(e){document.getElementById('server-state').textContent='server snapshot error: '+e.message}}
document.getElementById('offer-form').onsubmit=async(e)=>{e.preventDefault();try{const d=Object.fromEntries(new FormData(e.target));await post('/api/offers/create',d);notice('offer request queued')}catch(err){notice(err.message,true)}};
document.getElementById('refresh-offers').onclick=async()=>{try{await post('/api/offers/refresh');notice('offer refresh queued')}catch(e){notice(e.message,true)}};
let tierEditing=false;
function syncTierCheckboxes(s){if(tierEditing)return;const p=document.getElementById('tier-persistent'),g=document.getElementById('tier-global');p.checked=!!s.persistent_identity_enabled;g.checked=!!s.global_identity_enabled;g.disabled=!p.checked}
async function postTier(){try{await post('/api/identity/tier',{persistent:document.getElementById('tier-persistent').checked?'1':'0',global:document.getElementById('tier-global').checked?'1':'0'})}catch(e){notice(e.message,true)}}
document.addEventListener('DOMContentLoaded',()=>{const p=document.getElementById('tier-persistent'),g=document.getElementById('tier-global');const onchange=async()=>{tierEditing=true;g.disabled=!p.checked;if(!p.checked)g.checked=false;await postTier();tierEditing=false};p.addEventListener('change',onchange);g.addEventListener('change',onchange)});
async function refreshIdentity(){try{const r=await fetch('/api/identity/state',{cache:'no-store'});const s=await r.json();const el=document.getElementById('identity-status');lastIdentityPublicKey=(s.loaded&&s.unlocked)?(s.public_key||''):'';syncTierCheckboxes(s);if(!s.loaded){el.innerHTML='<span class="muted">No keystore loaded. Create or unlock one above.</span>';return}el.innerHTML=`<div class="server-grid"><div class="metric"><b>Status</b>${s.unlocked?'unlocked':'locked'}</div><div class="metric"><b>Alias</b>${esc(s.alias||'(none)')}</div><div class="metric"><b>Key generation</b>${esc(s.key_generation)}</div><div class="metric"><b>Created</b>${esc(s.created_at)}</div></div><p class="muted mono-break">path: ${esc(s.path)}<br>identity id: ${esc(s.identity_id)}<br>public key: ${esc(s.public_key)}${copyBtn(s.public_key)}</p>`}catch(e){document.getElementById('identity-status').textContent='identity status error: '+e.message}}
async function refreshHistory(){try{const r=await fetch('/api/history/list',{cache:'no-store'});const s=await r.json();const tbody=document.getElementById('history-rows');const status=document.getElementById('history-status');if(!s.unlocked){status.textContent='requires an unlocked keystore';tbody.innerHTML='<tr><td colspan="7" class="muted">locked</td></tr>';return}status.textContent=s.entries.length+' record(s) for this session'+"'"+'s mediator';tbody.innerHTML=s.entries.length?s.entries.map(en=>`<tr><td class="mono-break" title="${esc(en.fingerprint)}">${esc(short(en.fingerprint))}</td><td>${esc(en.mediator_id)}</td><td>${esc(en.first_seen)} / ${esc(en.last_seen)}</td><td>${esc(en.encounter_count)}</td><td>${en.locally_blocked?'<b class="error">BLOCKED</b>':esc(en.display_category)}</td><td>${esc(en.notes.length)}</td><td><div class="actions"><button data-block="${esc(en.fingerprint)}" data-blocked="${en.locally_blocked?1:0}">${en.locally_blocked?'Unblock':'Block'}</button></div></td></tr>`).join(''):'<tr><td colspan="7" class="muted">No counterparty records yet.</td></tr>';tbody.querySelectorAll('[data-block]').forEach(b=>b.onclick=async()=>{try{const path=b.dataset.blocked==='1'?'/api/history/unblock':'/api/history/block';await post(path,{fingerprint:b.dataset.block});notice('history updated');refreshHistory()}catch(e){notice(e.message,true)}})}catch(e){document.getElementById('history-status').textContent='history error: '+e.message}}
document.getElementById('ks-create').onclick=async()=>{try{const d=Object.fromEntries(new FormData(document.getElementById('keystore-form')));await post('/api/identity/create',{path:d.ks_path,passphrase:d.ks_passphrase,alias:d.ks_alias||''});notice('keystore created');refreshIdentity();refreshHistory()}catch(e){notice(e.message,true)}};
document.getElementById('ks-unlock').onclick=async()=>{try{const d=Object.fromEntries(new FormData(document.getElementById('keystore-form')));await post('/api/identity/unlock',{path:d.ks_path,passphrase:d.ks_passphrase});notice('keystore unlocked');refreshIdentity();refreshHistory()}catch(e){notice(e.message,true)}};
document.getElementById('ks-lock').onclick=async()=>{try{await post('/api/identity/lock');notice('keystore locked');refreshIdentity();refreshHistory()}catch(e){notice(e.message,true)}};
document.getElementById('ks-rotate').onclick=async()=>{try{const d=Object.fromEntries(new FormData(document.getElementById('keystore-form')));await post('/api/identity/rotate',{passphrase:d.ks_passphrase});notice('service-scoped key rotated');refreshIdentity()}catch(e){notice(e.message,true)}};
document.getElementById('ks-destroy').onclick=async()=>{try{const d=Object.fromEntries(new FormData(document.getElementById('keystore-form')));if(!confirm('Destroy keystore at '+d.ks_path+'? This cannot be undone.'))return;await post('/api/identity/destroy',{path:d.ks_path});notice('keystore destroyed');refreshIdentity();refreshHistory()}catch(e){notice(e.message,true)}};
document.getElementById('note-form').onsubmit=async(e)=>{e.preventDefault();try{const d=Object.fromEntries(new FormData(e.target));await post('/api/history/note',{fingerprint:d.note_fp,text:d.note_text});notice('note added');refreshHistory()}catch(err){notice(err.message,true)}};
document.getElementById('refresh-history').onclick=()=>refreshHistory();
)HTML"
#ifdef TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL
              R"HTML(
async function refreshBlindsig(){try{const r=await fetch('/api/blindsig/state',{cache:'no-store'});const s=await r.json();const chk=document.getElementById('blindsig-enable');const dis=document.getElementById('blindsig-disabled-notice');const body=document.getElementById('blindsig-panel-body');if(!s.enabled){chk.checked=false;dis.style.display='';body.style.display='none';return}chk.checked=true;dis.style.display='none';body.style.display='';const st=document.getElementById('blindsig-status');let html='stage: '+esc(s.stage);if(s.error)html+='<br><span class="error">error: '+esc(s.error)+'</span>';if(s.credential)html+='<br>credential ready - rho: '+esc(s.credential.rho_hex)+'<br>message: "'+esc(s.credential.mu)+'"<br>proof file: '+esc(s.credential.pi2_path);st.innerHTML=html}catch(e){document.getElementById('blindsig-status').textContent='blind-signature status error: '+e.message}}
document.getElementById('blindsig-fetch-info').onclick=async()=>{try{await post('/api/blindsig/info');notice('requested blind-signature info from mediator');refreshBlindsig()}catch(e){notice(e.message,true)}};
document.getElementById('blindsig-form').onsubmit=async(e)=>{e.preventDefault();try{const d=Object.fromEntries(new FormData(e.target));if(!d.blindsig_message)throw new Error('message required');await post('/api/blindsig/request',{message:d.blindsig_message});notice('blind-signature request submitted - proving in the background (~100-200s)');refreshBlindsig()}catch(err){notice(err.message,true)}};
refreshBlindsig();setInterval(refreshBlindsig,2000);
)HTML"
#endif
              R"HTML(
refreshClient();refreshServer();refreshIdentity();refreshHistory();setInterval(refreshClient,1000);setInterval(refreshServer,1500);setInterval(refreshIdentity,2000);setInterval(refreshHistory,2000);
</script>
</body>
</html>)HTML";

    const auto replace_all = [&](const std::string& needle,
                                 const std::string& replacement) {
        std::size_t position = 0U;
        while ((position = html.find(needle, position)) != std::string::npos) {
            html.replace(position, needle.size(), replacement);
            position += replacement.size();
        }
    };
    replace_all("__TOKEN__", token);
    replace_all("__SERVER_STATE_ENABLED__",
                server_state_enabled ? "true" : "false");
    replace_all("__SERVER_STATE_TEXT__",
                server_state_enabled ? "waiting for mediator snapshot"
                                     : "server snapshot disabled");
    return html;
}

void set_json_result(httplib::Response& response,
                     bool ok,
                     const std::string& message,
                     int status = 200) {
    response.status = status;
    response.set_content(
        std::string("{\"ok\":") + (ok ? "true" : "false") +
            (ok ? ",\"message\":\"" : ",\"error\":\"") +
            json_escape(message) + "\"}",
        "application/json; charset=utf-8");
}

void print_usage(const char* program) {
    std::cerr
        << "Usage:\n"
        << "  " << program
        << " client <mediator:port> <certificate-sha256> [options]\n"
        << "  " << program
        << " client-tor <proxy:port> <onion:port> <certificate-sha256> [options]\n\n"
        << "Options:\n"
        << "  --listen HOST        HTTP bind address (default 127.0.0.1)\n"
        << "  --port PORT          HTTP port (default 8080)\n"
        << "  --server-state FILE  read local mediator snapshot JSON\n"
        << "  --registry HOST:PORT      optional: periodically poll this registry's\n"
        << "                            public listing and show it in the Registry\n"
        << "                            visibility panel (requires --registry-pin).\n"
        << "                            Never this client's own network mesh view -\n"
        << "                            just what that one registry currently sees.\n"
        << "  --registry-pin HEX        the registry's certificate SHA-256 pin\n"
        << "                            (required with --registry).\n"
        << "  --registry-proxy HOST:PORT  SOCKS5 proxy for an .onion --registry\n";
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
        // Phase 4 history wiring: the mediator endpoint TEXT (not just the
        // parsed Endpoint), used as the implicit mediator_id for this
        // dashboard's counterparty history records - see history.hpp's
        // fingerprint-scoping decision (per-mediator, not global).
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
        int http_port = 8080;
        std::string server_state_file;
        std::optional<Endpoint> registry;
        std::optional<std::string> registry_pin;
        std::optional<Endpoint> registry_proxy;
        for (int index = option_index; index < argc; ++index) {
            const std::string argument = argv[index];
            if (argument == "--listen" && index + 1 < argc) {
                listen_host = argv[++index];
            } else if (argument == "--port" && index + 1 < argc) {
                http_port = static_cast<int>(parse_port(argv[++index]));
            } else if (argument == "--server-state" && index + 1 < argc) {
                server_state_file = argv[++index];
            } else if (argument == "--registry" && index + 1 < argc) {
                registry = parse_endpoint(argv[++index]);
            } else if (argument == "--registry-pin" && index + 1 < argc) {
                registry_pin = argv[++index];
            } else if (argument == "--registry-proxy" && index + 1 < argc) {
                registry_proxy = parse_endpoint(argv[++index]);
            } else if (argument == "--help") {
                print_usage(argv[0]);
                return EXIT_SUCCESS;
            } else {
                throw std::invalid_argument("unknown or incomplete dashboard option: " +
                                            argument);
            }
        }
        if (registry.has_value() != registry_pin.has_value()) {
            throw std::invalid_argument("--registry and --registry-pin must be given together");
        }
        if (registry_proxy.has_value() && !registry.has_value()) {
            throw std::invalid_argument("--registry-proxy requires --registry");
        }

        DashboardClient client(mediator, tls, proxy, mediator_id_text, registry,
                               registry_pin.has_value()
                                   ? std::optional<ClientTlsPolicy>(ClientTlsPolicy{*registry_pin})
                                   : std::nullopt,
                               registry_proxy);
        const std::string token = random_token();

        IdentityDashboardState identity_state;
        identity_state.mediator_id = mediator_id_text;

        // Phase 4b wiring: bridges DashboardClient's worker thread (which
        // knows nothing about keystores) to this process's own
        // IdentityDashboardState (which owns one) - see dashboard_client.hpp's
        // RecognitionKeyProvider/RecognitionOutcomeHandler comments for the
        // lock-ordering discipline this depends on. Must be set before
        // client.start() so no early RecognitionChallenge/Response frame can
        // race an unset callback.
        client.set_recognition_key_provider(
            [&identity_state]() -> std::optional<tradep2p::dashboard::RecognitionKeyMaterial> {
                std::scoped_lock lock(identity_state.mutex);
                // Security tier gate (specs.txt SS8): an unlocked keystore
                // alone must NOT be enough to auto-answer a challenge - that
                // would silently leak a persistent identity to anyone who
                // challenges a user who unlocked their keystore for an
                // unrelated feature (history/receipts), with no tier ever
                // actually being off in practice. Declining because the
                // tier is off looks identical on the wire to declining
                // because no keystore is unlocked at all - "declining is
                // not evidence of anything" (see the class comment above)
                // covers this case too, deliberately.
                if (!identity_state.persistent_identity_enabled ||
                    !identity_state.keystore.has_value() || !identity_state.keystore->is_unlocked()) {
                    return std::nullopt;
                }
                // Security tier (specs.txt SS8): global_identity_enabled
                // swaps the scope AND uses a fixed empty identifier instead
                // of mediator_id, so the same recognition pseudonym comes
                // out regardless of which mediator this process is talking
                // to. Both remain the SAME derivation mechanism
                // (derive_ed25519_keypair/derive_mldsa65_keypair) - only the
                // scope label and identifier differ, no new cryptography.
                const bool global = identity_state.global_identity_enabled;
                const std::string_view scope = global ? tradep2p::key_scope::kGlobalPseudonym
                                                       : tradep2p::key_scope::kMediatorPseudonym;
                const std::string_view scope_mldsa65 = global
                    ? tradep2p::key_scope::kGlobalPseudonymMlDsa65
                    : tradep2p::key_scope::kMediatorPseudonymMlDsa65;
                const std::string identifier = global ? std::string{} : identity_state.mediator_id;
                auto keypair = tradep2p::derive_ed25519_keypair(
                    identity_state.keystore->master_secret(), scope, identifier);
                auto mldsa65_keypair = tradep2p::derive_mldsa65_keypair(
                    identity_state.keystore->master_secret(), scope_mldsa65, identifier);
                tradep2p::dashboard::RecognitionKeyMaterial material;
                material.private_seed = std::move(keypair.private_seed);
                material.public_key = keypair.public_key;
                material.mldsa65_private_seed = std::move(mldsa65_keypair.private_seed);
                material.mldsa65_public_key = mldsa65_keypair.public_key;
                return material;
            });
        client.set_recognition_outcome_handler(
            [&identity_state](const std::array<std::uint8_t, 32>& fingerprint,
                              tradep2p::dashboard::RecognitionOutcome outcome) {
                std::scoped_lock lock(identity_state.mutex);
                if (!identity_state.keystore.has_value() || !identity_state.keystore->is_unlocked()) {
                    return;
                }
                auto& history = ensure_history_open_locked(identity_state);
                const tradep2p::CounterpartyFingerprint counterparty_fingerprint = fingerprint;
                history.record_encounter(
                    counterparty_fingerprint, identity_state.mediator_id,
                    outcome == tradep2p::dashboard::RecognitionOutcome::Successful
                        ? tradep2p::LocalOutcome::Successful
                        : tradep2p::LocalOutcome::Incomplete);
            });
#ifdef TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL
        // Experimental, unreviewed cryptography - specs.txt SS9.3a. Same
        // env-var-only gate as main.cpp's CLI client
        // (TRADEP2P_BLINDSIG_PROVER_PATH) - unset means the feature stays
        // fully absent from this dashboard process's behavior, not merely
        // hidden in the UI. Must run before client.start(), same timing
        // requirement as the recognition callbacks just above.
        if (const std::string prover_path = env_or_empty("TRADEP2P_BLINDSIG_PROVER_PATH");
            !prover_path.empty()) {
            client.enable_blindsig(prover_path);
            std::cout << "Blind-signature client enabled - EXPERIMENTAL, UNREVIEWED "
                         "cryptography, see specs.txt SS9.3a before relying on this.\n";
        }
#endif
        client.start();

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

        server.Get("/", [&](const httplib::Request& request, httplib::Response& response) {
            if (!host_allowed(request)) {
                response.status = 403;
                response.set_content("forbidden host", "text/plain; charset=utf-8");
                return;
            }
            response.set_header("Cache-Control", "no-store");
            response.set_header("X-Frame-Options", "DENY");
            response.set_header("Content-Security-Policy",
                                "default-src 'self'; style-src 'unsafe-inline'; "
                                "script-src 'unsafe-inline'; frame-ancestors 'none'");
            response.set_content(
                dashboard_html(token, !server_state_file.empty()),
                "text/html; charset=utf-8");
        });

        server.Get("/api/state",
                   [&](const httplib::Request& request, httplib::Response& response) {
                       if (!host_allowed(request)) {
                           response.status = 403;
                           return;
                       }
                       response.set_header("Cache-Control", "no-store");
                       response.set_content(client.state_json(),
                                            "application/json; charset=utf-8");
                   });

        server.Get("/api/server-state",
                   [&](const httplib::Request& request, httplib::Response& response) {
                       if (!host_allowed(request)) {
                           response.status = 403;
                           return;
                       }
                       response.set_header("Cache-Control", "no-store");
                       response.set_content(read_server_state(server_state_file),
                                            "application/json; charset=utf-8");
                   });

        const auto authorized = [&](const httplib::Request& request) {
            return request.get_header_value("X-TradeP2P-Token") == token;
        };

        const auto action = [&](auto handler) {
            return [&, handler](const httplib::Request& request,
                                httplib::Response& response) {
                if (!host_allowed(request)) {
                    set_json_result(response, false, "forbidden host", 403);
                    return;
                }
                if (!authorized(request)) {
                    set_json_result(response, false, "invalid dashboard token", 403);
                    return;
                }
                try {
                    handler(request);
                    set_json_result(response, true, "queued");
                } catch (const std::exception& error) {
                    set_json_result(response, false, error.what(), 400);
                }
            };
        };

        server.Post("/api/offers/refresh", action([&](const httplib::Request&) {
                        client.refresh_offers();
                    }));

        server.Post("/api/offers/create", action([&](const httplib::Request& request) {
                        TradeTerms terms;
                        terms.asset_a = required_param(request, "sell_asset");
                        terms.total_a = parse_u64(
                            required_param(request, "sell_amount"), "sell amount");
                        terms.asset_b = required_param(request, "buy_asset");
                        terms.total_b = parse_u64(
                            required_param(request, "buy_amount"), "buy amount");
                        terms.rounds = parse_u32(
                            required_param(request, "rounds"), "round count");
                        terms.first_sender = tradep2p::Party::A;
                        client.create_offer(
                            terms, required_param(request, "address"));
                    }));

        server.Post("/api/offers/join", action([&](const httplib::Request& request) {
                        client.join_offer(required_param(request, "room_id"),
                                          required_param(request, "address"));
                    }));

        server.Post("/api/offers/cancel", action([&](const httplib::Request& request) {
                        client.cancel_offer(required_param(request, "room_id"));
                    }));

        server.Post("/api/rooms/sent", action([&](const httplib::Request& request) {
                        client.mark_sent(required_param(request, "room_id"));
                    }));

        server.Post("/api/rooms/received", action([&](const httplib::Request& request) {
                        client.mark_received(required_param(request, "room_id"));
                    }));

        server.Post("/api/rooms/abort", action([&](const httplib::Request& request) {
                        client.abort_room(required_param(request, "room_id"));
                    }));

        server.Post("/api/recognition/recognize", action([&](const httplib::Request& request) {
                        const std::string suite = request.get_param_value("suite");
                        std::uint16_t suite_id = tradep2p::kRecognitionSuiteMlDsa65V1;
                        if (suite == "ed25519") {
                            suite_id = tradep2p::kRecognitionSuiteEd25519V1;
                        } else if (!suite.empty() && suite != "ml-dsa-65") {
                            throw std::invalid_argument("unknown recognition suite: " + suite);
                        }
                        client.recognize(required_param(request, "room_id"), suite_id);
                    }));

        server.Get("/api/identity/state",
                   [&](const httplib::Request& request, httplib::Response& response) {
                       if (!host_allowed(request)) {
                           response.status = 403;
                           return;
                       }
                       response.set_header("Cache-Control", "no-store");
                       std::scoped_lock lock(identity_state.mutex);
                       response.set_content(identity_state_json_locked(identity_state),
                                            "application/json; charset=utf-8");
                   });

        server.Get("/api/history/list",
                   [&](const httplib::Request& request, httplib::Response& response) {
                       if (!host_allowed(request)) {
                           response.status = 403;
                           return;
                       }
                       response.set_header("Cache-Control", "no-store");
                       std::scoped_lock lock(identity_state.mutex);
                       try {
                           response.set_content(history_list_json_locked(identity_state),
                                                "application/json; charset=utf-8");
                       } catch (const std::exception& error) {
                           response.set_content(
                               std::string("{\"ok\":false,\"error\":\"") +
                                   json_escape(error.what()) + "\"}",
                               "application/json; charset=utf-8");
                       }
                   });

        server.Post("/api/identity/create", action([&](const httplib::Request& request) {
                        const std::string path = required_param(request, "path");
                        const std::string passphrase = required_param(request, "passphrase");
                        const std::string alias =
                            request.has_param("alias") ? request.get_param_value("alias")
                                                        : std::string{};
                        std::scoped_lock lock(identity_state.mutex);
                        identity_state.keystore =
                            tradep2p::IdentityKeystore::create(path, passphrase, alias);
                        identity_state.keystore_path = path;
                        identity_state.history.reset();
                    }));

        server.Post("/api/identity/unlock", action([&](const httplib::Request& request) {
                        const std::string path = required_param(request, "path");
                        const std::string passphrase = required_param(request, "passphrase");
                        std::scoped_lock lock(identity_state.mutex);
                        identity_state.keystore =
                            tradep2p::IdentityKeystore::unlock(path, passphrase);
                        identity_state.keystore_path = path;
                        // A different identity may now be loaded - discard any
                        // already-open history handle, which belonged to
                        // whichever keystore was previously active.
                        identity_state.history.reset();
                    }));

        server.Post("/api/identity/lock", action([&](const httplib::Request&) {
                        std::scoped_lock lock(identity_state.mutex);
                        if (identity_state.keystore.has_value()) {
                            identity_state.keystore->lock();
                        }
                    }));

        // Security tier (specs.txt SS8): the user's own client-local choice,
        // no mediator involvement or negotiation - see
        // set_recognition_key_provider() above for what each flag actually
        // gates. "global" alone with "persistent" off is accepted but inert
        // (the provider already checks persistent_identity_enabled first),
        // rather than rejected, since the two checkboxes are independent
        // controls in the UI and toggling them in either order must work.
        server.Post("/api/identity/tier", action([&](const httplib::Request& request) {
                        const std::string persistent = required_param(request, "persistent");
                        const std::string global = required_param(request, "global");
                        std::scoped_lock lock(identity_state.mutex);
                        identity_state.persistent_identity_enabled = (persistent == "1");
                        identity_state.global_identity_enabled = (global == "1");
                    }));

        server.Post("/api/identity/rotate", action([&](const httplib::Request& request) {
                        const std::string passphrase = required_param(request, "passphrase");
                        std::scoped_lock lock(identity_state.mutex);
                        if (!identity_state.keystore.has_value() ||
                            !identity_state.keystore->is_unlocked()) {
                            throw std::invalid_argument("no unlocked keystore");
                        }
                        identity_state.keystore->rotate_service_scoped_key(passphrase);
                    }));

        server.Post("/api/identity/destroy", action([&](const httplib::Request& request) {
                        const std::string path = required_param(request, "path");
                        tradep2p::IdentityKeystore::destroy(path);
                        std::scoped_lock lock(identity_state.mutex);
                        if (identity_state.keystore_path == path) {
                            identity_state.keystore.reset();
                            identity_state.keystore_path.clear();
                            identity_state.history.reset();
                        }
                    }));

        server.Post("/api/history/block", action([&](const httplib::Request& request) {
                        const std::string fingerprint_text = required_param(request, "fingerprint");
                        std::scoped_lock lock(identity_state.mutex);
                        auto& history = ensure_history_open_locked(identity_state);
                        history.set_blocked(tradep2p::fingerprint_from_hex(fingerprint_text),
                                            identity_state.mediator_id, true);
                    }));

        server.Post("/api/history/unblock", action([&](const httplib::Request& request) {
                        const std::string fingerprint_text = required_param(request, "fingerprint");
                        std::scoped_lock lock(identity_state.mutex);
                        auto& history = ensure_history_open_locked(identity_state);
                        history.set_blocked(tradep2p::fingerprint_from_hex(fingerprint_text),
                                            identity_state.mediator_id, false);
                    }));

        server.Post("/api/history/note", action([&](const httplib::Request& request) {
                        const std::string fingerprint_text = required_param(request, "fingerprint");
                        const std::string text = required_param(request, "text");
                        std::scoped_lock lock(identity_state.mutex);
                        auto& history = ensure_history_open_locked(identity_state);
                        history.add_note(tradep2p::fingerprint_from_hex(fingerprint_text),
                                         identity_state.mediator_id, text);
                    }));

#ifdef TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL
        // Experimental, unreviewed cryptography - specs.txt SS9.3a. Mirrors
        // main.cpp's CLI `/blindsig info|request|status` surface exactly
        // (see DashboardClient::enable_blindsig()'s header comment) rather
        // than the wider 5-route surface an earlier draft of this feature's
        // plan sketched - BlindSigClientSession's finalize/self-verify are
        // automatic once the signer responds, so there is nothing for a
        // separate finalize/verify route to do that request+state don't
        // already cover.
        server.Post("/api/blindsig/info", action([&](const httplib::Request&) {
                        client.request_blindsig_info();
                    }));
        server.Post("/api/blindsig/request", action([&](const httplib::Request& request) {
                        const std::string message = required_param(request, "message");
                        client.submit_blindsig_request(message);
                    }));
        server.Get("/api/blindsig/state",
                   [&](const httplib::Request& request, httplib::Response& response) {
                       if (!host_allowed(request)) {
                           response.status = 403;
                           return;
                       }
                       response.set_header("Cache-Control", "no-store");
                       response.set_content(client.blindsig_state_json(),
                                            "application/json; charset=utf-8");
                   });
#endif

        std::cout << "TradeP2P interactive dashboard listening on http://"
                  << listen_host << ':' << http_port << "\n";
        std::cout << "The HTTP dashboard is intentionally local by default.\n";
        if (!server_state_file.empty()) {
            std::cout << "Reading mediator state from " << server_state_file << "\n";
        }

        if (!server.listen(listen_host, http_port)) {
            throw std::runtime_error("failed to bind dashboard HTTP listener");
        }
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "fatal: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
