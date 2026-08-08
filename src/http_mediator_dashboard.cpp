// Operator dashboard for one mediator process. Its state view never connects
// to the mediator over the TradeP2P protocol and holds no client identity;
// it only renders the privacy-reduced local snapshot the mediator already
// writes to TRADEP2P_LOBBY_STATE_FILE. Stays loopback-bound by default like
// the trading dashboard.
//
// Optionally (--admin-token, matching whatever the mediator itself was
// started with), it also becomes a thin authenticated front-end onto the
// mediator's own loopback admin TCP channel (lobby.cpp's
// admin_control_loop()) for exactly one write action: confirming a fee
// leg's receipt for a room stuck in WaitingForFeeConfirmation. The
// mediator's own admin token is never sent to the browser - only a
// freshly-generated, process-local session token is (the same pattern
// http_dashboard.cpp uses for its own write actions), required via the
// X-TradeP2P-Token header on the one POST route this adds. Without
// --admin-token, this binary is exactly as read-only as before.
#include <httplib.h>

#include <openssl/rand.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

std::string random_token() {
    std::array<unsigned char, 24> bytes{};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed while creating a session token");
    }
    static constexpr char digits[] = "0123456789abcdef";
    std::string token;
    token.reserve(bytes.size() * 2U);
    for (const unsigned char byte : bytes) {
        token.push_back(digits[(byte >> 4U) & 0x0fU]);
        token.push_back(digits[byte & 0x0fU]);
    }
    return token;
}

// Speaks the same plain, line-based protocol as admin-df7bffc8.php's
// mediator_admin_query() - a single request line, a single "OK ..." or
// "ERR ..." response line, connection closed after. Blocking, short-lived,
// loopback-only: this dashboard already runs on the same host as the
// mediator whose admin port it talks to.
struct AdminQueryResult {
    bool ok{false};
    std::string raw_or_error;
};

AdminQueryResult admin_query(const std::string& host, std::uint16_t port,
                             const std::string& command_line) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return {false, "could not create socket"};
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1) {
        ::close(fd);
        return {false, "invalid admin host"};
    }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(fd);
        return {false, "could not reach the mediator's admin channel at " + host + ":" +
                          std::to_string(port) + " - is it running with --admin-token?"};
    }
    const std::string line = command_line + "\n";
    if (::send(fd, line.data(), line.size(), 0) < 0) {
        ::close(fd);
        return {false, "failed to send admin command"};
    }
    std::array<char, 4096> buffer{};
    const ssize_t received = ::recv(fd, buffer.data(), buffer.size() - 1U, 0);
    ::close(fd);
    if (received <= 0) {
        return {false, "no response from admin channel"};
    }
    std::string response(buffer.data(), static_cast<std::size_t>(received));
    while (!response.empty() && (response.back() == '\n' || response.back() == '\r')) {
        response.pop_back();
    }
    if (response.rfind("OK", 0) != 0) {
        return {false, response.empty() ? "no response" : response};
    }
    return {true, response};
}

std::string json_escape(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (const unsigned char ch : text) {
        switch (ch) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (ch < 0x20U) {
                out += ' ';
            } else {
                out += static_cast<char>(ch);
            }
        }
    }
    return out;
}

// The admin channel is a plain line-based protocol (one command per line -
// see lobby.cpp's admin_control_loop()), so a room_id containing a newline
// or space could smuggle a second command onto the same connection. Room
// ids are always 32 raw bytes hex-encoded (64 lowercase hex characters) -
// reject anything else outright rather than trying to escape it.
bool is_valid_room_id_hex(const std::string& value) {
    if (value.size() != 64U) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

std::uint16_t parse_port(const std::string& value) {
    std::size_t used = 0U;
    const auto parsed = std::stoul(value, &used, 10);
    if (used != value.size() || parsed == 0U || parsed > 65535U) {
        throw std::invalid_argument("invalid port");
    }
    return static_cast<std::uint16_t>(parsed);
}

std::string read_state_file(const std::string& path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        return "{\"enabled\":true,\"available\":false,\"error\":\"state file not "
               "available yet\"}";
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    const std::string content = buffer.str();
    if (content.empty()) {
        return "{\"enabled\":true,\"available\":false,\"error\":\"state file is "
               "empty\"}";
    }
    return content;
}

std::string page_html(bool admin_enabled, const std::string& session_token) {
    std::string html = R"HTML(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TradeP2P Mediator Dashboard</title>
<style>
:root{--bg:#071019;--panel:#0d1824;--panel2:#101f2e;--line:#20384d;--text:#dcecff;--muted:#8da7bd;--cyan:#58d8ff;--green:#77ff9b;--amber:#ffd166;--red:#ff7575}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.wrap{width:min(1200px,calc(100% - 24px));margin:24px auto 60px}
.panel{border:1px solid var(--line);background:rgba(13,24,36,.96);border-radius:10px;padding:20px;margin-bottom:16px}
h1{font-size:1.5rem;margin:0 0 6px}h2{margin:0 0 14px;color:var(--cyan);font-size:1.05rem}
.muted{color:var(--muted)}.error{color:var(--red)}
.metric-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.metric{background:#08131d;border:1px solid var(--line);border-radius:9px;padding:12px}
.metric b{display:block;color:var(--cyan);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}
.metric span{font-size:1.4rem}
.metric.amber span{color:var(--amber)}
table{width:100%;border-collapse:collapse}th,td{padding:9px 8px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}
th{color:var(--muted);font-size:.8rem}
.status{display:inline-block;padding:.2rem .55rem;border-radius:99px;background:#38495c;font-size:.8rem}
.status.waitingforpeer{background:#604d16}.status.waitingforsent,.status.waitingforreceived{background:#155c35}
.status.waitingforfeeconfirmation{background:#6b4d16;color:var(--amber)}
.status.complete{background:#1c3a2b}.status.aborted{background:#6b2525}
button{font:inherit;background:#155c35;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:.35rem .7rem;cursor:pointer}
button:disabled{opacity:.5;cursor:default}
@media(max-width:700px){.metric-grid{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="wrap">
  <header class="panel">
    <div class="muted">TRADEP2P / MEDIATOR OPERATOR DASHBOARD</div>
    <h1>Mediator state</h1>
    <div id="summary" class="muted">loading snapshot&hellip;</div>
  </header>
  <section class="panel">
    <h2>// live metrics</h2>
    <div id="metrics" class="metric-grid"></div>
  </section>
  <section class="panel">
    <h2>// room persistence (phase 3)</h2>
    <div id="persistence" class="muted">loading snapshot&hellip;</div>
  </section>
  <section class="panel">
    <h2>// open offers</h2>
    <table><thead><tr><th>Room</th><th>Sell</th><th>Buy</th><th>Rounds</th></tr></thead>
    <tbody id="offers"><tr><td colspan="4" class="muted">waiting for snapshot</td></tr></tbody></table>
  </section>
  <section class="panel">
    <h2>// active rooms</h2>
    <table><thead><tr><th>Room</th><th>State</th><th>Round</th><th>Sender</th><th>Sell</th><th>Buy</th><th></th></tr></thead>
    <tbody id="rooms"><tr><td colspan="7" class="muted">waiting for snapshot</td></tr></tbody></table>
  </section>
</div>
<script>
const ADMIN_ENABLED=__ADMIN_ENABLED__;
const TOKEN="__TOKEN__";
const esc=(v)=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const short_=(v)=>{v=String(v??'');return v.length>22?v.slice(0,10)+'…'+v.slice(-10):v};
async function confirmFee(roomId,btn){
  btn.disabled=true;btn.textContent='confirming…';
  try{
    const r=await fetch('/api/confirm-fee',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-TradeP2P-Token':TOKEN},body:new URLSearchParams({room_id:roomId})});
    const body=await r.json().catch(()=>({ok:false,error:'invalid response'}));
    if(!r.ok||!body.ok)throw new Error(body.error||('HTTP '+r.status));
    btn.textContent='confirmed';
  }catch(e){
    btn.disabled=false;btn.textContent='Confirm fee received';
    alert('could not confirm: '+e.message);
  }
}
async function refresh(){
  try{
    const r=await fetch('/api/state',{cache:'no-store'});
    const s=await r.json();
    if(s.available===false){
      document.getElementById('summary').innerHTML='<span class="error">'+esc(s.error||'snapshot unavailable')+'</span>';
      return;
    }
    document.getElementById('summary').textContent=(s.bind||'')+' · snapshot '+(s.generated_at||'');
    const rooms=s.rooms||[];
    const pendingFees=rooms.filter(r=>r.state==='waiting_for_fee_confirmation').length;
    document.getElementById('metrics').innerHTML=
      '<div class="metric"><b>Connected clients</b><span>'+esc(s.clients??0)+'</span></div>'+
      '<div class="metric"><b>Pending invites</b><span>'+esc(s.pending_invites??0)+'</span></div>'+
      '<div class="metric"><b>Open offers</b><span>'+esc((s.offers||[]).length)+'</span></div>'+
      '<div class="metric"><b>Active rooms</b><span>'+esc(rooms.length)+'</span></div>'+
      '<div class="metric'+(pendingFees?' amber':'')+'"><b>Pending fee confirmations</b><span>'+esc(pendingFees)+'</span></div>';
    const persistenceEl=document.getElementById('persistence');
    if(s.room_persistence_enabled){
      persistenceEl.innerHTML='<div class="metric-grid">'+
        '<div class="metric"><b>Persistence</b><span>enabled</span></div>'+
        '<div class="metric"><b>Rooms restored at startup</b><span>'+esc(s.rooms_restored_at_startup??0)+'</span></div>'+
        '</div><p class="muted mono-break">TRADEP2P_ROOM_STATE_FILE: '+esc(s.room_persistence_path||'')+'</p>'+
        '<p class="muted">State machine and progress only - receive addresses are never persisted (see room_persistence.hpp).</p>';
    } else {
      persistenceEl.innerHTML='<span class="muted">Disabled. Start the mediator with TRADEP2P_ROOM_STATE_FILE set to enable crash recovery of in-flight room state.</span>';
    }
    const offers=s.offers||[];
    document.getElementById('offers').innerHTML=offers.length?offers.map(o=>
      `<tr><td title="${esc(o.room_id)}">${esc(short_(o.room_id))}</td><td>${esc(o.total_a)} ${esc(o.asset_a)}</td><td>${esc(o.total_b)} ${esc(o.asset_b)}</td><td>${esc(o.rounds)}</td></tr>`
    ).join(''):'<tr><td colspan="4" class="muted">No open offers.</td></tr>';
    document.getElementById('rooms').innerHTML=rooms.length?rooms.map(r=>{
      const canConfirm=ADMIN_ENABLED&&r.state==='waiting_for_fee_confirmation';
      const action=canConfirm?`<button onclick="confirmFee('${esc(r.room_id)}',this)">Confirm fee received</button>`:'';
      return `<tr><td title="${esc(r.room_id)}">${esc(short_(r.room_id))}</td><td><span class="status ${esc(String(r.state||'').toLowerCase().replace(/_/g,''))}">${esc(r.state)}</span></td><td>${esc(r.round)}/${esc(r.rounds)}</td><td>${esc(r.current_sender||'-')}</td><td>${esc(r.total_a)} ${esc(r.asset_a)}</td><td>${esc(r.total_b)} ${esc(r.asset_b)}</td><td>${action}</td></tr>`;
    }).join(''):'<tr><td colspan="7" class="muted">No active rooms.</td></tr>';
  }catch(e){
    document.getElementById('summary').innerHTML='<span class="error">dashboard refresh failed: '+esc(e.message)+'</span>';
  }
}
refresh();setInterval(refresh,1500);
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
    replace_all("__ADMIN_ENABLED__", admin_enabled ? "true" : "false");
    replace_all("__TOKEN__", session_token);
    return html;
}

void print_usage(const char* program) {
    std::cerr
        << "Usage:\n"
        << "  " << program << " <lobby-state-file> [options]\n\n"
        << "Options:\n"
        << "  --listen HOST      HTTP bind address (default 127.0.0.1)\n"
        << "  --port PORT        HTTP port (default 8091)\n"
        << "  --admin-token TOK  the mediator's own admin-channel token (same value\n"
        << "                     it was started with via --admin-token/\n"
        << "                     TRADEP2P_ADMIN_TOKEN). Enables one write action here:\n"
        << "                     confirming a fee leg's receipt for rooms stuck in\n"
        << "                     waiting_for_fee_confirmation. Leave unset to keep this\n"
        << "                     dashboard exactly as read-only as before.\n"
        << "  --admin-host HOST  host of the mediator's admin channel (default 127.0.0.1)\n"
        << "  --admin-port PORT  port of the mediator's admin channel (default 7444)\n\n"
        << "The state file is the path passed via TRADEP2P_LOBBY_STATE_FILE when "
           "starting the mediator.\n";
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
        const std::string state_file = argv[1];
        std::string listen_host = "127.0.0.1";
        int http_port = 8091;
        std::string admin_token;
        std::string admin_host = "127.0.0.1";
        int admin_port = 7444;

        for (int index = 2; index < argc; ++index) {
            const std::string argument = argv[index];
            if (argument == "--listen" && index + 1 < argc) {
                listen_host = argv[++index];
            } else if (argument == "--port" && index + 1 < argc) {
                http_port = static_cast<int>(parse_port(argv[++index]));
            } else if (argument == "--admin-token" && index + 1 < argc) {
                admin_token = argv[++index];
            } else if (argument == "--admin-host" && index + 1 < argc) {
                admin_host = argv[++index];
            } else if (argument == "--admin-port" && index + 1 < argc) {
                admin_port = static_cast<int>(parse_port(argv[++index]));
            } else if (argument == "--help") {
                print_usage(argv[0]);
                return EXIT_SUCCESS;
            } else {
                throw std::invalid_argument(
                    "unknown or incomplete mediator dashboard option: " + argument);
            }
        }

        const bool admin_enabled = !admin_token.empty();
        // Never sent to the browser - see the file comment. Regenerated
        // every process start like http_dashboard.cpp's own session token.
        const std::string session_token = admin_enabled ? random_token() : std::string{};

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
            response.set_content(page_html(admin_enabled, session_token),
                                 "text/html; charset=utf-8");
        });

        server.Get("/api/state", [&](const httplib::Request& request,
                                     httplib::Response& response) {
            if (!host_allowed(request)) {
                response.status = 403;
                return;
            }
            response.set_header("Cache-Control", "no-store");
            response.set_content(read_state_file(state_file),
                                 "application/json; charset=utf-8");
        });

        server.Post("/api/confirm-fee", [&](const httplib::Request& request,
                                            httplib::Response& response) {
            response.set_header("Cache-Control", "no-store");
            const auto fail = [&](int status, const std::string& error) {
                response.status = status;
                response.set_content(
                    "{\"ok\":false,\"error\":\"" + json_escape(error) + "\"}",
                    "application/json; charset=utf-8");
            };
            if (!host_allowed(request)) {
                fail(403, "forbidden host");
                return;
            }
            if (!admin_enabled) {
                fail(403, "admin actions are not enabled on this dashboard - restart it "
                          "with --admin-token");
                return;
            }
            if (request.get_header_value("X-TradeP2P-Token") != session_token) {
                fail(403, "invalid dashboard token");
                return;
            }
            const std::string room_id = request.get_param_value("room_id");
            if (!is_valid_room_id_hex(room_id)) {
                fail(400, "invalid room_id");
                return;
            }
            const auto result = admin_query(
                admin_host, static_cast<std::uint16_t>(admin_port),
                "CONFIRMFEE " + admin_token + " " + room_id);
            if (!result.ok) {
                fail(502, result.raw_or_error);
                return;
            }
            response.set_content("{\"ok\":true}", "application/json; charset=utf-8");
        });

        std::cout << "TradeP2P mediator dashboard listening on http://"
                  << listen_host << ':' << http_port << "\n";
        std::cout << "Reading mediator snapshot from " << state_file << "\n";
        if (admin_enabled) {
            std::cout << "Admin actions enabled: fee confirmations relayed to "
                      << admin_host << ':' << admin_port << "\n";
        } else {
            std::cout << "Read-only operator view. Keep it local or proxy it with "
                         "your own authentication.\n";
        }

        if (!server.listen(listen_host, http_port)) {
            throw std::runtime_error("failed to bind mediator dashboard HTTP listener");
        }
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "fatal: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
