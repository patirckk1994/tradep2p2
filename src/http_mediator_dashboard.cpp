// Read-only operator dashboard for one mediator process. It never connects
// to the mediator over the TradeP2P protocol and holds no client identity;
// it only renders the privacy-reduced local snapshot the mediator already
// writes to TRADEP2P_LOBBY_STATE_FILE. This is an admin tool, not a second
// network endpoint, so it stays loopback-bound by default like the trading
// dashboard.
#include <httplib.h>

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

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

std::string page_html() {
    return R"HTML(<!doctype html>
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
table{width:100%;border-collapse:collapse}th,td{padding:9px 8px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}
th{color:var(--muted);font-size:.8rem}
.status{display:inline-block;padding:.2rem .55rem;border-radius:99px;background:#38495c;font-size:.8rem}
.status.waitingforpeer{background:#604d16}.status.waitingforsent,.status.waitingforreceived{background:#155c35}
.status.complete{background:#1c3a2b}.status.aborted{background:#6b2525}
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
    <table><thead><tr><th>Room</th><th>State</th><th>Round</th><th>Sender</th><th>Sell</th><th>Buy</th></tr></thead>
    <tbody id="rooms"><tr><td colspan="6" class="muted">waiting for snapshot</td></tr></tbody></table>
  </section>
</div>
<script>
const esc=(v)=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const short_=(v)=>{v=String(v??'');return v.length>22?v.slice(0,10)+'…'+v.slice(-10):v};
async function refresh(){
  try{
    const r=await fetch('/api/state',{cache:'no-store'});
    const s=await r.json();
    if(s.available===false){
      document.getElementById('summary').innerHTML='<span class="error">'+esc(s.error||'snapshot unavailable')+'</span>';
      return;
    }
    document.getElementById('summary').textContent=(s.bind||'')+' · snapshot '+(s.generated_at||'');
    document.getElementById('metrics').innerHTML=
      '<div class="metric"><b>Connected clients</b><span>'+esc(s.clients??0)+'</span></div>'+
      '<div class="metric"><b>Pending invites</b><span>'+esc(s.pending_invites??0)+'</span></div>'+
      '<div class="metric"><b>Open offers</b><span>'+esc((s.offers||[]).length)+'</span></div>'+
      '<div class="metric"><b>Active rooms</b><span>'+esc((s.rooms||[]).length)+'</span></div>';
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
    const rooms=s.rooms||[];
    document.getElementById('rooms').innerHTML=rooms.length?rooms.map(r=>
      `<tr><td title="${esc(r.room_id)}">${esc(short_(r.room_id))}</td><td><span class="status ${esc(String(r.state||'').toLowerCase())}">${esc(r.state)}</span></td><td>${esc(r.round)}/${esc(r.rounds)}</td><td>${esc(r.current_sender||'-')}</td><td>${esc(r.total_a)} ${esc(r.asset_a)}</td><td>${esc(r.total_b)} ${esc(r.asset_b)}</td></tr>`
    ).join(''):'<tr><td colspan="6" class="muted">No active rooms.</td></tr>';
  }catch(e){
    document.getElementById('summary').innerHTML='<span class="error">dashboard refresh failed: '+esc(e.message)+'</span>';
  }
}
refresh();setInterval(refresh,1500);
</script>
</body>
</html>)HTML";
}

void print_usage(const char* program) {
    std::cerr
        << "Usage:\n"
        << "  " << program << " <lobby-state-file> [options]\n\n"
        << "Options:\n"
        << "  --listen HOST   HTTP bind address (default 127.0.0.1)\n"
        << "  --port PORT     HTTP port (default 8091)\n\n"
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

        for (int index = 2; index < argc; ++index) {
            const std::string argument = argv[index];
            if (argument == "--listen" && index + 1 < argc) {
                listen_host = argv[++index];
            } else if (argument == "--port" && index + 1 < argc) {
                http_port = static_cast<int>(parse_port(argv[++index]));
            } else if (argument == "--help") {
                print_usage(argv[0]);
                return EXIT_SUCCESS;
            } else {
                throw std::invalid_argument(
                    "unknown or incomplete mediator dashboard option: " + argument);
            }
        }

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
            response.set_content(page_html(), "text/html; charset=utf-8");
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

        std::cout << "TradeP2P mediator dashboard listening on http://"
                  << listen_host << ':' << http_port << "\n";
        std::cout << "Reading mediator snapshot from " << state_file << "\n";
        std::cout << "Read-only operator view. Keep it local or proxy it with "
                     "your own authentication.\n";

        if (!server.listen(listen_host, http_port)) {
            throw std::runtime_error("failed to bind mediator dashboard HTTP listener");
        }
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "fatal: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
