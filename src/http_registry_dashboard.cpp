// Read-only operator dashboard for one registry process. Like the mediator
// dashboard, it never speaks the TradeP2P protocol itself; it only renders
// the local snapshot the registry writes to TRADEP2P_REGISTRY_STATE_FILE.
// Loopback-bound by default, matching every other admin tool in this repo.
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
<title>TradeP2P Registry Dashboard</title>
<style>
:root{--bg:#071019;--panel:#0d1824;--line:#20384d;--text:#dcecff;--muted:#8da7bd;--cyan:#58d8ff;--green:#77ff9b;--amber:#ffd166;--red:#ff7575}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.wrap{width:min(1100px,calc(100% - 24px));margin:24px auto 60px}
.panel{border:1px solid var(--line);background:rgba(13,24,36,.96);border-radius:10px;padding:20px;margin-bottom:16px}
h1{font-size:1.5rem;margin:0 0 6px}h2{margin:0 0 14px;color:var(--cyan);font-size:1.05rem}
.muted{color:var(--muted)}.error{color:var(--red)}
.metric-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
.metric{background:#08131d;border:1px solid var(--line);border-radius:9px;padding:12px}
.metric b{display:block;color:var(--cyan);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}
.metric span{font-size:1.4rem}
table{width:100%;border-collapse:collapse}th,td{padding:9px 8px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}
th{color:var(--muted);font-size:.8rem}
.ttl-low{color:var(--amber)}
@media(max-width:700px){.metric-grid{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="wrap">
  <header class="panel">
    <div class="muted">TRADEP2P / REGISTRY OPERATOR DASHBOARD</div>
    <h1>Registered mediator nodes</h1>
    <div id="summary" class="muted">loading snapshot&hellip;</div>
  </header>
  <section class="panel">
    <h2>// live metrics</h2>
    <div id="metrics" class="metric-grid"></div>
  </section>
  <section class="panel">
    <h2>// nodes</h2>
    <table><thead><tr><th>Host</th><th>Port</th><th>Certificate pin (SHA-256)</th><th>TTL remaining</th></tr></thead>
    <tbody id="nodes"><tr><td colspan="4" class="muted">waiting for snapshot</td></tr></tbody></table>
  </section>
  <p class="muted">Registrations are unauthenticated and expire on their own; this view is informational only and offers no way to remove or ban a node from here.</p>
</div>
<script>
const esc=(v)=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
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
      '<div class="metric"><b>Registered nodes</b><span>'+esc(s.node_count??0)+'</span></div>'+
      '<div class="metric"><b>Snapshot generated</b><span style="font-size:.95rem">'+esc(s.generated_at||'-')+'</span></div>'+
      '<div class="metric"><b>Bind endpoint</b><span style="font-size:.95rem">'+esc(s.bind||'-')+'</span></div>';
    const nodes=s.nodes||[];
    document.getElementById('nodes').innerHTML=nodes.length?nodes.map(n=>{
      const low=Number(n.remaining_ttl_seconds)<60;
      return `<tr><td>${esc(n.host)}</td><td>${esc(n.port)}</td><td title="${esc(n.certificate_pin)}">${esc(String(n.certificate_pin||'').slice(0,16))}&hellip;</td><td class="${low?'ttl-low':''}">${esc(n.remaining_ttl_seconds)}s</td></tr>`;
    }).join(''):'<tr><td colspan="4" class="muted">No registered nodes.</td></tr>';
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
        << "  " << program << " <registry-state-file> [options]\n\n"
        << "Options:\n"
        << "  --listen HOST   HTTP bind address (default 127.0.0.1)\n"
        << "  --port PORT     HTTP port (default 8092)\n\n"
        << "The state file is the path passed via TRADEP2P_REGISTRY_STATE_FILE "
           "when starting the registry.\n";
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
        int http_port = 8092;

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
                    "unknown or incomplete registry dashboard option: " + argument);
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

        std::cout << "TradeP2P registry dashboard listening on http://"
                  << listen_host << ':' << http_port << "\n";
        std::cout << "Reading registry snapshot from " << state_file << "\n";
        std::cout << "Read-only operator view. Keep it local or proxy it with "
                     "your own authentication.\n";

        if (!server.listen(listen_host, http_port)) {
            throw std::runtime_error("failed to bind registry dashboard HTTP listener");
        }
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "fatal: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
