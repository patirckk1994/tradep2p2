// Operator dashboard for registry servers. It has two independent views:
// a read-only local snapshot (like the mediator dashboard, for a registry
// running on this same machine) and an on-demand live query against any
// registry's network endpoint, reusing the same pinned-TLS client the CLI
// `nodes` command uses. The live query is the only state-changing (outbound
// network) action here, so it is the only route behind the request token.
#include <httplib.h>

#include "tradep2p/registry.hpp"
#include "tradep2p/secure_channel.hpp"

#include <openssl/rand.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

using tradep2p::CertificatePin;
using tradep2p::ClientTlsPolicy;
using tradep2p::Endpoint;
using tradep2p::RegistryNodesMessage;

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

std::string random_token() {
    std::array<unsigned char, 24> bytes{};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed while creating dashboard token");
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

std::string json_escape(const std::string& text) {
    std::ostringstream out;
    for (const unsigned char ch : text) {
        switch (ch) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (ch < 0x20U) {
                out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<unsigned int>(ch) << std::dec;
            } else {
                out << static_cast<char>(ch);
            }
        }
    }
    return out.str();
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

std::string read_state_file(const std::string& path) {
    if (path.empty()) {
        return "{\"enabled\":false}";
    }
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

std::string nodes_to_json(const RegistryNodesMessage& nodes) {
    std::ostringstream json;
    json << "{\"ok\":true,\"nodes\":[";
    for (std::size_t index = 0; index < nodes.nodes.size(); ++index) {
        if (index != 0U) {
            json << ',';
        }
        const auto& node = nodes.nodes[index];
        json << "{\"host\":\"" << json_escape(node.host) << "\",\"port\":"
             << node.port << ",\"certificate_pin\":\""
             << tradep2p::certificate_pin_to_hex(node.certificate_pin)
             << "\",\"remaining_ttl_seconds\":" << node.remaining_ttl_seconds
             << '}';
    }
    json << "]}";
    return json.str();
}

std::string page_html(const std::string& token, bool snapshot_enabled) {
    std::string html = R"HTML(<!doctype html>
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
.muted{color:var(--muted)}.error{color:var(--red)}.notice{margin:8px 0 0;color:var(--amber)}
.metric-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
.metric{background:#08131d;border:1px solid var(--line);border-radius:9px;padding:12px}
.metric b{display:block;color:var(--cyan);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}
.metric span{font-size:1.4rem}
table{width:100%;border-collapse:collapse}th,td{padding:9px 8px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}
th{color:var(--muted);font-size:.8rem}
.ttl-low{color:var(--amber)}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
label{display:grid;gap:5px;color:var(--muted)}
input{font:inherit;padding:8px 9px;border-radius:6px;border:1px solid var(--line);background:#07111b;color:var(--text)}
button{font:inherit;padding:8px 13px;border-radius:6px;border:1px solid var(--line);background:#15334a;color:var(--text);cursor:pointer}
button:hover{border-color:var(--cyan)}
.actions{margin-top:10px}
@media(max-width:700px){.metric-grid{grid-template-columns:repeat(2,1fr)}.form-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="wrap">
  <header class="panel">
    <div class="muted">TRADEP2P / REGISTRY OPERATOR DASHBOARD</div>
    <h1>Registered mediator nodes</h1>
    <div id="notice" class="notice"></div>
  </header>
  <section class="panel">
    <h2>// query any registry</h2>
    <p class="muted">Connects live, over pinned TLS, to any registry server &mdash; not just one running on this machine.</p>
    <form id="query-form" class="form-grid">
      <label>Registry endpoint (host:port)<input name="endpoint" placeholder="registry.example:7555" required></label>
      <label>Certificate SHA-256 pin<input name="pin" placeholder="hex fingerprint" required></label>
    </form>
    <div class="actions"><button id="query-submit">Query registry</button></div>
    <div id="query-summary" class="muted" style="margin-top:10px"></div>
    <table><thead><tr><th>Host</th><th>Port</th><th>Certificate pin (SHA-256)</th><th>TTL remaining</th></tr></thead>
    <tbody id="query-nodes"><tr><td colspan="4" class="muted">no query yet</td></tr></tbody></table>
  </section>
  <section class="panel">
    <h2>// local snapshot</h2>
    <div id="summary" class="muted">__SNAPSHOT_TEXT__</div>
    <div id="metrics" class="metric-grid"></div>
    <table><thead><tr><th>Host</th><th>Port</th><th>Certificate pin (SHA-256)</th><th>TTL remaining</th></tr></thead>
    <tbody id="nodes"><tr><td colspan="4" class="muted">waiting for snapshot</td></tr></tbody></table>
  </section>
  <p class="muted">Registrations are unauthenticated and expire on their own; this view is informational only and offers no way to remove or ban a node from here.</p>
</div>
<script>
const TOKEN="__TOKEN__";
const snapshotEnabled=__SNAPSHOT_ENABLED__;
const esc=(v)=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function notice(text,bad){const n=document.getElementById('notice');n.textContent=text;n.className=bad?'notice error':'notice';setTimeout(()=>{if(n.textContent===text)n.textContent=''},6000)}
function renderNodeRows(target,nodes){
  target.innerHTML=nodes.length?nodes.map(n=>{
    const low=Number(n.remaining_ttl_seconds)<60;
    return `<tr><td>${esc(n.host)}</td><td>${esc(n.port)}</td><td title="${esc(n.certificate_pin)}">${esc(String(n.certificate_pin||'').slice(0,16))}&hellip;</td><td class="${low?'ttl-low':''}">${esc(n.remaining_ttl_seconds)}s</td></tr>`;
  }).join(''):'<tr><td colspan="4" class="muted">No nodes.</td></tr>';
}
async function submitQuery(e){
  e.preventDefault();
  const form=document.getElementById('query-form');
  const data=Object.fromEntries(new FormData(form));
  const summary=document.getElementById('query-summary');
  summary.textContent='querying…';
  try{
    const r=await fetch('/api/query',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-TradeP2P-Token':TOKEN},body:new URLSearchParams(data)});
    const body=await r.json().catch(()=>({ok:false,error:'invalid dashboard response'}));
    if(!r.ok||!body.ok)throw new Error(body.error||('HTTP '+r.status));
    summary.textContent=(body.nodes||[]).length+' node(s) at '+esc(data.endpoint);
    renderNodeRows(document.getElementById('query-nodes'),body.nodes||[]);
  }catch(err){
    summary.textContent='';
    notice('query failed: '+err.message,true);
    renderNodeRows(document.getElementById('query-nodes'),[]);
  }
}
document.getElementById('query-submit').addEventListener('click',submitQuery);
function renderSnapshot(s){
  if(s.available===false){
    document.getElementById('summary').innerHTML='<span class="error">'+esc(s.error||'snapshot unavailable')+'</span>';
    return;
  }
  document.getElementById('summary').textContent=(s.bind||'')+' · snapshot '+(s.generated_at||'');
  document.getElementById('metrics').innerHTML=
    '<div class="metric"><b>Registered nodes</b><span>'+esc(s.node_count??0)+'</span></div>'+
    '<div class="metric"><b>Snapshot generated</b><span style="font-size:.95rem">'+esc(s.generated_at||'-')+'</span></div>'+
    '<div class="metric"><b>Bind endpoint</b><span style="font-size:.95rem">'+esc(s.bind||'-')+'</span></div>';
  renderNodeRows(document.getElementById('nodes'),s.nodes||[]);
}
async function refreshSnapshot(){
  if(!snapshotEnabled)return;
  try{
    const r=await fetch('/api/state',{cache:'no-store'});
    renderSnapshot(await r.json());
  }catch(e){
    document.getElementById('summary').innerHTML='<span class="error">dashboard refresh failed: '+esc(e.message)+'</span>';
  }
}
refreshSnapshot();setInterval(refreshSnapshot,1500);
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
    replace_all("__TOKEN__", token);
    replace_all("__SNAPSHOT_ENABLED__", snapshot_enabled ? "true" : "false");
    replace_all("__SNAPSHOT_TEXT__",
                snapshot_enabled ? "waiting for registry snapshot"
                                 : "no local snapshot configured &mdash; use the "
                                   "live query above, or set "
                                   "TRADEP2P_REGISTRY_STATE_FILE on the registry "
                                   "and pass its path here");
    return html;
}

void set_json_result(httplib::Response& response, bool ok, const std::string& message,
                     int status = 200) {
    response.status = status;
    response.set_content(
        std::string("{\"ok\":") + (ok ? "true" : "false") +
            (ok ? ",\"message\":\"" : ",\"error\":\"") + json_escape(message) + "\"}",
        "application/json; charset=utf-8");
}

void print_usage(const char* program) {
    std::cerr
        << "Usage:\n"
        << "  " << program << " [registry-state-file] [options]\n\n"
        << "The state file argument is optional; omit it (or pass \"-\") to run "
           "with only the live query form.\n\n"
        << "Options:\n"
        << "  --listen HOST   HTTP bind address (default 127.0.0.1)\n"
        << "  --port PORT     HTTP port (default 8092)\n\n"
        << "The state file, if given, is the path passed via "
           "TRADEP2P_REGISTRY_STATE_FILE when starting a registry on this "
           "machine.\n";
}

} // namespace

int main(int argc, char** argv) {
    try {
        std::string state_file;
        std::string listen_host = "127.0.0.1";
        int http_port = 8092;
        int index = 1;

        if (index < argc && argv[index][0] != '-') {
            state_file = argv[index];
            ++index;
        } else if (index < argc && std::string(argv[index]) == "-") {
            ++index;
        }

        for (; index < argc; ++index) {
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

        const std::string token = random_token();

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
            response.set_content(page_html(token, !state_file.empty()),
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

        server.Post("/api/query", [&](const httplib::Request& request,
                                      httplib::Response& response) {
            if (!host_allowed(request)) {
                set_json_result(response, false, "forbidden host", 403);
                return;
            }
            if (request.get_header_value("X-TradeP2P-Token") != token) {
                set_json_result(response, false, "invalid dashboard token", 403);
                return;
            }
            try {
                const Endpoint endpoint =
                    parse_endpoint(required_param(request, "endpoint"));
                const std::string pin_text = required_param(request, "pin");
                // Validated for a clean error message; list_registered_nodes takes
                // the pin as hex text, not the decoded bytes.
                (void)tradep2p::certificate_pin_from_hex(pin_text);
                const RegistryNodesMessage nodes = tradep2p::list_registered_nodes(
                    endpoint, ClientTlsPolicy{pin_text});
                response.status = 200;
                response.set_header("Cache-Control", "no-store");
                response.set_content(nodes_to_json(nodes),
                                     "application/json; charset=utf-8");
            } catch (const std::exception& error) {
                set_json_result(response, false, error.what(), 400);
            }
        });

        std::cout << "TradeP2P registry dashboard listening on http://"
                  << listen_host << ':' << http_port << "\n";
        if (!state_file.empty()) {
            std::cout << "Reading local registry snapshot from " << state_file << "\n";
        } else {
            std::cout << "No local snapshot file given; use the live query form to "
                         "browse any registry.\n";
        }
        std::cout << "Operator view. Keep it local or proxy it with your own "
                     "authentication.\n";

        if (!server.listen(listen_host, http_port)) {
            throw std::runtime_error("failed to bind registry dashboard HTTP listener");
        }
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "fatal: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
