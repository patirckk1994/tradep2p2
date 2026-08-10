#!/usr/bin/env bash
# Ergonomic registry setup: generates a TLS identity if needed, builds the
# project if needed, and launches the registry plus its read-only operator
# dashboard. Configuration lives in a small shell-sourceable config file so a
# repeat run does not require re-typing flags.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$ROOT/registry.conf}"

print_usage() {
    cat <<'EOF'
Usage: ./setup_registry.sh [options]

Options:
  --config FILE       config file to read/write (default: ./registry.conf)
  --init-config        write a default config file to --config and exit
  --bind HOST:PORT     registry bind endpoint (default 0.0.0.0:7555)
  --cert FILE          TLS certificate path (default certs/registry.cert.pem)
  --key FILE           TLS private key path (default certs/registry.key.pem)
  --state-file FILE    registry snapshot path (default logs/registry-state.json)
  --admin-token TOKEN  enables a loopback-only channel to approve/reject
                        pending mediator registrations (LISTPENDING/APPROVE/
                        REJECT) without a restart (optional; see
                        --admin-port). Keep this secret. Leave unset and
                        every registration stays Pending forever - nothing
                        can ever be approved.
  --admin-port N       port for the admin control channel (default 7445,
                        only meaningful with --admin-token). This channel
                        always binds 127.0.0.1 regardless of --bind, so if
                        you run more than one registry on the same host
                        (e.g. a testing and a production instance), each
                        MUST use a different --admin-port or the second one
                        to start silently loses the bind (logged, not fatal).
  --gossip-peer HOST:PORT|PIN[|1]
                        (repeatable) single-hop gossip peer: pulls this
                        peer's own approved registrations periodically (the
                        same RegistryList request `nodes`/`nodes-tor`
                        already make - no new protocol). Trailing |1 means
                        auto-trust this peer's approval outright (merged
                        into your listings immediately, tagged with the
                        peer as source); omit it (default) to have each
                        peer-learned entry sit Pending here too, needing
                        your own --admin-token approval like a direct
                        registration. This registry never re-shares what it
                        learns from a peer - only your OWN direct,
                        approved registrations ever go out to anyone else.
  --gossip-proxy HOST:PORT
                        SOCKS5 proxy (e.g. a local Tor daemon) used for any
                        --gossip-peer whose host ends in .onion - one
                        shared proxy for all of them. Required if any
                        configured peer is onion-only; leave unset if none
                        are.
  --dashboard-port N   operator dashboard port (default 8092)
  --no-dashboard        do not launch the operator dashboard
  -h, --help            show this help

Settings are read from the config file first, then overridden by any flags
given on the command line. Re-run with --init-config to (re)write the file
with the current effective settings.
EOF
}

# Defaults.
REGISTRY_BIND="0.0.0.0:7555"
REGISTRY_CERT="$ROOT/certs/registry.cert.pem"
REGISTRY_KEY="$ROOT/certs/registry.key.pem"
REGISTRY_STATE_FILE="$ROOT/logs/registry-state.json"
ADMIN_TOKEN=""
ADMIN_PORT="7445"
GOSSIP_PEERS=""
GOSSIP_PROXY=""
DASHBOARD_PORT="8092"
RUN_DASHBOARD="1"

# Pre-scan for --config so it can actually select which file gets sourced
# below - see setup_mediator.sh's identical fix for why: without this,
# --config's own value never takes effect until one command too late,
# because sourcing otherwise happens before this flag is even parsed.
for (( scan = 1; scan <= $#; scan++ )); do
    if [[ "${!scan}" == "--config" ]]; then
        next=$((scan + 1))
        CONFIG_FILE="${!next}"
        break
    fi
done

if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
fi

INIT_CONFIG="0"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config) CONFIG_FILE="$2"; shift 2 ;;
        --init-config) INIT_CONFIG="1"; shift ;;
        --bind) REGISTRY_BIND="$2"; shift 2 ;;
        --cert) REGISTRY_CERT="$2"; shift 2 ;;
        --key) REGISTRY_KEY="$2"; shift 2 ;;
        --state-file) REGISTRY_STATE_FILE="$2"; shift 2 ;;
        --admin-token) ADMIN_TOKEN="$2"; shift 2 ;;
        --admin-port) ADMIN_PORT="$2"; shift 2 ;;
        --gossip-peer)
            if [[ -n "$GOSSIP_PEERS" ]]; then
                GOSSIP_PEERS="$GOSSIP_PEERS,$2"
            else
                GOSSIP_PEERS="$2"
            fi
            shift 2 ;;
        --gossip-proxy) GOSSIP_PROXY="$2"; shift 2 ;;
        --dashboard-port) DASHBOARD_PORT="$2"; shift 2 ;;
        --no-dashboard) RUN_DASHBOARD="0"; shift ;;
        -h|--help) print_usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; print_usage; exit 1 ;;
    esac
done

write_config() {
    cat > "$CONFIG_FILE" <<EOF
# TradeP2P registry config, read by setup_registry.sh.
REGISTRY_BIND="$REGISTRY_BIND"
REGISTRY_CERT="$REGISTRY_CERT"
REGISTRY_KEY="$REGISTRY_KEY"
REGISTRY_STATE_FILE="$REGISTRY_STATE_FILE"
ADMIN_TOKEN="$ADMIN_TOKEN"
ADMIN_PORT="$ADMIN_PORT"

# Comma-separated "host:port|pinhex|trust" entries - see --gossip-peer
# --help. Leave empty to disable gossip federation entirely.
GOSSIP_PEERS="$GOSSIP_PEERS"
# Only needed if any GOSSIP_PEERS entry is an .onion host.
GOSSIP_PROXY="$GOSSIP_PROXY"

DASHBOARD_PORT="$DASHBOARD_PORT"
RUN_DASHBOARD="$RUN_DASHBOARD"
EOF
    echo "wrote $CONFIG_FILE"
}

if [[ "$INIT_CONFIG" == "1" ]]; then
    write_config
    exit 0
fi

CLI="$ROOT/build/tradep2p_cli"
DASHBOARD_BIN="$ROOT/build/tradep2p-registry-dashboard"
if [[ ! -x "$CLI" || ( "$RUN_DASHBOARD" == "1" && ! -x "$DASHBOARD_BIN" ) ]]; then
    echo "building the project (first run only)..."
    "$ROOT/scripts/build.sh"
fi

mkdir -p "$(dirname "$REGISTRY_CERT")" "$(dirname "$REGISTRY_STATE_FILE")"
if [[ ! -f "$REGISTRY_CERT" || ! -f "$REGISTRY_KEY" ]]; then
    echo "generating a TLS identity at $REGISTRY_CERT / $REGISTRY_KEY ..."
    # ML-DSA-65 (FIPS 204) post-quantum signature - see setup_mediator.sh for
    # why RSA/ECDSA here would leave cert authentication non-PQ even with a
    # hybrid PQ key exchange. Requires OpenSSL 3.5+.
    openssl req -x509 -newkey ML-DSA-65 -nodes -days 365 \
        -subj "/CN=TradeP2P Registry" \
        -keyout "$REGISTRY_KEY" -out "$REGISTRY_CERT"
    chmod 600 "$REGISTRY_KEY"
fi
CERT_PIN="$(openssl x509 -in "$REGISTRY_CERT" -outform DER | openssl dgst -sha256 -hex | awk '{print $2}')"

DASHBOARD_PID=""
cleanup() {
    if [[ -n "$DASHBOARD_PID" ]]; then
        kill "$DASHBOARD_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

if [[ "$RUN_DASHBOARD" == "1" ]]; then
    if [[ -n "$ADMIN_TOKEN" ]]; then
        "$DASHBOARD_BIN" "$REGISTRY_STATE_FILE" --port "$DASHBOARD_PORT" \
            --admin-token "$ADMIN_TOKEN" --admin-port "$ADMIN_PORT" &
    else
        "$DASHBOARD_BIN" "$REGISTRY_STATE_FILE" --port "$DASHBOARD_PORT" &
    fi
    DASHBOARD_PID=$!
fi

echo "============================================================"
echo "TradeP2P registry"
echo "  bind:              $REGISTRY_BIND"
echo "  certificate pin:   $CERT_PIN"
echo "  (give this pin, plus the bind host:port, to mediator operators"
echo "   so they can pass it to setup_mediator.sh --registry / --registry-pin)"
if [[ -n "$ADMIN_TOKEN" ]]; then
    echo "  admin control:     127.0.0.1:$ADMIN_PORT (loopback only; LISTPENDING/APPROVE/REJECT)"
else
    echo "  admin control:     disabled - every registration stays Pending forever,"
    echo "                     nothing will ever appear on RegistryList or status.php"
    echo "                     until you re-run with --admin-token"
fi
if [[ -n "$GOSSIP_PEERS" ]]; then
    PEER_COUNT=$(( $(grep -o ',' <<< "$GOSSIP_PEERS" | wc -l) + 1 ))
    echo "  gossip peers:      $PEER_COUNT configured (single-hop; see --gossip-peer --help)"
fi
if [[ "$RUN_DASHBOARD" == "1" ]]; then
    echo "  operator dashboard: http://127.0.0.1:$DASHBOARD_PORT (loopback only; proxy it yourself to expose remotely)"
    if [[ -n "$ADMIN_TOKEN" ]]; then
        echo "                      admin actions enabled - can approve/reject pending registrations"
    fi
fi
echo "============================================================"

export TRADEP2P_REGISTRY_STATE_FILE="$REGISTRY_STATE_FILE"
if [[ -n "$ADMIN_TOKEN" ]]; then
    export TRADEP2P_REGISTRY_ADMIN_TOKEN="$ADMIN_TOKEN"
    export TRADEP2P_REGISTRY_ADMIN_PORT="$ADMIN_PORT"
fi
if [[ -n "$GOSSIP_PEERS" ]]; then
    export TRADEP2P_REGISTRY_GOSSIP_PEERS="$GOSSIP_PEERS"
    if [[ -n "$GOSSIP_PROXY" ]]; then
        export TRADEP2P_REGISTRY_GOSSIP_PROXY="$GOSSIP_PROXY"
    fi
fi
exec "$CLI" registry "$REGISTRY_BIND" "$REGISTRY_CERT" "$REGISTRY_KEY"
