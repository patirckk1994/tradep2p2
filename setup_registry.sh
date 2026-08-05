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
DASHBOARD_PORT="8092"
RUN_DASHBOARD="1"

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
    openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
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
    "$DASHBOARD_BIN" "$REGISTRY_STATE_FILE" --port "$DASHBOARD_PORT" &
    DASHBOARD_PID=$!
fi

echo "============================================================"
echo "TradeP2P registry"
echo "  bind:              $REGISTRY_BIND"
echo "  certificate pin:   $CERT_PIN"
echo "  (give this pin, plus the bind host:port, to mediator operators"
echo "   so they can pass it to setup_mediator.sh --registry / --registry-pin)"
if [[ "$RUN_DASHBOARD" == "1" ]]; then
    echo "  operator dashboard: http://127.0.0.1:$DASHBOARD_PORT (loopback only; proxy it yourself to expose remotely)"
fi
echo "============================================================"

export TRADEP2P_REGISTRY_STATE_FILE="$REGISTRY_STATE_FILE"
exec "$CLI" registry "$REGISTRY_BIND" "$REGISTRY_CERT" "$REGISTRY_KEY"
