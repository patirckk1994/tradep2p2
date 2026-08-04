#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)"
[[ -f "$ROOT/CMakeLists.txt" ]] || ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

find_binary() {
    local name="$1"
    for candidate in "$ROOT/build/$name" "$ROOT/$name"; do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return
        fi
    done
    echo "error: $name not found; run ./scripts/build.sh first" >&2
    exit 1
}

DASHBOARD="$(find_binary tradep2p-dashboard)"

MEDIATOR="${MEDIATOR:-127.0.0.1:20711}"
LISTEN="${LISTEN:-127.0.0.1}"
PORT="${PORT:-8080}"
RUNTIME_DIR="${RUNTIME_DIR:-$ROOT/runtime}"
CERT_FILE="${CERT_FILE:-$RUNTIME_DIR/mediator.cert.pem}"
STATE_FILE="${STATE_FILE:-$RUNTIME_DIR/lobby-state.json}"

if [[ -z "${CERT_SHA256:-}" ]]; then
    if [[ -f "$CERT_FILE" ]]; then
        CERT_SHA256="$(
            openssl x509 -in "$CERT_FILE" -outform DER |
            openssl dgst -sha256 -hex |
            awk '{print $2}'
        )"
    elif [[ -f "$RUNTIME_DIR/mediator.sha256" ]]; then
        CERT_SHA256="$(tr -d '[:space:]' < "$RUNTIME_DIR/mediator.sha256")"
    else
        echo "error: no mediator certificate or fingerprint found" >&2
        echo "start the mediator first, or set CERT_SHA256=<fingerprint>" >&2
        exit 1
    fi
fi

args=(
    client
    "$MEDIATOR"
    "$CERT_SHA256"
    --listen "$LISTEN"
    --port "$PORT"
)

[[ -n "$STATE_FILE" ]] && args+=(--server-state "$STATE_FILE")

echo
echo "TradeP2P dashboard client"
echo "  mediator: $MEDIATOR"
echo "  web UI:   http://$LISTEN:$PORT"
echo

exec "$DASHBOARD" "${args[@]}"
