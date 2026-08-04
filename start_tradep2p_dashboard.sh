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

CLI="$(find_binary tradep2p_cli)"
DASHBOARD="$(find_binary tradep2p-dashboard)"

MEDIATOR_BIND="${MEDIATOR_BIND:-127.0.0.1:20711}"
MEDIATOR_CONNECT="${MEDIATOR_CONNECT:-127.0.0.1:${MEDIATOR_BIND##*:}}"
LISTEN="${LISTEN:-127.0.0.1}"
PORT="${PORT:-8080}"

RUNTIME_DIR="${RUNTIME_DIR:-$ROOT/runtime}"
CERT_FILE="${CERT_FILE:-$RUNTIME_DIR/mediator.cert.pem}"
KEY_FILE="${KEY_FILE:-$RUNTIME_DIR/mediator.key.pem}"
STATE_FILE="${STATE_FILE:-$RUNTIME_DIR/lobby-state.json}"
MEDIATOR_LOG="${MEDIATOR_LOG:-$RUNTIME_DIR/mediator.log}"

mkdir -p "$RUNTIME_DIR"

if [[ ! -f "$CERT_FILE" || ! -f "$KEY_FILE" ]]; then
    echo "Generating mediator TLS certificate..."
    openssl req \
        -x509 \
        -newkey rsa:3072 \
        -sha256 \
        -nodes \
        -days 3650 \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -subj "/CN=TradeP2P Mediator"
    chmod 600 "$KEY_FILE"
    chmod 644 "$CERT_FILE"
fi

PIN="$(
    openssl x509 -in "$CERT_FILE" -outform DER |
    openssl dgst -sha256 -hex |
    awk '{print $2}'
)"
printf '%s\n' "$PIN" > "$RUNTIME_DIR/mediator.sha256"

cleanup() {
    if [[ -n "${MEDIATOR_PID:-}" ]]; then
        kill "$MEDIATOR_PID" 2>/dev/null || true
        wait "$MEDIATOR_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "Starting mediator..."
TRADEP2P_LOBBY_STATE_FILE="$STATE_FILE" \
    "$CLI" mediator "$MEDIATOR_BIND" "$CERT_FILE" "$KEY_FILE" \
    >"$MEDIATOR_LOG" 2>&1 &
MEDIATOR_PID=$!

sleep 0.6
if ! kill -0 "$MEDIATOR_PID" 2>/dev/null; then
    echo "error: mediator failed to start" >&2
    cat "$MEDIATOR_LOG" >&2 || true
    exit 1
fi

echo
echo "TradeP2P local stack"
echo "  mediator: $MEDIATOR_BIND"
echo "  dashboard: http://$LISTEN:$PORT"
echo "  state: $STATE_FILE"
echo "  mediator log: $MEDIATOR_LOG"
echo
echo "Press Ctrl-C to stop both."
echo

exec "$DASHBOARD" \
    client \
    "$MEDIATOR_CONNECT" \
    "$PIN" \
    --listen "$LISTEN" \
    --port "$PORT" \
    --server-state "$STATE_FILE"
