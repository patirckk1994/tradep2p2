#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
CLI="${TRADEP2P_BIN:-$BUILD_DIR/tradep2p_cli}"
DASHBOARD="${TRADEP2P_DASHBOARD_BIN:-$BUILD_DIR/tradep2p-dashboard}"
MEDIATOR_PORT="${MEDIATOR_PORT:-$((20000 + RANDOM % 20000))}"
DASHBOARD_A_PORT="${DASHBOARD_A_PORT:-8081}"
DASHBOARD_B_PORT="${DASHBOARD_B_PORT:-8082}"
OUT_DIR="${OUT_DIR:-$ROOT/test-output/dashboard-demo-$(date +%Y%m%d-%H%M%S)}"

for binary in "$CLI" "$DASHBOARD"; do
    [[ -x "$binary" ]] || {
        echo "missing executable: $binary" >&2
        echo "run scripts/build.sh first" >&2
        exit 1
    }
done
for tool in openssl awk; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing required command: $tool" >&2
        exit 1
    }
done

mkdir -p "$OUT_DIR"
CERT="$OUT_DIR/mediator.cert.pem"
KEY="$OUT_DIR/mediator.key.pem"
STATE="$OUT_DIR/lobby-state.json"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj "/CN=TradeP2P Dashboard Demo" \
    -keyout "$KEY" -out "$CERT" \
    >"$OUT_DIR/openssl.stdout.log" 2>"$OUT_DIR/openssl.stderr.log"
chmod 600 "$KEY"
PIN="$(openssl x509 -in "$CERT" -outform DER | openssl dgst -sha256 -hex | awk '{print $2}')"

MED_PID=""
A_PID=""
B_PID=""
cleanup() {
    set +e
    [[ -n "$A_PID" ]] && kill "$A_PID" 2>/dev/null
    [[ -n "$B_PID" ]] && kill "$B_PID" 2>/dev/null
    [[ -n "$MED_PID" ]] && kill "$MED_PID" 2>/dev/null
    wait "$A_PID" "$B_PID" "$MED_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

TRADEP2P_LOBBY_STATE_FILE="$STATE" \
    "$CLI" mediator "127.0.0.1:$MEDIATOR_PORT" "$CERT" "$KEY" \
    >"$OUT_DIR/mediator.log" 2>&1 &
MED_PID=$!
sleep 0.7

"$DASHBOARD" client "127.0.0.1:$MEDIATOR_PORT" "$PIN" \
    --port "$DASHBOARD_A_PORT" --server-state "$STATE" \
    >"$OUT_DIR/dashboard-a.log" 2>&1 &
A_PID=$!

"$DASHBOARD" client "127.0.0.1:$MEDIATOR_PORT" "$PIN" \
    --port "$DASHBOARD_B_PORT" --server-state "$STATE" \
    >"$OUT_DIR/dashboard-b.log" 2>&1 &
B_PID=$!

cat <<MSG
Two dashboard clients are running against one local lobby.

Party A: http://127.0.0.1:$DASHBOARD_A_PORT
Party B: http://127.0.0.1:$DASHBOARD_B_PORT

Create an offer in one browser tab, join it from the other, then use
'I sent it' and 'I verified receipt' to advance each settlement leg.

Mediator snapshot: $STATE
Logs:              $OUT_DIR
Press Ctrl-C to stop everything.
MSG

wait "$A_PID" "$B_PID"
