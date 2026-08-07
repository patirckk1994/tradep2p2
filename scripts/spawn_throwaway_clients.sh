#!/usr/bin/env bash
# Launches N throwaway dashboard clients for manually exploring rooms,
# recognition, and receipt-chain crypto telemetry - each with its own
# browser tab and (by default) its own disposable keystore, so recognition
# challenges have someone to answer them instead of showing "declined".
#
# By default this starts its own throwaway one-day mediator too (same
# pattern as dashboard_two_client_demo.sh), so it never touches a mediator
# you're already using interactively - that avoids racing your own clicks
# against a script driving the same session, which is exactly what caused
# a receipt-ack signature failure the last time this was done by hand
# against a live dashboard. Pass --mediator/--pin to attach to an existing
# mediator instead, but then avoid clicking in an already-open dashboard
# for that same mediator while this is running, for the same reason.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
CLI="${TRADEP2P_BIN:-$BUILD_DIR/tradep2p_cli}"
DASHBOARD="${TRADEP2P_DASHBOARD_BIN:-$BUILD_DIR/tradep2p-dashboard}"

COUNT=3
BASE_PORT=8090
MEDIATOR=""
PIN=""
MAKE_KEYSTORES=1
OUT_DIR="$ROOT/test-output/throwaway-clients-$(date +%Y%m%d-%H%M%S)"

usage() {
    cat <<EOF
usage: $(basename "$0") [options]

Starts COUNT throwaway dashboard clients, each on its own port, for
manually exploring rooms/recognition/receipt telemetry across more than
two parties. Prints one URL per client when ready.

Options:
  -n, --count N        number of clients to launch (default: 3)
  -p, --base-port PORT first client's port; each next client is PORT+1,
                        PORT+2, ... (default: 8090)
  --mediator HOST:PORT  attach to an already-running mediator instead of
                        starting a throwaway one (requires --pin)
  --pin HEX             that mediator's SHA-256 certificate pin
  --no-keystores        skip creating a throwaway keystore per client
                        (faster; recognition challenges will show as
                        "declined" since nothing can answer them)
  -h, --help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n|--count) COUNT="$2"; shift 2 ;;
        -p|--base-port) BASE_PORT="$2"; shift 2 ;;
        --mediator) MEDIATOR="$2"; shift 2 ;;
        --pin) PIN="$2"; shift 2 ;;
        --no-keystores) MAKE_KEYSTORES=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ -n "$MEDIATOR" && -z "$PIN" ]]; then
    echo "fatal: --mediator requires --pin" >&2
    exit 1
fi
if [[ -z "$MEDIATOR" && -n "$PIN" ]]; then
    echo "fatal: --pin requires --mediator" >&2
    exit 1
fi
if ! [[ "$COUNT" =~ ^[0-9]+$ ]] || [[ "$COUNT" -lt 1 ]]; then
    echo "fatal: --count must be a positive integer" >&2
    exit 1
fi

for binary in "$CLI" "$DASHBOARD"; do
    [[ -x "$binary" ]] || {
        echo "missing executable: $binary" >&2
        echo "run scripts/build.sh first" >&2
        exit 1
    }
done
for tool in curl python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing required command: $tool" >&2
        exit 1
    }
done

mkdir -p "$OUT_DIR"

MED_PID=""
CLIENT_PIDS=()
cleanup() {
    set +e
    for pid in "${CLIENT_PIDS[@]}"; do
        kill "$pid" 2>/dev/null
    done
    [[ -n "$MED_PID" ]] && kill "$MED_PID" 2>/dev/null
    wait "${CLIENT_PIDS[@]}" "$MED_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

port_in_use() {
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}
for ((i = 0; i < COUNT; ++i)); do
    p=$((BASE_PORT + i))
    if port_in_use "$p"; then
        echo "fatal: port $p is already in use - pick a different --base-port (need $COUNT free ports starting there)" >&2
        exit 1
    fi
done

if [[ -z "$MEDIATOR" ]]; then
    command -v openssl >/dev/null 2>&1 || { echo "missing required command: openssl" >&2; exit 1; }
    CERT="$OUT_DIR/mediator.cert.pem"
    KEY="$OUT_DIR/mediator.key.pem"
    STATE="$OUT_DIR/lobby-state.json"
    MEDIATOR_PORT=$((20000 + RANDOM % 20000))

    openssl req -x509 -newkey ML-DSA-65 -nodes -days 1 \
        -subj "/CN=TradeP2P Throwaway Clients Demo" \
        -keyout "$KEY" -out "$CERT" \
        >"$OUT_DIR/openssl.log" 2>&1
    chmod 600 "$KEY"
    PIN="$(openssl x509 -in "$CERT" -outform DER | openssl dgst -sha256 -hex | awk '{print $2}')"
    MEDIATOR="127.0.0.1:$MEDIATOR_PORT"

    TRADEP2P_LOBBY_STATE_FILE="$STATE" \
        "$CLI" mediator "$MEDIATOR" "$CERT" "$KEY" \
        >"$OUT_DIR/mediator.log" 2>&1 &
    MED_PID=$!
    sleep 0.7
    echo "started a throwaway mediator at $MEDIATOR (one-day ML-DSA-65 cert, logs: $OUT_DIR/mediator.log)"
else
    echo "attaching to existing mediator at $MEDIATOR"
fi

wait_ready() {
    local port="$1"
    for _ in $(seq 1 50); do
        curl -fsS "http://127.0.0.1:$port/" >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    return 1
}

echo
for ((i = 1; i <= COUNT; ++i)); do
    port=$((BASE_PORT + i - 1))
    log="$OUT_DIR/client-$i.log"
    "$DASHBOARD" client "$MEDIATOR" "$PIN" --port "$port" >"$log" 2>&1 &
    CLIENT_PIDS+=("$!")

    if ! wait_ready "$port"; then
        echo "client $i on port $port did not come up - see $log" >&2
        continue
    fi

    label="client $i: http://127.0.0.1:$port"
    if [[ "$MAKE_KEYSTORES" -eq 1 ]]; then
        token="$(curl -fsS "http://127.0.0.1:$port/" | grep -oP 'const TOKEN="\K[^"]+' || true)"
        if [[ -z "$token" ]]; then
            echo "client $i on port $port: could not read its dashboard token, skipping keystore" >&2
        else
            ks_path="$OUT_DIR/client-$i.keystore"
            if curl -fsS -X POST "http://127.0.0.1:$port/api/identity/create" \
                -H "X-TradeP2P-Token: $token" \
                --data-urlencode "path=$ks_path" \
                --data-urlencode "passphrase=throwaway-passphrase-$i" \
                --data-urlencode "alias=throwaway-$i" >/dev/null; then
                label="$label  (keystore unlocked - can answer recognition challenges)"
            else
                echo "client $i on port $port: keystore creation failed" >&2
            fi
        fi
    fi
    echo "$label"
done

echo
echo "Each URL above is a full dashboard - publish/join offers between them,"
echo "settle rounds, and open a room's 'crypto detail' toggle to see"
echo "recognition + receipt-chain telemetry populate."
echo "Logs and any keystores: $OUT_DIR"
echo "Press Ctrl-C to stop everything."

# set +e here: this call's only job is to block until Ctrl-C (or a client
# dies on its own) - a single already-failed client (reported above,
# already skipped) exiting non-zero must not be treated as this script
# failing, which would trip set -e and tear down every client that DID
# start, not just the broken one.
set +e
wait "${CLIENT_PIDS[@]}"
