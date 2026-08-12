#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_BUILD_DIR="$ROOT/build"
if [[ -d "$ROOT/build-blns7933-root" ]]; then
    DEFAULT_BUILD_DIR="$ROOT/build-blns7933-root"
fi
BUILD_DIR="${BUILD_DIR:-$DEFAULT_BUILD_DIR}"
DASHBOARD="${TRADEP2P_DASHBOARD_BIN:-$BUILD_DIR/tradep2p-dashboard}"

MEDIATOR=""
PIN=""
SERVER_STATE=""
OPERATOR_URL=""
BASE_PORT=8181
MAKE_KEYSTORES=1
Q7933_PROVER_PATH="${TRADEP2P_BLINDSIG_Q7933_PROVER_PATH:-$ROOT/blindsig-prover-q7933/target/release/blindsig-prover-q7933}"
OUT_DIR="${OUT_DIR:-$ROOT/test-output/q7933-two-client-demo-$(date +%Y%m%d-%H%M%S)}"

usage() {
    cat <<EOF
usage: $(basename "$0") --mediator HOST:PORT --pin HEX [options]

Launches exactly two throwaway trading dashboards with the q=7933 blind-signature
client path enabled. This script does NOT start the mediator, because the q7933
mediator path intentionally prompts for its keystore passphrase on startup.

Options:
  --mediator HOST:PORT       required mediator endpoint
  --pin HEX                  required mediator certificate pin
  --q7933-prover-path PATH   local blindsig-prover-q7933 binary
                             (default: $Q7933_PROVER_PATH)
  --base-port PORT           first dashboard port (second is PORT+1, default: 8181)
  --server-state FILE        optional mediator snapshot file for the dashboard's
                             read-only server-state panel
  --operator-url URL         optional operator dashboard URL to print in the final
                             instructions
  --no-keystores             skip creating throwaway identity keystores
  -h, --help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mediator) MEDIATOR="$2"; shift 2 ;;
        --pin) PIN="$2"; shift 2 ;;
        --q7933-prover-path) Q7933_PROVER_PATH="$2"; shift 2 ;;
        --base-port) BASE_PORT="$2"; shift 2 ;;
        --server-state) SERVER_STATE="$2"; shift 2 ;;
        --operator-url) OPERATOR_URL="$2"; shift 2 ;;
        --no-keystores) MAKE_KEYSTORES=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

[[ -n "$MEDIATOR" && -n "$PIN" ]] || {
    echo "fatal: --mediator and --pin are required" >&2
    usage >&2
    exit 1
}
[[ -x "$DASHBOARD" ]] || {
    echo "missing executable: $DASHBOARD" >&2
    echo "run scripts/build.sh first" >&2
    exit 1
}
[[ -x "$Q7933_PROVER_PATH" ]] || {
    echo "missing q7933 prover binary: $Q7933_PROVER_PATH" >&2
    echo "build it with: (cd blindsig-prover-q7933 && cargo build -p blindsig-prover-q7933 --release)" >&2
    exit 1
}
for tool in curl sed; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing required command: $tool" >&2
        exit 1
    }
done

mkdir -p "$OUT_DIR"

PIDS=()
cleanup() {
    set +e
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null
    done
    wait "${PIDS[@]}" 2>/dev/null
}
trap cleanup EXIT INT TERM

wait_ready() {
    local port="$1"
    for _ in $(seq 1 80); do
        curl -fsS "http://127.0.0.1:$port/" >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    return 1
}

dashboard_token() {
    local port="$1"
    curl -fsS "http://127.0.0.1:$port/" | sed -n 's/.*const TOKEN="\([0-9a-f]*\)";.*/\1/p' | head -n1
}

for index in 1 2; do
    port=$((BASE_PORT + index - 1))
    log="$OUT_DIR/client-$index.log"
    args=(client "$MEDIATOR" "$PIN" --port "$port")
    if [[ -n "$SERVER_STATE" ]]; then
        args+=(--server-state "$SERVER_STATE")
    fi
    TRADEP2P_BLINDSIG_Q7933_PROVER_PATH="$Q7933_PROVER_PATH" \
        "$DASHBOARD" "${args[@]}" >"$log" 2>&1 &
    PIDS+=("$!")
    if ! wait_ready "$port"; then
        echo "fatal: dashboard client $index failed to start on port $port (see $log)" >&2
        exit 1
    fi

    if [[ "$MAKE_KEYSTORES" -eq 1 ]]; then
        token="$(dashboard_token "$port")"
        if [[ -n "$token" ]]; then
            ks_path="$OUT_DIR/client-$index.identity.ks"
            curl -fsS -X POST "http://127.0.0.1:$port/api/identity/create" \
                -H "X-TradeP2P-Token: $token" \
                --data-urlencode "path=$ks_path" \
                --data-urlencode "passphrase=throwaway-passphrase-$index" \
                --data-urlencode "alias=q7933-throwaway-$index" >/dev/null || true
        fi
    fi
done

cat <<EOF
Two throwaway q7933-capable dashboard clients are running:

  Client A: http://127.0.0.1:$BASE_PORT
  Client B: http://127.0.0.1:$((BASE_PORT + 1))

Local q7933 prover:
  $Q7933_PROVER_PATH

Logs / throwaway keystores:
  $OUT_DIR
EOF

if [[ -n "$OPERATOR_URL" ]]; then
    echo
    echo "Operator dashboard:"
    echo "  $OPERATOR_URL"
fi

cat <<EOF

Suggested manual test:
  1. Open Client A and click "Fetch mediator q7933 info".
  2. Submit a q7933 blind-sign request from Client A.
  3. Approve/sign the pending ticket from the mediator operator dashboard.
  4. Return to Client A and click "Poll ticket" until the credential becomes ready.
  5. Use Client B for a second independent request so both clients stay throwaway.

Press Ctrl-C to stop both dashboards.
EOF

set +e
wait "${PIDS[@]}"
