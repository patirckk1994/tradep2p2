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

MEDIATOR_BIND="${MEDIATOR_BIND:-127.0.0.1:20711}"
RUNTIME_DIR="${RUNTIME_DIR:-$ROOT/runtime}"
CERT_FILE="${CERT_FILE:-$RUNTIME_DIR/mediator.cert.pem}"
KEY_FILE="${KEY_FILE:-$RUNTIME_DIR/mediator.key.pem}"
STATE_FILE="${STATE_FILE:-$RUNTIME_DIR/lobby-state.json}"

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
export TRADEP2P_LOBBY_STATE_FILE="$STATE_FILE"

echo
echo "TradeP2P mediator"
echo "  bind:        $MEDIATOR_BIND"
echo "  certificate: $CERT_FILE"
echo "  private key: $KEY_FILE"
echo "  fingerprint: $PIN"
echo "  state file:  $STATE_FILE"
echo

exec "$CLI" mediator "$MEDIATOR_BIND" "$CERT_FILE" "$KEY_FILE"
