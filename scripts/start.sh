#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -x "$ROOT/build/tradep2p-dashboard" ]]; then
    DASHBOARD="$ROOT/build/tradep2p-dashboard"
elif [[ -x "$ROOT/tradep2p-dashboard" ]]; then
    DASHBOARD="$ROOT/tradep2p-dashboard"
else
    echo "error: tradep2p-dashboard not found"
    echo "expected:"
    echo "  $ROOT/build/tradep2p-dashboard"
    echo "  $ROOT/tradep2p-dashboard"
    exit 1
fi

MEDIATOR="${MEDIATOR:-127.0.0.1:20711}"
LISTEN="${LISTEN:-127.0.0.1}"
PORT="${PORT:-8080}"

CERT_DIR="${CERT_DIR:-$ROOT/certs}"
CERT_FILE="${CERT_FILE:-$CERT_DIR/mediator.cert.pem}"
KEY_FILE="${KEY_FILE:-$CERT_DIR/mediator.key.pem}"
SERVER_STATE="${SERVER_STATE:-$ROOT/logs/lobby-state.json}"

mkdir -p "$CERT_DIR" "$(dirname "$SERVER_STATE")"

if [[ ! -f "$CERT_FILE" || ! -f "$KEY_FILE" ]]; then
    echo "Generating self-signed TradeP2P mediator certificate..."

    rm -f "$CERT_FILE" "$KEY_FILE"

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

    echo "generated:"
    echo "  certificate: $CERT_FILE"
    echo "  private key: $KEY_FILE"
    echo
fi

CERT_SHA256="$(
    openssl x509 \
        -in "$CERT_FILE" \
        -noout \
        -fingerprint \
        -sha256 |
    cut -d= -f2 |
    tr -d ':'
)"

echo "Starting TradeP2P dashboard"
echo "  mediator:  $MEDIATOR"
echo "  dashboard: http://$LISTEN:$PORT"
echo "  cert:      $CERT_FILE"
echo "  key:       $KEY_FILE"
echo
echo "Start the mediator with:"
echo "  export TRADEP2P_LOBBY_STATE_FILE=\"$SERVER_STATE\""
echo "  ./build/tradep2p_cli mediator \"$MEDIATOR\" \"$CERT_FILE\" \"$KEY_FILE\""
echo

exec "$DASHBOARD" \
    client \
    "$MEDIATOR" \
    "$CERT_SHA256" \
    --listen "$LISTEN" \
    --port "$PORT" \
    --server-state "$SERVER_STATE"
