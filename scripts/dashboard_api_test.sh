#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
CLI="${TRADEP2P_BIN:-$BUILD_DIR/tradep2p_cli}"
DASHBOARD="${TRADEP2P_DASHBOARD_BIN:-$BUILD_DIR/tradep2p-dashboard}"
MEDIATOR_PORT="${MEDIATOR_PORT:-$((20000 + RANDOM % 20000))}"
DASHBOARD_A_PORT="${DASHBOARD_A_PORT:-$((41000 + RANDOM % 1000))}"
DASHBOARD_B_PORT="${DASHBOARD_B_PORT:-$((43000 + RANDOM % 1000))}"
ROUNDS="${ROUNDS:-2}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-15}"
OUT_DIR="${OUT_DIR:-$ROOT/test-output/dashboard-api-$(date +%Y%m%d-%H%M%S)}"

for binary in "$CLI" "$DASHBOARD"; do
    [[ -x "$binary" ]] || { echo "missing executable: $binary" >&2; exit 1; }
done
for tool in openssl awk curl python3 sed; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing required command: $tool" >&2
        exit 1
    }
done

mkdir -p "$OUT_DIR"
CERT="$OUT_DIR/mediator.cert.pem"
KEY="$OUT_DIR/mediator.key.pem"
STATE="$OUT_DIR/lobby-state.json"

MED_PID=""; A_PID=""; B_PID=""
cleanup() {
    set +e
    [[ -n "$A_PID" ]] && kill "$A_PID" 2>/dev/null
    [[ -n "$B_PID" ]] && kill "$B_PID" 2>/dev/null
    [[ -n "$MED_PID" ]] && kill "$MED_PID" 2>/dev/null
    wait "$A_PID" "$B_PID" "$MED_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

wait_for_json() {
    local url="$1" expression="$2" label="$3"
    local ticks=$((TIMEOUT_SECONDS * 10))
    for ((i=0; i<ticks; ++i)); do
        if curl -fsS "$url" 2>/dev/null | python3 -c \
            "import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if ($expression) else 1)" \
            >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    echo "timeout waiting for $label" >&2
    return 1
}

post() {
    local port="$1" token="$2" path="$3" data="$4"
    curl -fsS -X POST "http://127.0.0.1:$port$path" \
        -H "X-TradeP2P-Token: $token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data "$data" >/dev/null
}

state_value() {
    local port="$1" expression="$2"
    curl -fsS "http://127.0.0.1:$port/api/state" | \
        python3 -c "import json,sys; d=json.load(sys.stdin); print($expression)"
}

openssl req -x509 -newkey ML-DSA-65 -nodes -days 1 \
    -subj "/CN=TradeP2P Dashboard API Test" \
    -keyout "$KEY" -out "$CERT" \
    >"$OUT_DIR/openssl.stdout.log" 2>"$OUT_DIR/openssl.stderr.log"
chmod 600 "$KEY"
PIN="$(openssl x509 -in "$CERT" -outform DER | openssl dgst -sha256 -hex | awk '{print $2}')"

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

wait_for_json "http://127.0.0.1:$DASHBOARD_A_PORT/api/state" 'd.get("connected") is True' "dashboard A connection"
wait_for_json "http://127.0.0.1:$DASHBOARD_B_PORT/api/state" 'd.get("connected") is True' "dashboard B connection"

TOKEN_A="$(curl -fsS "http://127.0.0.1:$DASHBOARD_A_PORT/" | sed -n 's/.*const TOKEN="\([0-9a-f]*\)";.*/\1/p' | head -n1)"
TOKEN_B="$(curl -fsS "http://127.0.0.1:$DASHBOARD_B_PORT/" | sed -n 's/.*const TOKEN="\([0-9a-f]*\)";.*/\1/p' | head -n1)"
[[ -n "$TOKEN_A" && -n "$TOKEN_B" ]] || { echo "could not read dashboard tokens" >&2; exit 1; }

post "$DASHBOARD_A_PORT" "$TOKEN_A" /api/offers/create \
    "sell_asset=QRL&sell_amount=500000&buy_asset=BTC&buy_amount=100000&rounds=$ROUNDS&address=btc-address-for-party-a"
wait_for_json "http://127.0.0.1:$DASHBOARD_A_PORT/api/server-state" 'len(d.get("offers", [])) >= 1' "mediator offer snapshot"
post "$DASHBOARD_B_PORT" "$TOKEN_B" /api/offers/refresh ""
wait_for_json "http://127.0.0.1:$DASHBOARD_B_PORT/api/state" 'len(d.get("offers", [])) >= 1' "published offer"
ROOM="$(state_value "$DASHBOARD_B_PORT" 'd["offers"][0]["room_id"]')"

post "$DASHBOARD_B_PORT" "$TOKEN_B" /api/offers/join \
    "room_id=$ROOM&address=qrl-address-for-party-b"
wait_for_json "http://127.0.0.1:$DASHBOARD_A_PORT/api/state" 'len(d.get("rooms", [])) == 1 and d["rooms"][0].get("has_turn")' "party A active room"
wait_for_json "http://127.0.0.1:$DASHBOARD_B_PORT/api/state" 'len(d.get("rooms", [])) == 1 and d["rooms"][0].get("has_turn")' "party B active room"

for ((step=0; step<ROUNDS*2; ++step)); do
    wait_for_json "http://127.0.0.1:$DASHBOARD_A_PORT/api/server-state" 'len(d.get("rooms", [])) == 1 and d["rooms"][0].get("state") == "waiting_for_sent"' "mediator waiting for sender"
    CURRENT_SENDER="$(curl -fsS "http://127.0.0.1:$DASHBOARD_A_PORT/api/server-state" | python3 -c 'import json,sys; print(json.load(sys.stdin)["rooms"][0]["current_sender"])')"
    PARTY_A="$(state_value "$DASHBOARD_A_PORT" 'd["rooms"][0]["party"]')"

    if [[ "$PARTY_A" == "$CURRENT_SENDER" ]]; then
        wait_for_json "http://127.0.0.1:$DASHBOARD_A_PORT/api/state" 'd["rooms"][0]["action"] == "sent" and d["rooms"][0]["turn"]["sender"] == "'$CURRENT_SENDER'"' "party A sender dashboard turn"
        wait_for_json "http://127.0.0.1:$DASHBOARD_B_PORT/api/state" 'd["rooms"][0]["action"] == "received" and d["rooms"][0]["turn"]["sender"] == "'$CURRENT_SENDER'"' "party B receiver dashboard turn"
        post "$DASHBOARD_A_PORT" "$TOKEN_A" /api/rooms/sent "room_id=$ROOM"
        wait_for_json "http://127.0.0.1:$DASHBOARD_A_PORT/api/server-state" 'len(d.get("rooms", [])) == 1 and d["rooms"][0].get("state") == "waiting_for_received"' "mediator waiting for party B receipt"
        post "$DASHBOARD_B_PORT" "$TOKEN_B" /api/rooms/received "room_id=$ROOM"
    else
        wait_for_json "http://127.0.0.1:$DASHBOARD_B_PORT/api/state" 'd["rooms"][0]["action"] == "sent" and d["rooms"][0]["turn"]["sender"] == "'$CURRENT_SENDER'"' "party B sender dashboard turn"
        wait_for_json "http://127.0.0.1:$DASHBOARD_A_PORT/api/state" 'd["rooms"][0]["action"] == "received" and d["rooms"][0]["turn"]["sender"] == "'$CURRENT_SENDER'"' "party A receiver dashboard turn"
        post "$DASHBOARD_B_PORT" "$TOKEN_B" /api/rooms/sent "room_id=$ROOM"
        wait_for_json "http://127.0.0.1:$DASHBOARD_A_PORT/api/server-state" 'len(d.get("rooms", [])) == 1 and d["rooms"][0].get("state") == "waiting_for_received"' "mediator waiting for party A receipt"
        post "$DASHBOARD_A_PORT" "$TOKEN_A" /api/rooms/received "room_id=$ROOM"
    fi

    if (( step + 1 < ROUNDS * 2 )); then
        wait_for_json "http://127.0.0.1:$DASHBOARD_A_PORT/api/server-state" 'len(d.get("rooms", [])) == 1 and d["rooms"][0].get("state") == "waiting_for_sent"' "next settlement turn"
    fi
done

wait_for_json "http://127.0.0.1:$DASHBOARD_A_PORT/api/state" 'd["rooms"][0]["status"] == "complete"' "party A completion"
wait_for_json "http://127.0.0.1:$DASHBOARD_B_PORT/api/state" 'd["rooms"][0]["status"] == "complete"' "party B completion"

echo "dashboard API settlement test completed"
echo "room: $ROOM"
echo "logs: $OUT_DIR"
