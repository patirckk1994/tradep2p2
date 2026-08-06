#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
BIN="${TRADEP2P_BIN:-$BUILD_DIR/tradep2p_cli}"
PORT="${PORT:-$((20000 + RANDOM % 20000))}"
ROUNDS="${ROUNDS:-2}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$ROOT/test-output/io-demo-$STAMP}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-12}"

if [[ ! -x "$BIN" ]]; then
    echo "missing executable: $BIN" >&2
    echo "run scripts/build.sh first or set TRADEP2P_BIN" >&2
    exit 1
fi

for tool in openssl stdbuf grep awk sed tee mkfifo; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing required command: $tool" >&2
        exit 1
    }
done

mkdir -p "$OUT_DIR"
A_FIFO="$OUT_DIR/client_a.in"
B_FIFO="$OUT_DIR/client_b.in"
A_LOG="$OUT_DIR/client_a.stdout.log"
B_LOG="$OUT_DIR/client_b.stdout.log"
A_ERR="$OUT_DIR/client_a.stderr.log"
B_ERR="$OUT_DIR/client_b.stderr.log"
MED_LOG="$OUT_DIR/mediator.stdout.log"
MED_ERR="$OUT_DIR/mediator.stderr.log"
A_IN="$OUT_DIR/client_a.stdin.log"
B_IN="$OUT_DIR/client_b.stdin.log"
CERT="$OUT_DIR/mediator.cert.pem"
KEY="$OUT_DIR/mediator.key.pem"

: > "$A_LOG"; : > "$B_LOG"; : > "$A_ERR"; : > "$B_ERR"
: > "$MED_LOG"; : > "$MED_ERR"; : > "$A_IN"; : > "$B_IN"
mkfifo "$A_FIFO" "$B_FIFO"

MED_PID=""
A_PID=""
B_PID=""

cleanup() {
    set +e
    exec 3>&- 4>&-
    [[ -n "$A_PID" ]] && kill "$A_PID" 2>/dev/null
    [[ -n "$B_PID" ]] && kill "$B_PID" 2>/dev/null
    [[ -n "$MED_PID" ]] && kill "$MED_PID" 2>/dev/null
    wait "$A_PID" "$B_PID" "$MED_PID" 2>/dev/null
    rm -f "$A_FIFO" "$B_FIFO"
}
trap cleanup EXIT INT TERM

wait_for_count() {
    local file="$1"
    local pattern="$2"
    local wanted="$3"
    local label="$4"
    local ticks=$((TIMEOUT_SECONDS * 10))
    local count=0

    for ((i=0; i<ticks; ++i)); do
        count="$(grep -F -c -- "$pattern" "$file" 2>/dev/null || true)"
        if (( count >= wanted )); then
            return 0
        fi
        sleep 0.1
    done

    echo "timeout waiting for: $label" >&2
    echo "pattern: $pattern" >&2
    echo "file: $file" >&2
    return 1
}

send_a() {
    printf '%s\n' "$*" | tee -a "$A_IN"
    printf '%s\n' "$*" >&3
}

send_b() {
    printf '%s\n' "$*" | tee -a "$B_IN"
    printf '%s\n' "$*" >&4
}

openssl req -x509 -newkey ML-DSA-65 -nodes -days 1 \
    -subj "/CN=TradeP2P IO Test" \
    -keyout "$KEY" -out "$CERT" \
    >"$OUT_DIR/openssl.stdout.log" 2>"$OUT_DIR/openssl.stderr.log"
chmod 600 "$KEY"
PIN="$(openssl x509 -in "$CERT" -outform DER | openssl dgst -sha256 -hex | awk '{print $2}')"

stdbuf -oL -eL "$BIN" mediator "127.0.0.1:$PORT" "$CERT" "$KEY" \
    > >(sed -u 's/^/[MED OUT] /' | tee "$MED_LOG") \
    2> >(sed -u 's/^/[MED ERR] /' | tee "$MED_ERR" >&2) &
MED_PID=$!
sleep 0.7
kill -0 "$MED_PID" 2>/dev/null || {
    echo "mediator failed to start; see $MED_ERR" >&2
    exit 1
}

stdbuf -oL -eL "$BIN" client "127.0.0.1:$PORT" "$PIN" < "$A_FIFO" \
    > >(sed -u 's/^/[A OUT] /' | tee "$A_LOG") \
    2> >(sed -u 's/^/[A ERR] /' | tee "$A_ERR" >&2) &
A_PID=$!

stdbuf -oL -eL "$BIN" client "127.0.0.1:$PORT" "$PIN" < "$B_FIFO" \
    > >(sed -u 's/^/[B OUT] /' | tee "$B_LOG") \
    2> >(sed -u 's/^/[B ERR] /' | tee "$B_ERR" >&2) &
B_PID=$!

# Keep both FIFO writers open for the whole session.
exec 3>"$A_FIFO"
exec 4>"$B_FIFO"

wait_for_count "$A_LOG" "anonymous client id:" 1 "client A welcome"
wait_for_count "$B_LOG" "anonymous client id:" 1 "client B welcome"

echo
printf '[A IN] '
send_a "/offer QRL 500000 BTC 100000 $ROUNDS btc-address-for-party-a"
wait_for_count "$A_LOG" "offer room created:" 1 "offer creation"
ROOM="$(grep -F "offer room created:" "$A_LOG" | tail -n1 | awk '{print $NF}')"
[[ "$ROOM" =~ ^[0-9A-Fa-f]+$ ]] || {
    echo "could not parse room id from $A_LOG" >&2
    exit 1
}
echo "room id: $ROOM"

echo
printf '[B IN] '
send_b "/offers"
wait_for_count "$B_LOG" "$ROOM" 1 "room in public offer list"

printf '[B IN] '
send_b "/join $ROOM qrl-address-for-party-b"
# The published offer id is also the active settlement-room id.
wait_for_count "$A_LOG" "room ready: $ROOM" 1 "client A room ready"
wait_for_count "$B_LOG" "room ready: $ROOM" 1 "client B room ready"

a_sent_seen=0
b_sent_seen=0
for ((round=1; round<=ROUNDS; ++round)); do
    if (( round % 2 == 1 )); then
        first="A"; second="B"
    else
        first="B"; second="A"
    fi

    for sender in "$first" "$second"; do
        if [[ "$sender" == "A" ]]; then
            receiver="B"
            sender_log="$A_LOG"
            receiver_log="$B_LOG"
        else
            receiver="A"
            sender_log="$B_LOG"
            receiver_log="$A_LOG"
        fi

        wait_for_count "$sender_log" "room $ROOM round $round: SEND" 1 "round $round sender $sender turn"

        echo
        if [[ "$sender" == "A" ]]; then
            printf '[A IN] '
            send_a "/sent $ROOM"
        else
            printf '[B IN] '
            send_b "/sent $ROOM"
        fi

        if [[ "$receiver" == "A" ]]; then
            ((a_sent_seen+=1))
            expected_sent_count="$a_sent_seen"
        else
            ((b_sent_seen+=1))
            expected_sent_count="$b_sent_seen"
        fi
        wait_for_count "$receiver_log" "peer reported sent in room $ROOM" "$expected_sent_count" "sent acknowledgement for receiver $receiver"

        if [[ "$receiver" == "A" ]]; then
            printf '[A IN] '
            send_a "/received $ROOM"
        else
            printf '[B IN] '
            send_b "/received $ROOM"
        fi
    done
done

wait_for_count "$A_LOG" "room complete: $ROOM" 1 "client A completion"
wait_for_count "$B_LOG" "room complete: $ROOM" 1 "client B completion"

echo
printf '[A IN] '
send_a "/quit"
printf '[B IN] '
send_b "/quit"

sleep 0.5

TRANSCRIPT="$OUT_DIR/transcript.txt"
{
    echo "TradeP2P deterministic IO demo"
    echo "room=$ROOM"
    echo "rounds=$ROUNDS"
    echo
    echo "===== CLIENT A STDIN ====="
    cat "$A_IN"
    echo
    echo "===== CLIENT A STDOUT ====="
    cat "$A_LOG"
    echo
    echo "===== CLIENT A STDERR ====="
    cat "$A_ERR"
    echo
    echo "===== CLIENT B STDIN ====="
    cat "$B_IN"
    echo
    echo "===== CLIENT B STDOUT ====="
    cat "$B_LOG"
    echo
    echo "===== CLIENT B STDERR ====="
    cat "$B_ERR"
    echo
    echo "===== MEDIATOR STDOUT ====="
    cat "$MED_LOG"
    echo
    echo "===== MEDIATOR STDERR ====="
    cat "$MED_ERR"
} > "$TRANSCRIPT"

echo
echo "IO demo complete."
echo "transcript: $TRANSCRIPT"
echo "all logs:   $OUT_DIR"
