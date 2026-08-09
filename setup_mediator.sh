#!/usr/bin/env bash
# Ergonomic mediator setup: generates a TLS identity if needed, builds the
# project if needed, and launches the mediator (optionally registered with a
# directory and optionally charging a fee) plus its read-only operator
# dashboard. Configuration lives in a small shell-sourceable config file so a
# repeat run does not require re-typing flags.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$ROOT/mediator.conf}"

print_usage() {
    cat <<'EOF'
Usage: ./setup_mediator.sh [options]

Options:
  --config FILE       config file to read/write (default: ./mediator.conf)
  --init-config        write a default config file to --config and exit
  --bind HOST:PORT     mediator bind endpoint (default 0.0.0.0:7443)
  --cert FILE          TLS certificate path (default certs/mediator.cert.pem)
  --key FILE           TLS private key path (default certs/mediator.key.pem)
  --state-file FILE    lobby snapshot path (default logs/lobby-state.json)
  --fee-asset ASSET    charge a mediator fee in this asset (optional)
  --fee-amount N       fee amount in integer units (required with --fee-asset)
  --fee-address ADDR   your receive address for the fee (required with --fee-asset)
  --fee-require-confirmation
                        the fee leg does not auto-complete on the payer's own
                        "I sent it" claim - the room stays open until you
                        confirm receipt via the admin control channel
                        (LISTPENDINGFEES/CONFIRMFEE). Honor-based like
                        everything else here (no blockchain check); off by
                        default. Only meaningful with --fee-asset and
                        --admin-token.
  --fee-position before-first|before-last|after-last
                        when the fee is actually collected relative to the
                        real trade rounds (default after-last, today's only
                        historical behavior - honor-based, paid last, a party
                        can complete the whole trade and never pay).
                        before-first: paid before any real tranche - most
                        protection against being crossed, most exposure for
                        the payer if the counterparty then doesn't cooperate.
                        before-last: paid before the LAST real round - most of
                        the trade's real skin-in-the-game has already changed
                        hands, a smaller window to skip out than after-last.
                        Degenerates to before-first when --rounds is 1 (no
                        earlier round exists to hook the fee onto). Only
                        meaningful with --fee-asset.
  --admin-token TOKEN  enables a loopback-only live control channel for
                        changing the fee without a restart (optional; see
                        --admin-port). Keep this secret - anyone who has it
                        can change the fee. Leave unset to disable the
                        channel entirely.
  --admin-port N       port for the admin control channel (default 7444,
                        only meaningful with --admin-token)
  --auth-port N        enables a public, unauthenticated port where ANY
                        caller can ask this mediator to sign a fresh nonce
                        with a persistent ML-DSA-65 identity key - proof of
                        continuity for a returning client who already knows
                        this mediator's key from prior trade history (see
                        `tradep2p_cli verify-mediator`). Nothing this
                        channel returns is sensitive, so unlike --admin-port
                        there is no token - leave unset to disable the
                        channel entirely (the default).
  --auth-key-file PATH  where the mediator auth key's 32-byte seed is
                        stored (created on first run if missing). Leave
                        unset and a fresh key is generated every restart -
                        every proof issued that run becomes unverifiable
                        against a later restart's key, a real, named
                        limitation of running without this set, not a
                        silent one. Only meaningful with --auth-port.
  --registry HOST:PORT registry endpoint to register with (optional)
  --registry-pin HEX   registry certificate SHA-256 pin (required with --registry)
  --advertise HOST:PORT the endpoint peers can reach this mediator on (defaults
                        to --bind). Also used, regardless of --registry, as
                        the mediator's own identity for receipt-ack
                        signatures - set this to whatever address your
                        clients actually connect through (e.g. an onion
                        address) whenever it differs from --bind (always
                        true for a 0.0.0.0 bind), or every room will hang
                        forever at the final-receipt-ack stage.
  --dashboard-port N   operator dashboard port (default 8091)
  --no-dashboard        do not launch the operator dashboard
  -h, --help            show this help

Settings are read from the config file first, then overridden by any flags
given on the command line. Re-run with --init-config to (re)write the file
with the current effective settings.
EOF
}

# Defaults.
MEDIATOR_BIND="0.0.0.0:7443"
MEDIATOR_CERT="$ROOT/certs/mediator.cert.pem"
MEDIATOR_KEY="$ROOT/certs/mediator.key.pem"
MEDIATOR_STATE_FILE="$ROOT/logs/lobby-state.json"
FEE_ASSET=""
FEE_AMOUNT=""
FEE_ADDRESS=""
FEE_REQUIRE_CONFIRMATION="0"
FEE_POSITION="after-last"
ADMIN_TOKEN=""
ADMIN_PORT="7444"
AUTH_PORT=""
AUTH_KEY_FILE=""
REGISTRY_ENDPOINT=""
REGISTRY_PIN=""
ADVERTISED_ENDPOINT=""
DASHBOARD_PORT="8091"
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
        --bind) MEDIATOR_BIND="$2"; shift 2 ;;
        --cert) MEDIATOR_CERT="$2"; shift 2 ;;
        --key) MEDIATOR_KEY="$2"; shift 2 ;;
        --state-file) MEDIATOR_STATE_FILE="$2"; shift 2 ;;
        --fee-asset) FEE_ASSET="$2"; shift 2 ;;
        --fee-amount) FEE_AMOUNT="$2"; shift 2 ;;
        --fee-address) FEE_ADDRESS="$2"; shift 2 ;;
        --fee-require-confirmation) FEE_REQUIRE_CONFIRMATION="1"; shift ;;
        --fee-position)
            case "$2" in
                before-first|before-last|after-last) FEE_POSITION="$2" ;;
                *) echo "invalid --fee-position: $2 (must be before-first, before-last, or after-last)" >&2; exit 1 ;;
            esac
            shift 2 ;;
        --admin-token) ADMIN_TOKEN="$2"; shift 2 ;;
        --admin-port) ADMIN_PORT="$2"; shift 2 ;;
        --auth-port) AUTH_PORT="$2"; shift 2 ;;
        --auth-key-file) AUTH_KEY_FILE="$2"; shift 2 ;;
        --registry) REGISTRY_ENDPOINT="$2"; shift 2 ;;
        --registry-pin) REGISTRY_PIN="$2"; shift 2 ;;
        --advertise) ADVERTISED_ENDPOINT="$2"; shift 2 ;;
        --dashboard-port) DASHBOARD_PORT="$2"; shift 2 ;;
        --no-dashboard) RUN_DASHBOARD="0"; shift ;;
        -h|--help) print_usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; print_usage; exit 1 ;;
    esac
done

write_config() {
    cat > "$CONFIG_FILE" <<EOF
# TradeP2P mediator config, read by setup_mediator.sh.
MEDIATOR_BIND="$MEDIATOR_BIND"
MEDIATOR_CERT="$MEDIATOR_CERT"
MEDIATOR_KEY="$MEDIATOR_KEY"
MEDIATOR_STATE_FILE="$MEDIATOR_STATE_FILE"

# Leave FEE_ASSET empty to charge no mediator fee.
FEE_ASSET="$FEE_ASSET"
FEE_AMOUNT="$FEE_AMOUNT"
FEE_ADDRESS="$FEE_ADDRESS"

# "1" to hold the fee leg open until you confirm it via the admin channel
# instead of trusting the payer's own claim. Needs ADMIN_TOKEN set too.
FEE_REQUIRE_CONFIRMATION="$FEE_REQUIRE_CONFIRMATION"

# before-first, before-last, or after-last (default) - see --fee-position
# above for what each means.
FEE_POSITION="$FEE_POSITION"

# Leave ADMIN_TOKEN empty to disable the live fee-control channel entirely.
# Keep this secret if set - anyone who has it can change the fee live.
ADMIN_TOKEN="$ADMIN_TOKEN"
ADMIN_PORT="$ADMIN_PORT"

# Leave AUTH_PORT empty to disable the mediator auth control channel
# entirely (default). Unlike ADMIN_TOKEN, nothing this channel returns is
# sensitive - there is no token to keep secret here.
AUTH_PORT="$AUTH_PORT"
AUTH_KEY_FILE="$AUTH_KEY_FILE"

# Leave REGISTRY_ENDPOINT empty to run standalone, unregistered.
REGISTRY_ENDPOINT="$REGISTRY_ENDPOINT"
REGISTRY_PIN="$REGISTRY_PIN"
ADVERTISED_ENDPOINT="$ADVERTISED_ENDPOINT"

DASHBOARD_PORT="$DASHBOARD_PORT"
RUN_DASHBOARD="$RUN_DASHBOARD"
EOF
    echo "wrote $CONFIG_FILE"
}

if [[ "$INIT_CONFIG" == "1" ]]; then
    write_config
    exit 0
fi

if [[ -n "$FEE_ASSET" && ( -z "$FEE_AMOUNT" || -z "$FEE_ADDRESS" ) ]]; then
    echo "fatal: --fee-asset requires --fee-amount and --fee-address" >&2
    exit 1
fi
if [[ -n "$REGISTRY_ENDPOINT" && -z "$REGISTRY_PIN" ]]; then
    echo "fatal: --registry requires --registry-pin" >&2
    exit 1
fi

CLI="$ROOT/build/tradep2p_cli"
DASHBOARD_BIN="$ROOT/build/tradep2p-mediator-dashboard"
if [[ ! -x "$CLI" || ( "$RUN_DASHBOARD" == "1" && ! -x "$DASHBOARD_BIN" ) ]]; then
    echo "building the project (first run only)..."
    "$ROOT/scripts/build.sh"
fi

mkdir -p "$(dirname "$MEDIATOR_CERT")" "$(dirname "$MEDIATOR_STATE_FILE")"
if [[ ! -f "$MEDIATOR_CERT" || ! -f "$MEDIATOR_KEY" ]]; then
    echo "generating a TLS identity at $MEDIATOR_CERT / $MEDIATOR_KEY ..."
    # ML-DSA-65 (FIPS 204): a post-quantum signature, not just a post-quantum
    # key exchange. This cert is pinned by SHA-256 fingerprint rather than
    # validated through a CA chain, so an RSA/ECDSA cert here would leave the
    # *authentication* half of the handshake breakable by Shor's algorithm
    # even though the key exchange is already hybrid post-quantum. Requires
    # OpenSSL 3.5+ (same floor already required for the X25519MLKEM768 group).
    openssl req -x509 -newkey ML-DSA-65 -nodes -days 365 \
        -subj "/CN=TradeP2P Mediator" \
        -keyout "$MEDIATOR_KEY" -out "$MEDIATOR_CERT"
    chmod 600 "$MEDIATOR_KEY"
fi
CERT_PIN="$(openssl x509 -in "$MEDIATOR_CERT" -outform DER | openssl dgst -sha256 -hex | awk '{print $2}')"

DASHBOARD_PID=""
cleanup() {
    if [[ -n "$DASHBOARD_PID" ]]; then
        kill "$DASHBOARD_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

if [[ "$RUN_DASHBOARD" == "1" ]]; then
    if [[ -n "$ADMIN_TOKEN" ]]; then
        "$DASHBOARD_BIN" "$MEDIATOR_STATE_FILE" --port "$DASHBOARD_PORT" \
            --admin-token "$ADMIN_TOKEN" --admin-port "$ADMIN_PORT" &
    else
        "$DASHBOARD_BIN" "$MEDIATOR_STATE_FILE" --port "$DASHBOARD_PORT" &
    fi
    DASHBOARD_PID=$!
fi

echo "============================================================"
echo "TradeP2P mediator"
echo "  bind:              $MEDIATOR_BIND"
echo "  certificate pin:   $CERT_PIN"
echo "  (share this pin with anyone who should connect a client here)"
if [[ -n "$FEE_ASSET" ]]; then
    echo "  fee:               $FEE_AMOUNT $FEE_ASSET -> $FEE_ADDRESS"
    echo "  fee position:      $FEE_POSITION"
    if [[ "$FEE_REQUIRE_CONFIRMATION" == "1" ]]; then
        echo "  fee confirmation:  required (honor-based, held until you confirm via admin channel)"
    fi
else
    echo "  fee:               none"
fi
if [[ -n "$ADMIN_TOKEN" ]]; then
    echo "  admin control:     127.0.0.1:$ADMIN_PORT (loopback only, live fee changes)"
fi
if [[ -n "$AUTH_PORT" ]]; then
    echo "  mediator auth:     ${MEDIATOR_BIND%:*}:$AUTH_PORT (unauthenticated, see --auth-port)"
fi
if [[ -n "$REGISTRY_ENDPOINT" ]]; then
    echo "  registry:          $REGISTRY_ENDPOINT (advertising ${ADVERTISED_ENDPOINT:-$MEDIATOR_BIND})"
fi
if [[ "$RUN_DASHBOARD" == "1" ]]; then
    if [[ -n "$ADMIN_TOKEN" ]]; then
        echo "  operator dashboard: http://127.0.0.1:$DASHBOARD_PORT (loopback only; admin actions enabled - can confirm fees)"
    else
        echo "  operator dashboard: http://127.0.0.1:$DASHBOARD_PORT (loopback only, read-only; proxy it yourself to expose remotely)"
    fi
fi
echo "============================================================"

export TRADEP2P_LOBBY_STATE_FILE="$MEDIATOR_STATE_FILE"
if [[ -n "$ADVERTISED_ENDPOINT" ]]; then
    export TRADEP2P_MEDIATOR_ID="$ADVERTISED_ENDPOINT"
fi
if [[ -n "$FEE_ASSET" ]]; then
    export TRADEP2P_FEE_ASSET="$FEE_ASSET"
    export TRADEP2P_FEE_AMOUNT="$FEE_AMOUNT"
    export TRADEP2P_FEE_ADDRESS="$FEE_ADDRESS"
fi
# A live SETFEE over the admin channel (e.g. from admin-df7bffc8.php) is
# otherwise memory-only - the next restart silently reloads whatever this
# file still says, undoing a change the operator believed was already
# saved. Only wired when the config file actually exists (an unwritten
# default has nothing to rewrite) and resolved to an absolute path, since
# the mediator's own working directory when it later opens this path may
# not match wherever this script happened to be invoked from.
if [[ -f "$CONFIG_FILE" ]]; then
    export TRADEP2P_FEE_CONFIG_FILE="$(cd "$(dirname "$CONFIG_FILE")" && pwd)/$(basename "$CONFIG_FILE")"
fi
if [[ "$FEE_REQUIRE_CONFIRMATION" == "1" ]]; then
    export TRADEP2P_FEE_REQUIRE_CONFIRMATION="1"
fi
if [[ "$FEE_POSITION" != "after-last" ]]; then
    export TRADEP2P_FEE_POSITION="$FEE_POSITION"
fi
if [[ -n "$ADMIN_TOKEN" ]]; then
    export TRADEP2P_ADMIN_TOKEN="$ADMIN_TOKEN"
    export TRADEP2P_ADMIN_PORT="$ADMIN_PORT"
fi
if [[ -n "$AUTH_PORT" ]]; then
    export TRADEP2P_MEDIATOR_AUTH_PORT="$AUTH_PORT"
    if [[ -n "$AUTH_KEY_FILE" ]]; then
        export TRADEP2P_MEDIATOR_AUTH_KEY_FILE="$AUTH_KEY_FILE"
    fi
fi

if [[ -n "$REGISTRY_ENDPOINT" ]]; then
    exec "$CLI" mediator-registered "$MEDIATOR_BIND" "$MEDIATOR_CERT" "$MEDIATOR_KEY" \
        "$REGISTRY_ENDPOINT" "$REGISTRY_PIN" \
        "${ADVERTISED_ENDPOINT:-$MEDIATOR_BIND}" "$CERT_PIN"
else
    exec "$CLI" mediator "$MEDIATOR_BIND" "$MEDIATOR_CERT" "$MEDIATOR_KEY"
fi
