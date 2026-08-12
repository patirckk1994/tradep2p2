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
  --admin-fee-token TOKEN
                        a second, more narrowly scoped credential for the
                        same admin channel: usable only for
                        LISTPENDINGFEES/FEEDETAILS/CONFIRMFEE, rejected for
                        SETFEE or anything else. Meant for an automated fee
                        checker (see plugins/) so it never needs a
                        credential powerful enough to change your fee.
                        Only meaningful with --admin-token; leave unset to
                        skip issuing this narrower credential at all.
  --fee-plugin-path PATH
                        load an in-process fee-checking plugin (a shared
                        object implementing include/tradep2p/
                        fee_plugin_abi.h) at startup and poll it for every
                        pending fee, auto-confirming any it reports paid -
                        no admin-channel action needed at all. Optional;
                        leave unset to load no plugin. Fails mediator
                        startup loudly if the path is wrong or the plugin's
                        ABI doesn't match. A crashing/hanging plugin takes
                        the whole mediator process down with it - see
                        plugins/README.md before using this in production;
                        the admin-channel option above (--admin-fee-token)
                        gives an out-of-process alternative with no such
                        risk.
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
  --registry HOST:PORT registry endpoint to register with (defaults to
                        standalone/unregistered - no registry is baked in;
                        set this yourself, or leave unset to stay standalone)
  --registry-pin HEX   registry certificate SHA-256 pin (required with --registry)
  --registry-proxy HOST:PORT
                        reach --registry through this SOCKS5 proxy (e.g. a
                        local Tor daemon on 127.0.0.1:9050) instead of a
                        direct connection - required when --registry is an
                        .onion address, since a direct TCP connection to one
                        never resolves. Only the registry leg is proxied;
                        the mediator's own listener is unaffected. Leave
                        unset for a directly-reachable (non-onion) registry.
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
  --blindsig-enable    turn on the EXPERIMENTAL, UNREVIEWED post-quantum
                        blind-signature primitive (specs.txt SS9.3a). Only
                        has any effect if the binary at $CLI was itself built
                        with -DTRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL=ON - this
                        flag alone does not compile it in. Requires
                        --blindsig-keystore-file and --blindsig-prover-path.
                        You will be prompted for the keystore passphrase on
                        every start (no echo, not a flag/env var, not
                        automatable) - incompatible with fully unattended
                        restarts by design.
  --blindsig-keystore-file PATH
                        path to an EXISTING blind-signature keystore, created
                        beforehand with a separate, explicit, one-time step:
                        `tradep2p_cli blindsig-keygen PATH PASSPHRASE`. This
                        script never creates one for you - a missing file is
                        a hard startup error, not auto-provisioned the way
                        --cert/--key are. Only meaningful with
                        --blindsig-enable.
  --blindsig-prover-path PATH
                        path to the blindsig-prover sidecar binary (built
                        separately: `cd blindsig-prover && cargo build
                        --release`). Only meaningful with --blindsig-enable.
  --blindsig-queue-size N
                        how many blind-sign requests may be queued at once
                        before the signer starts replying Busy (default 8).
                        Defensive, not a proving-throughput knob - each
                        request's own mediator-side cost is fast; see
                        specs.txt SS9.3a. Only meaningful with
                        --blindsig-enable.
  --blindsig-q7933-enable
                        turn on the EXPERIMENTAL, UNREVIEWED q=7933 blind-
                        signature path. Requires
                        --blindsig-q7933-keystore-file,
                        --blindsig-q7933-prover-path, and
                        --blindsig-q7933-ticket-store-dir. You will be
                        prompted for the q7933 keystore passphrase on every
                        start.
  --blindsig-q7933-keystore-file PATH
                        path to an EXISTING q7933 blind-signature keystore,
                        created beforehand with:
                        `tradep2p_cli blindsig-q7933-keygen PATH PASSPHRASE`
  --blindsig-q7933-prover-path PATH
                        path to the blindsig-prover-q7933 sidecar binary
                        (normally `blindsig-prover-q7933/target/release/blindsig-prover-q7933`)
  --blindsig-q7933-ticket-store-dir PATH
                        directory for durable pending/signed q7933 blind-sign
                        tickets; created if needed and survives mediator
                        restart by design
  --blindsig-q7933-queue-size N
                        q7933 blind-sign request queue capacity before the
                        mediator replies Busy (default 8)
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
ADMIN_FEE_TOKEN=""
ADMIN_PORT="7444"
FEE_PLUGIN_PATH=""
AUTH_PORT=""
AUTH_KEY_FILE=""
# No hardcoded default here on purpose - this used to point at a specific
# real registry's .onion address and pin, which doesn't belong committed to
# a public repo (rotated/removed after the fact - see git history). Defaults
# to fully standalone/unregistered; pass --registry HOST:PORT and
# --registry-pin HEX yourself to register with a real registry.
REGISTRY_ENDPOINT=""
REGISTRY_PIN=""
# Default assumes a local Tor daemon's standard SOCKS port - matches
# REGISTRY_ENDPOINT above being an .onion address. Pass --registry-proxy ''
# if pointing REGISTRY_ENDPOINT at a directly-reachable (non-onion) registry
# instead.
REGISTRY_PROXY="127.0.0.1:9050"
ADVERTISED_ENDPOINT=""
DASHBOARD_PORT="8091"
RUN_DASHBOARD="1"
BLINDSIG_ENABLE="0"
BLINDSIG_KEYSTORE_FILE=""
BLINDSIG_PROVER_PATH=""
BLINDSIG_QUEUE_SIZE=""
BLINDSIG_Q7933_ENABLE="0"
BLINDSIG_Q7933_KEYSTORE_FILE=""
BLINDSIG_Q7933_PROVER_PATH=""
BLINDSIG_Q7933_TICKET_STORE_DIR=""
BLINDSIG_Q7933_QUEUE_SIZE=""

# Pre-scan for --config so it can actually select which file gets sourced
# below - the real flag-parsing loop further down runs AFTER sourcing (so
# that command-line flags still override whatever the sourced file set),
# which means, without this prescan, --config's own value would never take
# effect until one command too late. Harmless to let the main loop parse
# --config again afterward.
for (( scan = 1; scan <= $#; scan++ )); do
    if [[ "${!scan}" == "--config" ]]; then
        next=$((scan + 1))
        CONFIG_FILE="${!next}"
        break
    fi
done

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
        --admin-fee-token) ADMIN_FEE_TOKEN="$2"; shift 2 ;;
        --admin-port) ADMIN_PORT="$2"; shift 2 ;;
        --fee-plugin-path) FEE_PLUGIN_PATH="$2"; shift 2 ;;
        --auth-port) AUTH_PORT="$2"; shift 2 ;;
        --auth-key-file) AUTH_KEY_FILE="$2"; shift 2 ;;
        --registry) REGISTRY_ENDPOINT="$2"; shift 2 ;;
        --registry-pin) REGISTRY_PIN="$2"; shift 2 ;;
        --registry-proxy) REGISTRY_PROXY="$2"; shift 2 ;;
        --advertise) ADVERTISED_ENDPOINT="$2"; shift 2 ;;
        --dashboard-port) DASHBOARD_PORT="$2"; shift 2 ;;
        --no-dashboard) RUN_DASHBOARD="0"; shift ;;
        --blindsig-enable) BLINDSIG_ENABLE="1"; shift ;;
        --blindsig-keystore-file) BLINDSIG_KEYSTORE_FILE="$2"; shift 2 ;;
        --blindsig-prover-path) BLINDSIG_PROVER_PATH="$2"; shift 2 ;;
        --blindsig-queue-size) BLINDSIG_QUEUE_SIZE="$2"; shift 2 ;;
        --blindsig-q7933-enable) BLINDSIG_Q7933_ENABLE="1"; shift ;;
        --blindsig-q7933-keystore-file) BLINDSIG_Q7933_KEYSTORE_FILE="$2"; shift 2 ;;
        --blindsig-q7933-prover-path) BLINDSIG_Q7933_PROVER_PATH="$2"; shift 2 ;;
        --blindsig-q7933-ticket-store-dir) BLINDSIG_Q7933_TICKET_STORE_DIR="$2"; shift 2 ;;
        --blindsig-q7933-queue-size) BLINDSIG_Q7933_QUEUE_SIZE="$2"; shift 2 ;;
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

# Optional narrower credential for the same channel - can only list/inspect
# pending fees and confirm one, never SETFEE. Meant for an automated fee
# checker (see plugins/). Only meaningful with ADMIN_TOKEN set.
ADMIN_FEE_TOKEN="$ADMIN_FEE_TOKEN"

# Leave empty to load no in-process fee plugin (default). See
# plugins/README.md before setting this - a crashing/hanging plugin takes
# the whole mediator process down with it.
FEE_PLUGIN_PATH="$FEE_PLUGIN_PATH"

# Leave AUTH_PORT empty to disable the mediator auth control channel
# entirely (default). Unlike ADMIN_TOKEN, nothing this channel returns is
# sensitive - there is no token to keep secret here.
AUTH_PORT="$AUTH_PORT"
AUTH_KEY_FILE="$AUTH_KEY_FILE"

# Leave REGISTRY_ENDPOINT empty to run standalone, unregistered.
REGISTRY_ENDPOINT="$REGISTRY_ENDPOINT"
REGISTRY_PIN="$REGISTRY_PIN"

# Leave empty for a directly-reachable registry. Required (typically your
# local Tor daemon, e.g. 127.0.0.1:9050) when REGISTRY_ENDPOINT is an
# .onion address - a direct connection to one never resolves.
REGISTRY_PROXY="$REGISTRY_PROXY"
ADVERTISED_ENDPOINT="$ADVERTISED_ENDPOINT"

DASHBOARD_PORT="$DASHBOARD_PORT"
RUN_DASHBOARD="$RUN_DASHBOARD"

# EXPERIMENTAL, UNREVIEWED - see specs.txt SS9.3a. "1" only has any effect
# if $CLI was itself built with -DTRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL=ON.
# BLINDSIG_KEYSTORE_FILE must already exist (created separately via
# `tradep2p_cli blindsig-keygen`) - this script never creates one. The
# keystore passphrase itself is never stored here or in any env var - you
# are prompted for it, with no echo, on every start.
BLINDSIG_ENABLE="$BLINDSIG_ENABLE"
BLINDSIG_KEYSTORE_FILE="$BLINDSIG_KEYSTORE_FILE"
BLINDSIG_PROVER_PATH="$BLINDSIG_PROVER_PATH"
BLINDSIG_QUEUE_SIZE="$BLINDSIG_QUEUE_SIZE"
BLINDSIG_Q7933_ENABLE="$BLINDSIG_Q7933_ENABLE"
BLINDSIG_Q7933_KEYSTORE_FILE="$BLINDSIG_Q7933_KEYSTORE_FILE"
BLINDSIG_Q7933_PROVER_PATH="$BLINDSIG_Q7933_PROVER_PATH"
BLINDSIG_Q7933_TICKET_STORE_DIR="$BLINDSIG_Q7933_TICKET_STORE_DIR"
BLINDSIG_Q7933_QUEUE_SIZE="$BLINDSIG_Q7933_QUEUE_SIZE"
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
if [[ "$BLINDSIG_ENABLE" == "1" ]]; then
    if [[ -z "$BLINDSIG_KEYSTORE_FILE" || -z "$BLINDSIG_PROVER_PATH" ]]; then
        echo "fatal: --blindsig-enable requires --blindsig-keystore-file and --blindsig-prover-path" >&2
        exit 1
    fi
    if [[ ! -f "$BLINDSIG_KEYSTORE_FILE" ]]; then
        echo "fatal: --blindsig-keystore-file $BLINDSIG_KEYSTORE_FILE does not exist - this script never" >&2
        echo "creates one; run: tradep2p_cli blindsig-keygen $BLINDSIG_KEYSTORE_FILE PASSPHRASE" >&2
        exit 1
    fi
    if [[ ! -x "$BLINDSIG_PROVER_PATH" ]]; then
        echo "fatal: --blindsig-prover-path $BLINDSIG_PROVER_PATH is not an executable file" >&2
        exit 1
    fi
fi
if [[ "$BLINDSIG_Q7933_ENABLE" == "1" ]]; then
    if [[ -z "$BLINDSIG_Q7933_KEYSTORE_FILE" || -z "$BLINDSIG_Q7933_PROVER_PATH" || -z "$BLINDSIG_Q7933_TICKET_STORE_DIR" ]]; then
        echo "fatal: --blindsig-q7933-enable requires --blindsig-q7933-keystore-file, --blindsig-q7933-prover-path, and --blindsig-q7933-ticket-store-dir" >&2
        exit 1
    fi
    if [[ ! -f "$BLINDSIG_Q7933_KEYSTORE_FILE" ]]; then
        echo "fatal: --blindsig-q7933-keystore-file $BLINDSIG_Q7933_KEYSTORE_FILE does not exist - run: tradep2p_cli blindsig-q7933-keygen $BLINDSIG_Q7933_KEYSTORE_FILE PASSPHRASE" >&2
        exit 1
    fi
    if [[ ! -x "$BLINDSIG_Q7933_PROVER_PATH" ]]; then
        echo "fatal: --blindsig-q7933-prover-path $BLINDSIG_Q7933_PROVER_PATH is not an executable file" >&2
        exit 1
    fi
    mkdir -p "$BLINDSIG_Q7933_TICKET_STORE_DIR"
fi

DEFAULT_CLI="$ROOT/build/tradep2p_cli"
DEFAULT_DASHBOARD_BIN="$ROOT/build/tradep2p-mediator-dashboard"
if [[ -x "$ROOT/build-blns7933-root/tradep2p_cli" ]]; then
    DEFAULT_CLI="$ROOT/build-blns7933-root/tradep2p_cli"
    DEFAULT_DASHBOARD_BIN="$ROOT/build-blns7933-root/tradep2p-mediator-dashboard"
fi
CLI="${TRADEP2P_BIN:-$DEFAULT_CLI}"
DASHBOARD_BIN="${TRADEP2P_MEDIATOR_DASHBOARD_BIN:-$DEFAULT_DASHBOARD_BIN}"
if [[ ! -x "$CLI" || ( "$RUN_DASHBOARD" == "1" && ! -x "$DASHBOARD_BIN" ) ]]; then
    echo "building the project (first run only)..."
    "$ROOT/scripts/build.sh"
fi
if [[ "$BLINDSIG_Q7933_ENABLE" == "1" ]]; then
    CLI_USAGE="$("$CLI" 2>&1 || true)"
    if ! grep -q "blindsig-q7933-keygen" <<<"$CLI_USAGE"; then
        echo "fatal: selected mediator binary does not include q7933 experimental support: $CLI" >&2
        echo "build and use the q7933-enabled output (e.g. build-blns7933-root/tradep2p_cli)" >&2
        exit 1
    fi
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
    if [[ -n "$ADMIN_FEE_TOKEN" ]]; then
        echo "                     + scoped fee-only token (LISTPENDINGFEES/FEEDETAILS/CONFIRMFEE only)"
    fi
fi
if [[ -n "$FEE_PLUGIN_PATH" ]]; then
    echo "  fee plugin:        $FEE_PLUGIN_PATH (in-process, polling pending fees)"
fi
if [[ -n "$AUTH_PORT" ]]; then
    echo "  mediator auth:     ${MEDIATOR_BIND%:*}:$AUTH_PORT (unauthenticated, see --auth-port)"
fi
if [[ "$BLINDSIG_ENABLE" == "1" ]]; then
    echo "  blind-sig (EXPERIMENTAL, unreviewed): enabled, prover at $BLINDSIG_PROVER_PATH"
    echo "                     see specs.txt SS9.3a - you will be prompted for the keystore"
    echo "                     passphrase below (no echo)"
fi
if [[ "$BLINDSIG_Q7933_ENABLE" == "1" ]]; then
    echo "  q7933 blind-sig (EXPERIMENTAL, unreviewed): enabled, prover at $BLINDSIG_Q7933_PROVER_PATH"
    echo "                     ticket store: $BLINDSIG_Q7933_TICKET_STORE_DIR"
    echo "                     operator actions available through the dashboard/admin channel"
    echo "                     you will be prompted for the q7933 keystore passphrase below"
fi
if [[ -n "$REGISTRY_ENDPOINT" ]]; then
    if [[ -n "$REGISTRY_PROXY" ]]; then
        echo "  registry:          $REGISTRY_ENDPOINT via SOCKS5 $REGISTRY_PROXY (advertising ${ADVERTISED_ENDPOINT:-$MEDIATOR_BIND})"
    else
        echo "  registry:          $REGISTRY_ENDPOINT (advertising ${ADVERTISED_ENDPOINT:-$MEDIATOR_BIND})"
    fi
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
    if [[ -n "$ADMIN_FEE_TOKEN" ]]; then
        export TRADEP2P_ADMIN_FEE_TOKEN="$ADMIN_FEE_TOKEN"
    fi
fi
if [[ -n "$FEE_PLUGIN_PATH" ]]; then
    export TRADEP2P_FEE_PLUGIN_PATH="$FEE_PLUGIN_PATH"
fi
if [[ -n "$AUTH_PORT" ]]; then
    export TRADEP2P_MEDIATOR_AUTH_PORT="$AUTH_PORT"
    if [[ -n "$AUTH_KEY_FILE" ]]; then
        export TRADEP2P_MEDIATOR_AUTH_KEY_FILE="$AUTH_KEY_FILE"
    fi
fi
if [[ "$BLINDSIG_ENABLE" == "1" ]]; then
    export TRADEP2P_BLINDSIG_ENABLE="1"
    export TRADEP2P_BLINDSIG_KEYSTORE_FILE="$BLINDSIG_KEYSTORE_FILE"
    export TRADEP2P_BLINDSIG_PROVER_PATH="$BLINDSIG_PROVER_PATH"
    if [[ -n "$BLINDSIG_QUEUE_SIZE" ]]; then
        export TRADEP2P_BLINDSIG_QUEUE_SIZE="$BLINDSIG_QUEUE_SIZE"
    fi
fi
if [[ "$BLINDSIG_Q7933_ENABLE" == "1" ]]; then
    export TRADEP2P_BLINDSIG_Q7933_ENABLE="1"
    export TRADEP2P_BLINDSIG_Q7933_KEYSTORE_FILE="$BLINDSIG_Q7933_KEYSTORE_FILE"
    export TRADEP2P_BLINDSIG_Q7933_PROVER_PATH="$BLINDSIG_Q7933_PROVER_PATH"
    export TRADEP2P_BLINDSIG_Q7933_TICKET_STORE_DIR="$BLINDSIG_Q7933_TICKET_STORE_DIR"
    if [[ -n "$BLINDSIG_Q7933_QUEUE_SIZE" ]]; then
        export TRADEP2P_BLINDSIG_Q7933_QUEUE_SIZE="$BLINDSIG_Q7933_QUEUE_SIZE"
    fi
fi

if [[ -n "$REGISTRY_ENDPOINT" && -n "$REGISTRY_PROXY" ]]; then
    exec "$CLI" mediator-registered-tor "$REGISTRY_PROXY" \
        "$MEDIATOR_BIND" "$MEDIATOR_CERT" "$MEDIATOR_KEY" \
        "$REGISTRY_ENDPOINT" "$REGISTRY_PIN" \
        "${ADVERTISED_ENDPOINT:-$MEDIATOR_BIND}" "$CERT_PIN"
elif [[ -n "$REGISTRY_ENDPOINT" ]]; then
    exec "$CLI" mediator-registered "$MEDIATOR_BIND" "$MEDIATOR_CERT" "$MEDIATOR_KEY" \
        "$REGISTRY_ENDPOINT" "$REGISTRY_PIN" \
        "${ADVERTISED_ENDPOINT:-$MEDIATOR_BIND}" "$CERT_PIN"
else
    exec "$CLI" mediator "$MEDIATOR_BIND" "$MEDIATOR_CERT" "$MEDIATOR_KEY"
fi
