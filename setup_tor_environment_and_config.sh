#!/usr/bin/env bash
# Ensures every TradeP2P service that should be reachable over Tor actually
# has a hidden service mapping in /etc/tor/torrc, then reloads Tor and
# reports back the resulting .onion addresses. Written because hosted
# trading (tradep2p-webclient) was rebuilt and re-enabled with NO hidden
# service of its own - its old onion address was repurposed to the registry
# when hosted trading was retired (see the "Registry ... Repurposed from the
# old hosted-trading hidden service" comment already in torrc), and nothing
# ever gave it a replacement. Confirmed by hand: the mediator and registry
# onion services both complete a real TLS handshake through Tor right now;
# the webclient has no HiddenServicePort anywhere and cannot be reached at
# any address.
#
# Idempotent and additive only: existing HiddenServiceDir/HiddenServicePort
# blocks are never touched, only missing ones are appended. Safe to re-run.
#
# This script deliberately does NOT edit any website config.php - same
# policy deploy.sh already states for itself ("Deliberately does NOT touch
# either side's config.php"). It only reports the onion addresses; apply
# them to registry_onion_url/mediator_onion_url/hosted_trading_onion_url
# yourself once you've looked at them.
#
# Must run as root (torrc lives under /etc, hidden service keys under
# /var/lib/tor are owned by debian-tor).
set -euo pipefail

print_usage() {
    cat <<'EOF'
Usage: sudo ./setup_tor_environment_and_config.sh [options]

Options:
  --torrc PATH            path to torrc (default /etc/tor/torrc)
  --webclient-port N      local port tradep2p-webclient listens on (default
                           8090, matches deploy.sh's production launch)
  --webclient-hs-port N   external hidden-service port for the webclient,
                           i.e. what visitors' URLs look like: http://x.onion:N/
                           (default 80, so the address needs no port suffix)
  --mediator-port N       local/external port for the mediator hidden
                           service (default 7443, only used if that block is
                           missing entirely - an existing one is never
                           touched)
  --registry-port N       local/external port for the registry hidden
                           service (default 7555, same "only if missing" rule)
  --mainsite-port N       local/external port for the main PHP site's hidden
                           service (default 80, same "only if missing" rule)
  --dry-run               print what would be added to torrc, change nothing
  --skip-reachability-test
                           skip the end-of-script SOCKS5 reachability check
                           (it can take 20-60s per service the first time a
                           hidden service descriptor needs to propagate)
  -h, --help               show this help

Run this after any change to which local ports the mediator/registry/
webclient/mainsite actually listen on, or after adding a new one of these
services for the first time. Re-running when everything is already correct
is a no-op other than the reachability test.
EOF
}

TORRC="/etc/tor/torrc"
WEBCLIENT_PORT="8090"
WEBCLIENT_HS_PORT="80"
MEDIATOR_PORT="7443"
REGISTRY_PORT="7555"
MAINSITE_PORT="80"
DRY_RUN="0"
SKIP_REACHABILITY="0"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --torrc) TORRC="$2"; shift 2 ;;
        --webclient-port) WEBCLIENT_PORT="$2"; shift 2 ;;
        --webclient-hs-port) WEBCLIENT_HS_PORT="$2"; shift 2 ;;
        --mediator-port) MEDIATOR_PORT="$2"; shift 2 ;;
        --registry-port) REGISTRY_PORT="$2"; shift 2 ;;
        --mainsite-port) MAINSITE_PORT="$2"; shift 2 ;;
        --dry-run) DRY_RUN="1"; shift ;;
        --skip-reachability-test) SKIP_REACHABILITY="1"; shift ;;
        -h|--help) print_usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; print_usage; exit 1 ;;
    esac
done

log() { echo "==> $*"; }
fail() { echo "FATAL: $*" >&2; exit 1; }

if [[ "$DRY_RUN" != "1" && "$EUID" -ne 0 ]]; then
    fail "must run as root (sudo ./setup_tor_environment_and_config.sh ...) - torrc and /var/lib/tor need root, except with --dry-run"
fi

[[ -f "$TORRC" ]] || fail "torrc not found at $TORRC"
command -v tor >/dev/null 2>&1 || fail "tor is not installed (or not on PATH)"

# has_hidden_service_dir DIR - true if torrc already has this exact
# "HiddenServiceDir DIR" line (with or without trailing slash variance),
# meaning some HiddenServicePort block for it already exists and must not
# be duplicated or altered.
has_hidden_service_dir() {
    local dir="$1"
    grep -qE "^[[:space:]]*HiddenServiceDir[[:space:]]+${dir%/}/?[[:space:]]*$" "$TORRC"
}

ADDITIONS=""
append_block() {
    # append_block COMMENT DIR PORT_LINES...
    local comment="$1" dir="$2"
    shift 2
    local block
    block="$(printf '\n# %s\nHiddenServiceDir %s\n' "$comment" "$dir")"
    for port_line in "$@"; do
        block+="$(printf '\nHiddenServicePort %s' "$port_line")"
    done
    block+=$'\n'
    ADDITIONS+="$block"
}

log "checking existing torrc ($TORRC) for the four TradeP2P hidden services ..."

if has_hidden_service_dir "/var/lib/tor/tradep2p-mediator/"; then
    echo "  mediator:   already present, leaving untouched"
else
    echo "  mediator:   MISSING - will add (127.0.0.1:$MEDIATOR_PORT)"
    append_block "Mediator (tradep2p_cli mediator/mediator-registered mode)." \
        "/var/lib/tor/tradep2p-mediator/" "$MEDIATOR_PORT 127.0.0.1:$MEDIATOR_PORT"
fi

if has_hidden_service_dir "/var/lib/tor/tradep2p-trading/"; then
    echo "  registry:   already present, leaving untouched"
else
    echo "  registry:   MISSING - will add (127.0.0.1:$REGISTRY_PORT)"
    append_block "Registry (tradep2p_cli registry mode)." \
        "/var/lib/tor/tradep2p-trading/" "$REGISTRY_PORT 127.0.0.1:$REGISTRY_PORT"
fi

if has_hidden_service_dir "/var/lib/tor/tradep2p-mainsite/"; then
    echo "  mainsite:   already present, leaving untouched"
else
    echo "  mainsite:   MISSING - will add (127.0.0.1:$MAINSITE_PORT)"
    append_block "Main PHP site (Apache)." \
        "/var/lib/tor/tradep2p-mainsite/" "$MAINSITE_PORT 127.0.0.1:$MAINSITE_PORT"
fi

if has_hidden_service_dir "/var/lib/tor/tradep2p-webclient/"; then
    echo "  webclient:  already present, leaving untouched"
else
    echo "  webclient:  MISSING - will add (127.0.0.1:$WEBCLIENT_PORT, external port $WEBCLIENT_HS_PORT)"
    append_block "Hosted trading (tradep2p-webclient) - added by setup_tor_environment_and_config.sh, this service previously had no hidden service of its own after its original onion address was repurposed to the registry above." \
        "/var/lib/tor/tradep2p-webclient/" "$WEBCLIENT_HS_PORT 127.0.0.1:$WEBCLIENT_PORT"
fi

if [[ -z "$ADDITIONS" ]]; then
    log "torrc already has all four hidden services configured - nothing to add."
else
    if [[ "$DRY_RUN" == "1" ]]; then
        log "dry run - would append the following to $TORRC:"
        echo "$ADDITIONS"
        exit 0
    fi

    log "backing up $TORRC ..."
    BACKUP="$TORRC.bak.$(date +%Y%m%d%H%M%S)"
    cp "$TORRC" "$BACKUP"
    echo "  backup at $BACKUP"

    log "appending missing hidden service block(s) ..."
    printf '%s' "$ADDITIONS" >> "$TORRC"

    # tor --verify-config also checks that every EXISTING HiddenServiceDir in
    # torrc is owned by the user it's about to run as. Run as plain root (as
    # this script itself is), that check fails against dirs already owned by
    # whatever user actually runs the tor daemon (debian-tor on Debian/
    # Ubuntu) - not a real problem, just the wrong invocation. Systemd itself
    # never hits this because tor@default.service's own User= directive
    # drops privileges before tor ever runs. Derive the right user from an
    # already-correctly-owned existing hidden service dir rather than
    # hardcoding "debian-tor", so this still works if that ever differs.
    TOR_USER="$(stat -c '%U' /var/lib/tor/tradep2p-mediator 2>/dev/null || echo debian-tor)"
    log "validating torrc with tor --verify-config (as $TOR_USER) ..."
    if ! sudo -u "$TOR_USER" tor --verify-config -f "$TORRC" >/tmp/tor-verify-config.log 2>&1; then
        cat /tmp/tor-verify-config.log >&2
        cp "$BACKUP" "$TORRC"
        fail "torrc failed validation - restored from backup, nothing was applied. See /tmp/tor-verify-config.log"
    fi
    echo "  torrc is valid"
fi

if [[ "$DRY_RUN" == "1" ]]; then
    exit 0
fi

if [[ -n "$ADDITIONS" ]]; then
    log "reloading tor ..."
    if systemctl reload tor@default 2>/dev/null; then
        :
    elif systemctl reload tor 2>/dev/null; then
        :
    else
        fail "could not reload tor via systemctl (tried tor@default and tor) - reload it manually, then re-run this script to see the resulting addresses"
    fi

    log "waiting for new hidden service key(s)/hostname(s) to be generated ..."
    for dir in tradep2p-mediator tradep2p-trading tradep2p-mainsite tradep2p-webclient; do
        path="/var/lib/tor/$dir/hostname"
        [[ -f "$path" ]] && continue
        waited=0
        while [[ ! -f "$path" && $waited -lt 30 ]]; do
            sleep 1
            waited=$((waited + 1))
        done
    done
fi

log "current onion addresses:"
for dir in tradep2p-mediator tradep2p-trading tradep2p-mainsite tradep2p-webclient; do
    path="/var/lib/tor/$dir/hostname"
    if [[ -r "$path" ]]; then
        echo "  $dir: $(cat "$path")"
    else
        echo "  $dir: (hostname file not readable yet - re-run this script in a few seconds, or check journalctl -u tor@default)"
    fi
done
echo "  Apply the ones you need to config.php's registry_onion_url /"
echo "  mediator_onion_url / hosted_trading_onion_url yourself - this script"
echo "  deliberately never edits config.php (same policy deploy.sh states for"
echo "  itself)."

if [[ "$SKIP_REACHABILITY" == "1" ]]; then
    exit 0
fi

if ! command -v curl >/dev/null 2>&1; then
    log "curl not found - skipping reachability test"
    exit 0
fi

log "reachability test through the local Tor SOCKS proxy (127.0.0.1:9050) - each can take up to a minute the first time ..."
test_tls_reachable() {
    local host_port="$1"
    # Captured into a variable rather than piped straight into grep -q: with
    # `set -o pipefail` (on for this whole script), grep -q closing its
    # stdin the instant it finds a match can SIGPIPE curl before curl exits
    # cleanly, which then makes the *pipeline's* exit status curl's
    # non-zero one instead of grep's success - a false "not reachable" even
    # though the match was genuinely found. Capturing first sidesteps that:
    # curl always runs to completion (or its own timeout) before grep ever
    # sees the output.
    # These services speak a custom binary protocol, not HTTP, so curl's
    # response body after the handshake is raw protocol bytes and can
    # contain NUL bytes - stripped here to avoid bash's harmless but noisy
    # "NULL byte in input ignored" warning on the command substitution.
    local output
    output="$(timeout 60 curl -sv --socks5-hostname 127.0.0.1:9050 -k "https://$host_port/" 2>&1 | tr -d '\0' || true)"
    grep -q "SSL connection using" <<<"$output"
}
test_http_reachable() {
    local url="$1"
    [[ "$(timeout 60 curl -s --socks5-hostname 127.0.0.1:9050 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)" != "000" ]]
}

for dir_port in "tradep2p-mediator:$MEDIATOR_PORT:tls" "tradep2p-trading:$REGISTRY_PORT:tls"; do
    IFS=: read -r dir port kind <<<"$dir_port"
    hostname_file="/var/lib/tor/$dir/hostname"
    [[ -r "$hostname_file" ]] || { echo "  $dir: skipped (no hostname file)"; continue; }
    onion="$(cat "$hostname_file")"
    if test_tls_reachable "$onion:$port"; then
        echo "  $dir ($onion:$port): OK - TLS handshake completed"
    else
        echo "  $dir ($onion:$port): NOT REACHABLE - check the local service is actually running on 127.0.0.1:$port"
    fi
done

mainsite_hostname_file="/var/lib/tor/tradep2p-mainsite/hostname"
if [[ -r "$mainsite_hostname_file" ]]; then
    onion="$(cat "$mainsite_hostname_file")"
    if test_http_reachable "http://$onion:$MAINSITE_PORT/"; then
        echo "  tradep2p-mainsite ($onion): OK - HTTP reachable"
    else
        echo "  tradep2p-mainsite ($onion): NOT REACHABLE - check Apache is running and DocumentRoot is correct"
    fi
fi

webclient_hostname_file="/var/lib/tor/tradep2p-webclient/hostname"
if [[ -r "$webclient_hostname_file" ]]; then
    onion="$(cat "$webclient_hostname_file")"
    if test_http_reachable "http://$onion:$WEBCLIENT_HS_PORT/"; then
        echo "  tradep2p-webclient ($onion): OK - HTTP reachable"
    else
        echo "  tradep2p-webclient ($onion): NOT REACHABLE - check tradep2p-webclient is actually running on 127.0.0.1:$WEBCLIENT_PORT"
    fi
fi

log "done."
