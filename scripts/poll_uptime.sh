#!/usr/bin/env bash
# Appends one up/down sample per configured service to a small TSV log,
# meant to be run periodically (cron) rather than continuously. Liveness is
# a raw TCP connect to each service's own port - deliberately not a full
# TradeP2P/TLS handshake, matching how most uptime monitors define "up":
# something is listening and accepting connections, not a full protocol
# round-trip. Never touches the registry/mediator's own state - purely an
# external observer.
#
# Usage: poll_uptime.sh <log-file> <name>:<host>:<port> [<name>:<host>:<port> ...]
# Example:
#   poll_uptime.sh /path/to/uptime.log registry:127.0.0.1:7555 mediator:127.0.0.1:7443
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <log-file> <name>:<host>:<port> [...]" >&2
    exit 1
fi

LOG_FILE="$1"
shift

now="$(date +%s)"

for target in "$@"; do
    name="${target%%:*}"
    rest="${target#*:}"
    host="${rest%%:*}"
    port="${rest##*:}"

    if timeout 5 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
        status="up"
        exec 3>&- 2>/dev/null || true
    else
        status="down"
    fi

    printf '%s\t%s\t%s\n' "$now" "$name" "$status" >> "$LOG_FILE"
done
