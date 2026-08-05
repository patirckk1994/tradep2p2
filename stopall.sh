#!/usr/bin/env bash
# Stops every TradeP2P process started from this checkout: the mediator, the
# registry, and all four HTTP dashboards/clients (mediator dashboard, registry
# dashboard, trading dashboard, public web client). Matches by each process's
# resolved executable (/proc/PID/exe), not by command-line text, so it finds
# processes started with a relative path just as reliably as an absolute one,
# and cannot touch anything outside this checkout's build/ directory. Does
# not touch Apache, PHP dev servers, or anything under htdocs/ — those are
# managed separately from your web server, not this repo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="$ROOT/build"

# tradep2p_cli is one binary shared by several subcommands; only the
# long-running server modes are in scope here, not an interactive `client`
# session someone may have open in another terminal.
CLI_SERVER_MODES=("mediator" "mediator-registered" "registry")

resolved_exe() {
    # A process whose on-disk binary was replaced by a later rebuild (while it
    # kept running off the old, now-unlinked inode) shows up here with a
    # trailing " (deleted)" — strip it so such processes still match.
    local path
    path="$(readlink -f "/proc/$1/exe" 2>/dev/null || true)"
    echo "${path% (deleted)}"
}

collect_matches() {
    # Prints "pid label" lines, one per matching process, for a given binary.
    local binary_path="$1" label="$2"
    local pid
    for pid in $(pgrep -f -- "$(basename "$binary_path")" 2>/dev/null || true); do
        [[ "$(resolved_exe "$pid")" == "$binary_path" ]] || continue
        echo "$pid $label"
    done
}

targets=()

while read -r pid label; do
    [[ -z "${pid:-}" ]] && continue
    targets+=("$pid|$label")
done < <(collect_matches "$BUILD/tradep2p-mediator-dashboard" "mediator dashboard")

while read -r pid label; do
    [[ -z "${pid:-}" ]] && continue
    targets+=("$pid|$label")
done < <(collect_matches "$BUILD/tradep2p-registry-dashboard" "registry dashboard")

while read -r pid label; do
    [[ -z "${pid:-}" ]] && continue
    targets+=("$pid|$label")
done < <(collect_matches "$BUILD/tradep2p-dashboard" "trading dashboard")

while read -r pid label; do
    [[ -z "${pid:-}" ]] && continue
    targets+=("$pid|$label")
done < <(collect_matches "$BUILD/tradep2p-webclient" "web client")

for pid in $(pgrep -f -- "tradep2p_cli" 2>/dev/null || true); do
    [[ "$(resolved_exe "$pid")" == "$BUILD/tradep2p_cli" ]] || continue
    mode="$(tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | sed -n '2p')"
    for allowed in "${CLI_SERVER_MODES[@]}"; do
        if [[ "$mode" == "$allowed" ]]; then
            targets+=("$pid|tradep2p_cli $mode")
            break
        fi
    done
done

if [[ "${#targets[@]}" -eq 0 ]]; then
    echo "nothing from this checkout appears to be running."
    exit 0
fi

for entry in "${targets[@]}"; do
    pid="${entry%%|*}"
    label="${entry#*|}"
    echo "stopping [$label] pid $pid"
    kill -TERM "$pid" 2>/dev/null || true
done

sleep 1.5

remaining=0
for entry in "${targets[@]}"; do
    pid="${entry%%|*}"
    label="${entry#*|}"
    if kill -0 "$pid" 2>/dev/null; then
        echo "still running, sending SIGKILL: [$label] pid $pid"
        kill -KILL "$pid" 2>/dev/null || true
        remaining=1
    fi
done

if [[ "$remaining" -eq 0 ]]; then
    echo "all stopped cleanly."
else
    echo "some processes needed SIGKILL; re-run this script to confirm they're gone."
fi
