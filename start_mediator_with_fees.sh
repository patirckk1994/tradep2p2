#!/usr/bin/env bash
# Convenience wrapper around setup_mediator.sh that always adds
# --fee-require-confirmation: the fee leg blocks until you explicitly
# confirm receipt (via the admin page's "Confirm fee received" or the
# admin channel's CONFIRMFEE command) instead of completing on the payer's
# own "I sent it" claim. Fee terms themselves still come from
# mediator.conf / --fee-asset / --fee-amount / --fee-address as usual -
# this only changes whether that leg auto-completes.
#
# Every other setup_mediator.sh flag (--bind, --advertise, --admin-token,
# --registry, ...) passes through unchanged - see ./setup_mediator.sh --help.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$ROOT/setup_mediator.sh" --fee-require-confirmation "$@"
