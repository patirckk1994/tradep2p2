# Fee-checking plugins

The mediator's fee leg is honor-based by default: a payer reports "sent"
and, unless the operator opted into `--fee-require-confirmation`, the room
completes on that claim alone (see `specs.txt` §2.1 - the mediator never
inspects a chain, never validates an address format, and never confirms
that value actually moved). With `--fee-require-confirmation` set, a room
instead parks in `WaitingForFeeConfirmation` until something explicitly
confirms it - by default, that "something" is a human operator typing
`CONFIRMFEE` at the admin channel after checking a block explorer
themselves.

This directory is about automating that human step. Two independent,
both-optional ways to do it - use either, both, or neither:

- **Mode A (daemon / out-of-process)** - a separate process (any language,
  any chain-RPC library you like) drives the mediator's existing
  loopback-only admin control channel over plain TCP.
- **Mode B (in-process / dlopen)** - a small C shared object, loaded
  directly into the mediator process, polled on a dedicated thread.

Neither mode changes the mediator's core honesty: **it still performs zero
chain inspection of its own.** All verification logic lives entirely
outside its trust-minimized core, in whatever plugin you write or run. A
plugin's confirmation is exactly as trusted as a human operator's
`CONFIRMFEE` was - no more, no less. Clients still cannot independently
verify a fee was paid; they can only trust that the operator (human or
automated) asserts it was.

## Mode A: admin-channel protocol

Requires the mediator started with `--admin-token` (or
`TRADEP2P_ADMIN_TOKEN`) set - see `setup_mediator.sh --help`. The channel
binds to `127.0.0.1` only, so your plugin process must run on the
mediator's own host (or reach it via an SSH tunnel/similar - the mediator
itself never listens beyond loopback).

Optionally, set `--admin-fee-token` (`TRADEP2P_ADMIN_FEE_TOKEN`) to a
second, separate secret and hand *that* to your plugin instead of the full
admin token. A connection authenticating with the scoped fee token can
only call `LISTPENDINGFEES`, `FEEDETAILS`, and `CONFIRMFEE` - `SETFEE` and
everything else is rejected. This means a compromised or buggy plugin can
at worst confirm fees early or fail to confirm a legitimate one; it can
never rewrite your fee configuration. Recommended over reusing the full
admin token for anything that isn't a trusted human.

Protocol: connect via TCP to `127.0.0.1:<admin-port>` (default 7444), send
one line, read one line back. Every request line starts with the command
name and your token; every response line starts with `OK` or `ERR`.

```
LISTPENDINGFEES <token>
  -> OK NONE
  -> OK <room_id_hex>[,<room_id_hex>...]

FEEDETAILS <token> <room_id_hex>
  -> OK <asset> <amount> <address> <since_unix_ts>
  -> ERR no room with that id is waiting for fee confirmation

CONFIRMFEE <token> <room_id_hex>
  -> OK
  -> ERR no room with that id is waiting for fee confirmation
```

A typical plugin loop:

1. `LISTPENDINGFEES` - get every room currently waiting on its fee.
2. `FEEDETAILS <room_id>` for each - get that room's own frozen fee terms
   (`asset`, `amount`, `address`) and the unix timestamp it started
   waiting at. Fee terms are frozen per-room at creation time, not the
   mediator's current live-configured fee (which can change under
   `SETFEE` between a room's creation and its fee leg becoming due) - use
   the value `FEEDETAILS` gives you, not whatever you last saw from
   `GETFEE`.
3. Check, by whatever chain-specific means you trust, whether `amount` of
   `asset` has arrived at `address` since `since_unix_ts`.
4. `CONFIRMFEE <room_id>` on a match.
5. Sleep, repeat. `CONFIRMFEE` on a room that already completed or was
   never pending simply returns `ERR` - safe to call speculatively, no
   special handling needed for a race against another confirmation path.

`FEEDETAILS`/`CONFIRMFEE`/`LISTPENDINGFEES` are ordinary line-based TCP -
any language can drive this without a client library.

## Mode B: in-process ABI (`dlopen`)

Requires the mediator built and run with `--fee-plugin-path PATH`
(`TRADEP2P_FEE_PLUGIN_PATH`) pointing at a shared object (`.so`) that
implements `include/tradep2p/fee_plugin_abi.h`. Plain C, not C++ - C++ has
no stable ABI across independently built shared objects, so the header
only requires two `extern "C"` symbols:

```c
int tradep2p_fee_plugin_abi_version(void);      // must equal TRADEP2P_FEE_PLUGIN_ABI_VERSION
int tradep2p_fee_plugin_check(const tradep2p_fee_check_request*); // 1=paid, 0=not yet, -1=error
```

At startup the mediator `dlopen()`s the path, resolves both symbols, and
checks the reported ABI version - any failure (bad path, missing symbol,
version mismatch) **aborts mediator startup with an error**, rather than
silently running with no plugin loaded. Once loaded, a dedicated thread
polls every pending fee every few seconds, builds a
`tradep2p_fee_check_request` from that room's own frozen fee terms (same
data `FEEDETAILS` exposes in Mode A), and calls
`tradep2p_fee_plugin_check()`. A `1` result confirms the room exactly as
an operator typing `CONFIRMFEE` would.

**Read this before choosing Mode B over Mode A:** the plugin runs on the
mediator's own thread, in the mediator's own address space. A crash, an
unhandled exception unwinding across the C boundary, or a hang inside your
`tradep2p_fee_plugin_check()` takes the *entire mediator process* down or
stalls it - not just fee confirmation. This is an inherent cost of
in-process loading (the same trade-off nginx/Apache/Postgres modules
accept), not a bug to work around. If you want process isolation - a
crashing checker that only stops *fee confirmation*, never the mediator
itself - use Mode A instead.

No example plugin implementation ships in this repo: real chain-RPC
verification logic is chain-specific and security-sensitive, and this
project has no basis to guess at it correctly on your behalf. Both modes
above give you everything needed to write your own from scratch.
