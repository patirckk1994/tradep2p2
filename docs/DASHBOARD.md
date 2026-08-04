# TradeP2P lobby dashboard

## Architecture

The dashboard executable contains two local-facing pieces:

1. a persistent anonymous TradeP2P protocol client connected to the mediator
   through the existing pinned TLS or SOCKS5/Tor transport;
2. a loopback HTTP server that renders the browser interface and accepts local
   form actions.

The browser does not speak the TradeP2P binary protocol directly. HTTP actions
are validated, encoded as normal protocol messages and placed on a queue. One
worker thread owns the `SecureChannel`, which avoids concurrent TLS reads and
writes from HTTP handler threads.

## Browser actions

| Browser action | Protocol message |
| --- | --- |
| Refresh offers | `ListOffers` |
| Publish offer | `CreateOffer` |
| Join offer | `JoinOffer` |
| Cancel offer | `CancelOffer` |
| I sent it | `Sent` |
| I verified receipt | `Received` |
| Abort room | `Abort` |

The `Sent` and `Received` buttons are shown according to the current `Turn`
message and the party assigned by `TradeReady`. A wrong action is rejected
locally before a protocol frame is queued, and the mediator still validates the
state transition independently.

## Client state

The dashboard keeps connection-scoped state for:

- anonymous client ID;
- currently visible public offers;
- rooms joined or created during the current connection;
- assigned party and peer handle;
- receive addresses exchanged when a room becomes active;
- current turn, amount, asset and destination;
- completed or aborted status;
- recent local and mediator events.

A reconnect creates a new anonymous client ID. Old rooms are cleared because
the protocol currently has no resume token or persistent client identity.

## Mediator snapshot

Set this before starting `tradep2p_cli mediator`:

```sh
export TRADEP2P_LOBBY_STATE_FILE="$PWD/logs/lobby-state.json"
```

The lobby writes the file atomically about once per second. It contains:

- bind endpoint;
- connected-client count;
- pending-invitation count;
- public open-offer IDs and terms;
- active room IDs, terms, state, current round and current sender.

It does **not** contain receive addresses or client IDs. The snapshot is a local
operator view, not a new network endpoint and not part of the peer protocol.

Pass the same file to the dashboard:

```sh
./build/tradep2p-dashboard client \
  127.0.0.1:7443 MEDIATOR_PIN \
  --server-state "$PWD/logs/lobby-state.json"
```

## HTTP security boundary

The dashboard defaults to:

```text
127.0.0.1:8080
```

State-changing requests require a random token embedded in the page served by
that dashboard process. The response also sets `X-Frame-Options: DENY`, a
restrictive content-security policy and `Cache-Control: no-store`.

This is still an administration interface. Keep it on loopback or put a
separately authenticated reverse proxy in front of it. Do not use
`--listen 0.0.0.0` casually.

## Test scripts

```sh
./scripts/dashboard_two_client_demo.sh
```

Starts one mediator and two dashboards for a manual trade.

```sh
./scripts/dashboard_api_test.sh
```

Starts one mediator and two dashboard clients, publishes and joins an offer,
and drives the fractional `sent`/`received` sequence through the HTTP API.

The scripts generate temporary one-day test certificates and write all output
under `test-output/`.
