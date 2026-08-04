# TradeP2P Minimal v0.6.1

Minimal anonymous offer-room mediator for progressive fractional peer-to-peer
settlement, now with an interactive local HTTP dashboard.

## Core model

Each published offer is also a waiting lobby. It records only:

- the asset and integer amount the creator sells;
- the asset and integer amount the creator buys;
- the number of fractional settlement rounds;
- the creator's opaque receive address.

Other clients list open offers and take one by room ID. The joining client then
provides its own opaque receive address. The same room becomes an active
fractional-settlement session.

The mediator does not create, inspect, verify, search, confirm or store
cryptocurrency transactions. Transfers happen externally. It coordinates only
`sent` and `received` acknowledgements.

## Interactive HTTP dashboard

`tradep2p-dashboard` is a real anonymous lobby client, not merely a log viewer.
From the browser you can:

- publish offers;
- refresh and browse open lobbies;
- join an offer with your receiving address;
- cancel your own waiting offer;
- see active settlement rooms and the current fractional turn;
- mark a transfer as externally sent;
- mark a transfer as externally verified and received;
- abort a room;
- see a local event stream;
- optionally see privacy-reduced mediator metrics and active-room state.

The dashboard binds to `127.0.0.1` by default and uses a random per-process
request token for state-changing HTTP calls. Do not expose it directly to the
public Internet.

### Start a local mediator and dashboard

Generate a certificate and its SHA-256 pin, then start the mediator with a
local state snapshot:

```sh
export TRADEP2P_LOBBY_STATE_FILE="$PWD/logs/lobby-state.json"
./build/tradep2p_cli mediator \
  127.0.0.1:7443 mediator.cert.pem mediator.key.pem
```

In another terminal:

```sh
./build/tradep2p-dashboard client \
  127.0.0.1:7443 MEDIATOR_CERT_SHA256 \
  --port 8080 \
  --server-state "$PWD/logs/lobby-state.json"
```

Open:

```text
http://127.0.0.1:8080
```

Through Tor:

```sh
./build/tradep2p-dashboard client-tor \
  127.0.0.1:9050 examplehiddenservice.onion:7443 MEDIATOR_CERT_SHA256 \
  --port 8080
```

The optional mediator snapshot contains counts, public offer terms, active room
IDs, round number and state. It deliberately omits client IDs and receiving
addresses. More detail is in [`docs/DASHBOARD.md`](docs/DASHBOARD.md).

## Terminal commands

Publish an offer lobby:

```text
/offer SELL_SYMBOL SELL_AMOUNT BUY_SYMBOL BUY_AMOUNT ROUNDS RECEIVE_ADDRESS
```

Example:

```text
/offer QRL 500000 BTC 100000 10 bc1-my-bitcoin-address
```

List open offers:

```text
/offers
```

Take an offer and provide the address where you receive the creator's sell
asset:

```text
/join ROOM_ID q1-my-qrl-address
```

Cancel an offer that has not been taken:

```text
/cancel ROOM_ID
```

During settlement:

```text
/sent ROOM_ID
/received ROOM_ID
/abort ROOM_ID
```

There is no chat and no direct invitation system in the normal client workflow.

## Address transmission

Addresses are opaque strings:

- 1 to 256 bytes;
- printable ASCII;
- no spaces or control characters;
- length-prefixed;
- never silently truncated;
- transmitted inside pinned TLS 1.3.

The mediator does not identify the chain or validate an address format.
Addresses are not shown in the public offer list. They are exchanged only when
an offer is taken and the active room begins.

## Transport hardening

- TLS 1.3 only;
- exact SHA-256 server-certificate pin required by clients;
- no client certificate, account or user authentication;
- 20-byte fixed frame header;
- 4 KiB hard payload limit;
- exact-length reads and writes;
- monotonic per-direction frame sequence numbers;
- replay and out-of-order rejection;
- strict binary decoding;
- truncated and trailing message data rejected;
- optional SOCKS5 transport for Tor onion endpoints.

## Semi-centralized node registry

The optional registry is a short-lived directory of mediator endpoints. Its IP
or hostname is supplied through the command line. Registrations expire after
300 seconds. Every listed mediator carries its own SHA-256 certificate pin,
which clients still verify when connecting.

Start a registry:

```sh
./build/tradep2p_cli registry 0.0.0.0:7555 registry.cert.pem registry.key.pem
```

Start a mediator with registry refresh:

```sh
./build/tradep2p_cli mediator-registered \
  0.0.0.0:7443 mediator.cert.pem mediator.key.pem \
  registry.example:7555 REGISTRY_PIN \
  mediator.example:7443 MEDIATOR_PIN
```

List mediator nodes:

```sh
./build/tradep2p_cli nodes registry.example:7555 REGISTRY_PIN
```

## Terminal client

Direct:

```sh
./build/tradep2p_cli client mediator.example:7443 MEDIATOR_PIN
```

Through Tor:

```sh
./build/tradep2p_cli client-tor \
  127.0.0.1:9050 examplehiddenservice.onion:7443 MEDIATOR_PIN
```

## v0.6.1 room-id fix

An accepted public offer now keeps the same room id throughout settlement. Both
clients, the HTTP dashboards, mediator snapshots and CLI commands therefore refer
to one stable id from `/offer` through completion or abort. This removes the
broken client-side alias path that could display the offer id while transmitting
round signals with a different active-room id.


## Build

Dependencies:

- CMake 3.20+;
- C++20 compiler;
- OpenSSL 3.x development files;
- POSIX threads and sockets.

```sh
./scripts/build.sh
```

Equivalent manual commands:

```sh
cmake -S . -B build
cmake --build build -j
```

## Test and demo scripts

The scripts are provided for you to run locally:

```sh
./scripts/unit_test.sh
./scripts/demo_io.sh
./scripts/dashboard_api_test.sh
./scripts/quick_test.sh
```

For a manual two-browser dashboard session:

```sh
./scripts/dashboard_two_client_demo.sh
```

That starts one local mediator and two browser clients, normally at
`http://127.0.0.1:8081` and `http://127.0.0.1:8082`.

The old `tests/*.sh` entry points remain as wrappers around the restored
`scripts/` directory.

## Current limitations

- offer and room state is memory-only;
- no reconnect or crash recovery for an interrupted trade;
- no automatic offer or room timeout yet;
- acknowledgements are user claims, not transaction proofs;
- browser dashboard does not control a wallet or broadcast transactions;
- registry advertisements are unauthenticated;
- no NAT traversal;
- Linux/POSIX socket implementation only.

This is protocol-test source code, not audited production financial software.
