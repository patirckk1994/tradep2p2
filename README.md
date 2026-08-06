# TradeP2P

An anonymous peer-to-peer trading mediator: a coordination layer that helps
two parties settle a trade across whatever chains their assets live on,
without ever holding, inspecting, or verifying the value that moves. Includes
an optional, additive identity and reputation layer (keystores, a local
counterparty history, live key-recognition, per-trade ephemeral keys,
mediator-signed receipts with a griefing-resistant withholding fix, and
selective private disclosure) that never produces a public transaction graph
or a mandatory identity.

For the full design rationale — threat model, the six constraints the
reputation layer must satisfy, what it deliberately does *not* claim to
solve (Sybil resistance chief among them) — see [`specs.txt`](specs.txt).
This README is the practical how-to-run-it manual.

## Quick start

Try the whole trading flow — a mediator, two terminal clients, one full
trade — in about a minute:

```sh
./scripts/build.sh
./scripts/demo_io.sh
```

This spins up a local mediator and two CLI clients, publishes an offer,
takes it, and settles every round automatically, printing a full transcript.
No setup, no config file, no keys.

For the interactive dashboard instead (two browser tabs, one mediator, click
through a trade yourself):

```sh
./scripts/dashboard_two_client_demo.sh
```

It prints the two dashboard URLs (normally `http://127.0.0.1:8081` and
`http://127.0.0.1:8082`) to open in your browser.

Both scripts generate a throwaway TLS identity under `test-output/` and clean
up their own processes on exit (`Ctrl-C` or normal completion).

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

Splitting a trade into rounds caps a defector's maximum theft at
`total / rounds` per trade — real protection, but not deterrence, since a
fresh identity costs nothing. That gap is what the optional identity layer
below exists to narrow (not close — see
[Current limitations](#current-limitations) and `specs.txt` §12).

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
- optionally see privacy-reduced mediator metrics and active-room state;
- manage a local keystore, counterparty history, and (once you've traded)
  mediator-signed receipts — see
  [Optional identity & reputation layer](#optional-identity--reputation-layer).

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

Or skip the manual certificate step entirely — `start_dashboard.sh`
generates one on first run if `certs/mediator.cert.pem` doesn't exist yet,
and prints the exact command to start the matching mediator:

```sh
./start_dashboard.sh
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

The same snapshot also powers a read-only operator dashboard, separate from
the trading dashboard above:

```sh
./build/tradep2p-mediator-dashboard "$PWD/logs/lobby-state.json" --port 8091
```

Open `http://127.0.0.1:8091` for connected-client counts, open offers and
active-room state at a glance. It never speaks the TradeP2P protocol itself.

## Public web client

`tradep2p-webclient` lets a website offer visitors a hosted client instead of
requiring them to install anything. Unlike `tradep2p-dashboard`, one process
serves many browser sessions:

```sh
./build/tradep2p-webclient client \
  127.0.0.1:7443 MEDIATOR_CERT_SHA256 \
  --port 8090 --accounts "$PWD/logs/webclient-accounts.tsv"
```

Open `http://127.0.0.1:8090` to register a username and password. That
account is a local convenience session for this web client only — it is
never sent to the mediator and has nothing to do with the anonymous protocol
identity a session gets when it connects. Logging in re-attaches your
existing session (and its live mediator connection) if one is still running;
logging out terminates it. The page carries a standing privacy warning: the
operator of a hosted web client can see session activity and source IP even
though the trade protocol stays anonymous to the mediator.

**Key-based login.** Once you've registered, the "Account" panel lets you
enroll an Ed25519 public key as an alternative to your password (never a
replacement — the password keeps working). Generate the keypair with a
native tool you trust — `tradep2p_cli`'s own keystore, or any Ed25519
keypair generator; this page never generates or holds your private key, by
design (see `specs.txt` §13.4 for exactly what this does and doesn't
protect against — stored-credential compromise, not a hostile operator of
this page). To log in with the key: the login screen's "Log in with a key"
panel requests a signed challenge, you sign it externally, and paste the
signature back. This is the honest, bounded scope of `--server-identity`
(see `--help`): set it to your public-facing domain if this process sits
behind a reverse proxy, or the signed challenge binds to the wrong identity.

Put this behind a TLS-terminating reverse proxy before exposing it publicly
— see [`nginx-webclient.conf.example`](nginx-webclient.conf.example). Use a
**subdomain** (e.g. `trade.example.com`), not a path under your main domain:
the pages fetch and link absolute paths like `/api/state`, so the web client
needs to own the whole origin it is served from. Once it's live, point your
site's `webclient_url` (in `htdocs/config.php`) at that subdomain.

`X-Forwarded-Proto` from the proxy is what tells the web client to mark its
session cookie `Secure`; the config example sets it. Registration and login
are also protected by a double-submit CSRF cookie in addition to the
`Origin` header check, and every other state-changing request needs a
matching per-session token, the same synchronizer-token pattern
`tradep2p-dashboard` already uses. Authentication attempts (password and
key-based) are rate-limited per account.

The web client does not yet surface the keystore/history/receipts panels
described below — that remains a CLI/dashboard-only surface for now (see
[Current limitations](#current-limitations)).

## Mediator fees

An operator can charge a fee per settled trade by setting environment
variables before starting the mediator:

```sh
export TRADEP2P_FEE_ASSET=BTC
export TRADEP2P_FEE_AMOUNT=500
export TRADEP2P_FEE_ADDRESS=your-fee-receive-address
./build/tradep2p_cli mediator 0.0.0.0:7443 mediator.cert.pem mediator.key.pem
```

Leaving `TRADEP2P_FEE_ASSET` unset charges no fee (the default). When a fee is
configured, the mediator advertises it to every connecting client and adds it
to the settlement as one extra final leg, paid by the offer creator after the
last trade round. It settles through the same `sent`/`received` acknowledgement
flow as every other transfer.

## Terminal commands — trading

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

## Optional identity & reputation layer

Everything in this section is off by default and additive: a room with
neither party using any of it settles exactly as described above. The
governing rule (`specs.txt` §3) is that continuity is scoped to the smallest
context that actually needs it — a keystore identity is never sent to the
mediator or a counterparty on its own, and nothing here produces a public,
cross-trade identifier. Run `/help` in the CLI for the exact command list;
this section explains what each layer is for and how the pieces fit
together.

### 1. Keystore

Everything else in this section is derived from one encrypted local
keystore. Create one before anything else:

```text
/keystore create ./my.keystore a-strong-passphrase optional-alias
/keystore unlock ./my.keystore a-strong-passphrase
/keystore lock
/keystore rotate a-strong-passphrase
/keystore show-identity ./my.keystore
/keystore destroy ./my.keystore
```

The keystore holds one random master secret, encrypted at rest
(ChaCha20-Poly1305, Argon2id-derived key). Every other key described below —
login, local-history, per-mediator pseudonym, per-trade ephemeral — is
deterministically derived from it via HKDF with a domain-separated label, or
(for per-trade keys specifically) generated fresh and never derived at all.
Losing the keystore means losing everything derived from it — there is no
recovery authority, by design (`specs.txt` §13.5). `tradep2p-dashboard` has
an equivalent keystore panel.

### 2. Journal

An encrypted, hash-chained, append-only record of your own client's
activity — crash recovery, duplicate-action prevention, and the source of
truth the counterparty-history counter below reads from. It is *not*
evidence to show anyone else; a user can write anything into their own
journal.

```text
/journal status
```

If a room's state looks wrong after a client or mediator restart:

```text
/recovery request ROOM_ID
```

This asks the mediator what it currently has on file for that room and
cross-checks it against your local journal.

### 3. Local counterparty history & blocklist

A purely local, never-transmitted record of who you've encountered before,
keyed by (public key fingerprint, mediator). Only actually *completed*
settlements increment the settlement counter — an abandoned room does not,
so a counterparty can't inflate standing with you by starting and
abandoning rooms for free.

```text
/history list
/history show FINGERPRINT
/block FINGERPRINT
/unblock FINGERPRINT
/note FINGERPRINT free text about this counterparty
```

### 4. Counterparty recognition

Answers exactly one question: *does the party in this room currently
control the same key I've seen before on this mediator?* Nothing more — not
"trustworthy," not "verified human." Run it once you're in a room together:

```text
/recognize ROOM_ID
```

This sends a live, single-use, expiring challenge to the counterparty (or
auto-answers one if they send it to you and your keystore is unlocked). A
successful proof looks up and prints your local settlement/incomplete count
for that key. An unknown key is the *normal* case for a stranger — it is
never shown as a warning. `tradep2p-dashboard` has an equivalent
"Recognize counterparty" button per room.

### 5. Per-trade ephemeral identities

Every room automatically generates and exchanges a fresh, random,
never-derived signing key the moment it becomes active — no command needed.
It has no privacy cost (unlike the pseudonym key above, it reveals nothing
linkable across rooms), and it is what receipts and disclosure, below, bind
to. **It does not hide anything from the mediator** — the mediator still
sees which live connection joined which room, regardless of what key signs
messages inside it (`specs.txt` §13.2).

### 6. Mediator-signed receipts, and the withholding fix

Once both parties are in a room, the mediator gates the trade's *actual
final tranche* — the last leg of the last round, or the fee leg if one is
configured — behind a signed receipt acknowledgement from both sides. This
is automatic; you'll see a prompt if your keystore is unlocked, and the
trade simply cannot advance past that point until both parties acknowledge.
The point of the gate: refusing to help produce evidence of an otherwise-
honest trade now costs exactly what refusing to send the final tranche
already costs, instead of costing nothing.

```text
/receipts ROOM_ID
```

prints whatever mediator-signed receipt chain (a "penultimate obligations
complete" stage, then a "settlement completed" stage, each chained to the
last and countersigned by the mediator) you're holding for that room, and
whether it still verifies. The client trust-on-first-use pins the
mediator's receipt-signing public key for the session — see
[Current limitations](#current-limitations) for what that does and doesn't
protect against.

### 7. Selective disclosure

Show a specific receipt chain — proof you genuinely settled a prior trade —
to the counterparty in a *different*, current room, without publishing it
anywhere or letting them replay it to someone else:

```text
/disclose SOURCE_ROOM_ID TARGET_ROOM_ID
```

`SOURCE_ROOM_ID` is the completed room whose receipts you're showing;
`TARGET_ROOM_ID` is your current negotiation. The disclosure is signed with
the *original* room's key (proving you were really a party to that trade)
but bound to the current room and the current recipient's key, so it cannot
be shown again elsewhere.

### 8. Web client login

Covered above under [Public web client](#public-web-client) — the same
challenge-response mechanism, scoped to that one hosted service rather than
the mediator protocol.

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

- TLS 1.3 only, with `X25519MLKEM768` (post-quantum hybrid) preferred over
  classical `X25519`/`P-256` — see [Post-quantum posture](#post-quantum-posture);
- exact SHA-256 server-certificate pin required by clients;
- no client certificate, account or user authentication at the transport
  layer (the identity layer above is entirely optional and application-level);
- 20-byte fixed frame header;
- 4 KiB hard payload limit;
- exact-length reads and writes;
- monotonic per-direction frame sequence numbers;
- replay and out-of-order rejection;
- strict binary decoding;
- truncated and trailing message data rejected;
- optional SOCKS5 transport for Tor onion endpoints.

## Post-quantum posture

Harvest-now-decrypt-later applies to key exchange, not signatures: an
adversary recording today's TLS traffic can decrypt it retroactively once a
cryptographically relevant quantum computer exists, so key exchange is the
one urgent item, and it's done — every connection negotiates the hybrid
`X25519MLKEM768` group first, falling back to classical groups only for a
peer that doesn't offer it. Mediator receipt-signing keys remain
classical-only (Ed25519) for now, which matters more than most other keys
here since receipts are meant to stay verifiable for years — a real, open
item, not yet built. Full posture and reasoning: `specs.txt` §11.

## Semi-centralized node registry

The optional registry is a short-lived directory of mediator endpoints. Its IP
or hostname is supplied through the command line. Registrations expire after
300 seconds. Every listed mediator carries its own SHA-256 certificate pin,
which clients still verify when connecting.

**Registration is currently unauthenticated** — anything with an unclaimed
`host:port` can list itself, and the registry has no way to confirm the
registrant actually controls that endpoint. This was already true for the
base trading protocol; it matters more now that the identity layer exists,
since a squatted mediator can issue syntactically valid, correctly-signed
receipts for trades that never involved real value. The client-side
trust-on-first-use pinning described under
[receipts](#6-mediator-signed-receipts-and-the-withholding-fix) is the
practical mitigation available today, not a substitute for fixing this
(`specs.txt` §15).

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

Set `TRADEP2P_REGISTRY_STATE_FILE` before starting the registry to get the
same kind of local snapshot the mediator writes, and view it with the
registry's own read-only operator dashboard:

```sh
export TRADEP2P_REGISTRY_STATE_FILE="$PWD/logs/registry-state.json"
./build/tradep2p_cli registry 0.0.0.0:7555 registry.cert.pem registry.key.pem &
./build/tradep2p-registry-dashboard "$PWD/logs/registry-state.json" --port 8092
```

## Quick setup scripts

`setup_mediator.sh` and `setup_registry.sh` wrap the steps above: they
generate a TLS identity if one is missing, build the project if needed, and
launch the mediator or registry together with its operator dashboard. Both
read from (and can write) a small config file so repeat runs don't need
flags. That config file is operator-specific (it ends up containing your
real fee address once configured) — it's written next to the script and is
already `.gitignore`d; don't commit it.

```sh
./setup_registry.sh --init-config          # write registry.conf, then edit it
./setup_registry.sh                        # start the registry + dashboard

./setup_mediator.sh --init-config \
  --fee-asset BTC --fee-amount 500 --fee-address your-address
./setup_mediator.sh                        # start the mediator + dashboard
```

Run either with `--help` for the full flag list, including `--registry` /
`--registry-pin` to have `setup_mediator.sh` register with a running registry.

`stopall.sh` stops every TradeP2P process this repo's scripts may have
started (mediator, registry, dashboards, web client) by matching on the
built binary paths — safe to run any time you want a clean slate.

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

## Build

Dependencies:

- CMake 3.20+;
- C++20 compiler;
- OpenSSL 3.x development files (3.5+ recommended — needed for the
  post-quantum hybrid TLS group; older 3.x builds without it fail loudly at
  startup rather than silently falling back);
- POSIX threads and sockets.

```sh
./scripts/build.sh
```

Equivalent manual commands:

```sh
cmake -S . -B build
cmake --build build -j
```

Builds five binaries (`tradep2p_cli`, `tradep2p-dashboard`,
`tradep2p-mediator-dashboard`, `tradep2p-registry-dashboard`,
`tradep2p-webclient`) and eleven `ctest` unit-test targets covering the
transport protocol and every layer of the identity system (keystore,
journal, recovery, local history, recognition, ephemeral identities,
receipts, login, disclosure).

## Test and demo scripts

The scripts are provided for you to run locally:

```sh
./scripts/unit_test.sh          # all ctest targets
./scripts/demo_io.sh            # full CLI trade, deterministic, non-interactive
./scripts/dashboard_api_test.sh
./scripts/quick_test.sh         # build + unit_test + demo_io in one go
```

For a manual two-browser dashboard session:

```sh
./scripts/dashboard_two_client_demo.sh
```

That starts one local mediator and two browser clients, normally at
`http://127.0.0.1:8081` and `http://127.0.0.1:8082`.

The old `tests/*.sh` entry points remain as wrappers around the `scripts/`
directory.

## Current limitations

- offer and room state is memory-only unless mediator-side persistence is
  explicitly enabled (`TRADEP2P_ROOM_STATE_FILE`) — and even then, receive
  addresses are deliberately never persisted, so a restored room needs both
  addresses re-supplied before settlement can resume;
- acknowledgements are user claims, not transaction proofs, including the
  mediator fee leg — settlement is honor-system throughout; no reputation
  mechanism here distinguishes an honest participant from a patient one
  (`specs.txt` §12);
- **registry registration is unauthenticated** — see
  [the registry section](#semi-centralized-node-registry) above; this is
  the single most important open item, and it directly limits how much the
  receipt/disclosure trust-on-first-use pinning can actually guarantee;
- per-trade ephemeral keys are not persisted — a process crash mid-room
  loses that room's signing key (already-issued receipts remain valid and
  disclosable regardless, since verifying them needs only the embedded
  public key);
- mediator receipt-signing keys are classical Ed25519 only, not yet hybrid
  post-quantum (unlike the TLS transport, which already is);
- unlinkable aggregate disclosure (blind-signed completion tokens) is
  documented future work, not implemented — no pairing-friendly curve
  support in this dependency set, and naive blind Schnorr over Ed25519 is
  unsafe under concurrent sessions (`specs.txt` §9.3);
- bond-anchored Sybil resistance is documented as an option with its costs
  stated, not implemented — this architecture does not claim Sybil
  resistance anywhere, and says so plainly (`specs.txt` §12);
- `tradep2p-webclient` does not yet surface the keystore/history/receipts/
  disclosure panels in the browser — that remains CLI/dashboard-only, a
  deliberate scope boundary given the materially different engineering
  problem of per-account key custody in a multi-tenant process
  (`specs.txt` §10, phase 9's status note);
- no automatic offer or room timeout yet;
- no NAT traversal;
- Linux/POSIX socket implementation only.

This is protocol-test source code, not audited production financial
software. Pre-audit, not for production use.
