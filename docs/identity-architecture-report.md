# TradeP2P — Architecture Report for the Identity/Keystore/Receipt System

Scope: read-only inspection of the repository as it exists today (branch
`dashboard`, commit `557fc61`). No code was written or modified to produce
this report. All file/line references were verified by reading the named
file; none are guessed.

Binaries actually built by `CMakeLists.txt` (project `TradeP2PMinimal`
v0.6.1): `tradep2p_cli` (`src/main.cpp`, all of `registry`/`nodes`/
`register-node`/`mediator`/`mediator-registered`/`client`/`client-tor` modes),
`tradep2p-dashboard` (`src/http_dashboard.cpp`), `tradep2p-webclient`
(`src/http_webclient.cpp`), `tradep2p-mediator-dashboard`
(`src/http_mediator_dashboard.cpp`), `tradep2p-registry-dashboard`
(`src/http_registry_dashboard.cpp`), and the test binary
`tradep2p_unit_tests` (`tests/protocol_tests.cpp`). There is no `htdocs/`
directory in the repository (the working tree has none; `git ls-files` also
shows none) — the `htdocs/config.php` mentioned in the ambient git-status
snapshot and `nginx-webclient.conf.example` belong to a separate,
out-of-repo, reverse-proxy deployment, not to the identity work.

---

## Answers to the three specific verification asks

These are called out up front because later phases depend on them; each is
also folded into its numbered section below.

**1. Registry authentication gap.** `register_node()` in
`src/registry.cpp:200-222` has no proof-of-control of anything — not the
claimed `host:port`, not the claimed certificate pin. Anyone who can reach the
registry's TLS port can send a `RegistryRegister` frame naming *any*
`host:port` and *any* 32-byte pin and it will be accepted and listed to every
`RegistryList` caller, as long as that `host:port` key is not already present
with a *different* pin. The only check that exists (`existing->second.node.
certificate_pin != node.certificate_pin` at line 208-216) prevents a second,
differently-pinned registration from *silently overwriting* an
already-registered endpoint's pin — i.e. it stops pin-hijacking of a live
entry, nothing more. It does **not** prevent: (a) initial squatting on an
unclaimed `host:port` with a fabricated pin, (b) re-registering the same
`host:port` with the *same* pin from anywhere (the "refresh" path, which is
the intended heartbeat use from `run_registry_heartbeat()` in
`src/main.cpp:461-473`, but is indistinguishable from an attacker replaying a
previously-seen registration), or (c) proving the registrant is actually the
TLS endpoint listening at that host:port. There is no challenge-response, no
signature over the tuple, nothing beyond "first pin wins, and only that
pin can keep re-registering it."

**2. Accept-loop / handshake concurrency bound.** This is *not* an unbounded
thread-per-connection design; it is a two-stage, explicitly bounded design in
both `LobbyServer::Impl::run()` (`src/lobby.cpp:202-267`) and
`RegistryServer::Impl::run()` (`src/registry.cpp:117-155`):
  - `SecureListener::accept_raw()` (`src/secure_channel.cpp:678-695`) is a
    bare, non-blocking-relevant `accept(2)` — it never touches TLS and cannot
    stall on a hostile peer.
  - Immediately after accept, an atomic counter `pending_handshakes_` is
    checked against `kMaxPendingHandshakes = 64` (`src/lobby.cpp:43`,
    `src/registry.cpp:33`, identical value in both). If 64 handshakes are
    already in flight, the new descriptor is closed immediately with no
    thread spawned (`src/lobby.cpp:215-219`; `src/registry.cpp:129-133`).
  - Otherwise a new `std::thread` is spawned (and `.detach()`-ed) to run
    `SecureListener::complete_handshake()`, which is the call that actually
    performs `SSL_accept()` and is bounded by the 10-second
    `SO_RCVTIMEO`/`SO_SNDTIMEO` set in `SecureChannel::make_server()`
    (`src/secure_channel.cpp:441-454`). A `HandshakeGuard` RAII struct
    decrements the counter when that thread exits, whether by success or
    exception.
  - In the lobby only (not the registry), a *second* cap applies after a
    successful handshake: `clients_.size() >= kMaxClients` (128,
    `src/lobby.cpp:38`) is checked under `hub_mutex_` before the connection is
    admitted as a long-lived client (`src/lobby.cpp:242-250`); if full, the
    thread sends an `Error` frame and exits without registering the client.
    Established lobby client threads then run indefinitely (blocking in
    `poll()` in `client_loop`, `src/lobby.cpp:407-480`) until disconnect —
    so up to 128 such threads can be alive concurrently, on top of up to 64
    concurrently mid-handshake, i.e. a bounded (not unbounded) worst case of
    roughly 192 live threads for the lobby.
  - The registry has no equivalent to `kMaxClients`: `handle_connection()`
    (`src/registry.cpp:168-198`) processes exactly one request/response pair
    and then calls `channel.close()`, so registry threads are inherently
    short-lived; the number of registered entries is separately capped by
    `kMaxRegistryNodes = 16` (`include/tradep2p/protocol.hpp:20`,
    enforced in `register_node()` at `src/registry.cpp:217-219`).

  Net: thread-per-connection is real, but it is bounded at every stage that
  matters (in-flight handshakes, established lobby clients, registry
  entries). There is no connection pool or reactor — each accepted TCP
  connection still costs one OS thread — but "unbounded" would overstate the
  current exposure. An identity phase that adds, e.g., a login challenge
  round-trip before `Welcome` should be aware it extends time spent inside
  the already-capped `kMaxPendingHandshakes`/`kMaxClients` windows, not that
  it introduces a new unbounded surface.

**3. Snapshot files are write-only; there is no restore path.** Neither
`LobbyServer::Impl` nor `RegistryServer::Impl` has any `load()`-style method
that reads `state_file_` back into `clients_`/`offers_`/`invites_`/`rooms_`
(lobby) or `entries_` (registry) at construction or at any other time. Both
constructors (`src/lobby.cpp:172-176`, `src/registry.cpp:92-95`) only read an
environment variable to learn the *path* to write to; `snapshot_loop()`
(`src/lobby.cpp:1067-1078`, `src/registry.cpp:252-263`) only calls
`write_state_snapshot()` on a timer, atomically renaming a `.tmp` file over
the real one. The three "reader" binaries —
`tradep2p-dashboard --server-state FILE` (`src/http_dashboard.cpp:90-104`,
`:265-334`), `tradep2p-mediator-dashboard` (`src/http_mediator_dashboard.cpp:
28-…, :199-205`), and `tradep2p-registry-dashboard`
(`src/http_registry_dashboard.cpp:108-…, :357-368`) — are all separate
processes that only `ifstream` the JSON file and re-serve it over their own
loopback HTTP API for a browser to render; none of them talks the TLS/frame
protocol back into the mediator or registry, and none of their output is ever
consumed by `LobbyServer`/`RegistryServer`. Confirmed empirically too: the
live files at `logs/lobby-state.json` and `logs/registry-state.json` are
pure display JSON (`{"enabled":true,"available":true,"generated_at":...,
"clients":0,...}`) with no fields a restore routine could round-trip into
`ClientId`/`RoomId` objects (no client IDs, no receive addresses, no room
party assignments — this is deliberately the "privacy-reduced" view the
README documents). **Conclusion: crash recovery of mediator-side room/offer
state is not possible today in any form** — a process restart starts from
empty containers, full stop. Phase 3 ("local signed journal + crash
recovery") must build its own read side from scratch; it cannot piggyback on
`snapshot_loop()`, which exists purely as a dashboard data feed.

---

## 1. Relevant existing files and classes

| File | Role |
|---|---|
| `include/tradep2p/protocol.hpp` / `src/protocol.cpp` | Wire types (`MessageType` enum, message structs), binary encode/decode (`Writer`/`Reader`, `src/protocol.cpp:14-128`), all `validate_*` functions, `kMaxFramePayload`/other size caps. |
| `include/tradep2p/secure_channel.hpp` / `src/secure_channel.cpp` | `SecureChannel` (one TLS 1.3 connection, frame send/receive), `SecureListener` (`accept_raw()` + `complete_handshake()`), all TLS hardening. |
| `include/tradep2p/mediator.hpp` / `src/mediator.cpp` | `MediatorSession` — the per-room fractional-settlement state machine (`SessionState` enum). |
| `include/tradep2p/lobby.hpp` / `src/lobby.cpp` | `LobbyServer` — the mediator process: accept loop, `Client` (per-connection), `OpenOffer`, `PendingInvite`, `RoomEntry` (wraps one `MediatorSession`), `clients_`/`offers_`/`invites_`/`rooms_` maps, `snapshot_loop()`. |
| `include/tradep2p/registry.hpp` / `src/registry.cpp` | `RegistryServer` — the node directory: `RegistryEntry`, `entries_` map, `register_node_once()`/`list_registered_nodes()` client helpers used by `tradep2p_cli`. |
| `include/tradep2p/dashboard_client.hpp` / `src/dashboard_client.cpp` | `DashboardClient` — a reusable anonymous protocol client driven by queued actions from an HTTP layer; used by both `tradep2p-dashboard` (single session, loopback) and `tradep2p-webclient` (many sessions, public-facing). |
| `src/http_dashboard.cpp` | `tradep2p-dashboard` binary: one operator, one anonymous mediator connection, loopback-only HTTP UI, optional read of the lobby snapshot file via `--server-state`. |
| `src/http_webclient.cpp` | `tradep2p-webclient` binary: multi-user hosted web client. Contains the **entire existing login flow** (`AccountStore`, `SessionManager`). |
| `src/http_mediator_dashboard.cpp`, `src/http_registry_dashboard.cpp` | Read-only admin viewers over the snapshot JSON files; independent processes, no protocol connection at all. |
| `src/main.cpp` | `tradep2p_cli`: CLI client (`run_client`), and process entry points for `registry`/`mediator`/`mediator-registered`/`nodes`/`register-node` modes. |
| `tests/protocol_tests.cpp` | Existing unit test coverage (wire encode/decode, validation). |

There is no `Account`, `User`, `Identity`, `Keystore`, `Wallet`, or `Session`
(protocol-level) class anywhere in `include/tradep2p` today. The only
"account" concept in the whole codebase is the web client's local
username/password convenience store described next.

## 2. Existing login flow

There is exactly one login flow in the repository, and it is **not** part of
the mediator protocol at all — it belongs solely to the hosted web client
(`tradep2p-webclient`, `src/http_webclient.cpp`), which the file's own header
comment (lines 1-8) describes as "a local convenience account... has nothing
to do with the mediator protocol, which stays fully anonymous."

- **Storage**: a flat, tab-separated file (default
  `logs/webclient-accounts.tsv`, `--accounts` flag) holding
  `username\tsalt_hex\thash_hex\tcreated_at` rows, one per account
  (`AccountStore`, `src/http_webclient.cpp:237-333`). The file is `chmod`ed to
  `S_IRUSR|S_IWUSR` after every append (line 327).
- **Hashing**: PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte salt, 32-byte
  output (`kPbkdf2Iterations = 600000`, `derive()` at lines 278-288), via
  OpenSSL's `PKCS5_PBKDF2_HMAC`.
- **Checking**: `AccountStore::verify()` (lines 260-275) does a
  constant-time `CRYPTO_memcmp`, and — notably — always pays the full PBKDF2
  cost even for an unknown username (dummy zero salt) specifically to prevent
  username-enumeration via timing (lines 264-269).
- **Session**: on successful login/register, `SessionManager::login()`
  (lines 363-386) creates or re-attaches a `WebSession` holding a
  `shared_ptr<DashboardClient>` (one persistent anonymous mediator
  connection per *account*, not per browser tab) and issues an `HttpOnly`,
  `SameSite=Strict` cookie (`kSessionCookie = "tp2p_session"`). CSRF is
  defended two ways: a pre-auth double-submit cookie/header pair for
  `/api/register` and `/api/login` (`kPreAuthCookie`/`kPreAuthHeader`,
  `require_preauth()`, lines 867-871) before any session token exists, and a
  per-session synchronizer token (`csrf_token`, checked in the `action()`
  wrapper at lines 987-1006) for every state-changing call afterward.
- **Which client(s) use it**: only `tradep2p-webclient`. Neither
  `tradep2p_cli` (`main.cpp`) nor `tradep2p-dashboard`
  (`http_dashboard.cpp`) has any username/password concept — both connect as
  a single anonymous mediator client per process, with `tradep2p-dashboard`
  explicitly scoped to loopback (README: "The dashboard binds to
  `127.0.0.1` by default... Do not expose it directly to the public
  Internet.").
- **Critically**: this account system never reaches the wire protocol. The
  mediator (`LobbyServer`) has no knowledge that accounts exist; it only ever
  sees the anonymous, per-connection `ClientId` assigned in
  `src/lobby.cpp:252-262`. A phase-7 ("service-scoped login") design must
  decide whether it extends *this* local web-client account concept, adds a
  wholly new mediator-side login message, or both — today they are
  completely disjoint.

## 3. Existing room and trade-round state machine

**Room lifecycle** (mediator side, `LobbyServer::Impl`, `src/lobby.cpp`):
1. A client sends `CreateOffer` → becomes an `OpenOffer` in `offers_`
   (`handle_create_offer`, lines 518-550), capped at `kMaxOpenOffers = 256`
   total and `kMaxOffersPerClient = 16` per creator.
2. Another client sends `JoinOffer` → the offer is promoted directly into a
   `RoomEntry` in `rooms_` under the *same* room id (`handle_join_offer`,
   lines 600-641), capped at `kMaxRooms = 256`. (A parallel invite path,
   `CreateOffer`-free — `InviteTrade`/`AcceptInvite`, lines 679-782 — reaches
   the same `RoomEntry` construction via `PendingInvite`, capped by
   `kMaxPendingInvites = 256` / `kMaxInvitesPerClient = 16`.)
3. `RoomEntry` (lines 364-395) is a thin wrapper: `id`, `party_a`, `party_b`
   (both raw `ClientId`s), one `MediatorSession session`, its own `mutex`, and
   an `active` flag. It is held only in the in-process `rooms_` map — never
   persisted (see §5).
4. Room ends via `Complete` (both legs of the last round acknowledged,
   `handle_received`/`handle_sent`), `Abort` (explicit `/abort`, a
   disconnect, or a peer-vanished detection), or the process exiting (state
   is simply lost).

**Round lifecycle** (`MediatorSession`, `include/tradep2p/mediator.hpp` +
`src/mediator.cpp`): a `SessionState` enum —
`WaitingForPeer → WaitingForSent → WaitingForReceived → (repeat per leg per
round) → WaitingForFeeSent (if a fee is configured) → Complete`, or
`Aborted` from any non-terminal state. Each round has two legs (`leg_index_`
0 then 1, alternating sender via `first_sender_for_round()`,
`src/mediator.cpp:41-45`); `advance_after_receipt()` (lines 151-166) moves
`leg_index_`/`round_index_` forward and flips state. The mediator never
inspects amounts beyond the honor-system `Sent`/`Received` signal —
`tranche_amount()` (`src/protocol.cpp`) only computes what each leg *should*
transfer for display/instruction purposes.

**Where state lives**: entirely in-process C++ containers —
`LobbyServer::Impl::clients_`/`offers_`/`invites_`/`rooms_`
(`std::unordered_map`, `src/lobby.cpp:1217-1220`), guarded by one
`hub_mutex_`, plus each `RoomEntry`'s own `mutex` for its `MediatorSession`.
Nothing here is backed by disk (see §5 for the one-way display snapshot).

**On disconnect**: `client_loop()`'s exit path calls
`remove_client(client->id)` (`src/lobby.cpp:407-480, :980-1052`), which,
under `hub_mutex_`: erases the client from `clients_`; erases any `OpenOffer`
the client created; erases any `PendingInvite` involving the client (and
queues an `InviteDeclined` notice to the other side); and for any `RoomEntry`
the client was a party of, marks it inactive, calls
`room->session.abort("peer disconnected")` if not already
`Complete`/`Aborted`, and sends an `Abort` frame to whichever party is still
connected. There is no reconnect/rejoin path for a room — a disconnect always
aborts any in-progress room for that client; a fresh connection gets a brand
new random `ClientId` with no memory of the old one.

## 4. Existing message framing and limits

Wire framing is implemented once, in `SecureChannel::send_frame()`/
`receive_frame()` (`src/secure_channel.cpp:528-628`) — a fixed 20-byte header
per frame:

```
bytes 0-3:  magic "TP2P"
bytes 4-5:  protocol version (kProtocolVersion = 5, must match exactly)
bytes 6-7:  MessageType (uint16, big-endian)
bytes 8-15: sequence number (uint64, must equal the connection's expected
            next value — strictly monotonic, one shared counter per direction)
bytes 16-19: payload length (uint32, big-endian)
```
followed by that many raw payload bytes. **`kMaxFramePayload = 4096`
(`include/tradep2p/protocol.hpp:14`) is a hard cap enforced on both send
(`send_frame`, line 534) and receive (`receive_frame`, line 609)** — any
message design (a keystore blob, a signed receipt, etc.) must fit its whole
encoded payload, including all nested `short_string` lengths, in 4096 bytes.

`MessageType` (`include/tradep2p/protocol.hpp:35-64`) is a contiguous
`uint16_t` enum from `Welcome = 1` to `OfferCancelled = 28`.
**`validate_message_type()` (`src/protocol.cpp:344-350`) rejects any value
outside `[Welcome, OfferCancelled]`** — so registering a new message type
requires: (a) appending a new contiguous enum value after
`OfferCancelled` in `protocol.hpp`, (b) widening the upper bound in
`validate_message_type()` to the new last value, (c) adding
`encode_*`/`decode_*` free functions (declared in `protocol.hpp`, defined in
`protocol.cpp`, following the existing `Writer`/`Reader` pattern at
`src/protocol.cpp:14-128`), and (d) adding a `case` to
`LobbyServer::Impl::dispatch()` (`src/lobby.cpp:489-515`, the *only* switch
that accepts messages from clients — anything not listed there throws
`"message type is not accepted from clients"`) and/or to
`RegistryServer::Impl::handle_connection()`
(`src/registry.cpp:168-198`, an `if`/`else if` chain, not a switch) if the
new type is registry-bound. Sequence numbers are per-connection and reset to
1 on every new `SecureChannel`, so they cannot serve as a cross-session
nonce/anti-replay mechanism for anything outside that one TLS connection.

## 5. Existing persistence mechanisms

Everything written to disk today is enumerated exactly:

| Path (default) | Writer | Read back by anyone? |
|---|---|---|
| `logs/lobby-state.json` (`TRADEP2P_LOBBY_STATE_FILE`) | `LobbyServer::Impl::snapshot_loop()`/`write_state_snapshot()` (`src/lobby.cpp:1067-1207`), every ~1s, atomic tmp-then-rename | **Never** by `LobbyServer` itself (no `load()` exists). Read-only, for-display, by two *other* processes: `tradep2p-dashboard --server-state` and `tradep2p-mediator-dashboard`. |
| `logs/registry-state.json` (`TRADEP2P_REGISTRY_STATE_FILE`) | `RegistryServer::Impl::snapshot_loop()`/`write_state_snapshot()` (`src/registry.cpp:252-327`), same pattern | **Never** by `RegistryServer`. Read-only, for-display, by `tradep2p-registry-dashboard`. |
| `logs/webclient-accounts.tsv` (`--accounts`) | `AccountStore::append_locked()` (`src/http_webclient.cpp:313-328`), append-only, `chmod 600` | **Yes** — `AccountStore::load()` (lines 290-311) reads this back into memory at `tradep2p-webclient` startup. This is the one place in the repo with an actual disk→memory restore path, and it is scoped to web-client login accounts only, not to protocol/room state. |
| Optional `TRADEP2P_LOG_FILE` (`TRADEP2P_LOG_ENABLED`) | `append_log()` (duplicated in `src/secure_channel.cpp:40-69` and `src/main.cpp:59-88`) | Diagnostic text log only (TLS/handshake/frame-type tracing); never parsed back by anything. |

**The distinction the prompt asked to make explicit**: `lobby-state.json` and
`registry-state.json` are *display snapshots* — one-way, best-effort,
privacy-reduced (no `ClientId`, no receive addresses, no invite data) JSON
dumps consumed only by separate read-only admin/dashboard HTTP processes.
Neither is ever a *restore path* — see the dedicated finding at the top of
this report. The account TSV is the only genuine restore path in the
codebase, and it restores login credentials, not mediator state.

## 6. Existing cryptographic dependencies

- **OpenSSL**: `find_package(OpenSSL 3.0 REQUIRED)` in `CMakeLists.txt`;
  the system actually linked against is OpenSSL 3.5.5 (verified via
  `openssl version` / installed `libssl-dev:amd64 3.5.5-1ubuntu3.3` in this
  environment). `OpenSSL::SSL` and `OpenSSL::Crypto` are both linked into the
  shared `tradep2p` static library, so both `libssl` and `libcrypto` symbols
  are already available to every binary without new linkage work.
- **TLS**: `src/secure_channel.cpp`, `harden_context()` (lines 264-277) pins
  the connection to **TLS 1.3 only** (`SSL_CTX_set_min/max_proto_version(...,
  TLS1_3_VERSION)`), two ciphersuites only
  (`TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384`), and groups
  `X25519:P-256`. **Session tickets are explicitly disabled** on both sides —
  `SSL_OP_NO_TICKET` in `SSL_CTX_set_options()` (line 269, applied via the
  shared `harden_context()` to both client and server contexts) and
  `SSL_CTX_set_num_tickets(ctx, 0)` additionally on the server context
  (`make_server_context`, line 317). This is a deliberate anti-correlation
  choice: it prevents a resumed-session ticket from linking two TCP
  connections from the same client across time, which matters a great deal
  once an identity phase might otherwise be tempted to rely on transport-
  level session continuity for anything. Neither side verifies the other's
  certificate through a CA chain: `SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE,
  nullptr)` on *both* client and server contexts (lines 286, 316) — trust is
  established entirely out-of-band via **exact SHA-256 certificate pinning**
  (`verify_server_pin()`, lines 501-526, called from `make_client()`); the
  server never authenticates the client at all (no client certificates are
  requested or checked anywhere).
- **Hashing/KDF actually used today**: `EVP_sha256()` appears in exactly two
  places — (1) `PKCS5_PBKDF2_HMAC(..., EVP_sha256(), ...)` for web-client
  password hashing (`src/http_webclient.cpp:281-286`), and (2)
  `X509_digest(certificate, EVP_sha256(), ...)` for computing/verifying the
  certificate pin (`src/secure_channel.cpp:510`). `CRYPTO_memcmp` is used
  once, for constant-time password-hash comparison
  (`src/http_webclient.cpp:273`). `RAND_bytes` is used for all random IDs
  (`ClientId`/`RoomId`/`InviteId` via `random_id<Id>()` in
  `src/lobby.cpp:84-91`, and account salts in `AccountStore::create()`).
- **Not touched anywhere in the repository today**: `EVP_KDF` (any of the
  newer OpenSSL 3.x KDF API), Ed25519 (`EVP_PKEY_ED25519`/`EVP_PKEY_new_raw_
  private_key` etc. — zero hits), AES-GCM or ChaCha20-Poly1305 as an
  *application-level* AEAD (the only appearances are as TLS 1.3 ciphersuite
  name strings passed to `SSL_CTX_set_ciphersuites`, not as directly-invoked
  `EVP_CIPHER` primitives). A phase that needs Ed25519 signing (for a signed
  local journal or mediator-signed receipts) or an AEAD for an at-rest
  keystore will be introducing all of that OpenSSL EVP surface area for the
  first time, against an OpenSSL 3.5.5 that supports it natively (no new
  external dependency required, just new API usage).

## 7. Existing CLI, dashboard, and hosted-web-client differences

| Binary | Process model | Trust boundary |
|---|---|---|
| `tradep2p_cli client` / `client-tor` (`src/main.cpp`) | One process = one anonymous mediator connection, driven interactively from stdin (`run_client`, lines 412-459). | Fully local/operator-controlled; the operator *is* the end user. No HTTP surface at all. |
| `tradep2p_cli mediator` / `mediator-registered` / `registry` | The trusted server processes (`LobbyServer`/`RegistryServer`). | Operator-controlled; holds the TLS private key and all in-memory room/registry state. Never sees anything password-like. |
| `tradep2p-dashboard` (`src/http_dashboard.cpp`) | One process = one anonymous mediator connection (via `DashboardClient`) + a loopback-only HTTP UI with a random per-process request token. | README is explicit: "binds to `127.0.0.1` by default... Do not expose it directly to the public Internet." Single operator/user; no accounts. |
| `tradep2p-webclient` (`src/http_webclient.cpp`) | One process serving **many** browser sessions, each with its own `DashboardClient` (own anonymous mediator connection) behind a username/password account. Designed to sit behind a TLS-terminating reverse proxy and be exposed publicly (`print_usage`, lines 746-762; explicit `kPrivacyNotice` string, lines 444-452). | **This is the one trust boundary where the operator controls served JavaScript and can observe activity the protocol otherwise hides.** The code says so directly to the end user: "The operator of this page can observe your account activity, session timing and source IP address, even though the trade protocol itself stays anonymous to the mediator." (`kPrivacyNotice`). CSP is set (`default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'`, `set_common_headers`, lines 849-855) but all page JS is inlined server-side — the operator authors 100% of the client-side code the browser executes, so any keystore/signing material handled in-browser is only as trustworthy as this operator. Any client-held private key material must never be generated or handled server-side here if the design goal is that the operator cannot impersonate the user; it would need to live purely in browser JS/WebCrypto/IndexedDB, out of this server process's reach — a materially different trust model than `tradep2p_cli`/`tradep2p-dashboard`, where the *user themselves* runs the whole binary. |
| `tradep2p-mediator-dashboard` / `tradep2p-registry-dashboard` | Fully separate, read-only viewers over the snapshot JSON files (no protocol connection whatsoever — confirmed via `grep` for TLS/`SecureChannel` usage: none). | Admin-only viewing tool; not a live participant in the protocol, cannot itself be a vector for identity data unless someone chooses to add fields to the JSON snapshot it reads. |

## 8. Integration points per phase (real files/functions only)

Phase numbering follows the nine `docs/identity-0N-*.md` filenames already
present in the repo (not read for content, only used here to anchor which
phase is which):

- **01 — primitives**: net-new code, most naturally a new
  `include/tradep2p/identity.hpp` / `src/identity.cpp` pair added to the
  `tradep2p` static library target in `CMakeLists.txt` (alongside
  `protocol.cpp`, `mediator.cpp`, etc., lines 9-16), since every later phase
  needs Ed25519 sign/verify and an AEAD, and none of the existing translation
  units currently touch `EVP_PKEY`. Would link only against the
  already-present `OpenSSL::Crypto` — no new external dependency.
- **02 — keystore**: on-disk key material has no precedent to extend; the
  closest analog is `AccountStore`'s file-based, `chmod 600`,
  load-at-startup pattern (`src/http_webclient.cpp:237-333`), but that file
  format (plain TSV of salt+hash) is not fit for storing private keys as-is
  and would need its own encrypted-at-rest format (AEAD from phase 01) rather
  than reuse.
- **03 — journal + crash recovery**: must be built from nothing, per the
  verified finding above — `LobbyServer::Impl`/`RegistryServer::Impl` have no
  `load()` path at all. The natural anchor points are the constructors
  (`src/lobby.cpp:172-176`, `src/registry.cpp:92-95`, where `state_file_` is
  currently only assigned a write path) and `snapshot_loop()`
  (`src/lobby.cpp:1067-1078`/`src/registry.cpp:252-263`, currently a
  write-only timer loop) if a signed append-only journal is meant to live
  alongside the existing display snapshot rather than replace it. This phase
  should not assume `lobby-state.json`/`registry-state.json` can be
  repurposed — they are lossy by design (no `ClientId`, no addresses).
- **04 — local counterparty history/blocklist**: purely client-side
  (`tradep2p_cli client`/`tradep2p-dashboard`/`tradep2p-webclient`), keyed
  most naturally on the ephemeral trade identity from phase 05, since today's
  only cross-request identifier visible to a client is the transient
  `ClientId` from `WelcomeMessage`/`TradeReadyMessage.peer_id`
  (`include/tradep2p/protocol.hpp:102-105, 184-192`), which is reassigned
  randomly per TLS connection (`src/lobby.cpp:252-262`) and therefore useless
  as a durable blocklist key today.
- **05 — per-trade ephemeral identity**: the natural wire touch points are
  `CreateOfferMessage`/`JoinOfferMessage`/`InviteTradeMessage`/
  `AcceptInviteMessage`/`TradeReadyMessage` (`include/tradep2p/protocol.hpp:
  107-192`) — any of these would need a new field (e.g. an ephemeral public
  key) added to the struct, its `encode_*`/`decode_*` pair
  (`src/protocol.cpp`), and its `validate_*` counterpart, all under the
  4096-byte frame cap (§4). Server-side, `RoomEntry`
  (`src/lobby.cpp:364-395`) and `MediatorSession`
  (`include/tradep2p/mediator.hpp:24-62`) would need to carry the identity
  material through room lifetime without the mediator needing to interpret
  it (consistent with the existing "mediator never inspects" design ethos
  stated in `MediatorSession`'s class comment).
- **06 — mediator-signed staged receipts**: needs the mediator to hold a
  signing key (extends `ServerTlsIdentity`,
  `include/tradep2p/secure_channel.hpp:21-24`, or a sibling struct) and a new
  message pair around `Sent`/`Received`/`Complete`
  (`handle_sent`/`handle_received`, `src/lobby.cpp:810-880`) or a wholly new
  `MessageType` requested after a room reaches `SessionState::Complete`
  (`src/mediator.cpp:151-166`). Registering the new type follows the exact
  mechanical steps in §4.
- **07 — service-scoped login**: this is the phase that must reconcile with
  the *existing* login flow described in §2. `tradep2p-webclient`'s
  `AccountStore`/`SessionManager` (`src/http_webclient.cpp:226-432`) is the
  only login code in the repo; it currently authenticates a browser session
  to *this specific web-client instance*, not to the mediator. "Service-
  scoped" login would need to either extend this account store to also bind
  a keystore identity per account, or introduce a parallel mediator-facing
  login message — today nothing at the `LobbyServer` level accepts anything
  resembling credentials (`dispatch()`, `src/lobby.cpp:489-515`, has no such
  case).
- **08 — selective disclosure**: layers on top of whatever field(s) phase 05
  adds to `TradeReadyMessage`/offer/invite messages; there is no existing
  disclosure-control concept anywhere in `protocol.hpp` to extend, so this is
  net-new message design constrained only by the 4096-byte cap and the
  existing `validate_*` pattern.
- **09 — hosted web-client integration**: must operate inside the trust
  model described in §7 of this report (the operator authors and serves all
  browser JS in `src/http_webclient.cpp`'s inlined `<script>` blocks, e.g.
  `app_html()` lines 582-744). Any client-held private key must be generated
  and used entirely in-browser (WebCrypto/IndexedDB) if it is meant to be
  opaque to the operator; the existing account-password flow
  (`/api/login`, `/api/register`, lines 897-943) is precedent for "operator
  can see login timing/activity, but the mediator stays anonymous" — the
  identity phase would need an equivalent, explicit privacy notice (extending
  `kPrivacyNotice`, lines 444-452) disclosing exactly what the hosted keystore
  does and does not protect against a malicious/compelled operator.

## 9. Privacy risks per integration point

- **Registry (phase-adjacent, but load-bearing for everything else)**: as
  detailed in the verification section, `RegistryNode` entries
  (`include/tradep2p/protocol.hpp:222-227`) are unauthenticated. If any later
  phase starts trusting registry entries as a basis for identity (e.g.
  "this mediator's signing key is the one pinned in the registry"), that
  trust is only as good as first-come-first-registered squatting resistance,
  which is none.
- **Stable identifiers becoming visible where none exist today**: the
  single biggest structural privacy risk. Today the *only* identifier a
  counterparty or the mediator ever sees is the random, connection-scoped
  `ClientId` (`include/tradep2p/protocol.hpp:26`, assigned fresh in
  `src/lobby.cpp:252-262`) — it does not survive a reconnect, is never
  written to the display snapshot's per-room JSON (`RoomSnapshot`,
  `src/lobby.cpp:1059-1065`, deliberately omits it, matching the README's
  "It deliberately omits client IDs and receiving addresses"), and is never
  logged with amounts. Any phase-05 ephemeral trade identity or phase-02
  keystore public key that flows into `TradeReadyMessage`, `OfferSummary`, or
  any offer-listing/`ListOffers` response (`include/tradep2p/protocol.hpp:
  116-134`) becomes visible to *every* client who lists offers, not just the
  eventual counterparty — this is a strictly larger disclosure surface than
  today's model, where an offer's `OfferSummary` carries only `TradeTerms`
  (asset/amount/rounds), nothing identity-shaped. If phase 05's "ephemeral"
  key is reused across multiple rooms by the same user (e.g. for
  convenience, or because phase 04's blocklist wants a stable key to match
  against), it stops being ephemeral in practice and becomes a durable
  cross-room correlation handle — exactly the property TLS session-ticket
  disabling (§6) was designed to prevent at the transport layer.
- **Local journal/history (phases 03-04) leaking into the display
  snapshot**: `write_state_snapshot()` in both `lobby.cpp` and `registry.cpp`
  already writes JSON to a world-readable-by-default path (no `chmod`
  hardening exists there, unlike `AccountStore`'s explicit `chmod 600` at
  `src/http_webclient.cpp:327`). If any journal/history data is ever added to
  that snapshot for dashboard convenience, it would inherit that weaker file
  permission posture; it should stay in its own separately-permissioned file.
- **Mediator-signed receipts (phase 06) as a correlation oracle**: a
  receipt signed by the mediator's key and handed to both parties is, by
  construction, a portable, verifiable-by-anyone artifact. If it embeds the
  room id, a counterparty-identifying key, and a timestamp, it becomes
  something a *third party* (not just the two trade participants) could use
  to prove "these two identities traded X for Y at time T" if it ever leaks —
  a capability that does not exist today (there is no signed artifact of any
  kind currently produced by the mediator; `Complete`/`CompleteMessage`,
  `include/tradep2p/protocol.hpp:209-211`, carries only the room id, no
  signature).
- **Hosted web client (phase 09) as the weakest trust boundary**: as
  established in §7, the operator of `tradep2p-webclient` authors all served
  JS and already sees account activity/timing/source IP. A hosted keystore
  is only private from that operator if key generation/use happens
  client-side and the server genuinely never receives the private key or an
  oracle for it (e.g. a "remember my password to unlock the keystore"
  convenience feature would defeat the entire premise). This is a design
  constraint to flag prominently in phase 09, not merely an implementation
  detail — the existing `kPrivacyNotice` text is the right place to extend,
  and its current honesty about the operator's visibility (§2, §7) is a
  precedent worth keeping.
- **Frame-size cap as an information-theoretic side channel**: because
  `kMaxFramePayload = 4096` is a hard, publicly-known cap (§4), and messages
  are not padded to a fixed size, an on-path observer (relevant especially
  over Tor, which this project already supports via `client-tor`/SOCKS5,
  `src/secure_channel.cpp:213-262`) can already distinguish message *types*
  and rough payload sizes from encrypted TLS record sizes to some extent.
  Adding variable-length identity/signature/receipt fields to existing
  message types changes their size fingerprint and should be considered if
  any phase cares about traffic-analysis resistance beyond what TLS 1.3 +
  no-ticket already provides.
