# Prompt: architecture report (run this first, in its own session)

Paste everything below into a fresh Claude Code session. Do not paste any of
the phase files alongside it — this session's only job is to read the repo
and report, not to write code.

---

You are working inside an existing peer-to-peer trading project
(`tradep2p2`). I'm about to add an optional decentralized public/private-key
identity system across nine phases (keystore, service-scoped login, per-trade
ephemeral identities, local signed journal + crash recovery, local
counterparty history/blocklist, mediator-signed staged receipts, selective
disclosure, hosted web-client integration). Before any of that lands, inspect
the repository and produce a concise architecture report. Do not assume
filenames, classes, message types, or dependencies — check them.

Report on:

1. Relevant existing files and classes.
2. Existing login flow (currently password-based; where the credentials
   live, how they're checked, which client(s) use it).
3. Existing room and trade-round state machine (room lifecycle, round
   lifecycle, where state lives in memory, what happens on disconnect).
4. Existing message framing and limits (frame size cap, message type enum,
   how encode/decode boundaries work, where a new message type would be
   registered).
5. Existing persistence mechanisms (what's written to disk, where,
   how/whether it's read back on startup — be explicit about the difference
   between a *display snapshot* and a *restore path* if both exist).
6. Existing cryptographic dependencies (OpenSSL version linked, what's
   already used for TLS vs. hashing vs. anything password-related, whether
   `EVP_KDF`, Ed25519, AES-GCM/ChaCha20-Poly1305 are already touched
   anywhere).
7. Existing CLI, dashboard, and hosted-web-client differences (which binaries
   exist, what each one's trust boundary looks like, particularly for the
   hosted web client where the operator controls the served JavaScript).
8. Exact places where identity support should integrate for each of the nine
   phases (name real files/functions, not proposed new ones).
9. Privacy risks introduced by each integration point — in particular, flag
   anywhere a stable identifier would become visible in a room, offer, or log
   that isn't visible today.

Also verify and report on, specifically, since later phases depend on these:

- Whether the registry (node registration) has any authentication beyond
  what's needed to prevent an unauthenticated pin refresh, and what the
  actual gap is.
- How connections are accepted and where the TLS handshake happens relative
  to the accept loop — specifically, whether there's any bound on concurrent
  in-progress handshakes/connections, or whether it's unbounded
  thread-per-connection.
- Whether mediator-side room state (`RoomEntry`/`rooms_` or equivalent) is
  ever reconstructed from anything on disk after a restart, or whether the
  existing snapshot file is write-only from the mediator's perspective.

Do not write or modify any code in this session. Output the report as
`docs/identity-architecture-report.md` in this repository and stop.
