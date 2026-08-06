# Optional decentralized identity — plan and prompts

This is the split form of a single ~2,500-word identity/keystore/receipt spec
that was too large to run as one Claude Code session against this codebase
(7,000+ lines, 9 phases, 11 new classes — roughly doubling the project). Each
file in `docs/identity-*.md` is a **self-contained prompt** for one session.

## How to use this

1. Run `docs/identity-00-architecture-report-prompt.md` in its own fresh
   session. Its output is `docs/identity-architecture-report.md` — commit it.
2. For each phase below, start a **new** session and give it exactly two
   things: `docs/identity-architecture-report.md` and that phase's prompt
   file. Do not paste the other phase files into the same session — that's
   what caused the context exhaustion / drift in the original single-prompt
   version.
3. Land phases in the order below, not the conceptual order the requirements
   were originally written in (crypto → keystore → login → ... → receipts).
   The reorder is by value delivered and by hard dependency, explained per
   phase.

## Phase order and why

| # | Phase | Why here |
|---|---|---|
| 1 | [Crypto primitives](identity-01-primitives.md) | Everything else depends on it. |
| 2 | [Encrypted local keystore](identity-02-keystore.md) | Nothing else can store a key without it. |
| 3 | [Journal, crash recovery, mediator room persistence](identity-03-journal-recovery.md) | Fixes a real fund-loss/state-loss bug today, independent of identity. Bundled with mediator-side persistence because the client journal alone cannot resurrect a room after a mediator restart — see that file for why. |
| 4 | [Local counterparty history and blocklist](identity-04-local-history-blocklist.md) | Nearly free once the keystore exists; real user value immediately. |
| 4b | [Personal counterparty recognition](identity-04b-counterparty-recognition.md) | Extends phase 4 with challenge-response proof-of-control so the "counterparty fingerprint" phase 4 records is actually backed by something, not just an assumed identifier. Depends only on phases 1/3/4 (not 5 — the recognition key is the phase-1 mediator-pseudonym key, not the phase-5 ephemeral key). Reuses the existing `Sent`/`Received`-style mediator relay pattern, so it's proven-shape work, not new mediator capability. |
| 5 | [Per-trade ephemeral identities](identity-05-ephemeral-trade-identity.md) | Needed before receipts can bind to something other than a long-term key. |
| 6 | [Mediator-signed staged receipts](identity-06-receipts.md) | Depends on phase 5. |
| 7 | [Service-scoped challenge-response login](identity-07-login.md) | Lowest value of the nine: it only affects the hosted web client's password replacement, and the current PBKDF2 path is already careful. Has its own prerequisite — see that file. |
| 8 | [Selective private receipt disclosure](identity-08-selective-disclosure.md) | Needs phase 6 to exist first. |
| 9 | [Hosted web-client integration and warnings](identity-09-hosted-webclient.md) | Last: touches the most surface (all in `http_webclient.cpp` — there's no separate `htdocs/` tree) and depends on everything above. |

## Two risks outside the identity scope that this plan does not fix

Flag these in the architecture report; don't silently fold them into a phase
that isn't about them.

- **Unauthenticated registry.** `RegistryRegisterMessage` carries no proof of
  control over a node — `src/registry.cpp:200-222` only prevents an
  unauthenticated *refresh* from stealing an already-registered pin (the
  intended heartbeat use case), it does not stop initial squatting on an
  unclaimed `host:port` with a fabricated pin, and there's no proof the
  registrant actually controls that endpoint. Identity work makes "run a
  hostile mediator" more valuable (a keyed reputation system is worth
  attacking), so this becomes higher priority, not lower, once any phase
  below ships. It's a registry-level fix, not an identity-system phase —
  track it separately, but land it before or alongside phase 6 (receipts),
  since receipts are the first thing a hostile mediator profits from
  forging.
- **TLS accept-loop concurrency — checked, and it's fine as-is.** The
  architecture report (`docs/identity-architecture-report.md`, verification
  item 2) confirms this is *not* unbounded: both the lobby and registry cap
  in-flight handshakes at `kMaxPendingHandshakes = 64` before spawning a
  thread at all, the lobby separately caps established clients at
  `kMaxClients = 128`, and each handshake is bounded to 10s
  (`SO_RCVTIMEO`/`SO_SNDTIMEO` in `SecureChannel::make_server`,
  `src/secure_channel.cpp:441-454`). Worst case is a few hundred live
  threads, not unbounded. Phase 7 (login) still extends time spent inside
  those already-capped windows by adding a challenge round trip before
  `Welcome` — worth being aware of when choosing challenge/response timeouts
  — but there is no separate "handshake pool" prerequisite to land first.
  This bullet originally claimed otherwise before the architecture report
  ran; corrected here rather than left wrong.

## Ground rules that apply to every phase (don't repeat per-file, but don't drop either)

- Optional feature. Existing unkeyed/password-based operation keeps working
  unless the architecture report says that's unsafe.
- Do not rank keyed users above unkeyed users. Do not display a key icon as a
  trust badge. A key means "controlled the same scoped key," nothing else.
- Small focused classes, not one identity manager. RAII for OpenSSL handles.
  Zero sensitive buffers where practical. Return structured errors, don't
  swallow crypto/persistence errors, don't silently regenerate a keystore or
  reset corrupted history.
- Canonical, versioned serialization for every signed object, with a
  domain-separation string per type (`TRADEP2P_LOGIN_CHALLENGE_V1`,
  `TRADEP2P_TRADE_MESSAGE_V1`, `TRADEP2P_RECEIPT_V1`,
  `TRADEP2P_JOURNAL_ENTRY_V1`, ...). No signing raw structs, no relying on
  compiler layout or JSON key order.
- Every phase: list files changed, new data structures, security invariants,
  compatibility impact; add unit tests, negative tests, serialization test
  vectors, malformed-input tests, migration handling where relevant; compile;
  run tests; report unresolved limitations honestly instead of glossing them.
- **User-manageable state gets wired into the appropriate CLI/dashboard in
  the same phase it's introduced — this is not deferred to phase 9.** Phase
  9 is specifically about the *hosted web client* (`tradep2p-webclient`), a
  separate binary with its own trust boundary; it is not a stand-in for "add
  a UI eventually." Match the surface to the trust boundary it belongs to
  (per the architecture report's §7):
  - `tradep2p_cli` (interactive client) and `tradep2p-dashboard` (loopback,
    single-operator HTTP UI) are where the end user's *own* identity state
    belongs: keystore create/unlock/lock/rotate/destroy, journal
    status/inspection, triggering a recovery request, local counterparty
    history/blocklist. Both are single-user, operator-is-the-user surfaces —
    fully appropriate for this.
  - `tradep2p-mediator-dashboard`/`tradep2p-registry-dashboard` are
    read-only operator/admin viewers with no protocol connection and no
    concept of a user identity — they should surface *operational* state a
    mediator/registry operator would care about (e.g. phase 3's room
    persistence: is it enabled, how many rooms were restored on last
    startup), never end-user keystore/history data, which they have no
    business seeing.
  - Phases 1-3 (crypto primitives, keystore, journal/recovery) landed
    library-only, with no CLI/dashboard wiring at all — this was a
    deliberate scoping choice at the time but is now a gap: there is
    currently no way for a user to actually create a keystore or see a
    journal entry. Phase 4 is required to close this gap for phases 2-3 as
    part of its own work, since phase 4 (local history/blocklist) is
    unusable without a keystore to unlock and a journal to read from in the
    first place — see `identity-04-local-history-blocklist.md`'s "CLI and
    dashboard wiring" section.

## The design tension this plan is resolving

A stable long-term public key is a *stronger* linker than the things this
codebase already goes out of its way to kill — `secure_channel.cpp` disables
TLS session tickets (`SSL_OP_NO_TICKET`, `SSL_CTX_set_num_tickets(ctx, 0)`,
`secure_channel.cpp:269,317`) specifically so TLS resumption can't correlate
sessions. A reputation key sitting in the offer book links every trade ever
made under it, permanently, to anyone who reads the offer book — including a
hostile mediator, which the unauthenticated registry above makes cheap to
become. That's not a weaker version of the existing privacy model, it's an
inversion of it, so treat "one key linked across trades" as the failure mode
to design against, not a simplification to accept for v1.

Separately: mediator acknowledgements are unverified claims by construction.
Two keypairs generated in a second can complete a hundred trades with zero
value moved and mint a spotless history — reputation from acks is reputation
about claim-making, not behavior, and costs nothing to farm. These are two
different problems with two different fixes, both deferred to phase 8:

- **Linkability** → blind-signed completion tokens. Chaumian blind signatures
  if you only need "I hold N completion tokens"; BBS+ if you want disclosed
  attributes (volume band, age band) without revealing which trades produced
  them. This fits the codebase's existing anonymity stance; it does nothing
  for Sybil resistance.
- **Sybil resistance** → cost anchoring, not social graph and not proof of
  work (a one-time amortizable tax). The fit for a non-custodial design: a
  reputation key publishes a bond address, and weight = value visibly at risk
  × age of that bond. Clients check a balance, not a trade history, so the
  mediator stays out of it and the design stays chain-agnostic. No slashing
  without a contract, but sunk cost plus age is a real, ongoing tax.

Also: receipts issued *at* completion let a defector refuse to sign and walk
away with nothing recorded for an otherwise-honest trade — withholding as
griefing. Phase 6 issues the penultimate receipt as a settlement step
*before* the final tranche so withholding costs the withholder the last leg
too; see that file.

And: "optional" tends not to stay optional in practice — once some offers
carry reputation, unkeyed offers get ignored and the anonymity set collapses
to "people with something to hide." The blind-credential route in phase 8 is
the one where opting in doesn't cost unlinkability, which is the only way
the keyed and unkeyed populations stay mixed. Keep that framing in mind when
implementing phases 4-7 even though phase 8 is last.
