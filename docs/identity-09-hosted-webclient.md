# Prompt: Phase 9 — hosted web-client integration and warnings

Prerequisite: `docs/identity-architecture-report.md` and phases 1-7 (crypto
primitives, keystore, journal/recovery, local history, ephemeral trade
identities, receipts, login) should already be merged — this phase wires
all of them into the hosted web client, so it's last. Phase 8 (selective
disclosure) is not a hard dependency but should exist per the plan order.
Paste this file plus the architecture report into a fresh session.

---

## Context

Phase 9 of the identity plan — the last one, and the one touching the most
existing surface. Per the architecture report (§1, §7), there is no
`htdocs/` or separate static-assets directory in this repository — all
served HTML/CSS/JS is inlined server-side in `src/http_webclient.cpp`
(`app_html()` and neighboring functions). That single file is both the
server logic and the entire browser-side surface for this phase; treat
"which files does this phase touch" as meaning that file's inlined
`<script>` blocks, not a separate frontend tree. It depends on everything
above, which is why it's scheduled last even though it was written earlier
in the original conceptual ordering.

## The honest threat model for a hosted key

State this plainly in the phase report and in whatever user-facing docs
this phase adds — don't soften it:

**A hosted page cannot protect a private key from a malicious or
compromised operator who controls the JavaScript delivered to the
browser.** No amount of client-side crypto changes that, because the
operator can always ship a build that exfiltrates the key to whoever is
running the page.

Therefore:

- Describe browser-key login (phase 7's challenge-response, as surfaced in
  the browser) as protection against **stored-password compromise** — e.g.
  a leaked `webclient-accounts.tsv`-equivalent, a database dump, credential
  stuffing from reuse elsewhere.
- Do **not** claim it protects against a hostile web operator. If existing
  marketing copy, README text, or in-app help text implies otherwise, fix
  the wording as part of this phase.
- Prefer, where feasible given the architecture report's constraints:
  WebAuthn, an external signer, a browser extension, a local companion
  service, or the native client — in roughly that order of preference for a
  browser context, native/CLI as the strongest option outside the browser
  entirely.
- Keep private-key export disabled by default in the browser client.
- Any browser key backup flow must be explicit and strongly warned — not a
  quiet "export" button next to routine settings.

## Do not weaken the native/CLI threat model to make the browser easier

If any part of phases 1-7 was implemented with a browser-friendly shortcut
in mind (e.g. weaker KDF parameters, relaxed replay windows, permissive
key-export defaults), check for that now and reject it — the CLI/native
threat model should not have been softened for this. If you find such a
shortcut already in the codebase from an earlier phase, flag it in this
phase's report rather than quietly building further on it.

## What this phase actually wires up

- Browser-side: generate/hold ephemeral trade keys (phase 5) behind
  whichever of the mechanisms above is chosen, surface local history/
  blocklist (phase 4) in the existing dashboard/web UI, surface receipts
  (phase 6) read-only unless explicit disclosure (phase 8) is invoked by the
  user.
- Server-side (the loopback/HTTP-facing part of the web client, per the
  architecture report's description of its trust boundary): wire phase 7's
  challenge-response as an option alongside the existing password path,
  including the migration handling that phase already specified.
- UI: no key icon presented as a trust badge (carried forward from
  `docs/IDENTITY-PLAN.md`'s ground rules) — a key means "controlled the same
  scoped key," and the UI copy must not imply more than that.

## Backward compatibility

Existing password-based operation continues to function. Do not allow
keyed users to silently exclude unkeyed users by default in any web-client
UI surface (e.g. offer filtering that defaults to hiding unkeyed offers) —
if such a filter is added at all, it must be an explicit user opt-in, not a
default.

Note honestly in the phase report: "do not silently exclude unkeyed users"
is a client-side UI policy, not something enforceable at the protocol
level — any forked or self-hosted client can ignore it. Document it as an
intention for this client's own UI, not a guarantee about the ecosystem.

## Tests to add

- Login: both password path and key-based challenge-response path work
  end-to-end through the browser-facing flow; migration path from phase 7
  is exercised through the actual web UI, not just the underlying protocol
  test.
- Key export is disabled by default; enabling it requires the explicit
  warned flow, and the resulting export is still encrypted per phase 2's
  keystore rules unless the user takes the separate, explicitly-dangerous
  plaintext path (if that path exists at all).
- Ephemeral trade key generation/display in the browser UI doesn't leak the
  underlying long-term identity (visual/DOM inspection-level check, not just
  a protocol-level unit test).
- UI copy/labels reviewed for any "verified"/"trusted"/"safe" language
  attached to keyed participants — this should fail a review if found, not
  just get caught informally.
- Existing unkeyed flows (offer creation, joining, trading) are unaffected —
  run the existing web-client test suite and confirm no regression.

## Deliverable checklist for this phase

- List files changed (this is realistically `src/http_webclient.cpp` for
  both the server logic and its inlined browser-side script, per the note
  above that no separate `htdocs/` tree exists).
- Explain new data flows between browser and the local HTTP-facing server
  process, and where each key/secret lives at each step.
- Explain security invariants: the honest hosted-key threat model above,
  default-disabled export, no trust-badge UI language.
- Explain compatibility impact: dual login paths, migration, no default
  exclusion of unkeyed users.
- Add all tests above.
- Compile, run the full test suite (not just this phase's new tests — this
  phase touches the most shared surface of the nine), and actually exercise
  the web UI in a browser per this project's usual verification approach
  before calling it done.
- Report unresolved limitations honestly, including a plain restatement of
  what a hosted key does and does not protect against, suitable for putting
  directly in user-facing docs.
