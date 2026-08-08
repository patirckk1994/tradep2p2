#!/usr/bin/env bash
# Promotes the current testing state (this checkout) to production: runs the
# test suite here first, fast-forwards main to match, pushes to GitHub,
# rebuilds the production worktree from main, refreshes the production
# website with the tested PHP/asset files and a fresh source zip (git
# archive - never uploads build output or secrets), and restarts the
# production mediator/dashboard from the freshly built binaries.
#
# Hosted trading (tradep2p-webclient) is retired - deploy.sh only ensures
# it stays down, it never (re)launches it. If it comes back intentionally,
# restore the launch+health-check block from git history.
#
# Deliberately does NOT touch either side's config.php (they intentionally
# differ - different ports, different "TESTING environment" label) or the
# downloads/ directory beyond the zip file itself.
#
# Run this from the TESTING checkout (the branch you've been developing and
# verifying on) - not from the production worktree.
set -euo pipefail

# --- Layout - override via environment if your paths differ. ---
TESTING_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRODUCTION_REPO="${PRODUCTION_REPO:-$TESTING_REPO-production}"
TESTING_WEB="${TESTING_WEB:-/var/www/html/testing}"
PRODUCTION_WEB="${PRODUCTION_WEB:-/var/www/html/new}"
GIT_REMOTE="${GIT_REMOTE:-test}"
PRODUCTION_BRANCH="${PRODUCTION_BRANCH:-main}"

# Files synced verbatim from the testing website to production - everything
# EXCEPT config.php (intentionally different per environment) and
# downloads/ (the zip is rebuilt and placed there separately, below).
WEB_SYNC_ITEMS=(index.php documentation.php webclient.php status.php
                admin-df7bffc8.php assets README.md .htaccess)

log() { echo "==> $*"; }
fail() { echo "FATAL: $*" >&2; exit 1; }

[[ -d "$TESTING_REPO/.git" || -f "$TESTING_REPO/.git" ]] || fail "not a git checkout: $TESTING_REPO"
[[ -d "$PRODUCTION_REPO" ]] || fail "production worktree not found at $PRODUCTION_REPO - see git worktree add"
[[ -d "$TESTING_WEB" ]] || fail "testing website not found at $TESTING_WEB"
[[ -d "$PRODUCTION_WEB" ]] || fail "production website not found at $PRODUCTION_WEB"

cd "$TESTING_REPO"
TESTING_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
[[ "$TESTING_BRANCH" != "HEAD" ]] || fail "testing checkout is in detached-HEAD state"
[[ "$TESTING_BRANCH" != "$PRODUCTION_BRANCH" ]] || fail "refusing to deploy FROM $PRODUCTION_BRANCH - run this from your testing branch"

if [[ -n "$(git status --porcelain)" ]]; then
    fail "uncommitted changes in $TESTING_REPO - commit or stash before deploying"
fi

log "building and testing $TESTING_BRANCH in $TESTING_REPO ..."
cmake --build "$TESTING_REPO/build" -j"$(nproc)"
for t in tradep2p_unit_tests tradep2p_journal_tests tradep2p_recovery_tests \
         tradep2p_receipt_tests tradep2p_login_tests tradep2p_keystore_tests \
         tradep2p_identity_tests tradep2p_history_tests tradep2p_recognition_tests \
         tradep2p_ephemeral_tests tradep2p_disclosure_tests; do
    bin="$TESTING_REPO/build/$t"
    [[ -x "$bin" ]] || continue
    log "  $t"
    "$bin"
done

# main is checked out in the production worktree, so it can't be
# force-moved from here (git refuses to update a branch checked out
# elsewhere) - push straight to the remote ref instead. git itself then
# enforces the fast-forward-only guarantee server-side (a real check
# against the remote's actual current state, not a possibly-stale local
# ref), so a diverged main safely aborts here rather than silently
# rewriting history.
log "fetching $PRODUCTION_BRANCH from $GIT_REMOTE for an up-to-date fast-forward check ..."
git fetch "$GIT_REMOTE" "$PRODUCTION_BRANCH"

log "pushing $TESTING_BRANCH to $GIT_REMOTE ..."
git push "$GIT_REMOTE" "$TESTING_BRANCH"

log "fast-forwarding $GIT_REMOTE/$PRODUCTION_BRANCH to $TESTING_BRANCH ..."
git push "$GIT_REMOTE" "$TESTING_BRANCH:$PRODUCTION_BRANCH"

log "updating production worktree ($PRODUCTION_REPO) ..."
cd "$PRODUCTION_REPO"
git checkout "$PRODUCTION_BRANCH"
git merge --ff-only "$GIT_REMOTE/$PRODUCTION_BRANCH"

log "building production ..."
mkdir -p build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build build -j"$(nproc)"
for t in tradep2p_unit_tests tradep2p_journal_tests tradep2p_recovery_tests tradep2p_receipt_tests; do
    bin="build/$t"
    [[ -x "$bin" ]] || continue
    log "  production: $t"
    "$bin"
done

log "building source zip from production HEAD ..."
ZIP_TMP="$(mktemp)"
git archive HEAD --prefix=tradep2p2/ --format=zip -o "$ZIP_TMP"

log "syncing website files: $TESTING_WEB -> $PRODUCTION_WEB (config.php untouched) ..."
for item in "${WEB_SYNC_ITEMS[@]}"; do
    src="$TESTING_WEB/$item"
    [[ -e "$src" ]] || continue
    rm -rf "${PRODUCTION_WEB:?}/$item"
    cp -r "$src" "$PRODUCTION_WEB/$item"
done
# protocol_spec.md is canonically the git repo's copy, not the website's.
cp "$PRODUCTION_REPO/protocol_spec.md" "$PRODUCTION_WEB/protocol_spec.md"
mkdir -p "$PRODUCTION_WEB/downloads"
mv "$ZIP_TMP" "$PRODUCTION_WEB/downloads/tradep2p2.zip"
chmod 644 "$PRODUCTION_WEB/downloads/tradep2p2.zip"
# Keep the testing site's own download link current too.
cp "$PRODUCTION_WEB/downloads/tradep2p2.zip" "$TESTING_WEB/downloads/tradep2p2.zip"

log "restarting production services ..."
pkill -f "$PRODUCTION_REPO/build/tradep2p_cli mediator" 2>/dev/null || true
pkill -f "$PRODUCTION_REPO/build/tradep2p-mediator-dashboard" 2>/dev/null || true
pkill -f "$PRODUCTION_REPO/build/tradep2p-webclient client" 2>/dev/null || true
sleep 1

cd "$PRODUCTION_REPO"
nohup ./setup_mediator.sh >/tmp/tradep2p-production-mediator.log 2>&1 &
disown
sleep 2

log "health check ..."
curl -sf -o /dev/null "http://127.0.0.1:8091/" || fail "production mediator dashboard did not come up - see /tmp/tradep2p-production-mediator.log"

log "deploy complete: $TESTING_BRANCH -> $PRODUCTION_BRANCH, pushed, rebuilt, website synced, services restarted."
