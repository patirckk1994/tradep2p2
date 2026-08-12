#!/usr/bin/env bash
set -euo pipefail

# Deterministic q=7933 CLI harness.
#
# Modes:
#   fast   - deterministic user-blind twice + JSON/error-contract checks
#   nizk1  - fast + a real NIZK1 prove/verify (~11.5 min on the reference machine)
#   nizk2  - fast + a real NIZK2 prove/verify using the committed genuine C++ fixture (~5 min)
#   full   - fast + both real proofs
#
# Every stdout/stderr/receipt/request is retained under OUT_DIR for later
# inspection. The deterministic seed flag is TEST-ONLY and must never be
# used for a real credential.

MODE="${1:-fast}"
OUT_DIR="${2:-cli-test-artifacts}"

case "$MODE" in
  fast|nizk1|nizk2|full) ;;
  *)
    echo "usage: $0 [fast|nizk1|nizk2|full] [output-dir]" >&2
    exit 2
    ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

BIN="$ROOT/target/release/blindsig-prover-q7933"
TEST_SEED_HEX="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
MU="q7933-cli-deterministic-v1"

# Deterministic, canonical B: B[i] = (7 + 41*i) mod 7933, encoded as the
# CLI's fixed-width big-endian-looking u16 hex text (four hex digits/value).
B_HEX="$(python3 - <<'PY'
print(''.join(f'{(7 + 41*i) % 7933:04x}' for i in range(512)))
PY
)"

echo "[1/5] building q7933 CLI" >&2
cargo build -p blindsig-prover-q7933 --release \
  >"$OUT_DIR/build.stdout" 2>"$OUT_DIR/build.stderr"

echo "[2/5] deterministic user-blind replay" >&2
"$BIN" user-blind \
  --b-hex "$B_HEX" \
  --mu "$MU" \
  --deterministic-seed-hex "$TEST_SEED_HEX" \
  >"$OUT_DIR/blind_1.json" 2>"$OUT_DIR/blind_1.stderr"

"$BIN" user-blind \
  --b-hex "$B_HEX" \
  --mu "$MU" \
  --deterministic-seed-hex "$TEST_SEED_HEX" \
  >"$OUT_DIR/blind_2.json" 2>"$OUT_DIR/blind_2.stderr"

python3 - "$OUT_DIR" <<'PY'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
a = json.loads((out / 'blind_1.json').read_text())
b = json.loads((out / 'blind_2.json').read_text())
assert a == b, 'deterministic user-blind replay changed output'
assert a.get('ok') is True
assert len(a['public']['b']) == 512
assert len(a['public']['c']) == 512
assert len(a['private']['r']) == 512
assert len(bytes.fromhex(a['public']['rho_hex'])) == 32
assert len(bytes.fromhex(a['private']['coins_hex'])) == 32

instance = dict(a)
instance.pop('ok', None)
(out / 'nizk1_instance.json').write_text(json.dumps(instance, sort_keys=True, separators=(',', ':')) + '\n')

p = a['public']
expected = {
    k: p[k] for k in (
        'b', 'c', 'enc_a', 'enc_pk',
        'ct1_r', 'ct2_r', 'ct1_mu', 'ct2_mu'
    )
}
(out / 'nizk1_expected.json').write_text(json.dumps(expected, sort_keys=True, separators=(',', ':')) + '\n')
PY

echo "[3/5] JSON failure contract" >&2
set +e
"$BIN" user-blind --b-hex 0000 --mu bad \
  >"$OUT_DIR/bad_b.json" 2>"$OUT_DIR/bad_b.stderr"
BAD_RC=$?
"$BIN" definitely-not-a-command \
  >"$OUT_DIR/bad_command.json" 2>"$OUT_DIR/bad_command.stderr"
BAD_CMD_RC=$?
set -e
printf '%s\n' "$BAD_RC" >"$OUT_DIR/bad_b.exitcode"
printf '%s\n' "$BAD_CMD_RC" >"$OUT_DIR/bad_command.exitcode"

python3 - "$OUT_DIR" <<'PY'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
for stem in ('bad_b', 'bad_command'):
    v = json.loads((out / f'{stem}.json').read_text())
    assert v.get('ok') is False, f'{stem}: failure must still be one JSON object with ok=false'
    assert int((out / f'{stem}.exitcode').read_text()) != 0
PY

if [[ "$MODE" == "nizk1" || "$MODE" == "full" ]]; then
  echo "[4/5] REAL NIZK1 prove + receipt verification" >&2
  RUST_LOG="${RUST_LOG:-info}" "$BIN" user-prove-nizk1 \
    --pi1-out "$OUT_DIR/pi1.receipt" \
    <"$OUT_DIR/nizk1_instance.json" \
    >"$OUT_DIR/nizk1_prove.json" 2>"$OUT_DIR/nizk1_prove.stderr"

  "$BIN" signer-verify-nizk1 \
    --pi1-in "$OUT_DIR/pi1.receipt" \
    <"$OUT_DIR/nizk1_expected.json" \
    >"$OUT_DIR/nizk1_verify.json" 2>"$OUT_DIR/nizk1_verify.stderr"

  python3 - "$OUT_DIR" <<'PY'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
p = json.loads((out / 'nizk1_prove.json').read_text())
v = json.loads((out / 'nizk1_verify.json').read_text())
assert p.get('ok') is True
assert v.get('ok') is True and v.get('verified') is True
PY
fi

if [[ "$MODE" == "nizk2" || "$MODE" == "full" ]]; then
  echo "[4/5] constructing NIZK2 request from committed genuine C++ signature fixture" >&2
  python3 - "$ROOT" "$OUT_DIR" <<'PY'
import json, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
blinded = (root / 'methods/examples/data/blinded_target_data.rs').read_text()
cross = (root / 'methods/examples/data/rust_crosscheck_data.rs').read_text()

def array(text, name):
    pat = rf'pub const {re.escape(name)}:\s*\[[^;\]]+;\s*(\d+)\]\s*=\s*\[(.*?)\];'
    m = re.search(pat, text, re.S)
    if not m:
        raise SystemExit(f'could not parse Rust fixture array {name}')
    declared = int(m.group(1))
    body = m.group(2).strip()
    rep = re.fullmatch(r'(-?\d+)\s*;\s*(\d+)', body)
    if rep:
        vals = [int(rep.group(1))] * int(rep.group(2))
    else:
        vals = [int(x.strip()) for x in body.split(',') if x.strip()]
    if len(vals) != declared:
        raise SystemExit(f'{name}: parsed {len(vals)}, declared {declared}')
    return vals

def rust_string(text, name):
    m = re.search(rf'pub const {re.escape(name)}:\s*&str\s*=\s*"([^"]*)"\s*;', text)
    if not m:
        raise SystemExit(f'could not parse Rust fixture string {name}')
    return m.group(1)

B = array(blinded, 'B')
R = array(blinded, 'R')
RHO = array(blinded, 'RHO')
MU = rust_string(blinded, 'MU')
T = array(cross, 'T')
S0 = array(cross, 'BLINDED_S0')
S1 = array(cross, 'BLINDED_S1')
rho_hex = bytes(RHO).hex()

request = {
    't': [x % 7933 for x in T],
    'b': [x % 7933 for x in B],
    'rho_hex': rho_hex,
    'mu': MU,
    'r': R,
    's0': S0,
    's1': S1,
}
expected = {
    't': request['t'],
    'b': request['b'],
    'rho_hex': rho_hex,
    'mu': MU,
}
(out / 'nizk2_request.json').write_text(json.dumps(request, sort_keys=True, separators=(',', ':')) + '\n')
(out / 'nizk2_expected.json').write_text(json.dumps(expected, sort_keys=True, separators=(',', ':')) + '\n')
PY

  echo "[4/5] REAL NIZK2 prove + receipt verification" >&2
  RUST_LOG="${RUST_LOG:-info}" "$BIN" user-finalize-prove-nizk2 \
    --pi2-out "$OUT_DIR/pi2.receipt" \
    <"$OUT_DIR/nizk2_request.json" \
    >"$OUT_DIR/nizk2_prove.json" 2>"$OUT_DIR/nizk2_prove.stderr"

  "$BIN" verify-signature \
    --pi2-in "$OUT_DIR/pi2.receipt" \
    <"$OUT_DIR/nizk2_expected.json" \
    >"$OUT_DIR/nizk2_verify.json" 2>"$OUT_DIR/nizk2_verify.stderr"

  python3 - "$OUT_DIR" <<'PY'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
p = json.loads((out / 'nizk2_prove.json').read_text())
v = json.loads((out / 'nizk2_verify.json').read_text())
assert p.get('ok') is True
assert v.get('ok') is True and v.get('verified') is True
PY
fi

echo "[5/5] writing analysis manifest" >&2
python3 - "$OUT_DIR" "$MODE" <<'PY'
import hashlib, json, pathlib, platform, sys
out = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
entries = {}
for path in sorted(p for p in out.iterdir() if p.is_file() and p.name != 'manifest.json'):
    data = path.read_bytes()
    entries[path.name] = {
        'bytes': len(data),
        'sha256': hashlib.sha256(data).hexdigest(),
    }
manifest = {
    'mode': mode,
    'platform': platform.platform(),
    'artifacts': entries,
}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
PY

printf '\nPASS: q7933 CLI deterministic harness (%s)\nArtifacts: %s\n' "$MODE" "$ROOT/$OUT_DIR"
