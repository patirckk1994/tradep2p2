#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"$ROOT/scripts/build.sh"
"$ROOT/scripts/unit_test.sh"
"$ROOT/scripts/demo_io.sh"
