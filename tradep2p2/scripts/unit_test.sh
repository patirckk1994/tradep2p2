#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"

if [[ ! -x "$BUILD_DIR/tradep2p_unit_tests" ]]; then
    echo "missing test binary: $BUILD_DIR/tradep2p_unit_tests" >&2
    echo "run scripts/build.sh first" >&2
    exit 1
fi

ctest --test-dir "$BUILD_DIR" --output-on-failure
