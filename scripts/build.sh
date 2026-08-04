#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}"

cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="${BUILD_TYPE:-Debug}"
cmake --build "$BUILD_DIR" -j "$JOBS"

echo "built: $BUILD_DIR/tradep2p_cli"
echo "built: $BUILD_DIR/tradep2p-dashboard"
echo "built: $BUILD_DIR/tradep2p_unit_tests"
