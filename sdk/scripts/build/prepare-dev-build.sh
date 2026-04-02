#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$SDK_ROOT"

source "$SDK_ROOT/build-paths.sh"

if [ ! -d "$BUILD_ROOT" ]; then
  pnpm run build
  exit 0
fi

if "$SCRIPT_DIR/check-build-freshness.sh" >/dev/null 2>&1; then
  printf '\033[0;32m✅ Build is fresh\033[0m\n'
  exit 0
fi

pnpm run build
