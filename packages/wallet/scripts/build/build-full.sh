#!/bin/bash

# Build WASM packages first, then build the SDK distribution.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/build-output-lock.sh"

cleanup_build_full() {
  release_build_output_lock
}

trap cleanup_build_full EXIT

acquire_build_output_lock
"$SCRIPT_DIR/build-wasm.sh"
"$SCRIPT_DIR/build-sdk.sh"
