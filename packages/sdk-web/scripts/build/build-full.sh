#!/bin/bash

# Build WASM packages first, then build the SDK distribution.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"$SCRIPT_DIR/build-wasm.sh"
"$SCRIPT_DIR/build-sdk.sh"
