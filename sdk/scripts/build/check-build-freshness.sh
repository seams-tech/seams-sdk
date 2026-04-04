#!/bin/bash

# Check if built SDK files are newer than source files
# This prevents tests from importing stale versions

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$SDK_ROOT"

# Source centralized build configuration
source "$SDK_ROOT/build-paths.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if dist directory exists
if [ ! -d "$BUILD_ROOT" ]; then
    echo -e "${RED}❌ Build directory '$BUILD_ROOT' does not exist${NC}"
    exit 1
fi

# Check if key built files exist
for required in \
    "$BUILD_WORKERS/$WORKER_SIGNER" \
    "$BUILD_WORKERS/$WORKER_HSS_CLIENT" \
    "$BUILD_WORKERS/$WORKER_TOUCH_CONFIRM" \
    "$BUILD_WORKERS/$WORKER_SHAMIR3PASS" \
    "$BUILD_WORKERS/$WORKER_ETH_SIGNER" \
    "$BUILD_WORKERS/$WORKER_TEMPO_SIGNER" \
    "$BUILD_WORKERS/$WORKER_WASM_ETH_SIGNER_WASM" \
    "$BUILD_WORKERS/$WORKER_WASM_TEMPO_SIGNER_WASM" \
    "$BUILD_WORKERS/$WORKER_SHAMIR3PASS_RUNTIME_JS" \
    "$BUILD_WORKERS/$WORKER_SHAMIR3PASS_RUNTIME_WASM" \
    "$BUILD_WORKERS/near_signer.wasm" \
    "$BUILD_ESM/index.js" \
    "$BUILD_ESM/core/TatchiPasskey/index.js" \
    "$BUILD_ESM/react/index.js" \
    "$BUILD_ESM/react/styles/styles.css"; do
    if [ ! -f "$required" ]; then
        echo -e "${RED}❌ Required build output not found: $required${NC}"
        exit 1
    fi
done

get_mtime() {
    stat -f %m "$1" 2>/dev/null || stat -c %Y "$1" 2>/dev/null || echo "0"
}

find_newer_sources() {
    local path="$1"
    if [ -d "$path" ]; then
        find "$path" -type f \( -name "*.ts" -o -name "*.js" -o -name "*.json" -o -name "*.rs" -o -name "*.toml" \) -newer "$LATEST_BUILD_PATH" -print
    elif [ -f "$path" ] && [ "$path" -nt "$LATEST_BUILD_PATH" ]; then
        printf '%s\n' "$path"
    fi
}

# Track the newest build artifact path directly so freshness checks can use
# `find -newer` instead of a bash loop that stats every source file.
LATEST_BUILD_PATH="$BUILD_ROOT"
LATEST_BUILD_TIME=$(get_mtime "$LATEST_BUILD_PATH")
for built in \
    "$BUILD_WORKERS/$WORKER_SIGNER" \
    "$BUILD_WORKERS/$WORKER_HSS_CLIENT" \
    "$BUILD_WORKERS/$WORKER_TOUCH_CONFIRM" \
    "$BUILD_WORKERS/$WORKER_SHAMIR3PASS" \
    "$BUILD_WORKERS/$WORKER_ETH_SIGNER" \
    "$BUILD_WORKERS/$WORKER_TEMPO_SIGNER" \
    "$BUILD_WORKERS/$WORKER_WASM_ETH_SIGNER_WASM" \
    "$BUILD_WORKERS/$WORKER_WASM_TEMPO_SIGNER_WASM" \
    "$BUILD_WORKERS/$WORKER_SHAMIR3PASS_RUNTIME_JS" \
    "$BUILD_WORKERS/$WORKER_SHAMIR3PASS_RUNTIME_WASM" \
    "$BUILD_WORKERS/near_signer.wasm" \
    "$BUILD_ESM/index.js" \
    "$BUILD_ESM/core/TatchiPasskey/index.js" \
    "$BUILD_ESM/react/index.js" \
    "$BUILD_ESM/react/styles/styles.css" \
    "$BUILD_CJS/index.cjs" \
    "$BUILD_TYPES/client/src/index.d.ts"; do
    if [ -f "$built" ]; then
        FILE_TIME=$(get_mtime "$built")
        if [ "$FILE_TIME" -gt "$LATEST_BUILD_TIME" ]; then
            LATEST_BUILD_TIME="$FILE_TIME"
            LATEST_BUILD_PATH="$built"
        fi
    fi
done

# Check if any source files are newer than the build
STALE_BUILD=false
STALE_FILES=()

# Check critical directories
for dir in "${CRITICAL_DIRS[@]}"; do
    while IFS= read -r file; do
        [ -n "$file" ] || continue
        STALE_BUILD=true
        STALE_FILES+=("$file")
    done < <(find_newer_sources "$dir")
done

# Check critical files
for file in "${CRITICAL_FILES[@]}"; do
    while IFS= read -r stale; do
        [ -n "$stale" ] || continue
        STALE_BUILD=true
        STALE_FILES+=("$stale")
    done < <(find_newer_sources "$file")
done

# Report results
if [ "$STALE_BUILD" = true ]; then
    echo -e "${RED}❌ Build is stale${NC}"
    echo -e "${YELLOW}Files newer than build:${NC}"
    for file in "${STALE_FILES[@]}"; do
        echo -e "  - $file"
    done
    exit 1
else
    echo -e "${GREEN}✅ Build is fresh${NC}"
    exit 0
fi
