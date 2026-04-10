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

BUILD_INPUT_MANIFEST="$BUILD_ROOT/.build-inputs.sha256"

find_source_files() {
    local root="$1"
    find "$root" \
        \( -name target -o -name pkg -o -name pkg-server -o -name node_modules -o -name dist -o -name .git \) -prune -o \
        -type f \( \
            -name "*.ts" -o \
            -name "*.tsx" -o \
            -name "*.js" -o \
            -name "*.mjs" -o \
            -name "*.json" -o \
            -name "*.css" -o \
            -name "*.rs" -o \
            -name "*.toml" -o \
            -name "*.sh" \
        \) -print
}

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

hash_file() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        echo -e "${RED}❌ Neither 'shasum' nor 'sha256sum' is available${NC}" >&2
        exit 1
    fi
}

hash_stdin() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{print $1}'
    else
        echo -e "${RED}❌ Neither 'shasum' nor 'sha256sum' is available${NC}" >&2
        exit 1
    fi
}

collect_build_inputs() {
    local path
    for path in "${CRITICAL_DIRS[@]}"; do
        if [ -d "$path" ]; then
            find_source_files "$path"
        fi
    done

    for path in "${CRITICAL_FILES[@]}"; do
        if [ -d "$path" ]; then
            find_source_files "$path"
        elif [ -f "$path" ]; then
            printf '%s\n' "$path"
        fi
    done

    find "$SDK_ROOT/scripts/build" -type f \( -name "*.sh" -o -name "*.mjs" \) -print
    find "$SDK_ROOT/scripts/checks" -type f \( -name "*.sh" -o -name "*.mjs" \) -print
}

compute_build_inputs_hash() {
    local tmp_file
    local path
    tmp_file="$(mktemp)"
    collect_build_inputs | awk 'NF' | LC_ALL=C sort -u > "$tmp_file"
    while IFS= read -r path; do
        [ -f "$path" ] || continue
        printf '%s\t%s\n' "$path" "$(hash_file "$path")"
    done < "$tmp_file" | hash_stdin
    rm -f "$tmp_file"
}

if [ "${1:-}" = "--print-input-hash" ]; then
    compute_build_inputs_hash
    exit 0
fi

find_newer_sources() {
    local path="$1"
    if [ -d "$path" ]; then
        find "$path" \
            \( -name target -o -name pkg -o -name pkg-server -o -name node_modules -o -name dist -o -name .git \) -prune -o \
            -type f \( -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.mjs" -o -name "*.json" -o -name "*.css" -o -name "*.rs" -o -name "*.toml" -o -name "*.sh" \) \
            -newer "$LATEST_BUILD_PATH" -print
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

CURRENT_INPUT_HASH="$(compute_build_inputs_hash)"
STORED_INPUT_HASH=""
if [ -f "$BUILD_INPUT_MANIFEST" ]; then
    STORED_INPUT_HASH="$(tr -d '[:space:]' < "$BUILD_INPUT_MANIFEST")"
fi

STALE_BUILD=false
STALE_FILES=()
if [ -z "$STORED_INPUT_HASH" ]; then
    STALE_BUILD=true
    STALE_FILES+=("$BUILD_INPUT_MANIFEST (missing build input manifest)")
elif [ "$CURRENT_INPUT_HASH" != "$STORED_INPUT_HASH" ]; then
    STALE_BUILD=true
    STALE_FILES+=("build input hash changed")
fi

if [ "$STALE_BUILD" = false ]; then
    for dir in "${CRITICAL_DIRS[@]}"; do
        while IFS= read -r file; do
            [ -n "$file" ] || continue
            STALE_BUILD=true
            STALE_FILES+=("$file")
        done < <(find_newer_sources "$dir")
    done

    for file in "${CRITICAL_FILES[@]}"; do
        while IFS= read -r stale; do
            [ -n "$stale" ] || continue
            STALE_BUILD=true
            STALE_FILES+=("$stale")
        done < <(find_newer_sources "$file")
    done
fi

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
