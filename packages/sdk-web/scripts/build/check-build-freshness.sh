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
    "$BUILD_WORKERS/$WORKER_EMAIL_OTP_RUNTIME_JS" \
    "$BUILD_WORKERS/$WORKER_EMAIL_OTP_RUNTIME_WASM" \
    "$BUILD_WORKERS/near_signer.wasm" \
    "$BUILD_ESM/index.js" \
    "$BUILD_ESM/SeamsWeb/index.js" \
    "$BUILD_ESM/react/index.js" \
    "$BUILD_ESM/react/styles/styles.css"; do
    if [ ! -f "$required" ]; then
        echo -e "${RED}❌ Required build output not found: $required${NC}"
        exit 1
    fi
done

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

hash_files_from_list() {
    local list_file="$1"
    if [ ! -s "$list_file" ]; then
        return 0
    fi

    if command -v shasum >/dev/null 2>&1; then
        while IFS= read -r path; do
            printf '%s\0' "$path"
        done < "$list_file" | xargs -0 shasum -a 256 -- | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        while IFS= read -r path; do
            printf '%s\0' "$path"
        done < "$list_file" | xargs -0 sha256sum -- | awk '{print $1}'
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
    local hash_count
    local tmp_file
    local hashes_file
    local path
    local path_count
    local paths_file
    tmp_file="$(mktemp)"
    paths_file="$(mktemp)"
    hashes_file="$(mktemp)"
    collect_build_inputs | awk 'NF' | LC_ALL=C sort -u > "$tmp_file"
    while IFS= read -r path; do
        [ -f "$path" ] || continue
        printf '%s\n' "$path"
    done < "$tmp_file" > "$paths_file"
    hash_files_from_list "$paths_file" > "$hashes_file"
    path_count="$(wc -l < "$paths_file")"
    hash_count="$(wc -l < "$hashes_file")"
    if [ "$path_count" -ne "$hash_count" ]; then
        echo -e "${RED}❌ Failed to hash every build input${NC}" >&2
        rm -f "$tmp_file" "$paths_file" "$hashes_file"
        exit 1
    fi
    paste "$paths_file" "$hashes_file" | hash_stdin
    rm -f "$tmp_file" "$paths_file" "$hashes_file"
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
            -newer "$BUILD_FRESHNESS_MARKER" -print
    elif [ -f "$path" ] && [ "$path" -nt "$BUILD_FRESHNESS_MARKER" ]; then
        printf '%s\n' "$path"
    fi
}

STALE_BUILD=false
STALE_FILES=()

if [ ! -f "$BUILD_INPUT_MANIFEST" ]; then
    STALE_BUILD=true
    STALE_FILES+=("$BUILD_INPUT_MANIFEST (missing build input manifest)")
fi

# The manifest is written after the SDK build finishes, so it is a cheap
# completion marker. Normal freshness checks avoid hashing every source input;
# builds still write a content hash through --print-input-hash for audit/debug.
BUILD_FRESHNESS_MARKER="$BUILD_INPUT_MANIFEST"

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
