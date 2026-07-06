#!/bin/bash

# Build the Rust/WASM packages consumed by the SDK build.
#
# Modes:
# - dev:  release NEAR/HSS browser hot paths; dev/no-opt auxiliary runtimes.
# - prod: release all WASM packages.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SDK_ROOT/build-paths.sh"
source "$SCRIPT_DIR/wasm-toolchain.sh"
source "$SCRIPT_DIR/build-output-lock.sh"
cd "$SDK_ROOT"

echo "Starting WASM build for @seams/sdk..."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() { echo -e "${BLUE}📦 $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️ $1${NC}"; }

WASM_SDK_BUILD_MODE="${WASM_SDK_BUILD_MODE:-dev}"
case "$WASM_SDK_BUILD_MODE" in
  dev)
    DEFAULT_WASM_PROFILE_ARGS=(--dev --no-opt)
    DEFAULT_WASM_PROFILE_LABEL="dev"
    ;;
  prod)
    DEFAULT_WASM_PROFILE_ARGS=(--release)
    DEFAULT_WASM_PROFILE_LABEL="release"
    ;;
  *)
    print_error "Unknown WASM_SDK_BUILD_MODE: $WASM_SDK_BUILD_MODE"
    echo "Use one of: dev, prod"
    exit 1
    ;;
esac

require_file() {
  local path="$1"
  local canonical_path
  local attempt
  canonical_path="$(node -e "console.log(require('path').resolve(process.argv[1]))" "$path")"
  for attempt in {1..600}; do
    if [ -f "$path" ] || [ -f "$canonical_path" ]; then
      return
    fi
    sleep 0.1
  done

  print_error "Missing expected WASM build output: $path"
  print_error "Canonical path checked: $canonical_path"
  ls -la "$(dirname "$canonical_path")" || true
  exit 1
}

run_in_dir() {
  local dir="$1"
  shift
  pushd "$SDK_ROOT/$dir" >/dev/null
  "$@"
  popd >/dev/null
}

build_near_signer() {
  run_in_dir "$SOURCE_WASM_SIGNER" \
    with_hss_hot_path_rustflags \
      with_wasm_bindgen_cli_for_lockfile "$SDK_ROOT/$SOURCE_WASM_SIGNER/Cargo.lock" \
      wasm-pack build --target web --out-dir pkg --out-name wasm_signer_worker --release --features hss-client-exports

  run_in_dir "$SOURCE_WASM_SIGNER" \
    with_hss_hot_path_rustflags \
      with_wasm_bindgen_cli_for_lockfile "$SDK_ROOT/$SOURCE_WASM_SIGNER/Cargo.lock" \
      env CARGO_PROFILE_RELEASE_OPT_LEVEL=3 \
        wasm-pack build --target web --out-dir pkg-server --out-name wasm_signer_worker --release --features hss-server-exports
}

build_hss_client_signer() {
  run_in_dir "$SOURCE_WASM_HSS_CLIENT_SIGNER" \
    with_hss_hot_path_rustflags \
      with_wasm_bindgen_cli_for_lockfile "$SDK_ROOT/$SOURCE_WASM_HSS_CLIENT_SIGNER/Cargo.lock" \
      wasm-pack build --target web --out-dir pkg --out-name hss_client_signer --release
}

with_hss_hot_path_rustflags() {
  local existing="${RUSTFLAGS:-}"
  local simd_flag="-C target-feature=+simd128"
  local combined="$simd_flag"
  local status
  if [ -n "$existing" ]; then
    combined="$existing $simd_flag"
  fi
  export RUSTFLAGS="$combined"
  set +e
  "$@"
  status=$?
  set -e
  if [ -n "$existing" ]; then
    export RUSTFLAGS="$existing"
  else
    unset RUSTFLAGS
  fi
  return "$status"
}

build_profiled_wasm_crate() {
  local source_dir="$1"
  local out_name="$2"
  run_in_dir "$source_dir" \
    with_wasm_bindgen_cli_for_lockfile "$SDK_ROOT/$source_dir/Cargo.lock" \
    wasm-pack build --target web --out-dir pkg --out-name "$out_name" "${DEFAULT_WASM_PROFILE_ARGS[@]}"
}

JOB_PIDS=()
JOB_LABELS=()
JOB_LOGS=()
JOB_COUNT=0
JOB_LOG_DIR=""

cleanup_build_wasm() {
  if [ -n "$JOB_LOG_DIR" ]; then
    rm -rf "$JOB_LOG_DIR"
  fi
  release_build_output_lock
}

trap cleanup_build_wasm EXIT

prepare_job_wasm_pack_cache() {
  local job_index="$1"
  local job_cache="$JOB_LOG_DIR/wasm-pack-cache-$job_index"
  mkdir -p "$job_cache"
  if [ -n "${WASM_PACK_CACHE:-}" ] && [ -d "$WASM_PACK_CACHE" ]; then
    cp -R "$WASM_PACK_CACHE"/. "$job_cache"/ 2>/dev/null || true
  fi
  normalize_wasm_opt_cache_layout "$job_cache"
  printf '%s\n' "$job_cache"
}

start_job() {
  local label="$1"
  shift
  local job_index="$JOB_COUNT"
  local log_file="$JOB_LOG_DIR/job-$job_index.log"
  local job_wasm_pack_cache
  job_wasm_pack_cache="$(prepare_job_wasm_pack_cache "$job_index")"

  JOB_LABELS[$job_index]="$label"
  JOB_LOGS[$job_index]="$log_file"
  (
    set -e
    export WASM_PACK_CACHE="$job_wasm_pack_cache"
    echo "== $label =="
    "$@"
  ) >"$log_file" 2>&1 &
  JOB_PIDS[$job_index]=$!
  JOB_COUNT=$((JOB_COUNT + 1))
}

wait_for_jobs() {
  local failed=0
  local i

  for i in "${!JOB_PIDS[@]}"; do
    if wait "${JOB_PIDS[$i]}"; then
      cat "${JOB_LOGS[$i]}"
      print_success "${JOB_LABELS[$i]}"
    else
      cat "${JOB_LOGS[$i]}" >&2 || true
      print_error "${JOB_LABELS[$i]} failed"
      failed=1
    fi
  done

  if [ "$failed" -ne 0 ]; then
    exit 1
  fi
}

print_step "Checking WASM toolchain (C compiler for wasm32)..."
ensure_wasm32_cc
print_success "WASM toolchain ready"

print_step "Acquiring WASM output build lock..."
acquire_build_output_lock
print_success "WASM output build lock acquired"

print_step "Preparing wasm-pack cache..."
ensure_wasm_pack_cache
print_success "wasm-pack cache ready: $WASM_PACK_CACHE"
print_step "Using $WASM_SDK_BUILD_MODE WASM mode (default profile: $DEFAULT_WASM_PROFILE_LABEL)"

print_step "Cleaning previous WASM package outputs..."
rm -rf \
  "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg" \
  "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg-server" \
  "$SDK_ROOT/$SOURCE_WASM_HSS_CLIENT_SIGNER/pkg" \
  "$SDK_ROOT/$SOURCE_WASM_ETH_SIGNER/pkg" \
  "$SDK_ROOT/$SOURCE_WASM_TEMPO_SIGNER/pkg" \
  "$SDK_ROOT/$SOURCE_WASM_SHAMIR3PASS_RUNTIME/pkg" \
  "$SDK_ROOT/$SOURCE_WASM_EMAIL_OTP_RUNTIME/pkg" \
  "$SDK_ROOT/$SOURCE_WASM_THRESHOLD_PRF/pkg"
print_success "WASM package outputs cleaned"

print_step "Building WASM packages in parallel..."
JOB_LOG_DIR="$(mktemp -d)"
start_job "NEAR signer WASM (browser + server HSS release)" build_near_signer
start_job "HSS client signer WASM (release)" build_hss_client_signer
start_job "Eth signer WASM ($DEFAULT_WASM_PROFILE_LABEL)" build_profiled_wasm_crate "$SOURCE_WASM_ETH_SIGNER" eth_signer
start_job "Tempo signer WASM ($DEFAULT_WASM_PROFILE_LABEL)" build_profiled_wasm_crate "$SOURCE_WASM_TEMPO_SIGNER" tempo_signer
start_job "Shamir3Pass runtime WASM ($DEFAULT_WASM_PROFILE_LABEL)" build_profiled_wasm_crate "$SOURCE_WASM_SHAMIR3PASS_RUNTIME" shamir3pass_runtime
start_job "Email OTP runtime WASM ($DEFAULT_WASM_PROFILE_LABEL)" build_profiled_wasm_crate "$SOURCE_WASM_EMAIL_OTP_RUNTIME" email_otp_runtime
start_job "threshold-prf WASM ($DEFAULT_WASM_PROFILE_LABEL)" build_profiled_wasm_crate "$SOURCE_WASM_THRESHOLD_PRF" threshold_prf
wait_for_jobs

print_step "Optimizing wasm-pack metadata for tree-shaking..."
if node "$SDK_ROOT/scripts/build/fix-wasm-pack-sideeffects.mjs" "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg"; then
  print_success "WASM package metadata optimized"
else
  print_warning "Failed to optimize WASM package metadata; bundler may deoptimize tree-shaking"
fi
if node "$SDK_ROOT/scripts/build/fix-wasm-pack-sideeffects.mjs" "$SDK_ROOT/$SOURCE_WASM_HSS_CLIENT_SIGNER/pkg" 2>/dev/null; then
  print_success "HSS client WASM package metadata optimized"
else
  print_warning "Failed to optimize HSS client WASM package metadata"
fi
if node "$SDK_ROOT/scripts/build/fix-wasm-pack-sideeffects.mjs" "$SDK_ROOT/$SOURCE_WASM_ETH_SIGNER/pkg" 2>/dev/null; then
  print_success "Eth WASM package metadata optimized"
else
  print_warning "Failed to optimize Eth WASM package metadata"
fi
if node "$SDK_ROOT/scripts/build/fix-wasm-pack-sideeffects.mjs" "$SDK_ROOT/$SOURCE_WASM_TEMPO_SIGNER/pkg" 2>/dev/null; then
  print_success "Tempo WASM package metadata optimized"
else
  print_warning "Failed to optimize Tempo WASM package metadata"
fi
if node "$SDK_ROOT/scripts/build/fix-wasm-pack-sideeffects.mjs" "$SDK_ROOT/$SOURCE_WASM_SHAMIR3PASS_RUNTIME/pkg" 2>/dev/null; then
  print_success "Shamir3Pass runtime WASM package metadata optimized"
else
  print_warning "Failed to optimize Shamir3Pass runtime WASM package metadata"
fi
if node "$SDK_ROOT/scripts/build/fix-wasm-pack-sideeffects.mjs" "$SDK_ROOT/$SOURCE_WASM_EMAIL_OTP_RUNTIME/pkg" 2>/dev/null; then
  print_success "Email OTP runtime WASM package metadata optimized"
else
  print_warning "Failed to optimize Email OTP runtime WASM package metadata"
fi
if node "$SDK_ROOT/scripts/build/fix-wasm-pack-sideeffects.mjs" "$SDK_ROOT/$SOURCE_WASM_THRESHOLD_PRF/pkg" 2>/dev/null; then
  print_success "threshold-prf WASM package metadata optimized"
else
  print_warning "Failed to optimize threshold-prf WASM package metadata"
fi

print_step "Checking expected WASM package outputs..."
require_file "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg/wasm_signer_worker.js"
require_file "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg/wasm_signer_worker.d.ts"
require_file "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg/wasm_signer_worker_bg.wasm"
require_file "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg-server/wasm_signer_worker.js"
require_file "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg-server/wasm_signer_worker.d.ts"
require_file "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg-server/wasm_signer_worker_bg.wasm"
require_file "$SDK_ROOT/$SOURCE_WASM_HSS_CLIENT_SIGNER/pkg/hss_client_signer.js"
require_file "$SDK_ROOT/$SOURCE_WASM_HSS_CLIENT_SIGNER/pkg/hss_client_signer.d.ts"
require_file "$SDK_ROOT/$SOURCE_WASM_HSS_CLIENT_SIGNER/pkg/hss_client_signer_bg.wasm"
require_file "$SDK_ROOT/$SOURCE_WASM_ETH_SIGNER/pkg/eth_signer.js"
require_file "$SDK_ROOT/$SOURCE_WASM_ETH_SIGNER/pkg/eth_signer.d.ts"
require_file "$SDK_ROOT/$SOURCE_WASM_ETH_SIGNER/pkg/eth_signer_bg.wasm"
require_file "$SDK_ROOT/$SOURCE_WASM_TEMPO_SIGNER/pkg/tempo_signer.js"
require_file "$SDK_ROOT/$SOURCE_WASM_TEMPO_SIGNER/pkg/tempo_signer.d.ts"
require_file "$SDK_ROOT/$SOURCE_WASM_TEMPO_SIGNER/pkg/tempo_signer_bg.wasm"
require_file "$SDK_ROOT/$SOURCE_WASM_SHAMIR3PASS_RUNTIME/pkg/shamir3pass_runtime.js"
require_file "$SDK_ROOT/$SOURCE_WASM_SHAMIR3PASS_RUNTIME/pkg/shamir3pass_runtime.d.ts"
require_file "$SDK_ROOT/$SOURCE_WASM_SHAMIR3PASS_RUNTIME/pkg/shamir3pass_runtime_bg.wasm"
require_file "$SDK_ROOT/$SOURCE_WASM_EMAIL_OTP_RUNTIME/pkg/email_otp_runtime.js"
require_file "$SDK_ROOT/$SOURCE_WASM_EMAIL_OTP_RUNTIME/pkg/email_otp_runtime.d.ts"
require_file "$SDK_ROOT/$SOURCE_WASM_EMAIL_OTP_RUNTIME/pkg/email_otp_runtime_bg.wasm"
require_file "$SDK_ROOT/$SOURCE_WASM_THRESHOLD_PRF/pkg/threshold_prf.js"
require_file "$SDK_ROOT/$SOURCE_WASM_THRESHOLD_PRF/pkg/threshold_prf.d.ts"
require_file "$SDK_ROOT/$SOURCE_WASM_THRESHOLD_PRF/pkg/threshold_prf_bg.wasm"
print_success "Expected WASM package outputs are present"

print_success "WASM build completed successfully!"
