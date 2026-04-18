#!/bin/bash

# Build the Rust/WASM packages consumed by the SDK build.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SDK_ROOT/build-paths.sh"
source "$SCRIPT_DIR/wasm-toolchain.sh"
cd "$SDK_ROOT"

echo "Starting WASM build for @tatchi-xyz/sdk..."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() { echo -e "${BLUE}📦 $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️ $1${NC}"; }

require_file() {
  local path="$1"
  if [ ! -f "$path" ]; then
    print_error "Missing expected WASM build output: $path"
    exit 1
  fi
}

print_step "Checking WASM toolchain (C compiler for wasm32)..."
ensure_wasm32_cc
print_success "WASM toolchain ready"

print_step "Preparing wasm-pack cache..."
ensure_wasm_pack_cache
print_success "wasm-pack cache ready: $WASM_PACK_CACHE"

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

print_step "Building WASM signer worker (release for active browser hot path)..."
pushd "$SDK_ROOT/$SOURCE_WASM_SIGNER" >/dev/null
if with_wasm_bindgen_cli_for_lockfile "$SDK_ROOT/$SOURCE_WASM_SIGNER/Cargo.lock" wasm-pack build --target web --out-dir pkg --out-name wasm_signer_worker --release; then
  print_success "WASM signer worker built (wasm-bindgen ${WASM_BINDGEN_CLI_VERSION_RESOLVED})"
else
  print_error "WASM signer build failed"
  exit 1
fi

print_step "Building WASM signer worker for server HSS hot path (release)..."
if with_wasm_bindgen_cli_for_lockfile "$SDK_ROOT/$SOURCE_WASM_SIGNER/Cargo.lock" wasm-pack build --target web --out-dir pkg-server --out-name wasm_signer_worker --release --no-opt --features hss-server-exports; then
  print_success "Server HSS WASM signer worker built (wasm-bindgen ${WASM_BINDGEN_CLI_VERSION_RESOLVED})"
else
  print_error "Server HSS WASM signer build failed"
  exit 1
fi
popd >/dev/null

print_step "Building separate HSS client signer WASM (release for browser HSS path)..."
pushd "$SDK_ROOT/$SOURCE_WASM_HSS_CLIENT_SIGNER" >/dev/null
if with_wasm_bindgen_cli_for_lockfile "$SDK_ROOT/$SOURCE_WASM_HSS_CLIENT_SIGNER/Cargo.lock" wasm-pack build --target web --out-dir pkg --out-name hss_client_signer --release; then
  print_success "HSS client signer WASM built (wasm-bindgen ${WASM_BINDGEN_CLI_VERSION_RESOLVED})"
else
  print_error "HSS client signer WASM build failed"
  exit 1
fi
popd >/dev/null

print_step "Building WASM eth signer (dev)..."
pushd "$SDK_ROOT/$SOURCE_WASM_ETH_SIGNER" >/dev/null
if with_wasm_bindgen_cli_for_lockfile "$SDK_ROOT/$SOURCE_WASM_ETH_SIGNER/Cargo.lock" wasm-pack build --target web --out-dir pkg --out-name eth_signer --dev --no-opt; then
  print_success "WASM eth signer built (wasm-bindgen ${WASM_BINDGEN_CLI_VERSION_RESOLVED})"
else
  print_error "WASM eth signer build failed"
  exit 1
fi
popd >/dev/null

print_step "Building WASM tempo signer (dev)..."
pushd "$SDK_ROOT/$SOURCE_WASM_TEMPO_SIGNER" >/dev/null
if with_wasm_bindgen_cli_for_lockfile "$SDK_ROOT/$SOURCE_WASM_TEMPO_SIGNER/Cargo.lock" wasm-pack build --target web --out-dir pkg --out-name tempo_signer --dev --no-opt; then
  print_success "WASM tempo signer built (wasm-bindgen ${WASM_BINDGEN_CLI_VERSION_RESOLVED})"
else
  print_error "WASM tempo signer build failed"
  exit 1
fi
popd >/dev/null

print_step "Building WASM shamir3pass runtime (dev)..."
pushd "$SDK_ROOT/$SOURCE_WASM_SHAMIR3PASS_RUNTIME" >/dev/null
if with_wasm_bindgen_cli_for_lockfile "$SDK_ROOT/$SOURCE_WASM_SHAMIR3PASS_RUNTIME/Cargo.lock" wasm-pack build --target web --out-dir pkg --out-name shamir3pass_runtime --dev --no-opt; then
  print_success "WASM shamir3pass runtime built (wasm-bindgen ${WASM_BINDGEN_CLI_VERSION_RESOLVED})"
else
  print_error "WASM shamir3pass runtime build failed"
  exit 1
fi
popd >/dev/null

print_step "Building WASM Email OTP runtime (dev)..."
pushd "$SDK_ROOT/$SOURCE_WASM_EMAIL_OTP_RUNTIME" >/dev/null
if with_wasm_bindgen_cli_for_lockfile "$SDK_ROOT/$SOURCE_WASM_EMAIL_OTP_RUNTIME/Cargo.lock" wasm-pack build --target web --out-dir pkg --out-name email_otp_runtime --dev --no-opt; then
  print_success "WASM Email OTP runtime built (wasm-bindgen ${WASM_BINDGEN_CLI_VERSION_RESOLVED})"
else
  print_error "WASM Email OTP runtime build failed"
  exit 1
fi
popd >/dev/null

print_step "Building threshold-prf WASM (dev)..."
pushd "$SDK_ROOT/$SOURCE_WASM_THRESHOLD_PRF" >/dev/null
if with_wasm_bindgen_cli_for_lockfile "$SDK_ROOT/$SOURCE_WASM_THRESHOLD_PRF/Cargo.lock" wasm-pack build --target web --out-dir pkg --out-name threshold_prf --dev --no-opt; then
  print_success "threshold-prf WASM built (wasm-bindgen ${WASM_BINDGEN_CLI_VERSION_RESOLVED})"
else
  print_error "threshold-prf WASM build failed"
  exit 1
fi
popd >/dev/null

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
