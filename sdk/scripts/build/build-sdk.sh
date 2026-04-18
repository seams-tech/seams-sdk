#!/bin/bash

# Build the TypeScript/JavaScript SDK from existing WASM package outputs.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPO_ROOT="$(cd "$SDK_ROOT/.." && pwd)"
source "$SDK_ROOT/build-paths.sh"
cd "$SDK_ROOT"

echo "Starting SDK build for @tatchi-xyz/sdk..."

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
    print_error "Missing required WASM output: $path"
    echo "Run pnpm build:wasm or pnpm build:sdk-full first."
    exit 1
  fi
}

if command -v bun >/dev/null 2>&1; then BUN_BIN="$(command -v bun)"; elif [ -x "$HOME/.bun/bin/bun" ]; then BUN_BIN="$HOME/.bun/bin/bun"; else BUN_BIN=""; fi

print_step "Checking existing WASM package outputs..."
require_file "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg/wasm_signer_worker.js"
require_file "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg/wasm_signer_worker.d.ts"
require_file "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg/wasm_signer_worker_bg.wasm"
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
require_file "$SDK_ROOT/$SOURCE_WASM_SHAMIR3PASS_RUNTIME/pkg/shamir3pass_runtime_bg.wasm"
require_file "$SDK_ROOT/$SOURCE_WASM_EMAIL_OTP_RUNTIME/pkg/email_otp_runtime.js"
require_file "$SDK_ROOT/$SOURCE_WASM_EMAIL_OTP_RUNTIME/pkg/email_otp_runtime_bg.wasm"
require_file "$SDK_ROOT/$SOURCE_WASM_THRESHOLD_PRF/pkg/threshold_prf_bg.wasm"
print_success "WASM package outputs are present"

print_step "Cleaning previous SDK build artifacts..."
rm -rf "$BUILD_ROOT/"
print_success "SDK build directory cleaned"

print_step "Building TypeScript..."
if npx tsc -p tsconfig.build.json; then print_success "TypeScript compilation completed"; else print_error "TypeScript compilation failed"; exit 1; fi

print_step "Generating CSS variables from palette.json (w3a-components.css)..."
if node "$SDK_ROOT/scripts/codegen/generate-w3a-components-css.mjs"; then print_success "w3a-components.css generated"; else print_error "Failed to generate w3a-components.css"; exit 1; fi

print_step "Bundling with Rolldown (dev)..."
if npx rolldown -c rolldown.config.ts; then print_success "Rolldown bundling completed"; else print_error "Rolldown bundling failed"; exit 1; fi

print_step "Asserting NEAR signer WASM imports stay within dist/esm..."
if node "$SDK_ROOT/scripts/checks/assert-near-signer-wasm-imports.mjs"; then print_success "NEAR signer WASM imports OK"; else print_error "NEAR signer WASM imports invalid"; exit 1; fi

print_step "Bundling browser-embedded SDK assets with Bun (dev, no minify)..."
if [ -z "$BUN_BIN" ]; then print_error "Bun not found. Install Bun or ensure it is on PATH."; exit 1; fi

mkdir -p "$BUILD_ESM/sdk"

# These bundles are loaded directly by browsers from /sdk/* (no bundler/import maps),
# so they must not contain bare module specifiers like `import "idb"`.
if "$BUN_BIN" build "$SDK_ROOT/../client/src/core/signingEngine/touchConfirm/ui/confirm-ui.ts" --outfile "$BUILD_ESM/sdk/tx-confirm-ui.js" --format esm --target browser --root "$REPO_ROOT" \
  && "$BUN_BIN" build "$SDK_ROOT/../client/src/core/WalletIframe/host/index.ts" --outfile "$BUILD_ESM/sdk/wallet-iframe-host-runtime.js" --format esm --target browser --root "$REPO_ROOT" \
  && "$BUN_BIN" build "$SDK_ROOT/../client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/tx-confirmer-wrapper.ts" --outfile "$BUILD_ESM/sdk/w3a-tx-confirmer.js" --format esm --target browser --root "$REPO_ROOT" \
  && "$BUN_BIN" build "$SDK_ROOT/../client/src/core/signingEngine/touchConfirm/ui/lit-components/ExportPrivateKey/iframe-export-bootstrap-script.ts" --outfile "$BUILD_ESM/sdk/iframe-export-bootstrap.js" --format esm --target browser --root "$REPO_ROOT" \
  && "$BUN_BIN" build "$SDK_ROOT/../client/src/core/signingEngine/touchConfirm/ui/lit-components/ExportPrivateKey/viewer.ts" --outfile "$BUILD_ESM/sdk/export-private-key-viewer.js" --format esm --target browser --root "$REPO_ROOT" \
  && "$BUN_BIN" build "$SDK_ROOT/../client/src/core/signingEngine/touchConfirm/ui/lit-components/HaloBorder/index.ts" --outfile "$BUILD_ESM/sdk/halo-border.js" --format esm --target browser --root "$REPO_ROOT" \
  && "$BUN_BIN" build "$SDK_ROOT/../client/src/core/signingEngine/touchConfirm/ui/lit-components/PasskeyHaloLoading/index.ts" --outfile "$BUILD_ESM/sdk/passkey-halo-loading.js" --format esm --target browser --root "$REPO_ROOT"; then
  print_success "Bun embedded-asset bundling completed"
else
  print_error "Bun embedded-asset bundling failed"; exit 1
fi

print_step "Bundling workers with Bun (dev, no minify)..."

if "$BUN_BIN" build "$SOURCE_SIGNING_WORKERS/near-signer.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --root "$REPO_ROOT" --entry-naming '[name].[ext]' \
  && "$BUN_BIN" build "$SOURCE_SIGNING_WORKERS/hss-client.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --root "$REPO_ROOT" --entry-naming '[name].[ext]' \
  && "$BUN_BIN" build "$SOURCE_SIGNING_WORKERS/passkey-confirm.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --root "$REPO_ROOT" --entry-naming '[name].[ext]' \
  && "$BUN_BIN" build "$SOURCE_SIGNING_WORKERS/email-otp.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --root "$REPO_ROOT" --entry-naming '[name].[ext]' \
  && "$BUN_BIN" build "$SOURCE_SIGNING_WORKERS/shamir3pass.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --root "$REPO_ROOT" --entry-naming '[name].[ext]' \
  && "$BUN_BIN" build "$SOURCE_SIGNING_WORKERS/eth-signer.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --root "$REPO_ROOT" --entry-naming '[name].[ext]' \
  && "$BUN_BIN" build "$SOURCE_SIGNING_WORKERS/tempo-signer.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --root "$REPO_ROOT" --entry-naming '[name].[ext]'; then
  print_success "Bun worker bundling completed"
else
  print_error "Bun worker bundling failed"; exit 1
fi

print_step "Copying worker WASM binaries next to worker JS..."
mkdir -p "$BUILD_WORKERS"
if cp "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg/wasm_signer_worker_bg.wasm" "$BUILD_WORKERS/" 2>/dev/null; then print_success "Signer WASM copied"; else print_warning "Signer WASM not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg/wasm_signer_worker_bg.wasm" "$BUILD_WORKERS/near_signer.wasm" 2>/dev/null; then print_success "near_signer.wasm copied"; else print_warning "near_signer.wasm not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_HSS_CLIENT_SIGNER/pkg/hss_client_signer_bg.wasm" "$BUILD_WORKERS/" 2>/dev/null; then print_success "HSS client signer WASM copied"; else print_warning "HSS client signer WASM not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_ETH_SIGNER/pkg/eth_signer_bg.wasm" "$BUILD_WORKERS/eth_signer.wasm" 2>/dev/null; then print_success "eth_signer.wasm copied"; else print_warning "eth_signer.wasm not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_TEMPO_SIGNER/pkg/tempo_signer_bg.wasm" "$BUILD_WORKERS/tempo_signer.wasm" 2>/dev/null; then print_success "tempo_signer.wasm copied"; else print_warning "tempo_signer.wasm not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_SHAMIR3PASS_RUNTIME/pkg/shamir3pass_runtime.js" "$BUILD_WORKERS/shamir3pass_runtime.js" 2>/dev/null; then print_success "shamir3pass_runtime.js copied"; else print_warning "shamir3pass_runtime.js not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_SHAMIR3PASS_RUNTIME/pkg/shamir3pass_runtime_bg.wasm" "$BUILD_WORKERS/shamir3pass_runtime_bg.wasm" 2>/dev/null; then print_success "shamir3pass_runtime_bg.wasm copied"; else print_warning "shamir3pass_runtime_bg.wasm not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_EMAIL_OTP_RUNTIME/pkg/email_otp_runtime.js" "$BUILD_WORKERS/email_otp_runtime.js" 2>/dev/null; then print_success "email_otp_runtime.js copied"; else print_warning "email_otp_runtime.js not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_EMAIL_OTP_RUNTIME/pkg/email_otp_runtime_bg.wasm" "$BUILD_WORKERS/email_otp_runtime_bg.wasm" 2>/dev/null; then print_success "email_otp_runtime_bg.wasm copied"; else print_warning "email_otp_runtime_bg.wasm not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_THRESHOLD_PRF/pkg/threshold_prf_bg.wasm" "$BUILD_WORKERS/$WORKER_THRESHOLD_PRF_WASM" 2>/dev/null; then print_success "threshold_prf.wasm copied"; else print_warning "threshold_prf.wasm not found"; fi

print_step "Copying server HSS WASM binary into dist/esm..."
SERVER_HSS_WASM_DIR="$BUILD_ESM/server/wasm/near_signer/pkg-server"
mkdir -p "$SERVER_HSS_WASM_DIR"
if cp "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg-server/wasm_signer_worker_bg.wasm" "$SERVER_HSS_WASM_DIR/" 2>/dev/null; then
  print_success "Server HSS WASM copied"
else
  print_warning "Server HSS WASM not found"
fi

print_step "Copying server threshold-prf WASM binary into dist/esm..."
SERVER_THRESHOLD_PRF_WASM_DIR="$BUILD_ESM/server/wasm/threshold_prf/pkg"
mkdir -p "$SERVER_THRESHOLD_PRF_WASM_DIR"
if cp "$SDK_ROOT/$SOURCE_WASM_THRESHOLD_PRF/pkg/threshold_prf_bg.wasm" "$SERVER_THRESHOLD_PRF_WASM_DIR/" 2>/dev/null; then
  print_success "Server threshold-prf WASM copied"
else
  print_warning "Server threshold-prf WASM not found"
fi

print_step "Copying browser HSS client WASM binary into dist/esm..."
HSS_CLIENT_WASM_DIR="$BUILD_ESM/wasm/hss_client_signer/pkg"
mkdir -p "$HSS_CLIENT_WASM_DIR"
if cp "$SDK_ROOT/$SOURCE_WASM_HSS_CLIENT_SIGNER/pkg/hss_client_signer_bg.wasm" "$HSS_CLIENT_WASM_DIR/" 2>/dev/null; then
  print_success "Browser HSS client WASM copied"
else
  print_warning "Browser HSS client WASM not found"
fi

print_step "Writing build input manifest..."
if "$SDK_ROOT/scripts/build/check-build-freshness.sh" --print-input-hash > "$BUILD_ROOT/.build-inputs.sha256"; then
  print_success "Build input manifest written"
else
  print_error "Failed to write build input manifest"
  exit 1
fi

print_success "SDK build completed successfully!"
