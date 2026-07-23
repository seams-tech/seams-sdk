#!/bin/bash

# Production build script for @seams/sdk
# - Builds WASM in release mode (wasm-pack --release)
# - Bundles with rolldown in NODE_ENV=production (better treeshaking, prod React)
# - Minifies worker JS via Bun

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPO_ROOT="$(cd "$SDK_ROOT/../.." && pwd)"
source "$SDK_ROOT/build-paths.sh"
source "$SCRIPT_DIR/build-output-lock.sh"
cd "$SDK_ROOT"

echo "Starting production build for @seams/sdk..."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() { echo -e "${BLUE}📦 $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️ $1${NC}"; }

cleanup_build_prod() {
  release_build_output_lock
}

trap cleanup_build_prod EXIT

if command -v bun >/dev/null 2>&1; then BUN_BIN="$(command -v bun)"; elif [ -x "$HOME/.bun/bin/bun" ]; then BUN_BIN="$HOME/.bun/bin/bun"; else BUN_BIN=""; fi

print_step "Acquiring WASM package-output build lock..."
acquire_build_output_lock
print_success "WASM package-output build lock acquired"

print_step "Cleaning previous build artifacts..."
rm -rf "$BUILD_ROOT/"
print_success "Build directory cleaned"

print_step "Building production WASM packages..."
if WASM_SDK_BUILD_MODE=prod "$SCRIPT_DIR/build-wasm.sh"; then
  print_success "Production WASM packages built"
else
  print_error "Production WASM build failed"
  exit 1
fi

print_step "Building TypeScript..."
if npx tsc -p tsconfig.build.json; then print_success "TypeScript compilation completed"; else print_error "TypeScript compilation failed"; exit 1; fi

print_step "Generating CSS variables from palette.json (w3a-components.css)..."
if node "$SDK_ROOT/scripts/codegen/generate-w3a-components-css.mjs"; then print_success "w3a-components.css generated"; else print_error "Failed to generate w3a-components.css"; exit 1; fi

print_step "Bundling with Rolldown (production)..."
if NODE_ENV=production npx rolldown -c rolldown.config.ts; then print_success "Rolldown bundling completed"; else print_error "Rolldown bundling failed"; exit 1; fi

print_step "Asserting NEAR signer WASM imports stay within dist/esm..."
if node "$SDK_ROOT/scripts/checks/assert-near-signer-wasm-imports.mjs"; then print_success "NEAR signer WASM imports OK"; else print_error "NEAR signer WASM imports invalid"; exit 1; fi

print_step "Asserting runtime package entry avoids browser bundles..."
if node "$SDK_ROOT/scripts/checks/assert-runtime-entry-bundles.mjs"; then print_success "Runtime package entry OK"; else print_error "Runtime package entry invalid"; exit 1; fi

print_step "Bundling browser-embedded SDK assets with Bun (minified)..."
if [ -z "$BUN_BIN" ]; then print_error "Bun not found. Install Bun or ensure it is on PATH."; exit 1; fi

mkdir -p "$BUILD_ESM/sdk"

# These bundles are loaded directly by browsers from /sdk/* (no bundler/import maps),
# so they must not contain bare module specifiers like `import "idb"`.
if NODE_ENV=production "$BUN_BIN" build "$SDK_ROOT/src/core/signingEngine/uiConfirm/ui/confirm-ui.ts" --outfile "$BUILD_ESM/sdk/tx-confirm-ui.js" --format esm --target browser --minify --root "$REPO_ROOT" \
  && NODE_ENV=production "$BUN_BIN" build "$SDK_ROOT/src/core/signingEngine/uiConfirm/ui/lit-components/IframeTxConfirmer/tx-confirmer-wrapper.ts" --outfile "$BUILD_ESM/sdk/w3a-tx-confirmer.js" --format esm --target browser --minify --root "$REPO_ROOT" \
  && NODE_ENV=production "$BUN_BIN" build "$SDK_ROOT/src/core/signingEngine/uiConfirm/ui/lit-components/ExportPrivateKey/iframe-export-bootstrap-script.ts" --outfile "$BUILD_ESM/sdk/iframe-export-bootstrap.js" --format esm --target browser --minify --root "$REPO_ROOT" \
  && NODE_ENV=production "$BUN_BIN" build "$SDK_ROOT/src/core/signingEngine/uiConfirm/ui/lit-components/ExportPrivateKey/viewer.ts" --outfile "$BUILD_ESM/sdk/export-private-key-viewer.js" --format esm --target browser --minify --root "$REPO_ROOT" \
  && NODE_ENV=production "$BUN_BIN" build "$SDK_ROOT/src/core/signingEngine/uiConfirm/ui/lit-components/HaloBorder/index.ts" --outfile "$BUILD_ESM/sdk/halo-border.js" --format esm --target browser --minify --root "$REPO_ROOT" \
  && NODE_ENV=production "$BUN_BIN" build "$SDK_ROOT/src/core/signingEngine/uiConfirm/ui/lit-components/PasskeyHaloLoading/index.ts" --outfile "$BUILD_ESM/sdk/passkey-halo-loading.js" --format esm --target browser --minify --root "$REPO_ROOT"; then
  print_success "Bun embedded-asset bundling completed"
else
  print_error "Bun embedded-asset bundling failed"; exit 1
fi

print_step "Bundling workers with Bun (minified)..."
mkdir -p "$BUILD_WORKERS"

if "$BUN_BIN" build "$SOURCE_SIGNING_WORKERS/near-signer.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --minify --root "$REPO_ROOT" --entry-naming '[name].[ext]' \
  && "$BUN_BIN" build "$SOURCE_SIGNING_WORKERS/ecdsa-derivation-client.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --minify --root "$REPO_ROOT" --entry-naming '[name].[ext]' \
  && "$BUN_BIN" build "$SOURCE_SIGNING_WORKERS/ecdsa-presign-client.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --minify --root "$REPO_ROOT" --entry-naming '[name].[ext]' \
  && "$BUN_BIN" build "$SOURCE_SIGNING_WORKERS/ecdsa-online-client.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --minify --root "$REPO_ROOT" --entry-naming '[name].[ext]' \
  && "$BUN_BIN" build "$SOURCE_SIGNING_WORKERS/passkey-confirm.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --minify --root "$REPO_ROOT" --entry-naming '[name].[ext]' \
  && "$BUN_BIN" build "$SOURCE_SIGNING_WORKERS/email-otp.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --minify --root "$REPO_ROOT" --entry-naming '[name].[ext]' \
  && "$BUN_BIN" build "$SOURCE_SIGNING_WORKERS/shamir3pass.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --minify --root "$REPO_ROOT" --entry-naming '[name].[ext]' \
  && "$BUN_BIN" build "$SOURCE_SIGNING_WORKERS/evm-crypto.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --minify --root "$REPO_ROOT" --entry-naming '[name].[ext]' \
  && "$BUN_BIN" build "$SOURCE_SIGNING_WORKERS/tempo-signer.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --minify --root "$REPO_ROOT" --entry-naming '[name].[ext]'; then
  print_success "Bun worker bundling completed"
else
  print_error "Bun worker bundling failed"; exit 1
fi

print_step "Copying worker WASM binaries next to worker JS..."
if cp "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg/wasm_signer_worker_bg.wasm" "$BUILD_WORKERS/" 2>/dev/null; then print_success "Signer WASM copied"; else print_warning "Signer WASM not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg/wasm_signer_worker_bg.wasm" "$BUILD_WORKERS/near_signer.wasm" 2>/dev/null; then print_success "near_signer.wasm copied"; else print_warning "near_signer.wasm not found"; fi
if cp "$SDK_ROOT/$SOURCE_ED25519_YAO_CLIENT/pkg/router_ab_ed25519_yao_client_bg.wasm" "$BUILD_WORKERS/$ED25519_YAO_CLIENT_WASM" 2>/dev/null; then print_success "Ed25519 Yao Client WASM copied"; else print_warning "Ed25519 Yao Client WASM not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_ECDSA_REGISTRATION_CLIENT/pkg/ecdsa_registration_client_bg.wasm" "$BUILD_WORKERS/" 2>/dev/null; then print_success "ECDSA registration client WASM copied"; else print_warning "ECDSA registration client WASM not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_ECDSA_DERIVATION_CLIENT/pkg/router_ab_ecdsa_derivation_client_bg.wasm" "$BUILD_WORKERS/" 2>/dev/null; then print_success "ECDSA client signer WASM copied"; else print_warning "ECDSA client signer WASM not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_ECDSA_PRESIGN_CLIENT/pkg/router_ab_ecdsa_presign_client_bg.wasm" "$BUILD_WORKERS/" 2>/dev/null; then print_success "ECDSA presign WASM copied"; else print_warning "ECDSA presign WASM not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_ECDSA_ONLINE_CLIENT/pkg/router_ab_ecdsa_online_client_bg.wasm" "$BUILD_WORKERS/" 2>/dev/null; then print_success "ECDSA online WASM copied"; else print_warning "ECDSA online WASM not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_EVM_CRYPTO/pkg/evm_crypto_bg.wasm" "$BUILD_WORKERS/evm_crypto.wasm" 2>/dev/null; then print_success "evm_crypto.wasm copied"; else print_warning "evm_crypto.wasm not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_EVM_CRYPTO/pkg/evm_crypto_bg.wasm" "$BUILD_WORKERS/evm_crypto_bg.wasm" 2>/dev/null; then print_success "evm_crypto_bg.wasm copied"; else print_warning "evm_crypto_bg.wasm not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_TEMPO_SIGNER/pkg/tempo_signer_bg.wasm" "$BUILD_WORKERS/tempo_signer.wasm" 2>/dev/null; then print_success "tempo_signer.wasm copied"; else print_warning "tempo_signer.wasm not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_TEMPO_SIGNER/pkg/tempo_signer_bg.wasm" "$BUILD_WORKERS/tempo_signer_bg.wasm" 2>/dev/null; then print_success "tempo_signer_bg.wasm copied"; else print_warning "tempo_signer_bg.wasm not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_SHAMIR3PASS_RUNTIME/pkg/shamir3pass_runtime.js" "$BUILD_WORKERS/shamir3pass_runtime.js" 2>/dev/null; then print_success "shamir3pass_runtime.js copied"; else print_warning "shamir3pass_runtime.js not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_SHAMIR3PASS_RUNTIME/pkg/shamir3pass_runtime_bg.wasm" "$BUILD_WORKERS/shamir3pass_runtime_bg.wasm" 2>/dev/null; then print_success "shamir3pass_runtime_bg.wasm copied"; else print_warning "shamir3pass_runtime_bg.wasm not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_EMAIL_OTP_RUNTIME/pkg/email_otp_runtime.js" "$BUILD_WORKERS/email_otp_runtime.js" 2>/dev/null; then print_success "email_otp_runtime.js copied"; else print_warning "email_otp_runtime.js not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_EMAIL_OTP_RUNTIME/pkg/email_otp_runtime_bg.wasm" "$BUILD_WORKERS/email_otp_runtime_bg.wasm" 2>/dev/null; then print_success "email_otp_runtime_bg.wasm copied"; else print_warning "email_otp_runtime_bg.wasm not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_THRESHOLD_PRF/pkg/threshold_prf_bg.wasm" "$BUILD_WORKERS/$WORKER_THRESHOLD_PRF_WASM" 2>/dev/null; then print_success "threshold_prf.wasm copied"; else print_warning "threshold_prf.wasm not found"; fi

print_step "Copying browser ECDSA registration client WASM binary into dist/esm..."
ECDSA_REGISTRATION_CLIENT_WASM_DIR="$BUILD_ESM/wasm/ecdsa_registration_client/pkg"
mkdir -p "$ECDSA_REGISTRATION_CLIENT_WASM_DIR"
if cp "$SDK_ROOT/$SOURCE_WASM_ECDSA_REGISTRATION_CLIENT/pkg/ecdsa_registration_client_bg.wasm" "$ECDSA_REGISTRATION_CLIENT_WASM_DIR/" 2>/dev/null; then
  print_success "Browser ECDSA registration client WASM copied"
else
  print_warning "Browser ECDSA registration client WASM not found"
fi

print_step "Copying browser ECDSA export client WASM binary into dist/esm..."
ECDSA_DERIVATION_CLIENT_WASM_DIR="$BUILD_ESM/wasm/router_ab_ecdsa_derivation_client/pkg"
mkdir -p "$ECDSA_DERIVATION_CLIENT_WASM_DIR"
if cp "$SDK_ROOT/$SOURCE_WASM_ECDSA_DERIVATION_CLIENT/pkg/router_ab_ecdsa_derivation_client_bg.wasm" "$ECDSA_DERIVATION_CLIENT_WASM_DIR/" 2>/dev/null; then
  print_success "Browser ECDSA export client WASM copied"
else
  print_warning "Browser ECDSA export client WASM not found"
fi

print_step "Copying Ed25519 Yao Client WASM binary into dist/esm..."
ED25519_YAO_CLIENT_WASM_DIR="$BUILD_ESM/wasm/router_ab_ed25519_yao_client/pkg"
mkdir -p "$ED25519_YAO_CLIENT_WASM_DIR"
if cp "$SDK_ROOT/$SOURCE_ED25519_YAO_CLIENT/pkg/router_ab_ed25519_yao_client_bg.wasm" "$ED25519_YAO_CLIENT_WASM_DIR/" 2>/dev/null; then
  print_success "Ed25519 Yao Client WASM copied"
else
  print_warning "Ed25519 Yao Client WASM not found"
fi

print_step "Copying Ed25519 Yao Client WASM next to browser SDK chunks..."
if cp "$SDK_ROOT/$SOURCE_ED25519_YAO_CLIENT/pkg/router_ab_ed25519_yao_client_bg.wasm" "$BUILD_ESM/sdk/$ED25519_YAO_CLIENT_WASM" 2>/dev/null; then
  print_success "Browser SDK Ed25519 Yao Client WASM copied"
else
  print_warning "Browser SDK Ed25519 Yao Client WASM not found"
fi

print_step "Emitting hosted wallet static asset tree..."
if node "$SDK_ROOT/scripts/build/emit-static-wallet-assets.mjs"; then print_success "Hosted wallet static asset tree emitted"; else print_error "Hosted wallet static asset emission failed"; exit 1; fi

print_step "Asserting hosted wallet static asset tree..."
if node "$SDK_ROOT/scripts/checks/assert-static-wallet-assets.mjs"; then print_success "Hosted wallet static assets OK"; else print_error "Hosted wallet static assets invalid"; exit 1; fi

print_step "Hashing build inputs..."
if "$SDK_ROOT/scripts/build/check-build-freshness.sh" --print-input-hash > "$BUILD_ROOT/.build-inputs.sha256"; then
  print_success "Build input manifest written"
else
  print_error "Failed to write build input manifest"
  exit 1
fi

print_success "Production build completed successfully!"
