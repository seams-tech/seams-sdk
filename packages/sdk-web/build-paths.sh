#!/bin/bash

# Centralized build configuration (bash version)
# This file defines all paths used across the build system

# Build output directories
BUILD_ROOT="dist"
BUILD_WORKERS="dist/workers"
BUILD_ESM="dist/esm"
BUILD_TYPES="dist/types"

# Source directories
SOURCE_ROOT="src"
SOURCE_CORE="src/core"
SOURCE_SIGNING_WORKERS="src/core/signingEngine/workerManager/workers"
SOURCE_WASM_SIGNER="../../wasm/near_signer"
SOURCE_WASM_HSS_CLIENT_SIGNER="../../wasm/hss_client_signer"
SOURCE_WASM_ETH_SIGNER="../../wasm/eth_signer"
SOURCE_WASM_TEMPO_SIGNER="../../wasm/tempo_signer"
SOURCE_WASM_SHAMIR3PASS_RUNTIME="../../wasm/shamir3pass_runtime"
SOURCE_WASM_EMAIL_OTP_RUNTIME="../../wasm/email_otp_runtime"
SOURCE_WASM_THRESHOLD_PRF="../../wasm/threshold_prf"

# Critical directories for build freshness checking
CRITICAL_DIRS=(
    "src/core"
    "src/react"
    "src/utils"
    "../sdk-server-ts/src"
    "../shared-ts/src"
    "../../crates/signer-core"
    "../../crates/ed25519-hss"
    "../../crates/ecdsa-hss"
    "../../crates/threshold-prf"
    "../../wasm/near_signer"
    "../../wasm/hss_client_signer"
    "../../wasm/eth_signer"
    "../../wasm/tempo_signer"
    "../../wasm/shamir3pass_runtime"
    "../../wasm/email_otp_runtime"
    "../../wasm/threshold_prf"
)

# Frontend deployment paths (used only for local dev/test copying)
FRONTEND_ROOT="../../apps/web-client/src/public"
FRONTEND_SDK="../../apps/web-client/src/public/sdk"
FRONTEND_WORKERS="../../apps/web-client/src/public/sdk/workers"

# Runtime paths (used by workers and tests)
RUNTIME_SDK_BASE="/sdk"
RUNTIME_WORKERS_BASE="/sdk/workers"
RUNTIME_TOUCH_CONFIRM_WORKER="/sdk/workers/passkey-confirm.worker.js"
RUNTIME_SIGNER_WORKER="/sdk/workers/near-signer.worker.js"
RUNTIME_HSS_CLIENT_WORKER="/sdk/workers/hss-client.worker.js"

# Worker file names
WORKER_TOUCH_CONFIRM="passkey-confirm.worker.js"
WORKER_SIGNER="near-signer.worker.js"
WORKER_HSS_CLIENT="hss-client.worker.js"
WORKER_SHAMIR3PASS="shamir3pass.worker.js"
WORKER_ETH_SIGNER="eth-signer.worker.js"
WORKER_TEMPO_SIGNER="tempo-signer.worker.js"
WORKER_WASM_SIGNER_JS="wasm_signer_worker.js"
WORKER_WASM_SIGNER_WASM="wasm_signer_worker_bg.wasm"
WORKER_HSS_CLIENT_SIGNER_JS="hss_client_signer.js"
WORKER_HSS_CLIENT_SIGNER_WASM="hss_client_signer_bg.wasm"
WORKER_WASM_ETH_SIGNER_WASM="eth_signer.wasm"
WORKER_WASM_TEMPO_SIGNER_WASM="tempo_signer.wasm"
WORKER_SHAMIR3PASS_RUNTIME_JS="shamir3pass_runtime.js"
WORKER_SHAMIR3PASS_RUNTIME_WASM="shamir3pass_runtime_bg.wasm"
WORKER_EMAIL_OTP_RUNTIME_JS="email_otp_runtime.js"
WORKER_EMAIL_OTP_RUNTIME_WASM="email_otp_runtime_bg.wasm"
WORKER_THRESHOLD_PRF_WASM="threshold_prf.wasm"

# Critical files to check for build freshness
CRITICAL_FILES=(
    "src/core/signingEngine/uiConfirm/UiConfirmManager.ts"
    "src/core/signingEngine/workerManager/SignerWorkerManager.ts"
    "src/core/signingEngine/workerManager/session.ts"
    "src/core/signingEngine/workerManager/validation.ts"
    "src/core/signingEngine/workerManager/nearKeyOps"
    "src/core/signingEngine/chains/near"
    "src/core/signingEngine/chains/tempo"
    "src/core/signingEngine/chains"
    "src/core/signingEngine/uiConfirm/handlers"
    "src/core/signingEngine/stepUpConfirmation/channel"
    "src/SeamsWeb/signingSurface/BrowserSigningSurface.ts"
    "src/SeamsWeb/index.ts"
    "src/SeamsWeb/operations/near/actions.ts"
    "src/SeamsWeb/operations/auth/login.ts"
    "src/SeamsWeb/operations/registration/registration.ts"
    "src/index.ts"
    "rolldown.config.ts"
    "tsconfig.json"
)

# Helper functions
get_worker_path() {
    echo "${BUILD_WORKERS}/$1"
}

get_runtime_worker_path() {
    echo "${RUNTIME_WORKERS_BASE}/$1"
}

get_frontend_worker_path() {
    echo "${FRONTEND_WORKERS}/$1"
}
