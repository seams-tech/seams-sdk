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
SOURCE_STATIC="src/static"
SOURCE_SIGNING_WORKERS="src/core/signingEngine/workerManager/workers"
SOURCE_WASM_SIGNER="../../wasm/near_signer"
SOURCE_ED25519_YAO_CLIENT="../../crates/router-ab-ed25519-yao-client"
SOURCE_WASM_ECDSA_CLIENT_SIGNER="../../wasm/ecdsa_client_signer"
SOURCE_WASM_ETH_SIGNER="../../wasm/eth_signer"
SOURCE_WASM_TEMPO_SIGNER="../../wasm/tempo_signer"
SOURCE_WASM_SHAMIR3PASS_RUNTIME="../../wasm/shamir3pass_runtime"
SOURCE_WASM_EMAIL_OTP_RUNTIME="../../wasm/email_otp_runtime"
SOURCE_WASM_THRESHOLD_PRF="../../wasm/threshold_prf"

# Critical directories for build freshness checking
CRITICAL_DIRS=(
    "src/core"
    "src/react"
    "src/static"
    "src/utils"
    "../sdk-server-ts/src"
    "../shared-ts/src"
    "../../crates/signer-core"
    "../../crates/router-ab-ed25519-yao-client"
    "../../crates/ecdsa-hss"
    "../../crates/threshold-prf"
    "../../wasm/near_signer"
    "../../wasm/ecdsa_client_signer"
    "../../wasm/eth_signer"
    "../../wasm/tempo_signer"
    "../../wasm/shamir3pass_runtime"
    "../../wasm/email_otp_runtime"
    "../../wasm/threshold_prf"
)

# Runtime paths (used by workers and tests)
RUNTIME_SDK_BASE="/sdk"
RUNTIME_WORKERS_BASE="/sdk/workers"
RUNTIME_TOUCH_CONFIRM_WORKER="/sdk/workers/passkey-confirm.worker.js"
RUNTIME_SIGNER_WORKER="/sdk/workers/near-signer.worker.js"
RUNTIME_ECDSA_HSS_CLIENT_WORKER="/sdk/workers/ecdsa-hss-client.worker.js"

# Worker file names
WORKER_TOUCH_CONFIRM="passkey-confirm.worker.js"
WORKER_SIGNER="near-signer.worker.js"
WORKER_ECDSA_HSS_CLIENT="ecdsa-hss-client.worker.js"
WORKER_SHAMIR3PASS="shamir3pass.worker.js"
WORKER_ETH_SIGNER="eth-signer.worker.js"
WORKER_TEMPO_SIGNER="tempo-signer.worker.js"
WORKER_WASM_SIGNER_JS="wasm_signer_worker.js"
WORKER_WASM_SIGNER_WASM="wasm_signer_worker_bg.wasm"
ED25519_YAO_CLIENT_JS="router_ab_ed25519_yao_client.js"
ED25519_YAO_CLIENT_WASM="router_ab_ed25519_yao_client_bg.wasm"
WORKER_ECDSA_CLIENT_SIGNER_JS="ecdsa_client_signer.js"
WORKER_ECDSA_CLIENT_SIGNER_WASM="ecdsa_client_signer_bg.wasm"
WORKER_WASM_ETH_SIGNER_WASM="eth_signer.wasm"
WORKER_WASM_ETH_SIGNER_BG_WASM="eth_signer_bg.wasm"
WORKER_WASM_TEMPO_SIGNER_WASM="tempo_signer.wasm"
WORKER_WASM_TEMPO_SIGNER_BG_WASM="tempo_signer_bg.wasm"
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
