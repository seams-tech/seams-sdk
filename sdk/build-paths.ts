// Centralized build configuration
// This file defines all paths used across the build system

export const BUILD_PATHS = {
  // Build output directories
  BUILD: {
    ROOT: 'dist',
    WORKERS: 'dist/workers',
    ESM: 'dist/esm',
    TYPES: 'dist/types',
  },

  // Source directories
  SOURCE: {
    ROOT: '../client/src',
    CORE: '../client/src/core',
    SIGNING_WORKERS: '../client/src/core/signingEngine/workerManager/workers',
    WASM_SIGNER: '../wasm/near_signer',
    WASM_HSS_CLIENT_SIGNER: '../wasm/hss_client_signer',
    WASM_ETH_SIGNER: '../wasm/eth_signer',
    WASM_TEMPO_SIGNER: '../wasm/tempo_signer',
    WASM_SHAMIR3PASS_RUNTIME: '../wasm/shamir3pass_runtime',
    WASM_EMAIL_OTP_RUNTIME: '../wasm/email_otp_runtime',
    CRITICAL_DIRS: [
      '../client/src/core',
      '../client/src/react',
      '../client/src/utils',
      '../server/src',
      '../shared/src',
      '../wasm/near_signer',
      '../wasm/hss_client_signer',
      '../wasm/eth_signer',
      '../wasm/tempo_signer',
      '../wasm/shamir3pass_runtime',
      '../wasm/email_otp_runtime',
    ],
  },

  // Frontend deployment paths
  FRONTEND: {
    ROOT: '../examples/seams-site/src/public',
    SDK: '../examples/seams-site/src/public/sdk',
    WORKERS: '../examples/seams-site/src/public/sdk/workers',
  },

  // Runtime paths (used by workers and tests)
  RUNTIME: {
    SDK_BASE: '/sdk',
    WORKERS_BASE: '/sdk/workers',
    TOUCH_CONFIRM_WORKER: '/sdk/workers/passkey-confirm.worker.js',
    SIGNER_WORKER: '/sdk/workers/near-signer.worker.js',
    HSS_CLIENT_WORKER: '/sdk/workers/hss-client.worker.js',
    EMAIL_OTP_WORKER: '/sdk/workers/email-otp.worker.js',
  },

  // Worker file names
  WORKERS: {
    TOUCH_CONFIRM: 'passkey-confirm.worker.js',
    SIGNER: 'near-signer.worker.js',
    HSS_CLIENT: 'hss-client.worker.js',
    EMAIL_OTP: 'email-otp.worker.js',
    SHAMIR3PASS: 'shamir3pass.worker.js',
    WASM_SIGNER_JS: 'wasm_signer_worker.js',
    WASM_SIGNER_WASM: 'wasm_signer_worker_bg.wasm',
    HSS_CLIENT_SIGNER_JS: 'hss_client_signer.js',
    HSS_CLIENT_SIGNER_WASM: 'hss_client_signer_bg.wasm',
    EMAIL_OTP_RUNTIME_JS: 'email_otp_runtime.js',
    EMAIL_OTP_RUNTIME_WASM: 'email_otp_runtime_bg.wasm',
  },

  // Test worker file paths (for test files)
  TEST_WORKERS: {
    TOUCH_CONFIRM: '/sdk/workers/passkey-confirm.worker.js',
    SIGNER: '/sdk/workers/near-signer.worker.js',
    HSS_CLIENT: '/sdk/workers/hss-client.worker.js',
    EMAIL_OTP: '/sdk/workers/email-otp.worker.js',
    SHAMIR3PASS: '/sdk/workers/shamir3pass.worker.js',
    WASM_SIGNER_JS: '/sdk/workers/wasm_signer_worker.js',
    WASM_SIGNER_WASM: '/sdk/workers/wasm_signer_worker_bg.wasm',
    HSS_CLIENT_SIGNER_JS: '/sdk/workers/hss_client_signer.js',
    HSS_CLIENT_SIGNER_WASM: '/sdk/workers/hss_client_signer_bg.wasm',
    EMAIL_OTP_RUNTIME_JS: '/sdk/workers/email_otp_runtime.js',
    EMAIL_OTP_RUNTIME_WASM: '/sdk/workers/email_otp_runtime_bg.wasm',
  },
} as const;

// Helper functions
export const getWorkerPath = (workerName: string): string =>
  `${BUILD_PATHS.BUILD.WORKERS}/${workerName}`;
export const getRuntimeWorkerPath = (workerName: string): string =>
  `${BUILD_PATHS.RUNTIME.WORKERS_BASE}/${workerName}`;
export const getFrontendWorkerPath = (workerName: string): string =>
  `${BUILD_PATHS.FRONTEND.WORKERS}/${workerName}`;

// Default export for easier importing
export default BUILD_PATHS;
