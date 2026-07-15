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
    ROOT: 'src',
    CORE: 'src/core',
    STATIC: 'src/static',
    SIGNING_WORKERS: 'src/core/signingEngine/workerManager/workers',
    WASM_SIGNER: '../../wasm/near_signer',
    ED25519_YAO_CLIENT: '../../crates/router-ab-ed25519-yao-client',
    WASM_ECDSA_CLIENT_SIGNER: '../../wasm/ecdsa_client_signer',
    WASM_ETH_SIGNER: '../../wasm/eth_signer',
    WASM_TEMPO_SIGNER: '../../wasm/tempo_signer',
    WASM_SHAMIR3PASS_RUNTIME: '../../wasm/shamir3pass_runtime',
    WASM_EMAIL_OTP_RUNTIME: '../../wasm/email_otp_runtime',
    CRITICAL_DIRS: [
      'src/core',
      'src/react',
      'src/static',
      'src/utils',
      '../sdk-server-ts/src',
      '../shared-ts/src',
      '../../crates/router-ab-ed25519-yao-client',
      '../../wasm/near_signer',
      '../../wasm/ecdsa_client_signer',
      '../../wasm/eth_signer',
      '../../wasm/tempo_signer',
      '../../wasm/shamir3pass_runtime',
      '../../wasm/email_otp_runtime',
    ],
  },

  // Runtime paths (used by workers and tests)
  RUNTIME: {
    SDK_BASE: '/sdk',
    WORKERS_BASE: '/sdk/workers',
    TOUCH_CONFIRM_WORKER: '/sdk/workers/passkey-confirm.worker.js',
    SIGNER_WORKER: '/sdk/workers/near-signer.worker.js',
    ECDSA_HSS_CLIENT_WORKER: '/sdk/workers/ecdsa-hss-client.worker.js',
    EMAIL_OTP_WORKER: '/sdk/workers/email-otp.worker.js',
  },

  // Worker file names
  WORKERS: {
    TOUCH_CONFIRM: 'passkey-confirm.worker.js',
    SIGNER: 'near-signer.worker.js',
    ECDSA_HSS_CLIENT: 'ecdsa-hss-client.worker.js',
    EMAIL_OTP: 'email-otp.worker.js',
    SHAMIR3PASS: 'shamir3pass.worker.js',
    WASM_SIGNER_JS: 'wasm_signer_worker.js',
    WASM_SIGNER_WASM: 'wasm_signer_worker_bg.wasm',
    ED25519_YAO_CLIENT_JS: 'router_ab_ed25519_yao_client.js',
    ED25519_YAO_CLIENT_WASM: 'router_ab_ed25519_yao_client_bg.wasm',
    ECDSA_CLIENT_SIGNER_JS: 'ecdsa_client_signer.js',
    ECDSA_CLIENT_SIGNER_WASM: 'ecdsa_client_signer_bg.wasm',
    WASM_ETH_SIGNER_WASM: 'eth_signer.wasm',
    WASM_ETH_SIGNER_BG_WASM: 'eth_signer_bg.wasm',
    WASM_TEMPO_SIGNER_WASM: 'tempo_signer.wasm',
    WASM_TEMPO_SIGNER_BG_WASM: 'tempo_signer_bg.wasm',
    EMAIL_OTP_RUNTIME_JS: 'email_otp_runtime.js',
    EMAIL_OTP_RUNTIME_WASM: 'email_otp_runtime_bg.wasm',
  },

  // Test worker file paths (for test files)
  TEST_WORKERS: {
    TOUCH_CONFIRM: '/sdk/workers/passkey-confirm.worker.js',
    SIGNER: '/sdk/workers/near-signer.worker.js',
    ECDSA_HSS_CLIENT: '/sdk/workers/ecdsa-hss-client.worker.js',
    EMAIL_OTP: '/sdk/workers/email-otp.worker.js',
    SHAMIR3PASS: '/sdk/workers/shamir3pass.worker.js',
    WASM_SIGNER_JS: '/sdk/workers/wasm_signer_worker.js',
    WASM_SIGNER_WASM: '/sdk/workers/wasm_signer_worker_bg.wasm',
    ED25519_YAO_CLIENT_JS: '/sdk/workers/router_ab_ed25519_yao_client.js',
    ED25519_YAO_CLIENT_WASM: '/sdk/workers/router_ab_ed25519_yao_client_bg.wasm',
    ECDSA_CLIENT_SIGNER_JS: '/sdk/workers/ecdsa_client_signer.js',
    ECDSA_CLIENT_SIGNER_WASM: '/sdk/workers/ecdsa_client_signer_bg.wasm',
    WASM_ETH_SIGNER_WASM: '/sdk/workers/eth_signer.wasm',
    WASM_ETH_SIGNER_BG_WASM: '/sdk/workers/eth_signer_bg.wasm',
    WASM_TEMPO_SIGNER_WASM: '/sdk/workers/tempo_signer.wasm',
    WASM_TEMPO_SIGNER_BG_WASM: '/sdk/workers/tempo_signer_bg.wasm',
    EMAIL_OTP_RUNTIME_JS: '/sdk/workers/email_otp_runtime.js',
    EMAIL_OTP_RUNTIME_WASM: '/sdk/workers/email_otp_runtime_bg.wasm',
  },
} as const;

// Helper functions
export const getWorkerPath = (workerName: string): string =>
  `${BUILD_PATHS.BUILD.WORKERS}/${workerName}`;
export const getRuntimeWorkerPath = (workerName: string): string =>
  `${BUILD_PATHS.RUNTIME.WORKERS_BASE}/${workerName}`;

// Default export for easier importing
export default BUILD_PATHS;
