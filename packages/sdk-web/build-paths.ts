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
    WASM_ECDSA_CLIENT: '../../wasm/router_ab_ecdsa_client',
    WASM_ECDSA_PRESIGN_CLIENT: '../../wasm/router_ab_ecdsa_presign_client',
    WASM_ECDSA_ONLINE_CLIENT: '../../wasm/router_ab_ecdsa_online_client',
    WASM_ECDSA_SIGNING_WORKER: '../../wasm/router_ab_ecdsa_signing_worker',
    WASM_EVM_CRYPTO: '../../wasm/evm_crypto',
    WASM_TEMPO_SIGNER: '../../wasm/tempo_signer',
    WASM_SHAMIR3PASS_RUNTIME: '../../wasm/shamir3pass_runtime',
    WASM_EMAIL_OTP_RUNTIME: '../../wasm/email_otp_runtime',
    WASM_WALLET_CUSTODY_CEREMONY: '../../wasm/wallet_custody_ceremony',
    CRITICAL_DIRS: [
      'src/core',
      'src/react',
      'src/static',
      'src/utils',
      '../sdk-server-ts/src',
      '../shared-ts/src',
      '../../crates/router-ab-ed25519-yao-client',
      '../../wasm/near_signer',
      '../../wasm/router_ab_ecdsa_client',
      '../../wasm/router_ab_ecdsa_presign_client',
      '../../wasm/router_ab_ecdsa_online_client',
      '../../wasm/router_ab_ecdsa_signing_worker',
      '../../wasm/evm_crypto',
      '../../wasm/tempo_signer',
      '../../wasm/shamir3pass_runtime',
      '../../wasm/email_otp_runtime',
      '../../wasm/wallet_custody_ceremony',
    ],
  },

  // Runtime paths (used by workers and tests)
  RUNTIME: {
    SDK_BASE: '/sdk',
    WORKERS_BASE: '/sdk/workers',
    TOUCH_CONFIRM_WORKER: '/sdk/workers/passkey-confirm.worker.js',
    PASSKEY_MPC_SESSION_WORKER: '/sdk/workers/passkey-mpc-session.worker.js',
    PASSKEY_MPC_EXPORT_WORKER: '/sdk/workers/passkey-mpc-export.worker.js',
    SIGNER_WORKER: '/sdk/workers/near-signer.worker.js',
    ECDSA_DERIVATION_CLIENT_WORKER: '/sdk/workers/ecdsa-derivation-client.worker.js',
    ECDSA_PRESIGN_CLIENT_WORKER: '/sdk/workers/ecdsa-presign-client.worker.js',
    ECDSA_ONLINE_CLIENT_WORKER: '/sdk/workers/ecdsa-online-client.worker.js',
    EMAIL_OTP_WORKER: '/sdk/workers/email-otp.worker.js',
    WALLET_CUSTODY_CEREMONY_WORKER: '/sdk/workers/wallet-custody-ceremony.worker.js',
  },

  // Worker file names
  WORKERS: {
    TOUCH_CONFIRM: 'passkey-confirm.worker.js',
    PASSKEY_MPC_SESSION: 'passkey-mpc-session.worker.js',
    PASSKEY_MPC_EXPORT: 'passkey-mpc-export.worker.js',
    SIGNER: 'near-signer.worker.js',
    ECDSA_DERIVATION_CLIENT: 'ecdsa-derivation-client.worker.js',
    ECDSA_PRESIGN_CLIENT: 'ecdsa-presign-client.worker.js',
    ECDSA_ONLINE_CLIENT: 'ecdsa-online-client.worker.js',
    EMAIL_OTP: 'email-otp.worker.js',
    WALLET_CUSTODY_CEREMONY: 'wallet-custody-ceremony.worker.js',
    SHAMIR3PASS: 'shamir3pass.worker.js',
    WASM_SIGNER_JS: 'wasm_signer_worker.js',
    WASM_SIGNER_WASM: 'wasm_signer_worker_bg.wasm',
    ED25519_YAO_CLIENT_JS: 'router_ab_ed25519_yao_client.js',
    ED25519_YAO_CLIENT_WASM: 'router_ab_ed25519_yao_client_bg.wasm',
    ECDSA_CLIENT_JS: 'router_ab_ecdsa_client.js',
    ECDSA_CLIENT_WASM: 'router_ab_ecdsa_client_bg.wasm',
    ECDSA_PRESIGN_CLIENT_WASM: 'router_ab_ecdsa_presign_client_bg.wasm',
    ECDSA_ONLINE_CLIENT_WASM: 'router_ab_ecdsa_online_client_bg.wasm',
    WASM_EVM_CRYPTO_WASM: 'evm_crypto.wasm',
    WASM_EVM_CRYPTO_BG_WASM: 'evm_crypto_bg.wasm',
    WASM_TEMPO_SIGNER_WASM: 'tempo_signer.wasm',
    WASM_TEMPO_SIGNER_BG_WASM: 'tempo_signer_bg.wasm',
    EMAIL_OTP_RUNTIME_JS: 'email_otp_runtime.js',
    EMAIL_OTP_RUNTIME_WASM: 'email_otp_runtime_bg.wasm',
    WALLET_CUSTODY_CEREMONY_WASM: 'wallet_custody_ceremony_bg.wasm',
  },

  // Test worker file paths (for test files)
  TEST_WORKERS: {
    TOUCH_CONFIRM: '/sdk/workers/passkey-confirm.worker.js',
    PASSKEY_MPC_SESSION: '/sdk/workers/passkey-mpc-session.worker.js',
    PASSKEY_MPC_EXPORT: '/sdk/workers/passkey-mpc-export.worker.js',
    SIGNER: '/sdk/workers/near-signer.worker.js',
    ECDSA_DERIVATION_CLIENT: '/sdk/workers/ecdsa-derivation-client.worker.js',
    ECDSA_PRESIGN_CLIENT: '/sdk/workers/ecdsa-presign-client.worker.js',
    ECDSA_ONLINE_CLIENT: '/sdk/workers/ecdsa-online-client.worker.js',
    EMAIL_OTP: '/sdk/workers/email-otp.worker.js',
    WALLET_CUSTODY_CEREMONY: '/sdk/workers/wallet-custody-ceremony.worker.js',
    SHAMIR3PASS: '/sdk/workers/shamir3pass.worker.js',
    WASM_SIGNER_JS: '/sdk/workers/wasm_signer_worker.js',
    WASM_SIGNER_WASM: '/sdk/workers/wasm_signer_worker_bg.wasm',
    ED25519_YAO_CLIENT_JS: '/sdk/workers/router_ab_ed25519_yao_client.js',
    ED25519_YAO_CLIENT_WASM: '/sdk/workers/router_ab_ed25519_yao_client_bg.wasm',
    ECDSA_CLIENT_JS: '/sdk/workers/router_ab_ecdsa_client.js',
    ECDSA_CLIENT_WASM: '/sdk/workers/router_ab_ecdsa_client_bg.wasm',
    ECDSA_PRESIGN_CLIENT_WASM: '/sdk/workers/router_ab_ecdsa_presign_client_bg.wasm',
    ECDSA_ONLINE_CLIENT_WASM: '/sdk/workers/router_ab_ecdsa_online_client_bg.wasm',
    WASM_EVM_CRYPTO_WASM: '/sdk/workers/evm_crypto.wasm',
    WASM_EVM_CRYPTO_BG_WASM: '/sdk/workers/evm_crypto_bg.wasm',
    WASM_TEMPO_SIGNER_WASM: '/sdk/workers/tempo_signer.wasm',
    WASM_TEMPO_SIGNER_BG_WASM: '/sdk/workers/tempo_signer_bg.wasm',
    EMAIL_OTP_RUNTIME_JS: '/sdk/workers/email_otp_runtime.js',
    EMAIL_OTP_RUNTIME_WASM: '/sdk/workers/email_otp_runtime_bg.wasm',
    WALLET_CUSTODY_CEREMONY_WASM: '/sdk/workers/wallet_custody_ceremony_bg.wasm',
  },
} as const;

// Helper functions
export const getWorkerPath = (workerName: string): string =>
  `${BUILD_PATHS.BUILD.WORKERS}/${workerName}`;
export const getRuntimeWorkerPath = (workerName: string): string =>
  `${BUILD_PATHS.RUNTIME.WORKERS_BASE}/${workerName}`;

// Default export for easier importing
export default BUILD_PATHS;
