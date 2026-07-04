/// <reference types="vite/client" />

// Project-specific env typings for Vite
// Note: Keep keys in sync with .env files and CI/Pages envs.
interface ImportMetaEnv {
  readonly VITE_RELAYER_URL?: string;
  readonly VITE_CONSOLE_BASE_URL?: string;
  readonly VITE_SEAMS_PROJECT_ENVIRONMENT_ID?: string;
  readonly VITE_SEAMS_PUBLISHABLE_KEY?: string;
  readonly VITE_RELAYER_ACCOUNT_ID?: string;

  readonly VITE_NEAR_NETWORK?: 'testnet' | 'mainnet';
  readonly VITE_NEAR_RPC_URL?: string;
  readonly VITE_NEAR_EXPLORER?: string;
  readonly VITE_TEMPO_RPC_URL?: string;
  readonly VITE_TEMPO_EXPLORER?: string;
  readonly VITE_TEMPO_FEE_TOKEN?: string;
  // Arc-specific EVM demo overrides.
  readonly VITE_ARC_RPC_URL?: string;
  readonly VITE_ARC_EXPLORER?: string;
  readonly VITE_SIGNING_SESSION_TTL_MS?: string;
  readonly VITE_SIGNING_SESSION_REMAINING_USES?: string;
  readonly VITE_SIGNING_SESSION_PERSISTENCE_MODE?: string;
  readonly VITE_SIGNING_SESSION_SEAL_KEY_VERSION?: string;
  readonly VITE_SIGNING_SESSION_SHAMIR_P_B64U?: string;
  readonly VITE_ROUTER_AB_NORMAL_SIGNING_WORKER_ID?: string;
  readonly VITE_ROR_ALLOWED_ORIGINS?: string;
  readonly VITE_DEMO_CONTRACT_ID?: string;

  readonly VITE_WALLET_ORIGIN?: string;
  readonly VITE_WALLET_SERVICE_PATH?: string;
  readonly VITE_SDK_BASE_PATH?: string;
  readonly VITE_RP_ID_BASE?: string;
  readonly VITE_DOCS_ORIGIN?: string;
  readonly VITE_DASHBOARD_WALLETS_ROUTES_ENABLED?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
