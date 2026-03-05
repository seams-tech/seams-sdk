import type { TatchiConfigsInput } from '@tatchi-xyz/sdk/react';

const DEFAULT_NEAR_RPC_URL = 'https://test.rpc.fastnear.com';
const DEFAULT_NEAR_EXPLORER_URL = 'https://testnet.nearblocks.io';
const DEFAULT_DOCS_ORIGIN = 'https://docs.example.localhost';
const DEFAULT_TEMPO_RPC_URL = 'https://rpc.moderato.tempo.xyz';
const DEFAULT_TEMPO_EXPLORER_URL = 'https://explore.tempo.xyz';
const DEFAULT_TEMPO_FEE_TOKEN = '0x20c0000000000000000000000000000000000001';
// Arc-specific EVM demo defaults. Generic EVM behavior is still `chain: 'evm'`.
const DEFAULT_ARC_RPC_URL = 'https://rpc.testnet.arc.network';
const DEFAULT_ARC_EXPLORER_URL = 'https://testnet.arcscan.app';
const DEFAULT_SIGNING_SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_SIGNING_SESSION_REMAINING_USES = 10_000;
const DEFAULT_DEMO_CONTRACT_ID = 'w3a-v1.testnet';

function toTrimmedString(value: unknown): string {
  return String(value ?? '').trim();
}

function toOptionalString(value: unknown): string | undefined {
  const trimmed = toTrimmedString(value);
  return trimmed || undefined;
}

function parseNonNegativeInt(value: unknown, fallback: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(0, Math.floor(parsed));
}

function parseBooleanFlag(value: unknown, fallback: boolean): boolean {
  const normalized = String(value ?? '')
    .trim()
    .toLowerCase();
  if (!normalized) return fallback;
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

function parseSigningSessionPersistenceMode(
  value: unknown,
): NonNullable<TatchiConfigsInput['signingSessionPersistenceMode']> {
  const normalized = String(value ?? '')
    .trim()
    .toLowerCase();
  if (normalized === 'sealed_refresh_v1') return 'sealed_refresh_v1';
  return 'none';
}

function stripTrailingSlash(path: string): string {
  if (path.length <= 1) return path;
  return path.endsWith('/') ? path.slice(0, -1) : path;
}

const env = import.meta.env;

const docsOrigin = stripTrailingSlash(toTrimmedString(env.VITE_DOCS_ORIGIN)) || DEFAULT_DOCS_ORIGIN;
const baseUrl = stripTrailingSlash(toTrimmedString(env.BASE_URL || '/')) || '/';
const nearNetwork = env.VITE_NEAR_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
const nearChainNetwork: 'near-mainnet' | 'near-testnet' =
  nearNetwork === 'mainnet' ? 'near-mainnet' : 'near-testnet';
const nearRpcUrl = toTrimmedString(env.VITE_NEAR_RPC_URL) || DEFAULT_NEAR_RPC_URL;
const nearExplorerUrl = toTrimmedString(env.VITE_NEAR_EXPLORER) || DEFAULT_NEAR_EXPLORER_URL;
const tempoRpcUrl = toTrimmedString(env.VITE_TEMPO_RPC_URL) || DEFAULT_TEMPO_RPC_URL;
const tempoExplorerUrl = toTrimmedString(env.VITE_TEMPO_EXPLORER) || DEFAULT_TEMPO_EXPLORER_URL;
const tempoFeeToken = toTrimmedString(env.VITE_TEMPO_FEE_TOKEN) || DEFAULT_TEMPO_FEE_TOKEN;
// Arc env keys stay Arc-branded because this demo config wires Arc testnet explicitly.
const arcRpcUrl = toTrimmedString(env.VITE_ARC_RPC_URL) || DEFAULT_ARC_RPC_URL;
const arcExplorerUrl = toTrimmedString(env.VITE_ARC_EXPLORER) || DEFAULT_ARC_EXPLORER_URL;
const signingSessionPersistenceMode = parseSigningSessionPersistenceMode(
  env.VITE_SIGNING_SESSION_PERSISTENCE_MODE,
);
const signingSessionSealKeyVersion = toOptionalString(env.VITE_SIGNING_SESSION_SEAL_KEY_VERSION);
const signingSessionSealShamirPrimeB64u = toOptionalString(env.VITE_SIGNING_SESSION_SHAMIR_P_B64U);
const chains: NonNullable<TatchiConfigsInput['chains']> = [
  {
    network: nearChainNetwork,
    rpcUrl: nearRpcUrl,
    explorerUrl: nearExplorerUrl,
  },
  {
    network: 'tempo-testnet',
    rpcUrl: tempoRpcUrl,
    explorerUrl: tempoExplorerUrl,
    chainId: 42_431,
  },
  {
    network: 'arc-testnet',
    rpcUrl: arcRpcUrl,
    explorerUrl: arcExplorerUrl,
    chainId: 5_042_002,
  },
];

export const FRONTEND_CONFIG = Object.freeze({
  relayerUrl: toOptionalString(env.VITE_RELAYER_URL),
  consoleBaseUrl: toOptionalString(env.VITE_CONSOLE_BASE_URL),
  googleOidcClientId: toOptionalString(env.VITE_GOOGLE_OIDC_CLIENT_ID),
  consoleAuth: {
    bearerToken: toOptionalString(env.VITE_CONSOLE_BEARER_TOKEN),
    orgId: toOptionalString(env.VITE_CONSOLE_ORG_ID),
    userId: toOptionalString(env.VITE_CONSOLE_USER_ID),
    roles: toOptionalString(env.VITE_CONSOLE_ROLES),
    projectId: toOptionalString(env.VITE_CONSOLE_PROJECT_ID),
    environmentId: toOptionalString(env.VITE_CONSOLE_ENVIRONMENT_ID),
  },
  relayerAccountId: toOptionalString(env.VITE_RELAYER_ACCOUNT_ID),
  nearNetwork,
  nearRpcUrl,
  nearExplorerUrl,
  tempoRpcUrl,
  tempoExplorerUrl,
  tempoFeeToken,
  arcRpcUrl,
  arcExplorerUrl,
  chains,
  walletOrigin: toOptionalString(env.VITE_WALLET_ORIGIN),
  walletServicePath: toOptionalString(env.VITE_WALLET_SERVICE_PATH),
  sdkBasePath: toOptionalString(env.VITE_SDK_BASE_PATH),
  rpIdBase: toOptionalString(env.VITE_RP_ID_BASE),
  docsOrigin,
  baseUrl,
  demoContractId: toTrimmedString(env.VITE_DEMO_CONTRACT_ID) || DEFAULT_DEMO_CONTRACT_ID,
  signingSessionDefaults: {
    ttlMs: parseNonNegativeInt(env.VITE_SIGNING_SESSION_TTL_MS, DEFAULT_SIGNING_SESSION_TTL_MS),
    remainingUses: parseNonNegativeInt(
      env.VITE_SIGNING_SESSION_REMAINING_USES,
      DEFAULT_SIGNING_SESSION_REMAINING_USES,
    ),
  },
  signingSessionPersistenceMode,
  signingSessionSealKeyVersion,
  signingSessionSealShamirPrimeB64u,
  dashboardFlags: {
    walletsRoutesEnabled: parseBooleanFlag(env.VITE_DASHBOARD_WALLETS_ROUTES_ENABLED, true),
  },
});

export type FrontendConfig = typeof FRONTEND_CONFIG;
