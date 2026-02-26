const DEFAULT_NEAR_RPC_URL = 'https://test.rpc.fastnear.com'
const DEFAULT_NEAR_EXPLORER_URL = 'https://testnet.nearblocks.io'
const DEFAULT_DOCS_ORIGIN = 'https://docs.example.localhost'
const DEFAULT_TEMPO_RPC_URL = 'https://rpc.moderato.tempo.xyz'
const DEFAULT_TEMPO_EXPLORER_URL = 'https://explore.tempo.xyz'
const DEFAULT_ARC_RPC_URL = 'https://rpc.testnet.arc.network'
const DEFAULT_ARC_EXPLORER_URL = 'https://testnet.arcscan.app'
const DEFAULT_SIGNING_SESSION_TTL_MS = 24 * 60 * 60 * 1000
const DEFAULT_SIGNING_SESSION_REMAINING_USES = 10_000
const DEFAULT_DEMO_CONTRACT_ID = 'w3a-v1.testnet'

function toTrimmedString(value: unknown): string {
  return String(value ?? '').trim()
}

function toOptionalString(value: unknown): string | undefined {
  const trimmed = toTrimmedString(value)
  return trimmed || undefined
}

function parseNonNegativeInt(value: unknown, fallback: number): number {
  const parsed = Number(value)
  if (!Number.isFinite(parsed)) return fallback
  return Math.max(0, Math.floor(parsed))
}

function stripTrailingSlash(path: string): string {
  if (path.length <= 1) return path
  return path.endsWith('/') ? path.slice(0, -1) : path
}

const env = import.meta.env

const docsOrigin = stripTrailingSlash(toTrimmedString(env.VITE_DOCS_ORIGIN)) || DEFAULT_DOCS_ORIGIN
const baseUrl = stripTrailingSlash(toTrimmedString(env.BASE_URL || '/')) || '/'

export const FRONTEND_CONFIG = Object.freeze({
  relayerUrl: toOptionalString(env.VITE_RELAYER_URL),
  relayerAccountId: toOptionalString(env.VITE_RELAYER_ACCOUNT_ID),
  nearNetwork: env.VITE_NEAR_NETWORK === 'mainnet' ? 'mainnet' : 'testnet',
  nearRpcUrl: toTrimmedString(env.VITE_NEAR_RPC_URL) || DEFAULT_NEAR_RPC_URL,
  nearExplorerUrl: toTrimmedString(env.VITE_NEAR_EXPLORER) || DEFAULT_NEAR_EXPLORER_URL,
  tempoRpcUrl: toTrimmedString(env.VITE_TEMPO_RPC_URL) || DEFAULT_TEMPO_RPC_URL,
  tempoExplorerUrl: toTrimmedString(env.VITE_TEMPO_EXPLORER) || DEFAULT_TEMPO_EXPLORER_URL,
  arcRpcUrl: toTrimmedString(env.VITE_ARC_RPC_URL) || DEFAULT_ARC_RPC_URL,
  arcExplorerUrl: toTrimmedString(env.VITE_ARC_EXPLORER) || DEFAULT_ARC_EXPLORER_URL,
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
})

export type FrontendConfig = typeof FRONTEND_CONFIG
