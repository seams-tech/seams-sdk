import type { SeamsConfigsInput } from '@seams/sdk/react';
import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
  MAX_WALLET_SESSION_REMAINING_USES,
  MAX_WALLET_SESSION_TTL_MS,
} from '@seams/sdk/advanced';

const DEFAULT_NEAR_RPC_URL = 'https://test.rpc.fastnear.com,https://rpc.testnet.near.org';
const DEFAULT_NEAR_EXPLORER_URL = 'https://testnet.nearblocks.io';
const DEFAULT_DOCS_ORIGIN = 'https://docs.localhost';
const DEFAULT_TEMPO_RPC_URL = 'https://rpc.moderato.tempo.xyz';
const DEFAULT_TEMPO_EXPLORER_URL = 'https://explore.testnet.tempo.xyz';
const DEFAULT_TEMPO_FEE_TOKEN = '0x20c0000000000000000000000000000000000001';
const DEFAULT_ARC_RPC_URL = 'https://rpc.drpc.testnet.arc.network';
const DEFAULT_ARC_EXPLORER_URL = 'https://testnet.arcscan.app';
const DEFAULT_DEMO_CONTRACT_ID = 'seams-v1.testnet';

export type FrontendNetwork = 'testnet' | 'mainnet';

type ManagedRegistrationConfig = NonNullable<SeamsConfigsInput['registration']>;

export type FrontendDeployment = {
  network: FrontendNetwork;
  apiOrigin: string;
  relayerUrl: string;
  consoleBaseUrl: string;
  projectEnvironmentId: string;
  publishableKey: string;
  signingWorkerId: string;
  managedRegistration: ManagedRegistrationConfig | undefined;
  nearNetwork: FrontendNetwork;
  nearRpcUrl: string;
  nearExplorerUrl: string;
  tempoRpcUrl: string;
  tempoExplorerUrl: string;
  tempoFeeToken: string;
  arcRpcUrl: string;
  arcRpcRequestUrl: string;
  arcExplorerUrl: string;
  chains: NonNullable<SeamsConfigsInput['chains']>;
  walletOrigin: string;
  walletServicePath: string;
  sdkBasePath: string;
  rpIdBase: string;
  demoContractId: string;
  signingSessionDefaults: {
    ttlMs: number;
    remainingUses: number;
  };
  signingSessionPersistenceMode: NonNullable<SeamsConfigsInput['signingSessionPersistenceMode']>;
  routerAb: SeamsConfigsInput['routerAb'];
  enableIntendedE2E: boolean;
  dashboardFlags: {
    walletsRoutesEnabled: boolean;
  };
};

type FrontendSiteCommon = FrontendDeployment & {
  siteOrigin: string;
  docsOrigin: string;
  baseUrl: string;
  siteKind: 'staging' | 'production';
  defaultNetwork: FrontendNetwork;
};

export type StagingFrontendConfig = FrontendSiteCommon & {
  siteKind: 'staging';
  defaultNetwork: 'testnet';
  availableNetworks: readonly ['testnet'];
  deployments: {
    testnet: FrontendDeployment;
    mainnet?: never;
  };
};

export type ProductionFrontendConfig = FrontendSiteCommon & {
  siteKind: 'production';
  defaultNetwork: 'testnet';
  availableNetworks: readonly ['testnet', 'mainnet'];
  deployments: {
    testnet: FrontendDeployment;
    mainnet: FrontendDeployment;
  };
};

export type FrontendConfig = StagingFrontendConfig | ProductionFrontendConfig;

function toTrimmedString(value: unknown): string {
  return String(value ?? '').trim();
}

function toOptionalString(value: unknown): string | undefined {
  const trimmed = toTrimmedString(value);
  return trimmed || undefined;
}

function parseSigningSessionPolicyValue(args: {
  value: unknown;
  fallback: number;
  maximum: number;
  field: string;
}): number {
  const raw = toTrimmedString(args.value);
  if (!raw) return args.fallback;
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed <= 0 || parsed > args.maximum) {
    throw new Error(
      `${args.field} must be a positive safe integer no greater than ${args.maximum}`,
    );
  }
  return parsed;
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

function currentBrowserHostname(): string {
  if (typeof globalThis.location === 'undefined') return '';
  return toTrimmedString(globalThis.location.hostname);
}

function parseSigningSessionPersistenceMode(
  value: unknown,
): NonNullable<SeamsConfigsInput['signingSessionPersistenceMode']> {
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

function resolveManagedRegistrationConfig(
  source: Record<string, unknown>,
  prefix: string,
): ManagedRegistrationConfig | undefined {
  const projectEnvironmentId = toOptionalString(source[`${prefix}SEAMS_PROJECT_ENVIRONMENT_ID`]);
  const publishableKey = toOptionalString(source[`${prefix}SEAMS_PUBLISHABLE_KEY`]);

  if (projectEnvironmentId && !publishableKey) {
    throw new Error(
      `Missing ${prefix}SEAMS_PUBLISHABLE_KEY: managed registration requires both project environment and publishable key`,
    );
  }
  if (publishableKey && !projectEnvironmentId) {
    throw new Error(
      `Missing ${prefix}SEAMS_PROJECT_ENVIRONMENT_ID: managed registration requires both project environment and publishable key`,
    );
  }
  if (!projectEnvironmentId || !publishableKey) return undefined;

  return {
    mode: 'managed',
    projectEnvironmentId,
    publishableKey,
  };
}

function resolveRouterAbConfig(
  source: Record<string, unknown>,
  prefix: string,
  managedRegistration: ManagedRegistrationConfig | undefined,
): SeamsConfigsInput['routerAb'] | undefined {
  const signingWorkerId = toOptionalString(source[`${prefix}ROUTER_AB_NORMAL_SIGNING_WORKER_ID`]);
  if (signingWorkerId) {
    return {
      normalSigning: {
        mode: 'enabled',
        signingWorkerId,
      },
    };
  }

  if (managedRegistration) {
    throw new Error(
      `Missing ${prefix}ROUTER_AB_NORMAL_SIGNING_WORKER_ID: managed threshold registrations require Router A/B normal signing`,
    );
  }

  return undefined;
}

function resolveArcRpcRequestUrl(arcRpcUrl: string): string {
  return Array.from(
    new Set(
      [arcRpcUrl, DEFAULT_ARC_RPC_URL]
        .flatMap((value) => value.split(/[\s,]+/u))
        .map((value) => value.trim())
        .filter(Boolean),
    ),
  ).join(',');
}

function readEnvironmentValue(source: Record<string, unknown>, key: string, fallback = ''): string {
  return toTrimmedString(source[key]) || fallback;
}

function resolveLanePrefix(network: FrontendNetwork, siteKind: 'staging' | 'production'): string {
  return siteKind === 'staging' ? 'VITE_' : `VITE_${network.toUpperCase()}_`;
}

function resolveRequiredLaneValue(
  source: Record<string, unknown>,
  key: string,
  prefix: string,
  network: FrontendNetwork,
): string {
  const value = toOptionalString(source[`${prefix}${key}`]);
  if (!value) {
    throw new Error(`Missing ${prefix}${key}: ${network} frontend configuration is incomplete`);
  }
  return value;
}

function buildChains(
  source: Record<string, unknown>,
  prefix: string,
  network: FrontendNetwork,
  nearRpcUrl: string,
  nearExplorerUrl: string,
): NonNullable<SeamsConfigsInput['chains']> {
  const nearChainNetwork: 'near-mainnet' | 'near-testnet' =
    network === 'mainnet' ? 'near-mainnet' : 'near-testnet';
  const chains: NonNullable<SeamsConfigsInput['chains']> = [
    {
      network: nearChainNetwork,
      rpcUrl: nearRpcUrl,
      explorerUrl: nearExplorerUrl,
    },
  ];

  if (network === 'testnet') {
    const tempoRpcUrl =
      readEnvironmentValue(source, `${prefix}TEMPO_RPC_URL`) || DEFAULT_TEMPO_RPC_URL;
    const tempoExplorerUrl =
      readEnvironmentValue(source, `${prefix}TEMPO_EXPLORER`) || DEFAULT_TEMPO_EXPLORER_URL;
    const arcRpcUrl = readEnvironmentValue(source, `${prefix}ARC_RPC_URL`) || DEFAULT_ARC_RPC_URL;
    const arcExplorerUrl =
      readEnvironmentValue(source, `${prefix}ARC_EXPLORER`) || DEFAULT_ARC_EXPLORER_URL;
    chains.push(
      {
        network: 'tempo-testnet',
        rpcUrl: tempoRpcUrl,
        explorerUrl: tempoExplorerUrl,
        chainId: 42_431,
      },
      {
        network: 'arc-testnet',
        rpcUrl: resolveArcRpcRequestUrl(arcRpcUrl),
        explorerUrl: arcExplorerUrl,
        chainId: 5_042_002,
      },
    );
  }
  return chains;
}

function buildDeployment(
  source: ImportMetaEnv,
  siteKind: 'staging' | 'production',
  network: FrontendNetwork,
  laneOrigin: string,
  walletOrigin: string,
): FrontendDeployment {
  const laneValues = source as Record<string, unknown>;
  const prefix = resolveLanePrefix(network, siteKind);
  const registration = resolveManagedRegistrationConfig(laneValues, prefix);
  const configuredNearNetwork = toOptionalString(laneValues[`${prefix}NEAR_NETWORK`]);
  if (configuredNearNetwork && configuredNearNetwork !== network) {
    throw new Error(
      `Invalid ${prefix}NEAR_NETWORK: expected ${network}, received ${configuredNearNetwork || 'empty'}`,
    );
  }
  if (siteKind === 'production' && !registration) {
    throw new Error(
      `Missing ${prefix}SEAMS_PROJECT_ENVIRONMENT_ID or ${prefix}SEAMS_PUBLISHABLE_KEY: production registration is managed`,
    );
  }
  const relayerUrl =
    siteKind === 'staging' ? readEnvironmentValue(laneValues, `${prefix}RELAYER_URL`) : laneOrigin;
  const consoleBaseUrl =
    siteKind === 'staging'
      ? readEnvironmentValue(laneValues, `${prefix}CONSOLE_BASE_URL`, relayerUrl)
      : laneOrigin;
  const nearRpcUrl =
    siteKind === 'staging'
      ? readEnvironmentValue(laneValues, `${prefix}NEAR_RPC_URL`, DEFAULT_NEAR_RPC_URL)
      : resolveRequiredLaneValue(laneValues, 'NEAR_RPC_URL', prefix, network);
  const nearExplorerUrl =
    siteKind === 'staging'
      ? readEnvironmentValue(laneValues, `${prefix}NEAR_EXPLORER`, DEFAULT_NEAR_EXPLORER_URL)
      : resolveRequiredLaneValue(laneValues, 'NEAR_EXPLORER', prefix, network);
  const tempoRpcUrl =
    network === 'testnet'
      ? readEnvironmentValue(laneValues, `${prefix}TEMPO_RPC_URL`, DEFAULT_TEMPO_RPC_URL)
      : '';
  const tempoExplorerUrl =
    network === 'testnet'
      ? readEnvironmentValue(laneValues, `${prefix}TEMPO_EXPLORER`, DEFAULT_TEMPO_EXPLORER_URL)
      : '';
  const tempoFeeToken =
    network === 'testnet'
      ? readEnvironmentValue(laneValues, `${prefix}TEMPO_FEE_TOKEN`, DEFAULT_TEMPO_FEE_TOKEN)
      : '';
  const arcRpcUrl =
    network === 'testnet'
      ? readEnvironmentValue(laneValues, `${prefix}ARC_RPC_URL`, DEFAULT_ARC_RPC_URL)
      : '';
  const arcExplorerUrl =
    network === 'testnet'
      ? readEnvironmentValue(laneValues, `${prefix}ARC_EXPLORER`, DEFAULT_ARC_EXPLORER_URL)
      : '';
  const rpIdBase =
    readEnvironmentValue(laneValues, `${prefix}RP_ID_BASE`) ||
    (walletOrigin ? new URL(walletOrigin).hostname : currentBrowserHostname());
  const signingSessionPersistenceMode = parseSigningSessionPersistenceMode(
    readEnvironmentValue(laneValues, `${prefix}SIGNING_SESSION_PERSISTENCE_MODE`),
  );
  const routerAb = resolveRouterAbConfig(laneValues, prefix, registration);
  const signingWorkerId =
    toOptionalString(laneValues[`${prefix}ROUTER_AB_NORMAL_SIGNING_WORKER_ID`]) || '';

  return {
    network,
    apiOrigin: laneOrigin,
    relayerUrl,
    consoleBaseUrl,
    projectEnvironmentId: registration?.projectEnvironmentId || '',
    publishableKey: registration?.publishableKey || '',
    signingWorkerId,
    managedRegistration: registration,
    nearNetwork: network,
    nearRpcUrl,
    nearExplorerUrl,
    tempoRpcUrl,
    tempoExplorerUrl,
    tempoFeeToken,
    arcRpcUrl,
    arcRpcRequestUrl: arcRpcUrl ? resolveArcRpcRequestUrl(arcRpcUrl) : '',
    arcExplorerUrl,
    chains: buildChains(source, prefix, network, nearRpcUrl, nearExplorerUrl),
    walletOrigin,
    walletServicePath: readEnvironmentValue(laneValues, `${prefix}WALLET_SERVICE_PATH`),
    sdkBasePath: readEnvironmentValue(laneValues, `${prefix}SDK_BASE_PATH`),
    rpIdBase,
    demoContractId: readEnvironmentValue(
      laneValues,
      `${prefix}DEMO_CONTRACT_ID`,
      network === 'mainnet' ? '' : DEFAULT_DEMO_CONTRACT_ID,
    ),
    signingSessionDefaults: {
      ttlMs: parseSigningSessionPolicyValue({
        value: readEnvironmentValue(laneValues, `${prefix}SIGNING_SESSION_TTL_MS`),
        fallback: DEFAULT_WALLET_SESSION_TTL_MS,
        maximum: MAX_WALLET_SESSION_TTL_MS,
        field: `${prefix}SIGNING_SESSION_TTL_MS`,
      }),
      remainingUses: parseSigningSessionPolicyValue({
        value: readEnvironmentValue(laneValues, `${prefix}SIGNING_SESSION_REMAINING_USES`),
        fallback: DEFAULT_WALLET_SESSION_REMAINING_USES,
        maximum: MAX_WALLET_SESSION_REMAINING_USES,
        field: `${prefix}SIGNING_SESSION_REMAINING_USES`,
      }),
    },
    signingSessionPersistenceMode,
    routerAb,
    enableIntendedE2E: parseBooleanFlag(source.VITE_ENABLE_INTENDED_E2E, source.DEV === true),
    dashboardFlags: {
      walletsRoutesEnabled: parseBooleanFlag(source.VITE_DASHBOARD_WALLETS_ROUTES_ENABLED, true),
    },
  };
}

function buildSiteConfig(source: ImportMetaEnv): FrontendConfig {
  const siteKind = source.VITE_SITE_ID === 'production' ? 'production' : 'staging';
  const docsOrigin = stripTrailingSlash(
    toTrimmedString(source.VITE_DOCS_ORIGIN) || DEFAULT_DOCS_ORIGIN,
  );
  const baseUrl = stripTrailingSlash(toTrimmedString(source.BASE_URL || '/')) || '/';
  const siteOrigin =
    toTrimmedString(source.VITE_SITE_ORIGIN) ||
    (siteKind === 'production' ? 'https://seams.sh' : 'https://staging.seams.sh');
  const testnetOrigin =
    siteKind === 'production'
      ? 'https://test.api.seams.sh'
      : readEnvironmentValue(source as Record<string, unknown>, 'VITE_RELAYER_URL');
  const testnetWalletOrigin =
    siteKind === 'production'
      ? 'https://test.sign.seams.sh'
      : readEnvironmentValue(source as Record<string, unknown>, 'VITE_WALLET_ORIGIN');
  const testnet = buildDeployment(source, siteKind, 'testnet', testnetOrigin, testnetWalletOrigin);

  if (siteKind === 'staging') {
    return {
      ...testnet,
      siteOrigin,
      docsOrigin,
      baseUrl,
      siteKind,
      defaultNetwork: 'testnet',
      availableNetworks: ['testnet'],
      deployments: { testnet },
    };
  }

  const mainnet = buildDeployment(
    source,
    siteKind,
    'mainnet',
    'https://api.seams.sh',
    'https://sign.seams.sh',
  );
  if (mainnet.nearNetwork !== 'mainnet') {
    throw new Error('Production mainnet frontend must use mainnet NEAR configuration');
  }

  return {
    ...testnet,
    siteOrigin,
    docsOrigin,
    baseUrl,
    siteKind,
    defaultNetwork: 'testnet',
    availableNetworks: ['testnet', 'mainnet'],
    deployments: { testnet, mainnet },
  };
}

export const FRONTEND_CONFIG = Object.freeze(buildSiteConfig(import.meta.env));

export function getFrontendDeployment(
  config: FrontendConfig,
  network: FrontendNetwork = config.defaultNetwork,
): FrontendDeployment {
  switch (config.siteKind) {
    case 'staging':
      if (network !== 'testnet') {
        throw new Error('Staging frontend only supports testnet');
      }
      return config.deployments.testnet;
    case 'production':
      return config.deployments[network];
    default:
      return assertNever(config);
  }
}

export function buildSeamsSdkConfig(deployment: FrontendDeployment): SeamsConfigsInput {
  return {
    chains: deployment.chains,
    iframeWallet: deployment.walletOrigin
      ? {
          walletOrigin: deployment.walletOrigin,
          ...(deployment.walletServicePath
            ? { walletServicePath: deployment.walletServicePath }
            : {}),
          ...(deployment.rpIdBase ? { rpIdOverride: deployment.rpIdBase } : {}),
          ...(deployment.sdkBasePath ? { sdkBasePath: deployment.sdkBasePath } : {}),
        }
      : undefined,
    signingSessionDefaults: deployment.signingSessionDefaults,
    signingSessionPersistenceMode: deployment.signingSessionPersistenceMode,
    ...(deployment.routerAb ? { routerAb: deployment.routerAb } : {}),
    ...(deployment.enableIntendedE2E
      ? {
          routerAbEcdsaDerivationPresignaturePool: {
            enabled: true,
            targetDepth: 1,
            lowWatermark: 0,
            maxRefillInFlight: 1,
            refillAttemptTimeoutMs: 30_000,
          },
        }
      : {}),
    relayer: {
      url: deployment.relayerUrl,
    },
    ...(deployment.managedRegistration ? { registration: deployment.managedRegistration } : {}),
  };
}

function assertNever(value: never): never {
  throw new Error(`Unsupported frontend configuration branch: ${String(value)}`);
}
