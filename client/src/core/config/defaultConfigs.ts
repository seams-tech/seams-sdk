import type {
  TatchiArcChainNetwork,
  TatchiChainConfig,
  TatchiChainConfigInput,
  TatchiChainNetwork,
  TatchiNearChainNetwork,
  TatchiTempoChainNetwork,
  ThresholdEcdsaPresignPoolPolicy,
  TatchiConfigs,
  TatchiConfigsInput,
} from '../types/tatchi';
import type { RegistrationSignerOptions } from '../types/registrationSignerOptions';
import { coerceSignerMode } from '../types/signer-worker';
import { toTrimmedString } from '@shared/utils/validation';
import { coerceThemeName } from '@shared/utils/theme';
import {
  chainFamilyFromNetwork,
  cloneChainConfig,
  cloneResolvedChainConfig,
  isTatchiChainNetwork,
} from './chains';
import {
  cloneRegistrationSignerOptions,
  coerceBoolean,
  coerceOptionalPositiveInt,
  coercePositiveIntInRange,
  coerceThemePaletteName,
  toStringRecord,
} from './utils/configHelpers';

// Default SDK configs suitable for local dev.
// Cross-origin wallet isolation is recommended; set iframeWallet in your app config when you have a dedicated origin.
// Consumers can shallow-merge overrides by field.

export const DEFAULT_REGISTRATION_SIGNER_OPTIONS: RegistrationSignerOptions = {
  tempo: {
    enabled: true,
    participantIds: [1, 2],
    sessionKind: 'jwt',
    ttlMs: 24 * 60 * 60 * 1000,
    remainingUses: 10_000,
  },
  evm: {
    enabled: true,
    participantIds: [1, 2],
    sessionKind: 'jwt',
    ttlMs: 24 * 60 * 60 * 1000,
    remainingUses: 10_000,
  },
};

export const DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY: ThresholdEcdsaPresignPoolPolicy = {
  enabled: true,
  targetDepth: 3,
  lowWatermark: 1,
  maxRefillInFlight: 1,
  refillAttemptTimeoutMs: 30_000,
};

export const DEFAULT_CHAIN_CONFIGS: TatchiChainConfig[] = [
  {
    network: 'near-testnet',
    // You can provide a single URL or a comma-separated list for failover.
    // First URL is treated as primary, subsequent URLs are fallbacks.
    rpcUrl: 'https://test.rpc.fastnear.com, https://rpc.testnet.near.org',
    explorerUrl: 'https://testnet.nearblocks.io',
  },
  {
    network: 'tempo-testnet',
    rpcUrl: 'https://rpc.moderato.tempo.xyz',
    explorerUrl: 'https://explore.tempo.xyz',
  },
  {
    network: 'arc-testnet',
    rpcUrl: 'https://rpc.testnet.arc.network',
    explorerUrl: 'https://testnet.arcscan.app',
    chainId: 5_042_002,
  },
];

export const PASSKEY_MANAGER_DEFAULT_CONFIGS: TatchiConfigs = {
  chains: DEFAULT_CHAIN_CONFIGS.map(cloneResolvedChainConfig),
  relayerAccount: 'w3a-relayer.testnet',
  appearance: {
    theme: 'dark',
    palette: 'default',
    tokens: {
      light: { colors: {} },
      dark: { colors: {} },
    },
  },
  signerMode: { mode: 'local-signer' },
  // Warm signing session defaults used by login/unlock flows.
  // Enforcement (TTL/uses) is owned by the UserConfirm worker (wallet origin); signer workers remain one-shot.
  signingSessionDefaults: {
    ttlMs: 24 * 60 * 60 * 1000, // 1 day
    remainingUses: 10_000,
  },
  thresholdEcdsaPresignPool: DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY,
  registrationSignerDefaults: DEFAULT_REGISTRATION_SIGNER_OPTIONS,
  relayer: {
    // accountId: 'w3a-relayer.testnet',
    // No default relayer URL. Force apps to configure via env/overrides.
    // Using an empty string triggers early validation errors in code paths that require it.
    url: '',
    delegateActionRoute: '/signed-delegate',
    smartAccountDeployRoute: '/smart-account/deploy',
    smartAccountDeploymentMode: 'enforce',
    smartAccountDeploymentMaxAttempts: 2,
    emailRecovery: {
      // Require at least 0.01 NEAR available to start email recovery.
      minBalanceYocto: '10000000000000000000000', // 0.01 NEAR
      // Poll every 4 seconds for verification status / access key.
      pollingIntervalMs: 4000,
      // Stop polling after 30 minutes.
      maxPollingDurationMs: 30 * 60 * 1000,
      // Expire pending recovery records after 30 minutes.
      pendingTtlMs: 30 * 60 * 1000,
      // Default recovery mailbox for examples / docs.
      mailtoAddress: 'recover@web3authn.org',
      emailDkimVerifierContract: 'email-dkim-verifier-v1.testnet',
    },
  },
  // Configure iframeWallet in application code to point at your dedicated wallet origin when available.
  iframeWallet: {
    walletOrigin: 'https://wallet.example.localhost',
    walletServicePath: '/wallet-service',
    sdkBasePath: '/sdk',
    rpIdOverride: 'example.localhost',
  },
};

// Default threshold participant identifiers (2P FROST).
// These are intentionally exported as standalone constants so apps can reuse them when wiring
// threshold signing across client + server environments.
export const THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID = 1 as const;
export const THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID = 2 as const;
export const THRESHOLD_ED25519_2P_PARTICIPANT_IDS = [
  THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID,
  THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID,
] as const;

function normalizeResolvedChainConfig(args: {
  input: TatchiChainConfigInput;
  fallback?: TatchiChainConfig;
}): TatchiChainConfig {
  const networkRaw = (args.input as { network?: unknown }).network;
  if (!isTatchiChainNetwork(networkRaw)) {
    throw new Error(`[configPresets] Invalid chain network: ${String(networkRaw || '')}`);
  }
  const network = networkRaw as TatchiChainNetwork;
  const rpcUrl = toTrimmedString(args.input.rpcUrl) || toTrimmedString(args.fallback?.rpcUrl);
  if (!rpcUrl) {
    throw new Error(`[configPresets] Missing required config: chains.${network}.rpcUrl`);
  }
  const explorerUrl =
    toTrimmedString(args.input.explorerUrl) || toTrimmedString(args.fallback?.explorerUrl);
  if (!explorerUrl) {
    throw new Error(`[configPresets] Missing required config: chains.${network}.explorerUrl`);
  }

  if (chainFamilyFromNetwork(network) === 'arc') {
    const chainId = coerceOptionalPositiveInt(
      (args.input as { chainId?: unknown }).chainId,
      (args.fallback as { chainId?: number } | undefined)?.chainId,
    );
    return {
      network: network as TatchiArcChainNetwork,
      rpcUrl,
      explorerUrl,
      ...(typeof chainId === 'number' ? { chainId } : {}),
    };
  }

  if (chainFamilyFromNetwork(network) === 'near') {
    return {
      network: network as TatchiNearChainNetwork,
      rpcUrl,
      explorerUrl,
    };
  }

  return {
    network: network as TatchiTempoChainNetwork,
    rpcUrl,
    explorerUrl,
  };
}

function mergeChainConfigs(
  defaults: readonly TatchiChainConfig[],
  overrides: TatchiConfigsInput['chains'],
): TatchiChainConfig[] {
  const defaultCopies = defaults.map(cloneResolvedChainConfig);
  if (!Array.isArray(overrides) || overrides.length === 0) {
    return defaultCopies;
  }

  const mergedByNetwork = new Map<TatchiChainNetwork, TatchiChainConfig>(
    defaultCopies.map((chain) => [chain.network, chain]),
  );
  const orderedNetworks: TatchiChainNetwork[] = [];

  for (const rawOverride of overrides) {
    const override = cloneChainConfig(rawOverride);
    if (!isTatchiChainNetwork(override.network)) {
      throw new Error(`[configPresets] Invalid chain network: ${String(override.network || '')}`);
    }
    const network = override.network;
    const fallback = mergedByNetwork.get(network);
    const resolved = normalizeResolvedChainConfig({
      input: override as TatchiChainConfigInput,
      fallback,
    });
    mergedByNetwork.set(network, resolved);
    if (!orderedNetworks.includes(network)) {
      orderedNetworks.push(network);
    }
  }

  for (const chain of defaultCopies) {
    if (!orderedNetworks.includes(chain.network)) {
      orderedNetworks.push(chain.network);
    }
  }

  const merged = orderedNetworks
    .map((network) => mergedByNetwork.get(network))
    .filter((chain): chain is TatchiChainConfig => !!chain);
  const hasNearChain = merged.some((chain) => chainFamilyFromNetwork(chain.network) === 'near');
  if (!hasNearChain) {
    throw new Error(
      '[configPresets] Missing required config: chains (at least one near-* network)',
    );
  }
  return merged;
}

// Merge defaults with overrides
export function buildConfigsFromEnv(overrides: TatchiConfigsInput = {}): TatchiConfigs {
  const defaults = PASSKEY_MANAGER_DEFAULT_CONFIGS;
  const relayerUrl = overrides.relayer?.url ?? defaults.relayer?.url ?? '';
  const chains = mergeChainConfigs(defaults.chains, overrides.chains);
  const relayerAccount =
    toTrimmedString(overrides.relayerAccount) || toTrimmedString(defaults.relayerAccount);
  const signerMode = coerceSignerMode(overrides.signerMode, defaults.signerMode);
  const smartAccountDeploymentMode =
    overrides.relayer?.smartAccountDeploymentMode === 'observe' ? 'observe' : 'enforce';
  const smartAccountDeploymentMaxAttempts = coercePositiveIntInRange(
    overrides.relayer?.smartAccountDeploymentMaxAttempts,
    defaults.relayer?.smartAccountDeploymentMaxAttempts ?? 2,
    1,
    5,
  );
  const appearanceTheme = coerceThemeName(overrides.appearance?.theme) ?? defaults.appearance.theme;
  const appearancePalette =
    coerceThemePaletteName(overrides.appearance?.palette) ?? defaults.appearance.palette;
  const defaultLightColors = toStringRecord(defaults.appearance.tokens.light.colors);
  const defaultDarkColors = toStringRecord(defaults.appearance.tokens.dark.colors);
  const overrideLightColors = toStringRecord(overrides.appearance?.tokens?.light?.colors);
  const overrideDarkColors = toStringRecord(overrides.appearance?.tokens?.dark?.colors);
  const registrationSignerDefaults = cloneRegistrationSignerOptions(
    overrides.registrationSignerDefaults ?? defaults.registrationSignerDefaults,
  );
  const thresholdEcdsaPresignPoolDefaults =
    overrides.thresholdEcdsaPresignPool ??
    defaults.thresholdEcdsaPresignPool ??
    DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY;
  const thresholdEcdsaPresignPoolEnabledDefault =
    thresholdEcdsaPresignPoolDefaults.enabled ??
    DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY.enabled;
  const thresholdEcdsaPresignPoolTargetDepthDefault =
    thresholdEcdsaPresignPoolDefaults.targetDepth ??
    DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY.targetDepth;
  const thresholdEcdsaPresignPoolLowWatermarkDefault =
    thresholdEcdsaPresignPoolDefaults.lowWatermark ??
    DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY.lowWatermark;
  const thresholdEcdsaPresignPoolMaxRefillInFlightDefault =
    thresholdEcdsaPresignPoolDefaults.maxRefillInFlight ??
    DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY.maxRefillInFlight;
  const thresholdEcdsaPresignPoolRefillAttemptTimeoutMsDefault =
    thresholdEcdsaPresignPoolDefaults.refillAttemptTimeoutMs ??
    DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY.refillAttemptTimeoutMs;
  const thresholdEcdsaPresignPoolTargetDepth = coercePositiveIntInRange(
    overrides.thresholdEcdsaPresignPool?.targetDepth ?? thresholdEcdsaPresignPoolTargetDepthDefault,
    thresholdEcdsaPresignPoolTargetDepthDefault,
    1,
    64,
  );
  const thresholdEcdsaPresignPoolLowWatermark = coercePositiveIntInRange(
    overrides.thresholdEcdsaPresignPool?.lowWatermark ??
      thresholdEcdsaPresignPoolLowWatermarkDefault,
    thresholdEcdsaPresignPoolLowWatermarkDefault,
    0,
    thresholdEcdsaPresignPoolTargetDepth,
  );
  const merged: TatchiConfigs = {
    chains,
    appearance: {
      theme: appearanceTheme,
      palette: appearancePalette,
      tokens: {
        light: {
          colors: {
            ...defaultLightColors,
            ...overrideLightColors,
          },
        },
        dark: {
          colors: {
            ...defaultDarkColors,
            ...overrideDarkColors,
          },
        },
      },
    },
    relayerAccount,
    signerMode,
    signingSessionDefaults: {
      ttlMs: overrides.signingSessionDefaults?.ttlMs ?? defaults.signingSessionDefaults?.ttlMs,
      remainingUses:
        overrides.signingSessionDefaults?.remainingUses ??
        defaults.signingSessionDefaults?.remainingUses,
    },
    thresholdEcdsaPresignPool: {
      enabled: coerceBoolean(
        overrides.thresholdEcdsaPresignPool?.enabled,
        thresholdEcdsaPresignPoolEnabledDefault,
      ),
      targetDepth: thresholdEcdsaPresignPoolTargetDepth,
      lowWatermark: thresholdEcdsaPresignPoolLowWatermark,
      maxRefillInFlight: coercePositiveIntInRange(
        overrides.thresholdEcdsaPresignPool?.maxRefillInFlight ??
          thresholdEcdsaPresignPoolMaxRefillInFlightDefault,
        thresholdEcdsaPresignPoolMaxRefillInFlightDefault,
        1,
        8,
      ),
      refillAttemptTimeoutMs: coercePositiveIntInRange(
        overrides.thresholdEcdsaPresignPool?.refillAttemptTimeoutMs ??
          thresholdEcdsaPresignPoolRefillAttemptTimeoutMsDefault,
        thresholdEcdsaPresignPoolRefillAttemptTimeoutMsDefault,
        5_000,
        120_000,
      ),
    },
    registrationSignerDefaults,
    relayer: {
      url: relayerUrl,
      delegateActionRoute:
        overrides.relayer?.delegateActionRoute ?? defaults.relayer?.delegateActionRoute,
      smartAccountDeployRoute:
        overrides.relayer?.smartAccountDeployRoute ?? defaults.relayer?.smartAccountDeployRoute,
      smartAccountDeploymentMode,
      smartAccountDeploymentMaxAttempts,
      emailRecovery: {
        minBalanceYocto:
          overrides.relayer?.emailRecovery?.minBalanceYocto ??
          defaults.relayer?.emailRecovery?.minBalanceYocto,
        pollingIntervalMs:
          overrides.relayer?.emailRecovery?.pollingIntervalMs ??
          defaults.relayer?.emailRecovery?.pollingIntervalMs,
        maxPollingDurationMs:
          overrides.relayer?.emailRecovery?.maxPollingDurationMs ??
          defaults.relayer?.emailRecovery?.maxPollingDurationMs,
        pendingTtlMs:
          overrides.relayer?.emailRecovery?.pendingTtlMs ??
          defaults.relayer?.emailRecovery?.pendingTtlMs,
        mailtoAddress:
          overrides.relayer?.emailRecovery?.mailtoAddress ??
          defaults.relayer?.emailRecovery?.mailtoAddress,
        emailDkimVerifierContract:
          overrides.relayer?.emailRecovery?.emailDkimVerifierContract ??
          defaults.relayer?.emailRecovery?.emailDkimVerifierContract,
      },
    },
    authenticatorOptions: overrides.authenticatorOptions ?? defaults.authenticatorOptions,
    iframeWallet: {
      // Preserve explicit empty-string walletOrigin ("") because it is used as a sentinel
      // to disable iframe-wallet mode in tests and some apps.
      walletOrigin: overrides.iframeWallet?.walletOrigin ?? defaults.iframeWallet?.walletOrigin,
      rpIdOverride: overrides.iframeWallet?.rpIdOverride ?? defaults.iframeWallet?.rpIdOverride,
      // IMPORTANT: the following fields are often wired from CI env vars like `VITE_SDK_BASE_PATH`.
      // When a GitHub Actions env var is missing, expressions like `${{ vars.VITE_SDK_BASE_PATH }}`
      // frequently become the empty string at build-time. Treat empty strings as "unset" so we
      // fall back to SDK defaults instead of accidentally generating root-relative URLs like:
      //   https://wallet.example.com/w3a-components.css  (wrong; should be /sdk/w3a-components.css)
      walletServicePath:
        toTrimmedString(overrides.iframeWallet?.walletServicePath) ||
        toTrimmedString(defaults.iframeWallet?.walletServicePath) ||
        '/wallet-service',
      sdkBasePath:
        toTrimmedString(overrides.iframeWallet?.sdkBasePath) ||
        toTrimmedString(defaults.iframeWallet?.sdkBasePath) ||
        '/sdk',
    },
  };
  if (!merged.relayer.url) {
    throw new Error('[configPresets] Missing required config: relayer.url');
  }
  return merged;
}
