import type {
  ThemePaletteName,
  ThresholdEcdsaPresignPoolPolicy,
  TatchiConfigs,
  TatchiConfigsInput,
} from '../types/tatchi';
import type { RegistrationSignerOptions } from '../types/registrationSignerOptions';
import { coerceSignerMode } from '../types/signer-worker';
import { toTrimmedString } from '@shared/utils/validation';
import { coerceThemeName } from '@shared/utils/theme';

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
  targetDepth: 20,
  lowWatermark: 5,
  maxRefillInFlight: 2,
  refillAttemptTimeoutMs: 30_000,
};

export const PASSKEY_MANAGER_DEFAULT_CONFIGS: TatchiConfigs = {
  // You can provide a single URL or a comma-separated list for failover.
  // First URL is treated as primary, subsequent URLs are fallbacks.
  nearRpcUrl: 'https://test.rpc.fastnear.com, https://rpc.testnet.near.org',
  nearNetwork: 'testnet',
  contractId: 'w3a-v1.testnet',
  appearance: {
    theme: 'dark',
    palette: 'default',
    tokens: {
      light: { colors: {} },
      dark: { colors: {} },
    },
  },
  // Default account domain for newly created accounts (subaccounts under the relayer).
  // In most deployments this is the same as `contractId`, but it can differ.
  relayerAccount: 'w3a-v1.testnet',
  nearExplorerUrl: 'https://testnet.nearblocks.io',
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
    // accountId: 'w3a-v1.testnet',
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
    },
  },
  emailDkimVerifierContract: 'email-dkim-verifier-v1.testnet',
  // Configure iframeWallet in application code to point at your dedicated wallet origin when available.
  iframeWallet: {
    walletOrigin: 'https://wallet.example.localhost',
    walletServicePath: '/wallet-service',
    sdkBasePath: '/sdk',
    rpIdOverride: 'example.localhost',
  }
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

function coercePositiveIntInRange(value: unknown, fallback: number, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback;
  const rounded = Math.trunc(value);
  if (rounded < min) return min;
  if (rounded > max) return max;
  return rounded;
}

function coerceBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function coerceThemePaletteName(value: unknown): ThemePaletteName | undefined {
  return value === 'default' ? value : undefined;
}

function toStringRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

function cloneRegistrationSignerOptions(
  value: RegistrationSignerOptions,
): RegistrationSignerOptions {
  return {
    tempo: {
      ...value.tempo,
      participantIds: Array.isArray(value.tempo.participantIds)
        ? [...value.tempo.participantIds]
        : [],
      ...(value.tempo.smartAccount ? { smartAccount: { ...value.tempo.smartAccount } } : {}),
    },
    evm: {
      ...value.evm,
      participantIds: Array.isArray(value.evm.participantIds)
        ? [...value.evm.participantIds]
        : [],
      ...(value.evm.smartAccount ? { smartAccount: { ...value.evm.smartAccount } } : {}),
    },
  };
}

// Merge defaults with overrides
export function buildConfigsFromEnv(overrides: TatchiConfigsInput = {}): TatchiConfigs {

  const defaults = PASSKEY_MANAGER_DEFAULT_CONFIGS;
  const relayerUrl = overrides.relayer?.url ?? defaults.relayer?.url ?? '';
  const relayerAccount = toTrimmedString(overrides.relayerAccount)
    || toTrimmedString(overrides.contractId)
    || toTrimmedString(defaults.relayerAccount)
    || toTrimmedString(defaults.contractId);
  const signerMode = coerceSignerMode(overrides.signerMode, defaults.signerMode);
  const smartAccountDeploymentMode =
    overrides.relayer?.smartAccountDeploymentMode === 'observe'
      ? 'observe'
      : 'enforce';
  const smartAccountDeploymentMaxAttempts = coercePositiveIntInRange(
    overrides.relayer?.smartAccountDeploymentMaxAttempts,
    defaults.relayer?.smartAccountDeploymentMaxAttempts ?? 2,
    1,
    5,
  );
  const appearanceTheme =
    coerceThemeName(overrides.appearance?.theme)
    ?? defaults.appearance.theme;
  const appearancePalette =
    coerceThemePaletteName(overrides.appearance?.palette)
    ?? defaults.appearance.palette;
  const defaultLightColors = toStringRecord(defaults.appearance.tokens.light.colors);
  const defaultDarkColors = toStringRecord(defaults.appearance.tokens.dark.colors);
  const overrideLightColors = toStringRecord(overrides.appearance?.tokens?.light?.colors);
  const overrideDarkColors = toStringRecord(overrides.appearance?.tokens?.dark?.colors);
  const registrationSignerDefaults = cloneRegistrationSignerOptions(
    overrides.registrationSignerDefaults ?? defaults.registrationSignerDefaults,
  );
  const thresholdEcdsaPresignPoolDefaults = (
    overrides.thresholdEcdsaPresignPool
    ?? defaults.thresholdEcdsaPresignPool
    ?? DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY
  );
  const thresholdEcdsaPresignPoolEnabledDefault =
    thresholdEcdsaPresignPoolDefaults.enabled
    ?? DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY.enabled;
  const thresholdEcdsaPresignPoolTargetDepthDefault =
    thresholdEcdsaPresignPoolDefaults.targetDepth
    ?? DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY.targetDepth;
  const thresholdEcdsaPresignPoolLowWatermarkDefault =
    thresholdEcdsaPresignPoolDefaults.lowWatermark
    ?? DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY.lowWatermark;
  const thresholdEcdsaPresignPoolMaxRefillInFlightDefault =
    thresholdEcdsaPresignPoolDefaults.maxRefillInFlight
    ?? DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY.maxRefillInFlight;
  const thresholdEcdsaPresignPoolRefillAttemptTimeoutMsDefault =
    thresholdEcdsaPresignPoolDefaults.refillAttemptTimeoutMs
    ?? DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY.refillAttemptTimeoutMs;
  const thresholdEcdsaPresignPoolTargetDepth = coercePositiveIntInRange(
    overrides.thresholdEcdsaPresignPool?.targetDepth ?? thresholdEcdsaPresignPoolTargetDepthDefault,
    thresholdEcdsaPresignPoolTargetDepthDefault,
    1,
    64,
  );
  const thresholdEcdsaPresignPoolLowWatermark = coercePositiveIntInRange(
    overrides.thresholdEcdsaPresignPool?.lowWatermark ?? thresholdEcdsaPresignPoolLowWatermarkDefault,
    thresholdEcdsaPresignPoolLowWatermarkDefault,
    0,
    thresholdEcdsaPresignPoolTargetDepth,
  );
  const merged: TatchiConfigs = {
    nearRpcUrl: overrides.nearRpcUrl ?? defaults.nearRpcUrl,
    nearNetwork: overrides.nearNetwork ?? defaults.nearNetwork,
    contractId: overrides.contractId ?? defaults.contractId,
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
    nearExplorerUrl: overrides.nearExplorerUrl ?? defaults.nearExplorerUrl,
    signerMode,
    signingSessionDefaults: {
      ttlMs: overrides.signingSessionDefaults?.ttlMs
        ?? defaults.signingSessionDefaults?.ttlMs,
      remainingUses: overrides.signingSessionDefaults?.remainingUses
        ?? defaults.signingSessionDefaults?.remainingUses,
    },
    thresholdEcdsaPresignPool: {
      enabled: coerceBoolean(
        overrides.thresholdEcdsaPresignPool?.enabled,
        thresholdEcdsaPresignPoolEnabledDefault,
      ),
      targetDepth: thresholdEcdsaPresignPoolTargetDepth,
      lowWatermark: thresholdEcdsaPresignPoolLowWatermark,
      maxRefillInFlight: coercePositiveIntInRange(
        overrides.thresholdEcdsaPresignPool?.maxRefillInFlight
          ?? thresholdEcdsaPresignPoolMaxRefillInFlightDefault,
        thresholdEcdsaPresignPoolMaxRefillInFlightDefault,
        1,
        8,
      ),
      refillAttemptTimeoutMs: coercePositiveIntInRange(
        overrides.thresholdEcdsaPresignPool?.refillAttemptTimeoutMs
          ?? thresholdEcdsaPresignPoolRefillAttemptTimeoutMsDefault,
        thresholdEcdsaPresignPoolRefillAttemptTimeoutMsDefault,
        5_000,
        120_000,
      ),
    },
    registrationSignerDefaults,
    relayer: {
      url: relayerUrl,
      delegateActionRoute: overrides.relayer?.delegateActionRoute
        ?? defaults.relayer?.delegateActionRoute,
      smartAccountDeployRoute: overrides.relayer?.smartAccountDeployRoute
        ?? defaults.relayer?.smartAccountDeployRoute,
      smartAccountDeploymentMode,
      smartAccountDeploymentMaxAttempts,
      emailRecovery: {
        minBalanceYocto: overrides.relayer?.emailRecovery?.minBalanceYocto
          ?? defaults.relayer?.emailRecovery?.minBalanceYocto,
        pollingIntervalMs: overrides.relayer?.emailRecovery?.pollingIntervalMs
          ?? defaults.relayer?.emailRecovery?.pollingIntervalMs,
        maxPollingDurationMs: overrides.relayer?.emailRecovery?.maxPollingDurationMs
          ?? defaults.relayer?.emailRecovery?.maxPollingDurationMs,
        pendingTtlMs: overrides.relayer?.emailRecovery?.pendingTtlMs
          ?? defaults.relayer?.emailRecovery?.pendingTtlMs,
        mailtoAddress: overrides.relayer?.emailRecovery?.mailtoAddress
          ?? defaults.relayer?.emailRecovery?.mailtoAddress,
      },
    },
    authenticatorOptions: overrides.authenticatorOptions ?? defaults.authenticatorOptions,
    emailDkimVerifierContract: overrides.emailDkimVerifierContract
      ?? defaults.emailDkimVerifierContract,
    iframeWallet: {
      // Preserve explicit empty-string walletOrigin ("") because it is used as a sentinel
      // to disable iframe-wallet mode in tests and some apps.
      walletOrigin: overrides.iframeWallet?.walletOrigin
        ?? defaults.iframeWallet?.walletOrigin,
      rpIdOverride: overrides.iframeWallet?.rpIdOverride
        ?? defaults.iframeWallet?.rpIdOverride,
      // IMPORTANT: the following fields are often wired from CI env vars like `VITE_SDK_BASE_PATH`.
      // When a GitHub Actions env var is missing, expressions like `${{ vars.VITE_SDK_BASE_PATH }}`
      // frequently become the empty string at build-time. Treat empty strings as "unset" so we
      // fall back to SDK defaults instead of accidentally generating root-relative URLs like:
      //   https://wallet.example.com/w3a-components.css  (wrong; should be /sdk/w3a-components.css)
      walletServicePath: toTrimmedString(overrides.iframeWallet?.walletServicePath)
        || toTrimmedString(defaults.iframeWallet?.walletServicePath)
        || '/wallet-service',
      sdkBasePath: toTrimmedString(overrides.iframeWallet?.sdkBasePath)
        || toTrimmedString(defaults.iframeWallet?.sdkBasePath)
        || '/sdk',
    }
  };
  if (!merged.contractId) {
    throw new Error('[configPresets] Missing required config: contractId');
  }
  if (!merged.relayer.url) {
    throw new Error('[configPresets] Missing required config: relayer.url');
  }
  return merged;
}
