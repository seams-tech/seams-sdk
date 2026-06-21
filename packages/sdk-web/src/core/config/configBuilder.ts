import { toTrimmedString } from '@shared/utils/validation';
import type {
  EmailOtpAuthPolicy,
  SigningSessionPersistenceMode,
  SeamsConfigsInput,
  SeamsConfigsReadonly,
  SeamsWalletMode,
  RouterAbEcdsaHssPresignaturePoolPolicy,
} from '../types/seams';
import {
  copyEcdsaSignerProvisioningDefaults,
  resolveBoolean,
  resolveChains,
  resolveIntegerInRange,
  resolveTheme,
  resolveThemePalette,
  toColorTokenRecord,
  type IntRange,
} from './configHelpers';
import { normalizeWalletHostVariant } from '../browser/walletIframe/hostVariant';
import { parseSigningSessionSealKeyVersion } from '../signingEngine/session/keyMaterialBrands';

const THRESHOLD_ECDSA_PRESIGN_POOL_LIMITS = {
  targetDepth: { min: 1, max: 64 } satisfies IntRange,
  maxRefillInFlight: { min: 1, max: 8 } satisfies IntRange,
  refillAttemptTimeoutMs: { min: 5_000, max: 120_000 } satisfies IntRange,
};

function resolveSigningSessionPersistenceMode(args: {
  value: unknown;
  fallback: SigningSessionPersistenceMode;
}): SigningSessionPersistenceMode {
  const raw = String(args.value || '')
    .trim()
    .toLowerCase();
  if (!raw) return args.fallback;
  if (raw === 'none') return 'none';
  if (raw === 'sealed_refresh_v1') return 'sealed_refresh_v1';
  throw new Error(
    `[configPresets] Invalid config: signingSessionPersistenceMode (${raw}); expected "none" or "sealed_refresh_v1"`,
  );
}

function resolveEmailOtpAuthPolicy(args: {
  value: unknown;
  fallback: EmailOtpAuthPolicy;
}): EmailOtpAuthPolicy {
  const raw = String(args.value || '')
    .trim()
    .toLowerCase();
  if (!raw) return args.fallback;
  if (raw === 'session') return 'session';
  if (raw === 'per_operation') return 'per_operation';
  throw new Error(
    `[configPresets] Invalid config: emailOtpAuthPolicy (${raw}); expected "session" or "per_operation"`,
  );
}

function isBase64UrlNoPadding(value: string): boolean {
  return /^[A-Za-z0-9_-]+$/.test(value);
}

function joinUrlPath(baseUrl: string, path: string): string {
  const base = String(baseUrl || '')
    .trim()
    .replace(/\/+$/, '');
  const suffix = String(path || '').trim();
  if (!base) return '';
  if (!suffix) return base;
  return `${base}${suffix.startsWith('/') ? suffix : `/${suffix}`}`;
}

function resolveRegistrationConfig(args: {
  overrides: SeamsConfigsInput;
  defaults: SeamsConfigsReadonly;
  relayerUrl: string;
}): SeamsConfigsReadonly['registration'] {
  const registrationOverrides = args.overrides.registration;
  const registrationDefaults = args.defaults.registration;
  const managedOverrides =
    registrationOverrides && registrationOverrides.mode === 'managed'
      ? registrationOverrides
      : null;
  const managedDefaults = registrationDefaults.mode === 'managed' ? registrationDefaults : null;
  const backendProxyOverrides =
    registrationOverrides && registrationOverrides.mode !== 'managed'
      ? registrationOverrides
      : null;
  const backendProxyDefaults =
    registrationDefaults.mode === 'backend_proxy' ? registrationDefaults : null;
  const mode =
    registrationOverrides?.mode ?? registrationDefaults.mode ?? ('backend_proxy' as const);

  if (mode === 'managed') {
    const environmentId =
      toTrimmedString(managedOverrides?.environmentId) ||
      toTrimmedString(managedDefaults?.environmentId);
    const publishableKey =
      toTrimmedString(managedOverrides?.publishableKey) ||
      toTrimmedString(managedDefaults?.publishableKey);
    const paymentMode = managedOverrides?.paymentMode ?? managedDefaults?.paymentMode ?? 'disabled';
    if (!environmentId) {
      throw new Error('[configPresets] Missing required config: registration.environmentId');
    }
    if (!publishableKey) {
      throw new Error('[configPresets] Missing required config: registration.publishableKey');
    }
    return {
      mode: 'managed',
      environmentId,
      publishableKey,
      paymentMode,
    };
  }

  const bootstrapUrl =
    toTrimmedString(backendProxyOverrides?.registrationBootstrapUrl) ||
    toTrimmedString(backendProxyDefaults?.bootstrapUrl) ||
    joinUrlPath(args.relayerUrl, '/wallets/register/intent');
  if (!bootstrapUrl) {
    throw new Error(
      '[configPresets] Missing required config: registration.registrationBootstrapUrl',
    );
  }
  return {
    mode: 'backend_proxy',
    bootstrapUrl,
  };
}

function resolveSigningSessionSeal(args: {
  mode: SigningSessionPersistenceMode;
  overrides: SeamsConfigsInput;
  defaults: SeamsConfigsReadonly;
}): SeamsConfigsReadonly['signing']['sessionSeal'] {
  if (args.mode !== 'sealed_refresh_v1') {
    return {};
  }

  const keyVersion =
    toTrimmedString(args.overrides.signingSessionSeal?.keyVersion) ||
    toTrimmedString(args.defaults.signing.sessionSeal.signingSessionSealKeyVersion);
  const shamirPrimeB64u =
    toTrimmedString(args.overrides.signingSessionSeal?.shamirPrimeB64u) ||
    toTrimmedString(args.defaults.signing.sessionSeal.shamirPrimeB64u);

  if (!shamirPrimeB64u) {
    throw new Error(
      '[configPresets] Missing required config: signingSessionSeal.shamirPrimeB64u when signingSessionPersistenceMode="sealed_refresh_v1"',
    );
  }
  if (!isBase64UrlNoPadding(shamirPrimeB64u)) {
    throw new Error(
      '[configPresets] Invalid config: signingSessionSeal.shamirPrimeB64u must be base64url (no padding)',
    );
  }

  return {
    ...(keyVersion
      ? { signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(keyVersion) }
      : {}),
    shamirPrimeB64u,
  };
}

function resolveRouterAbNormalSigningConfig(args: {
  overrides: SeamsConfigsInput;
  defaults: SeamsConfigsReadonly;
}): SeamsConfigsReadonly['signing']['routerAb']['normalSigning'] {
  const override = args.overrides.routerAb?.normalSigning;
  const fallback = args.defaults.signing.routerAb.normalSigning;
  const rawMode = override?.mode ?? fallback.mode;
  const rawSigningWorkerId =
    override && 'signingWorkerId' in override ? override.signingWorkerId : undefined;

  if (rawSigningWorkerId !== undefined && rawMode !== 'enabled') {
    throw new Error(
      '[configPresets] Invalid config: routerAb.normalSigning.signingWorkerId requires routerAb.normalSigning.mode="enabled"',
    );
  }

  if (rawMode === 'disabled') {
    return { mode: 'disabled' };
  }
  if (rawMode !== 'enabled') {
    throw new Error(
      '[configPresets] Invalid config: routerAb.normalSigning.mode must be "disabled" or "enabled"',
    );
  }

  const signingWorkerId =
    toTrimmedString(rawSigningWorkerId) ||
    (fallback.mode === 'enabled' ? toTrimmedString(fallback.signingWorkerId) : '');
  if (!signingWorkerId) {
    throw new Error(
      '[configPresets] Missing required config: routerAb.normalSigning.signingWorkerId when routerAb.normalSigning.mode="enabled"',
    );
  }
  return {
    mode: 'enabled',
    signingWorkerId,
  };
}

export function buildConfigsFromDefaults(args: {
  defaults: SeamsConfigsReadonly;
  overrides?: SeamsConfigsInput;
  fallbackRouterAbEcdsaHssPresignaturePoolPolicy: RouterAbEcdsaHssPresignaturePoolPolicy;
}): SeamsConfigsReadonly {
  const defaults = args.defaults;
  const overrides = args.overrides ?? {};

  const chains = resolveChains(defaults.network.chains, overrides.chains);
  const relayerUrl = toTrimmedString(overrides.relayer?.url ?? defaults.network.relayer.url);
  const relayerAccount =
    toTrimmedString(overrides.relayerAccount) ||
    toTrimmedString(defaults.network.relayer.accountId);
  const relayerDelegateActionRoute =
    overrides.relayer?.delegateActionRoute ?? defaults.network.relayer.routes.delegateAction;

  const signingSessionPersistenceMode = resolveSigningSessionPersistenceMode({
    value: overrides.signingSessionPersistenceMode,
    fallback: defaults.signing.sessionPersistenceMode,
  });
  const emailOtpAuthPolicy = resolveEmailOtpAuthPolicy({
    value: overrides.emailOtpAuthPolicy,
    fallback: defaults.signing.emailOtp.authPolicy,
  });
  const signingSessionSeal = resolveSigningSessionSeal({
    mode: signingSessionPersistenceMode,
    overrides,
    defaults,
  });
  const routerAbNormalSigning = resolveRouterAbNormalSigningConfig({
    overrides,
    defaults,
  });
  const provisioningDefaults = copyEcdsaSignerProvisioningDefaults(
    overrides.provisioningDefaults ?? defaults.signing.thresholdEcdsa.provisioningDefaults,
  );

  const routerAbEcdsaHssPresignaturePoolDefaults =
    defaults.signing.routerAbEcdsaHss.presignaturePool ??
    args.fallbackRouterAbEcdsaHssPresignaturePoolPolicy;
  const routerAbEcdsaHssPresignaturePoolTargetDepth = resolveIntegerInRange({
    value: overrides.routerAbEcdsaHssPresignaturePool?.targetDepth,
    fallback: routerAbEcdsaHssPresignaturePoolDefaults.targetDepth,
    range: THRESHOLD_ECDSA_PRESIGN_POOL_LIMITS.targetDepth,
    path: 'routerAbEcdsaHssPresignaturePool.targetDepth',
  });
  const routerAbEcdsaHssPresignaturePoolLowWatermark = resolveIntegerInRange({
    value: overrides.routerAbEcdsaHssPresignaturePool?.lowWatermark,
    fallback: routerAbEcdsaHssPresignaturePoolDefaults.lowWatermark,
    range: { min: 0, max: routerAbEcdsaHssPresignaturePoolTargetDepth },
    path: 'routerAbEcdsaHssPresignaturePool.lowWatermark',
  });

  const appearanceTheme = resolveTheme({
    value: overrides.appearance?.theme,
    fallback: defaults.ui.appearance.theme,
  });
  const appearancePalette = resolveThemePalette({
    value: overrides.appearance?.palette,
    fallback: defaults.ui.appearance.palette,
  });
  const defaultLightColors = toColorTokenRecord(defaults.ui.appearance.tokens.light.colors);
  const defaultDarkColors = toColorTokenRecord(defaults.ui.appearance.tokens.dark.colors);
  const overrideLightColors = toColorTokenRecord(overrides.appearance?.tokens?.light?.colors);
  const overrideDarkColors = toColorTokenRecord(overrides.appearance?.tokens?.dark?.colors);

  const walletOriginOverrideProvided =
    !!overrides.iframeWallet &&
    Object.prototype.hasOwnProperty.call(overrides.iframeWallet, 'walletOrigin');
  const walletOriginRaw = overrides.iframeWallet?.walletOrigin ?? defaults.wallet.iframe.origin;
  const walletOrigin = toTrimmedString(walletOriginRaw);
  const walletMode: SeamsWalletMode = walletOriginOverrideProvided
    ? walletOrigin
      ? 'iframe'
      : 'direct'
    : defaults.wallet.mode;

  const walletRpIdOverride =
    overrides.iframeWallet?.rpIdOverride ?? defaults.wallet.iframe.rpIdOverride;
  // IMPORTANT: the following fields are often wired from CI env vars like `VITE_SDK_BASE_PATH`.
  // When a GitHub Actions env var is missing, expressions like `${{ vars.VITE_SDK_BASE_PATH }}`
  // frequently become the empty string at build-time. Treat empty strings as "unset" so we
  // fall back to SDK defaults instead of accidentally generating root-relative URLs like:
  //   https://wallet.example.com/w3a-components.css  (wrong; should be /sdk/w3a-components.css)
  const walletServicePath =
    toTrimmedString(overrides.iframeWallet?.walletServicePath) ||
    toTrimmedString(defaults.wallet.iframe.servicePath) ||
    '/wallet-service';
  const walletSdkBasePath =
    toTrimmedString(overrides.iframeWallet?.sdkBasePath) ||
    toTrimmedString(defaults.wallet.iframe.sdkBasePath) ||
    '/sdk';
  const walletHostVariant = normalizeWalletHostVariant(
    overrides.iframeWallet?.walletHostVariant || defaults.wallet.iframe.walletHostVariant,
  );

  if (!relayerUrl) {
    throw new Error('[configPresets] Missing required config: relayer.url');
  }
  if (walletMode === 'iframe' && !walletOrigin) {
    throw new Error(
      '[configPresets] Missing required config: iframeWallet.walletOrigin (iframe mode enabled)',
    );
  }

  const registration = resolveRegistrationConfig({
    overrides,
    defaults,
    relayerUrl,
  });
  return {
    network: {
      chains,
      relayer: {
        accountId: relayerAccount,
        url: relayerUrl,
        routes: {
          delegateAction: relayerDelegateActionRoute,
        },
        emailRecovery: {
          minBalanceYocto:
            overrides.relayer?.emailRecovery?.minBalanceYocto ??
            defaults.network.relayer.emailRecovery.minBalanceYocto,
          pollingIntervalMs:
            overrides.relayer?.emailRecovery?.pollingIntervalMs ??
            defaults.network.relayer.emailRecovery.pollingIntervalMs,
          maxPollingDurationMs:
            overrides.relayer?.emailRecovery?.maxPollingDurationMs ??
            defaults.network.relayer.emailRecovery.maxPollingDurationMs,
          pendingTtlMs:
            overrides.relayer?.emailRecovery?.pendingTtlMs ??
            defaults.network.relayer.emailRecovery.pendingTtlMs,
          mailtoAddress:
            overrides.relayer?.emailRecovery?.mailtoAddress ??
            defaults.network.relayer.emailRecovery.mailtoAddress,
          emailDkimVerifierContract:
            overrides.relayer?.emailRecovery?.emailDkimVerifierContract ??
            defaults.network.relayer.emailRecovery.emailDkimVerifierContract,
        },
      },
    },
    registration,
    signing: {
      sessionDefaults: {
        ttlMs: overrides.signingSessionDefaults?.ttlMs ?? defaults.signing.sessionDefaults.ttlMs,
        remainingUses:
          overrides.signingSessionDefaults?.remainingUses ??
          defaults.signing.sessionDefaults.remainingUses,
      },
      emailOtp: {
        authPolicy: emailOtpAuthPolicy,
      },
      sessionPersistenceMode: signingSessionPersistenceMode,
      sessionSeal: signingSessionSeal,
      routerAb: {
        normalSigning: routerAbNormalSigning,
      },
      routerAbEcdsaHss: {
        presignaturePool: {
          enabled: resolveBoolean({
            value: overrides.routerAbEcdsaHssPresignaturePool?.enabled,
            fallback: routerAbEcdsaHssPresignaturePoolDefaults.enabled,
            path: 'routerAbEcdsaHssPresignaturePool.enabled',
          }),
          targetDepth: routerAbEcdsaHssPresignaturePoolTargetDepth,
          lowWatermark: routerAbEcdsaHssPresignaturePoolLowWatermark,
          maxRefillInFlight: resolveIntegerInRange({
            value: overrides.routerAbEcdsaHssPresignaturePool?.maxRefillInFlight,
            fallback: routerAbEcdsaHssPresignaturePoolDefaults.maxRefillInFlight,
            range: THRESHOLD_ECDSA_PRESIGN_POOL_LIMITS.maxRefillInFlight,
            path: 'routerAbEcdsaHssPresignaturePool.maxRefillInFlight',
          }),
          refillAttemptTimeoutMs: resolveIntegerInRange({
            value: overrides.routerAbEcdsaHssPresignaturePool?.refillAttemptTimeoutMs,
            fallback: routerAbEcdsaHssPresignaturePoolDefaults.refillAttemptTimeoutMs,
            range: THRESHOLD_ECDSA_PRESIGN_POOL_LIMITS.refillAttemptTimeoutMs,
            path: 'routerAbEcdsaHssPresignaturePool.refillAttemptTimeoutMs',
          }),
        },
      },
      thresholdEcdsa: {
        provisioningDefaults,
      },
    },
    webauthn: {
      authenticatorOptions:
        overrides.authenticatorOptions ?? defaults.webauthn.authenticatorOptions,
    },
    wallet:
      walletMode === 'iframe'
        ? {
            mode: 'iframe',
            iframe: {
              origin: walletOrigin,
              servicePath: walletServicePath,
              sdkBasePath: walletSdkBasePath,
              walletHostVariant,
              rpIdOverride: walletRpIdOverride,
            },
          }
        : {
            mode: 'direct',
            iframe: {
              ...(walletOrigin ? { origin: walletOrigin } : {}),
              servicePath: walletServicePath,
              sdkBasePath: walletSdkBasePath,
              walletHostVariant,
              rpIdOverride: walletRpIdOverride,
            },
          },
    ui: {
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
    },
  };
}
