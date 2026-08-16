import { toTrimmedString } from '@shared/utils/validation';
import type {
  EmailOtpAuthPolicy,
  SigningSessionPersistenceMode,
  SeamsConfigsInput,
  SeamsConfigsReadonly,
  SeamsRegistrationNearAccountProvisioning,
  SeamsWalletMode,
  RouterAbEcdsaDerivationPresignaturePoolPolicy,
} from '../types/seams';
import {
  copyEcdsaSignerProvisioningDefaults,
  resolveBoolean,
  resolveChains,
  resolveIntegerInRange,
  resolveAppearanceTheme,
  resolveThemePalette,
  type IntRange,
} from './configHelpers';
import { normalizeWalletHostVariant } from '../browser/walletIframe/hostVariant';
import {
  SIGNING_SESSION_SEAL_ALG,
  SIGNING_SESSION_SEAL_GROUP_ID,
} from '@shared/utils/signingSessionSeal';

const THRESHOLD_ECDSA_PRESIGN_POOL_LIMITS = {
  targetDepth: { min: 1, max: 64 } satisfies IntRange,
  maxRefillInFlight: { min: 1, max: 8 } satisfies IntRange,
  refillAttemptTimeoutMs: { min: 5_000, max: 120_000 } satisfies IntRange,
};

export type BuildConfigsOptions = {
  allowDirectWalletMode?: 'wallet_host';
};

export class HostedWalletOriginRequiredError extends Error {
  readonly code = 'SEAMS_HOSTED_WALLET_ORIGIN_REQUIRED';

  constructor() {
    // Refactor 90 Phase 0E absorbs this named boundary error into the typed config-error taxonomy.
    super(
      '[SEAMS_HOSTED_WALLET_ORIGIN_REQUIRED] Missing required config: iframeWallet.walletOrigin. Browser wallet capabilities require a hosted wallet iframe origin.',
    );
    this.name = 'HostedWalletOriginRequiredError';
  }
}

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

function joinUrlPath(baseUrl: string, path: string): string {
  const base = String(baseUrl || '')
    .trim()
    .replace(/\/+$/, '');
  const suffix = String(path || '').trim();
  if (!base) return '';
  if (!suffix) return base;
  return `${base}${suffix.startsWith('/') ? suffix : `/${suffix}`}`;
}

function resolveRegistrationNearAccountProvisioning(
  value: unknown,
): SeamsRegistrationNearAccountProvisioning {
  if (!value || typeof value !== 'object') return { kind: 'implicit_account' };
  const kind = String((value as { kind?: unknown }).kind || '').trim();
  switch (kind) {
    case '':
    case 'implicit_account':
      return { kind: 'implicit_account' };
    case 'relayer_named_subaccount':
      return { kind: 'relayer_named_subaccount' };
    default:
      throw new Error(
        `[configPresets] Invalid config: registration.nearAccountProvisioning.kind (${kind})`,
      );
  }
}

/**
 * Registration is managed-only. `/wallets/register/setup` authenticates with a
 * publishable key alone, so the credential must reach the browser; the former
 * backend-proxied mode had no way to supply one, and its `bootstrapUrl` only
 * ever pointed at the deleted intent route.
 */
function resolveRegistrationConfig(args: {
  overrides: SeamsConfigsInput;
  defaults: SeamsConfigsReadonly;
}): SeamsConfigsReadonly['registration'] {
  const overrides = args.overrides.registration;
  const defaults = args.defaults.registration;
  const projectEnvironmentId =
    toTrimmedString(overrides?.projectEnvironmentId) ||
    toTrimmedString(defaults.projectEnvironmentId);
  const publishableKey =
    toTrimmedString(overrides?.publishableKey) || toTrimmedString(defaults.publishableKey);
  /* Declaring registration config and leaving it incomplete is a mistake worth
     reporting at build time. Declaring none is not: an app that only signs for
     an already-registered wallet never registers, and registration credentials
     are not a precondition for the rest of the SDK. That case fails where it
     is actually wrong — at the registration call. */
  if (overrides !== undefined) {
    if (!projectEnvironmentId) {
      throw new Error('[configPresets] Missing required config: registration.projectEnvironmentId');
    }
    if (!publishableKey) {
      throw new Error('[configPresets] Missing required config: registration.publishableKey');
    }
  }
  return {
    mode: 'managed',
    projectEnvironmentId,
    publishableKey,
    paymentMode: overrides?.paymentMode ?? defaults.paymentMode ?? 'disabled',
    nearAccountProvisioning: resolveRegistrationNearAccountProvisioning(
      overrides?.nearAccountProvisioning ?? defaults.nearAccountProvisioning,
    ),
  };
}

function resolveSigningSessionSeal(args: {
  mode: SigningSessionPersistenceMode;
}): SeamsConfigsReadonly['signing']['sessionSeal'] {
  if (args.mode !== 'sealed_refresh_v1') {
    return { mode: 'none' };
  }
  return {
    mode: 'sealed_refresh_v1',
    protocol: {
      algorithm: SIGNING_SESSION_SEAL_ALG,
      groupId: SIGNING_SESSION_SEAL_GROUP_ID,
    },
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
  fallbackRouterAbEcdsaDerivationPresignaturePoolPolicy: RouterAbEcdsaDerivationPresignaturePoolPolicy;
  options?: BuildConfigsOptions;
}): SeamsConfigsReadonly {
  const defaults = args.defaults;
  const overrides = args.overrides ?? {};
  const allowDirectWalletMode = args.options?.allowDirectWalletMode === 'wallet_host';

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
  });
  const routerAbNormalSigning = resolveRouterAbNormalSigningConfig({
    overrides,
    defaults,
  });
  const provisioningDefaults = copyEcdsaSignerProvisioningDefaults(
    overrides.provisioningDefaults ?? defaults.signing.thresholdEcdsa.provisioningDefaults,
  );

  const routerAbEcdsaDerivationPresignaturePoolDefaults =
    defaults.signing.routerAbEcdsaDerivation.presignaturePool ??
    args.fallbackRouterAbEcdsaDerivationPresignaturePoolPolicy;
  const routerAbEcdsaDerivationPresignaturePoolTargetDepth = resolveIntegerInRange({
    value: overrides.routerAbEcdsaDerivationPresignaturePool?.targetDepth,
    fallback: routerAbEcdsaDerivationPresignaturePoolDefaults.targetDepth,
    range: THRESHOLD_ECDSA_PRESIGN_POOL_LIMITS.targetDepth,
    path: 'routerAbEcdsaDerivationPresignaturePool.targetDepth',
  });
  const routerAbEcdsaDerivationPresignaturePoolLowWatermark = resolveIntegerInRange({
    value: overrides.routerAbEcdsaDerivationPresignaturePool?.lowWatermark,
    fallback: routerAbEcdsaDerivationPresignaturePoolDefaults.lowWatermark,
    range: { min: 0, max: routerAbEcdsaDerivationPresignaturePoolTargetDepth },
    path: 'routerAbEcdsaDerivationPresignaturePool.lowWatermark',
  });

  const rawAppearance = overrides.appearance as Record<string, unknown> | undefined;
  const appearanceTheme = resolveAppearanceTheme({
    value: rawAppearance?.theme,
    fallback: defaults.ui.appearance.theme,
    legacyTokens: rawAppearance?.tokens,
  });
  const appearancePalette = resolveThemePalette({
    value: overrides.appearance?.palette,
    fallback: defaults.ui.appearance.palette,
  });

  const walletOriginRaw = overrides.iframeWallet?.walletOrigin;
  const walletOrigin = toTrimmedString(walletOriginRaw);
  const walletMode: SeamsWalletMode = walletOrigin
    ? 'iframe'
    : allowDirectWalletMode
      ? 'direct'
      : 'iframe';

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
    throw new HostedWalletOriginRequiredError();
  }

  const registration = resolveRegistrationConfig({ overrides, defaults });
  return {
    network: {
      chains,
      relayer: {
        accountId: relayerAccount,
        url: relayerUrl,
        routes: {
          delegateAction: relayerDelegateActionRoute,
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
      routerAbEcdsaDerivation: {
        presignaturePool: {
          enabled: resolveBoolean({
            value: overrides.routerAbEcdsaDerivationPresignaturePool?.enabled,
            fallback: routerAbEcdsaDerivationPresignaturePoolDefaults.enabled,
            path: 'routerAbEcdsaDerivationPresignaturePool.enabled',
          }),
          targetDepth: routerAbEcdsaDerivationPresignaturePoolTargetDepth,
          lowWatermark: routerAbEcdsaDerivationPresignaturePoolLowWatermark,
          maxRefillInFlight: resolveIntegerInRange({
            value: overrides.routerAbEcdsaDerivationPresignaturePool?.maxRefillInFlight,
            fallback: routerAbEcdsaDerivationPresignaturePoolDefaults.maxRefillInFlight,
            range: THRESHOLD_ECDSA_PRESIGN_POOL_LIMITS.maxRefillInFlight,
            path: 'routerAbEcdsaDerivationPresignaturePool.maxRefillInFlight',
          }),
          refillAttemptTimeoutMs: resolveIntegerInRange({
            value: overrides.routerAbEcdsaDerivationPresignaturePool?.refillAttemptTimeoutMs,
            fallback: routerAbEcdsaDerivationPresignaturePoolDefaults.refillAttemptTimeoutMs,
            range: THRESHOLD_ECDSA_PRESIGN_POOL_LIMITS.refillAttemptTimeoutMs,
            path: 'routerAbEcdsaDerivationPresignaturePool.refillAttemptTimeoutMs',
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
      },
    },
  };
}
