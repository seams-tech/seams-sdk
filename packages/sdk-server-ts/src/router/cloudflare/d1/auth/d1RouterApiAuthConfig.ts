import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';
import type {
  EmailOtpChallengeAction,
  EmailOtpChallengeOperation,
} from '../../../../core/EmailOtpStores';
import type { SignerWasmModuleSupplier } from '../../../../core/types';
import { EMAIL_OTP_CODE_LENGTH } from '../../../../core/authService/emailOtpConfig';
import type { RouterAbEcdsaPresignRuntime } from '../../../../core/routerAbSigning/RouterAbEcdsaPresignRuntime';
import type { RouterAbEd25519YaoProductRegistrationRuntimeV1 } from '../../../domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration';
import type { RouterAbEcdsaStrictRegistrationPort } from '../../../domains/ecdsa/routerAbEcdsaStrictRegistration';
import type { SigningSessionSealShamir3PassRootConfig } from '../../../../threshold/session/signingSessionSeal/crypto/cipher';
import { parseSigningSessionSealRootConfig } from '../../../../threshold/session/signingSessionSeal/options';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import type { NormalizedLogger } from '../../../../core/logger';
import type { LinkedDeviceOwnerAuthorizationPortV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type {
  LinkedDeviceAggregateRevocationPortV1,
  LinkedDeviceLocalStateInvalidationPortV1,
  LinkedDeviceManagementAuthorizationPortV1,
  LinkedDeviceWalletSessionRevocationPortV1,
} from '../../../../core/deviceLinking/linkedDeviceManagement';
import type { WebAuthnRpId } from '@shared/utils/domainIds';
import type { DeviceLinkingRouteServiceV1 } from '../../../transport/fetch/routes/deviceLinking';
import type { DeviceLinkingGatewayCompletionServiceV1 } from '../../../transport/fetch/routes/deviceLinkingGateway';
import type { LinkedDeviceTargetPlannerV1 } from '../deviceLinking/d1LinkedDeviceTargetCredentialProvider';
import type { LinkedDeviceR102ProvisioningExecutionPortV1 } from '../deviceLinking/d1LinkedDeviceProvisioningProvider';
import type { D1LinkedDeviceManagementMetadataPortV1 } from '../deviceLinking/d1LinkedDeviceManagementStore';
import {
  normalizeOidcExchangeConfig,
  type CloudflareD1OidcExchangeConfig,
  type NormalizedCloudflareD1OidcExchangeConfig,
} from '../oidc/d1OidcBoundary';

export type CloudflareD1EmailOtpDeliveryProviderInput = {
  readonly challengeId: string;
  readonly walletId: string;
  readonly userId: string;
  readonly orgId?: string;
  readonly email: string;
  readonly emailHint: string;
  readonly otpCode: string;
  readonly otpChannel: WalletEmailOtpChannel;
  readonly action: EmailOtpChallengeAction;
  readonly operation: EmailOtpChallengeOperation;
  readonly expiresAtMs: number;
};

export type CloudflareD1EmailOtpDeliveryProviderResult =
  | { readonly ok: true; readonly providerMessageId?: string }
  | { readonly ok: false; readonly code: string; readonly message: string };

export interface CloudflareD1EmailOtpDeliveryProvider {
  deliver(
    input: CloudflareD1EmailOtpDeliveryProviderInput,
  ): Promise<CloudflareD1EmailOtpDeliveryProviderResult>;
}

export type CloudflareD1EmailOtpServerSealConfig = {
  readonly rootSecretB64u: string;
  readonly currentKeyVersion: string;
  readonly acceptedWarmKeyVersions?: readonly string[];
};

export type CloudflareD1LinkedDeviceExecutionOptionsV1 = {
  readonly nowV1: () => number;
  readonly rpId: WebAuthnRpId;
  readonly expectedOrigin: string;
  readonly logger: NormalizedLogger;
};

export type CloudflareD1LinkedDeviceSessionOptionsV1 = {
  readonly ownerAuthorization: LinkedDeviceOwnerAuthorizationPortV1;
  readonly authenticateOwnerRequestV1: DeviceLinkingRouteServiceV1['authenticateOwnerRequestV1'];
  readonly targetPlanner: LinkedDeviceTargetPlannerV1;
  readonly provisioningActivation: Pick<
    LinkedDeviceR102ProvisioningExecutionPortV1,
    'recordHolderDeliveriesAndActivateV1'
  >;
  readonly acknowledgeReceiptV1: DeviceLinkingRouteServiceV1['acknowledgeReceiptV1'];
  readonly retryCommittedDeliveryV1: DeviceLinkingRouteServiceV1['retryCommittedDeliveryV1'];
};

export type CloudflareD1LinkedDeviceManagementOptionsV1 = {
  readonly metadata: D1LinkedDeviceManagementMetadataPortV1;
  readonly authorization: LinkedDeviceManagementAuthorizationPortV1;
  readonly aggregateRevocation: LinkedDeviceAggregateRevocationPortV1;
  readonly walletSessionRevocation: LinkedDeviceWalletSessionRevocationPortV1;
  readonly localStateInvalidation: LinkedDeviceLocalStateInvalidationPortV1;
};

export type CloudflareD1LinkedDeviceGatewayOptionsV1 = {
  readonly ownerAuthorization: LinkedDeviceOwnerAuthorizationPortV1;
  readonly authenticateGatewayRequestV1: DeviceLinkingGatewayCompletionServiceV1['authenticateGatewayRequestV1'];
};

type CloudflareD1LinkedDeviceCompositionWithoutSessionV1 = {
  readonly execution: CloudflareD1LinkedDeviceExecutionOptionsV1;
  readonly session?: never;
  readonly management?: never;
  readonly gateway?: CloudflareD1LinkedDeviceGatewayOptionsV1;
};

type CloudflareD1LinkedDeviceCompositionWithSessionV1 = {
  readonly execution: CloudflareD1LinkedDeviceExecutionOptionsV1;
  readonly session: CloudflareD1LinkedDeviceSessionOptionsV1;
  readonly management?: CloudflareD1LinkedDeviceManagementOptionsV1;
  readonly gateway?: CloudflareD1LinkedDeviceGatewayOptionsV1;
};

/**
 * Optional R103 composition. Each enabled surface requires its complete
 * external boundary; omitted surfaces stay fail-closed at their route.
 */
export type CloudflareD1LinkedDeviceCompositionOptionsV1 =
  | CloudflareD1LinkedDeviceCompositionWithoutSessionV1
  | CloudflareD1LinkedDeviceCompositionWithSessionV1;

export type CloudflareD1GithubOAuthConfig = {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly callbackUrl: string;
};

export interface CloudflareD1RouterApiAuthServiceOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly relayerAccount?: string;
  readonly relayerPublicKey?: string;
  readonly relayerPrivateKey?: string;
  readonly nearRpcUrl?: string;
  readonly signerWasmModuleOrPath?: SignerWasmModuleSupplier;
  readonly accountInitialBalance?: string;
  readonly implicitNearAccountTestFundingEnabled?: boolean | string;
  readonly googleOidcClientId?: string;
  readonly githubOAuth?: CloudflareD1GithubOAuthConfig;
  readonly oidcExchange?: CloudflareD1OidcExchangeConfig;
  readonly accountIdDerivationSecret?: string;
  readonly emailOtpServerSeal?: CloudflareD1EmailOtpServerSealConfig;
  readonly emailOtpDeliveryMode?: string;
  readonly emailOtpRuntimeProfile?: string;
  readonly emailOtpDemoAllowedOrigins?: string | readonly string[];
  readonly emailOtpDeliveryProvider?: CloudflareD1EmailOtpDeliveryProvider;
  readonly emailOtpDevOutboxEnabled?: boolean | string;
  readonly emailOtpProduction?: boolean | string;
  readonly emailOtpChallengeTtlMs?: number | string;
  readonly emailOtpGrantTtlMs?: number | string;
  readonly emailOtpMaxAttempts?: number | string;
  readonly emailOtpLockoutTtlMs?: number | string;
  readonly emailOtpCodeLength?: number | string;
  readonly emailOtpMaxActiveChallengesPerContext?: number | string;
  readonly emailOtpChallengeRateLimitMax?: number | string;
  readonly emailOtpChallengeRateLimitWindowMs?: number | string;
  readonly emailOtpVerifyRateLimitMax?: number | string;
  readonly emailOtpVerifyRateLimitWindowMs?: number | string;
  readonly emailOtpGrantRateLimitMax?: number | string;
  readonly emailOtpGrantRateLimitWindowMs?: number | string;
  readonly emailOtpGoogleRegistrationAttemptRateLimitMax?: number | string;
  readonly emailOtpGoogleRegistrationAttemptRateLimitWindowMs?: number | string;
  readonly routerAbEcdsaPresignRuntime?: RouterAbEcdsaPresignRuntime | null;
  readonly ed25519YaoProductRegistration?: RouterAbEd25519YaoProductRegistrationRuntimeV1 | null;
  readonly ecdsaStrictRegistration: RouterAbEcdsaStrictRegistrationPort;
  readonly linkedDevice?: CloudflareD1LinkedDeviceCompositionOptionsV1;
}

export type EmailOtpDeliveryMode =
  | 'email_provider'
  | 'provider_and_demo_code'
  | 'log'
  | 'dev_d1_outbox'
  | 'demo_code_response';

export type EmailOtpRuntimeProfile =
  | 'development'
  | 'testnet_live_demo'
  | 'testnet_service'
  | 'mainnet_service';

export type EmailOtpRuntimeConfig = {
  readonly deliveryMode: EmailOtpDeliveryMode;
  readonly runtimeProfile: EmailOtpRuntimeProfile;
  readonly demoAllowedOrigins: readonly string[];
  readonly deliveryProvider?: CloudflareD1EmailOtpDeliveryProvider;
  readonly devOutboxEnabled: boolean;
  readonly production: boolean;
  readonly challengeTtlMs: number;
  readonly grantTtlMs: number;
  readonly maxAttempts: number;
  readonly lockoutTtlMs: number;
  readonly codeLength: typeof EMAIL_OTP_CODE_LENGTH;
  readonly maxActiveChallengesPerContext: number;
  readonly rateLimits: {
    readonly challenge: EmailOtpRateLimitPolicy;
    readonly verify: EmailOtpRateLimitPolicy;
    readonly grant: EmailOtpRateLimitPolicy;
    readonly googleRegistrationAttempt: EmailOtpRateLimitPolicy;
  };
};

export type EmailOtpRateLimitPolicy = {
  readonly limit: number;
  readonly windowMs: number;
};

export type EmailOtpServerSealRuntimeConfig =
  | {
      readonly configured: true;
      readonly rootConfig: SigningSessionSealShamir3PassRootConfig;
    }
  | {
      readonly configured: false;
      readonly message: string;
    };

export type NormalizedCloudflareD1RouterApiAuthServiceOptions = Omit<
  CloudflareD1RouterApiAuthServiceOptions,
  | 'relayerAccount'
  | 'relayerPublicKey'
  | 'relayerPrivateKey'
  | 'nearRpcUrl'
  | 'accountInitialBalance'
  | 'implicitNearAccountTestFundingEnabled'
  | 'googleOidcClientId'
  | 'oidcExchange'
  | 'accountIdDerivationSecret'
  | 'emailOtpServerSeal'
  | 'emailOtpDeliveryMode'
  | 'emailOtpRuntimeProfile'
  | 'emailOtpDemoAllowedOrigins'
  | 'emailOtpDeliveryProvider'
  | 'emailOtpDevOutboxEnabled'
  | 'emailOtpProduction'
  | 'emailOtpChallengeTtlMs'
  | 'emailOtpGrantTtlMs'
  | 'emailOtpMaxAttempts'
  | 'emailOtpLockoutTtlMs'
  | 'emailOtpCodeLength'
  | 'emailOtpMaxActiveChallengesPerContext'
  | 'emailOtpChallengeRateLimitMax'
  | 'emailOtpChallengeRateLimitWindowMs'
  | 'emailOtpVerifyRateLimitMax'
  | 'emailOtpVerifyRateLimitWindowMs'
  | 'emailOtpGrantRateLimitMax'
  | 'emailOtpGrantRateLimitWindowMs'
  | 'emailOtpGoogleRegistrationAttemptRateLimitMax'
  | 'emailOtpGoogleRegistrationAttemptRateLimitWindowMs'
  | 'routerAbEcdsaPresignRuntime'
> & {
  readonly relayerAccount?: string;
  readonly relayerPublicKey?: string;
  readonly relayerPrivateKey?: string;
  readonly nearRpcUrl?: string;
  readonly accountInitialBalance?: string;
  readonly implicitNearAccountTestFundingEnabled: boolean;
  readonly googleOidcClientId?: string;
  readonly githubOAuth?: CloudflareD1GithubOAuthConfig;
  readonly oidcExchange?: NormalizedCloudflareD1OidcExchangeConfig;
  readonly accountIdDerivationSecret?: string;
  readonly emailOtp: EmailOtpRuntimeConfig;
  readonly emailOtpServerSeal: EmailOtpServerSealRuntimeConfig;
  readonly routerAbEcdsaPresignRuntime?: RouterAbEcdsaPresignRuntime | null;
};

export function requireD1RouterApiAuthScopeString(input: unknown, field: string): string {
  const value = toOptionalTrimmedString(input);
  if (!value) throw new Error(`${field} is required for Cloudflare D1 Router API auth service`);
  return value;
}

export function parseBooleanFlag(input: unknown, fallback: boolean, field: string): boolean {
  if (input == null || input === '') return fallback;
  if (typeof input === 'boolean') return input;
  const value = toOptionalTrimmedString(input)?.toLowerCase();
  switch (value) {
    case '1':
    case 'true':
    case 'yes':
    case 'on':
      return true;
    case '0':
    case 'false':
    case 'no':
    case 'off':
      return false;
    default:
      throw new Error(`${field} must be a boolean flag`);
  }
}

export function normalizeD1RouterApiAuthOptions(
  input: CloudflareD1RouterApiAuthServiceOptions,
): NormalizedCloudflareD1RouterApiAuthServiceOptions {
  const githubClientId = toOptionalTrimmedString(input.githubOAuth?.clientId);
  const githubClientSecret = toOptionalTrimmedString(input.githubOAuth?.clientSecret);
  const githubCallbackUrl = toOptionalTrimmedString(input.githubOAuth?.callbackUrl);
  const githubOAuth =
    githubClientId && githubClientSecret && githubCallbackUrl
      ? {
          clientId: githubClientId,
          clientSecret: githubClientSecret,
          callbackUrl: githubCallbackUrl,
        }
      : undefined;
  if (input.githubOAuth && !githubOAuth) {
    throw new Error('githubOAuth requires clientId, clientSecret, and callbackUrl');
  }
  return {
    database: input.database,
    namespace: requireD1RouterApiAuthScopeString(input.namespace, 'namespace'),
    orgId: requireD1RouterApiAuthScopeString(input.orgId, 'orgId'),
    projectId: requireD1RouterApiAuthScopeString(input.projectId, 'projectId'),
    envId: requireD1RouterApiAuthScopeString(input.envId, 'envId'),
    relayerAccount: toOptionalTrimmedString(input.relayerAccount),
    relayerPublicKey: toOptionalTrimmedString(input.relayerPublicKey),
    relayerPrivateKey: toOptionalTrimmedString(input.relayerPrivateKey),
    nearRpcUrl: toOptionalTrimmedString(input.nearRpcUrl),
    signerWasmModuleOrPath:
      typeof input.signerWasmModuleOrPath === 'string'
        ? toOptionalTrimmedString(input.signerWasmModuleOrPath)
        : input.signerWasmModuleOrPath,
    accountInitialBalance: toOptionalTrimmedString(input.accountInitialBalance),
    implicitNearAccountTestFundingEnabled: parseBooleanFlag(
      input.implicitNearAccountTestFundingEnabled,
      false,
      'implicitNearAccountTestFundingEnabled',
    ),
    googleOidcClientId: toOptionalTrimmedString(input.googleOidcClientId),
    githubOAuth,
    oidcExchange: normalizeOidcExchangeConfig(input),
    accountIdDerivationSecret: toOptionalTrimmedString(input.accountIdDerivationSecret),
    emailOtp: normalizeEmailOtpConfig(input),
    emailOtpServerSeal: normalizeEmailOtpServerSealConfig(input),
    routerAbEcdsaPresignRuntime: input.routerAbEcdsaPresignRuntime,
    ed25519YaoProductRegistration: input.ed25519YaoProductRegistration,
    ecdsaStrictRegistration: input.ecdsaStrictRegistration,
    linkedDevice: input.linkedDevice,
  };
}

function configuredInteger(input: {
  readonly field: string;
  readonly raw: unknown;
  readonly fallback: number;
  readonly min: number;
  readonly max: number;
}): number {
  if (input.raw == null || input.raw === '') return input.fallback;
  const value = typeof input.raw === 'number' ? input.raw : Number(input.raw);
  if (!Number.isFinite(value)) throw new Error(`${input.field} must be a finite number`);
  if (value < input.min || value > input.max) {
    throw new Error(`${input.field} must be between ${input.min} and ${input.max}`);
  }
  return Math.floor(value);
}

function normalizeEmailOtpDeliveryMode(
  input: unknown,
  fallback: EmailOtpDeliveryMode,
): EmailOtpDeliveryMode {
  const value = toOptionalTrimmedString(input)?.toLowerCase() || fallback;
  switch (value) {
    case 'email_provider':
    case 'provider_and_demo_code':
    case 'log':
    case 'dev_d1_outbox':
    case 'demo_code_response':
      return value;
    default:
      throw new Error(
        'emailOtpDeliveryMode must be one of email_provider, provider_and_demo_code, log, dev_d1_outbox, or demo_code_response',
      );
  }
}

function normalizeEmailOtpRuntimeProfile(
  input: unknown,
  production: boolean,
): EmailOtpRuntimeProfile {
  const configured = toOptionalTrimmedString(input)?.toLowerCase();
  if (!configured) {
    if (production) {
      throw new Error('emailOtpRuntimeProfile is required when emailOtpProduction is enabled');
    }
    return 'development';
  }
  const value = configured;
  switch (value) {
    case 'development':
    case 'testnet_live_demo':
    case 'testnet_service':
    case 'mainnet_service':
      return value;
    default:
      throw new Error(
        'emailOtpRuntimeProfile must be one of development, testnet_live_demo, testnet_service, or mainnet_service',
      );
  }
}

function normalizeEmailOtpCodeLength(input: unknown): typeof EMAIL_OTP_CODE_LENGTH {
  const codeLength = configuredInteger({
    field: 'emailOtpCodeLength',
    raw: input,
    fallback: EMAIL_OTP_CODE_LENGTH,
    min: EMAIL_OTP_CODE_LENGTH,
    max: 8,
  });
  if (codeLength !== EMAIL_OTP_CODE_LENGTH) {
    throw new Error(`emailOtpCodeLength must be ${EMAIL_OTP_CODE_LENGTH}`);
  }
  return EMAIL_OTP_CODE_LENGTH;
}

function normalizeDemoOrigin(input: unknown): string {
  const value = toOptionalTrimmedString(input);
  if (!value) throw new Error('emailOtpDemoAllowedOrigins contains an empty origin');
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`emailOtpDemoAllowedOrigins contains an invalid origin: ${value}`);
  }
  if (parsed.protocol !== 'https:' || parsed.origin !== value) {
    throw new Error(
      `emailOtpDemoAllowedOrigins must contain exact HTTPS origins without paths: ${value}`,
    );
  }
  return parsed.origin;
}

function emailOtpDemoAllowedOriginInputs(input: unknown): readonly unknown[] {
  if (Array.isArray(input)) return input;
  const value = toOptionalTrimmedString(input);
  if (!value) return [];
  return value.split(',');
}

function normalizeEmailOtpDemoAllowedOrigins(input: unknown): readonly string[] {
  const values = emailOtpDemoAllowedOriginInputs(input);
  return [...new Set(values.map(normalizeDemoOrigin))];
}

function assertEmailOtpDeliveryProfile(input: {
  readonly deliveryMode: EmailOtpDeliveryMode;
  readonly runtimeProfile: EmailOtpRuntimeProfile;
  readonly demoAllowedOrigins: readonly string[];
}): void {
  if (input.runtimeProfile === 'mainnet_service' && input.deliveryMode !== 'email_provider') {
    throw new Error('mainnet_service requires emailOtpDeliveryMode=email_provider');
  }
  if (
    input.deliveryMode !== 'demo_code_response' &&
    input.deliveryMode !== 'provider_and_demo_code'
  ) {
    return;
  }
  if (input.runtimeProfile !== 'testnet_live_demo') {
    throw new Error(`${input.deliveryMode} requires emailOtpRuntimeProfile=testnet_live_demo`);
  }
  if (input.demoAllowedOrigins.length === 0) {
    throw new Error(`${input.deliveryMode} requires at least one emailOtpDemoAllowedOrigins entry`);
  }
}

function emailOtpRateLimitPolicy(input: {
  readonly limitField: string;
  readonly limitRaw: unknown;
  readonly limitFallback: number;
  readonly limitMax: number;
  readonly windowField: string;
  readonly windowRaw: unknown;
  readonly windowFallback: number;
}): EmailOtpRateLimitPolicy {
  return {
    limit: configuredInteger({
      field: input.limitField,
      raw: input.limitRaw,
      fallback: input.limitFallback,
      min: 1,
      max: input.limitMax,
    }),
    windowMs: configuredInteger({
      field: input.windowField,
      raw: input.windowRaw,
      fallback: input.windowFallback,
      min: 1_000,
      max: 24 * 60 * 60_000,
    }),
  };
}

function normalizeEmailOtpConfig(
  input: CloudflareD1RouterApiAuthServiceOptions,
): EmailOtpRuntimeConfig {
  const production = parseBooleanFlag(input.emailOtpProduction, false, 'emailOtpProduction');
  const runtimeProfile = normalizeEmailOtpRuntimeProfile(input.emailOtpRuntimeProfile, production);
  const deliveryMode = normalizeEmailOtpDeliveryMode(
    input.emailOtpDeliveryMode,
    runtimeProfile === 'testnet_live_demo' ? 'demo_code_response' : 'email_provider',
  );
  const demoAllowedOrigins = normalizeEmailOtpDemoAllowedOrigins(input.emailOtpDemoAllowedOrigins);
  assertEmailOtpDeliveryProfile({ deliveryMode, runtimeProfile, demoAllowedOrigins });
  if (deliveryMode === 'provider_and_demo_code' && !input.emailOtpDeliveryProvider) {
    throw new Error('provider_and_demo_code requires an Email OTP delivery provider');
  }
  const challengeDefault = production
    ? { limit: 30, windowMs: 60_000 }
    : { limit: 100, windowMs: 60_000 };
  const verifyDefault = production
    ? { limit: 30, windowMs: 60_000 }
    : { limit: 100, windowMs: 60_000 };
  const grantDefault = production
    ? { limit: 30, windowMs: 60_000 }
    : { limit: 100, windowMs: 60_000 };
  const googleRegistrationAttemptDefault = production
    ? { limit: 12, windowMs: 10 * 60_000 }
    : { limit: 200, windowMs: 60_000 };
  return {
    deliveryMode,
    runtimeProfile,
    demoAllowedOrigins,
    ...(input.emailOtpDeliveryProvider ? { deliveryProvider: input.emailOtpDeliveryProvider } : {}),
    production,
    devOutboxEnabled:
      deliveryMode === 'dev_d1_outbox' &&
      !production &&
      parseBooleanFlag(input.emailOtpDevOutboxEnabled, true, 'emailOtpDevOutboxEnabled'),
    challengeTtlMs: configuredInteger({
      field: 'emailOtpChallengeTtlMs',
      raw: input.emailOtpChallengeTtlMs,
      fallback: 5 * 60_000,
      min: 30_000,
      max: 15 * 60_000,
    }),
    grantTtlMs: configuredInteger({
      field: 'emailOtpGrantTtlMs',
      raw: input.emailOtpGrantTtlMs,
      fallback: 30_000,
      min: 10_000,
      max: 5 * 60_000,
    }),
    maxAttempts: configuredInteger({
      field: 'emailOtpMaxAttempts',
      raw: input.emailOtpMaxAttempts,
      fallback: 5,
      min: 1,
      max: 10,
    }),
    lockoutTtlMs: configuredInteger({
      field: 'emailOtpLockoutTtlMs',
      raw: input.emailOtpLockoutTtlMs,
      fallback: 5 * 60_000,
      min: 60_000,
      max: 24 * 60 * 60_000,
    }),
    codeLength: normalizeEmailOtpCodeLength(input.emailOtpCodeLength),
    maxActiveChallengesPerContext: configuredInteger({
      field: 'emailOtpMaxActiveChallengesPerContext',
      raw: input.emailOtpMaxActiveChallengesPerContext,
      fallback: 5,
      min: 1,
      max: 20,
    }),
    rateLimits: {
      challenge: emailOtpRateLimitPolicy({
        limitField: 'emailOtpChallengeRateLimitMax',
        limitRaw: input.emailOtpChallengeRateLimitMax,
        limitFallback: challengeDefault.limit,
        limitMax: 500,
        windowField: 'emailOtpChallengeRateLimitWindowMs',
        windowRaw: input.emailOtpChallengeRateLimitWindowMs,
        windowFallback: challengeDefault.windowMs,
      }),
      verify: emailOtpRateLimitPolicy({
        limitField: 'emailOtpVerifyRateLimitMax',
        limitRaw: input.emailOtpVerifyRateLimitMax,
        limitFallback: verifyDefault.limit,
        limitMax: 1000,
        windowField: 'emailOtpVerifyRateLimitWindowMs',
        windowRaw: input.emailOtpVerifyRateLimitWindowMs,
        windowFallback: verifyDefault.windowMs,
      }),
      grant: emailOtpRateLimitPolicy({
        limitField: 'emailOtpGrantRateLimitMax',
        limitRaw: input.emailOtpGrantRateLimitMax,
        limitFallback: grantDefault.limit,
        limitMax: 1000,
        windowField: 'emailOtpGrantRateLimitWindowMs',
        windowRaw: input.emailOtpGrantRateLimitWindowMs,
        windowFallback: grantDefault.windowMs,
      }),
      googleRegistrationAttempt: emailOtpRateLimitPolicy({
        limitField: 'emailOtpGoogleRegistrationAttemptRateLimitMax',
        limitRaw: input.emailOtpGoogleRegistrationAttemptRateLimitMax,
        limitFallback: googleRegistrationAttemptDefault.limit,
        limitMax: 1000,
        windowField: 'emailOtpGoogleRegistrationAttemptRateLimitWindowMs',
        windowRaw: input.emailOtpGoogleRegistrationAttemptRateLimitWindowMs,
        windowFallback: googleRegistrationAttemptDefault.windowMs,
      }),
    },
  };
}

function missingEmailOtpServerSealConfig(): EmailOtpServerSealRuntimeConfig {
  return {
    configured: false,
    message:
      'Email OTP server seal requires emailOtpServerSeal.rootSecretB64u and currentKeyVersion',
  };
}

function normalizeEmailOtpServerSealConfig(
  input: CloudflareD1RouterApiAuthServiceOptions,
): EmailOtpServerSealRuntimeConfig {
  const raw = input.emailOtpServerSeal;
  if (!raw) return missingEmailOtpServerSealConfig();
  const rootSecretB64u = toOptionalTrimmedString(raw.rootSecretB64u);
  const currentKeyVersion = toOptionalTrimmedString(raw.currentKeyVersion);
  if (!rootSecretB64u || !currentKeyVersion) {
    return missingEmailOtpServerSealConfig();
  }
  try {
    return {
      configured: true,
      rootConfig: parseSigningSessionSealRootConfig({
        rootSecretB64u,
        currentKeyVersion,
        acceptedWarmKeyVersions: raw.acceptedWarmKeyVersions,
      }),
    };
  } catch (error: unknown) {
    return {
      configured: false,
      message: configErrorMessage(error) || 'Email OTP Shamir configuration is invalid',
    };
  }
}

function configErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}
