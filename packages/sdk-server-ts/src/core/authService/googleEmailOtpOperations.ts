import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  type GoogleProviderSubject,
  type VerifiedGoogleEmail,
} from '@shared/utils/domainIds';
import { deriveHostedNearAccountId, isHostedHmacReadableRelayerWalletId } from '../hostedAccountIds';
import type { AuthServiceConfig, ThresholdRuntimePolicyScope } from '../types';
import type { IdentityStore } from '../IdentityStore';
import type {
  EmailOtpRegistrationAttemptStore,
  EmailOtpWalletEnrollmentStore,
} from '../EmailOtpStores';
import { parseBoundaryWalletId } from './webauthnWalletBinding';
import {
  cleanupGoogleEmailOtpDevRegistrationStateWithStores,
  completeGoogleEmailOtpRegistrationAttemptWithStore,
  consumeGoogleEmailOtpRegistrationAttemptRateLimitWithDeps,
  failGoogleEmailOtpRegistrationAttemptWithStore,
  recordGoogleEmailOtpRegistrationAttemptPublicKeyWithStore,
  resolveGoogleEmailOtpSessionWithDeps,
  validateGoogleEmailOtpRegistrationCandidateWalletWithStore,
  type GoogleEmailOtpResolutionResult,
  type GoogleEmailOtpRegistrationRateLimitConsumer,
  type GoogleEmailOtpRegistrationRateLimitResult,
} from './googleEmailOtpRegistration';

type GoogleEmailOtpStores = {
  readonly identityStore: IdentityStore;
  readonly registrationAttemptStore: EmailOtpRegistrationAttemptStore;
  readonly walletEnrollmentStore: EmailOtpWalletEnrollmentStore;
};

type GoogleEmailOtpEnvironment = {
  readonly config: AuthServiceConfig;
  readonly readConfigValue: (name: string) => string;
  readonly isProductionEnvironment: boolean;
};

export type GoogleEmailOtpOperationsInput = GoogleEmailOtpStores &
  GoogleEmailOtpEnvironment & {
    readonly consumeRateLimit: GoogleEmailOtpRegistrationRateLimitConsumer;
  };

function hostedAccountScope(input?: ThresholdRuntimePolicyScope): {
  projectId: string;
  envId: string;
} {
  const orgId = toOptionalTrimmedString(input?.orgId);
  const projectId = toOptionalTrimmedString(input?.projectId);
  const envId = toOptionalTrimmedString(input?.envId);
  if (orgId && projectId && envId) {
    return { projectId, envId };
  }
  throw new Error(
    'runtimePolicyScope.orgId, runtimePolicyScope.projectId, and runtimePolicyScope.envId are required for hosted wallet id derivation',
  );
}

function isHostedHmacReadableWalletId(input: {
  readonly config: AuthServiceConfig;
  readonly walletId: string;
}): boolean {
  return isHostedHmacReadableRelayerWalletId({
    walletId: input.walletId,
    relayerAccount: input.config.relayerAccount,
  });
}

async function deriveHostedOidcWalletId(input: {
  readonly env: GoogleEmailOtpEnvironment;
  readonly providerSubject?: string;
  readonly sub?: string;
  readonly email?: string;
  readonly authProvider: string;
  readonly runtimePolicyScope?: ThresholdRuntimePolicyScope;
  readonly walletIdDerivationNonce?: string;
  readonly collisionCounter?: number;
}): Promise<string> {
  const subject = toOptionalTrimmedString(input.providerSubject ?? input.sub);
  const email = toOptionalTrimmedString(input.email);
  const walletIdDerivationNonce = toOptionalTrimmedString(input.walletIdDerivationNonce);
  if (!subject && !email) {
    throw new Error('Cannot derive hosted wallet id without provider subject or verified email');
  }
  const scope = hostedAccountScope(input.runtimePolicyScope);
  return deriveHostedNearAccountId({
    accountIdDerivationSecret: input.env.readConfigValue('ACCOUNT_ID_DERIVATION_SECRET'),
    relayerAccount: input.env.config.relayerAccount,
    projectId: scope.projectId,
    envId: scope.envId,
    authProvider: input.authProvider,
    ...(subject ? { providerSubject: subject } : {}),
    ...(email ? { verifiedEmail: email } : {}),
    ...(walletIdDerivationNonce ? { walletIdDerivationNonce } : {}),
    ...(input.collisionCounter ? { collisionCounter: input.collisionCounter } : {}),
  });
}

export async function resolveOidcWalletIdWithGoogleEmailOtp(input: {
  readonly deps: GoogleEmailOtpOperationsInput;
  readonly request: {
    providerSubject?: string;
    sub?: string;
    email?: string;
    accountMode?: unknown;
    appSessionVersion?: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    restartRegistrationOffer?: unknown;
  };
}): Promise<string> {
  const providerSubject = toOptionalTrimmedString(
    input.request.providerSubject ?? input.request.sub,
  );
  if (!providerSubject) {
    throw new Error('Cannot resolve OIDC wallet id without provider subject');
  }

  if (providerSubject.startsWith('google:')) {
    const resolution = await resolveGoogleEmailOtpSessionForAuthService(input);
    if (resolution.ok) return resolution.walletId;
    const error = new Error(resolution.message) as Error & { code?: string };
    error.code = resolution.code;
    throw error;
  }

  const wallet = `wallet:${providerSubject}`;
  const linkedWalletId = parseBoundaryWalletId(
    await input.deps.identityStore.getUserIdBySubject(wallet),
  );
  if (linkedWalletId) return linkedWalletId;

  return await deriveHostedOidcWalletId({
    env: input.deps,
    providerSubject,
    sub: input.request.sub,
    email: input.request.email,
    authProvider: 'oidc',
    ...(input.request.runtimePolicyScope
      ? { runtimePolicyScope: input.request.runtimePolicyScope }
      : {}),
  });
}

export async function consumeGoogleEmailOtpRegistrationAttemptRateLimitForAuthService(input: {
  readonly deps: GoogleEmailOtpOperationsInput;
  readonly request: {
    providerSubject?: unknown;
    email?: unknown;
    accountMode?: unknown;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    clientIp?: string;
    appSessionUserId?: string;
    restartRegistrationOffer?: unknown;
  };
}): Promise<GoogleEmailOtpRegistrationRateLimitResult> {
  return await consumeGoogleEmailOtpRegistrationAttemptRateLimitWithDeps({
    request: input.request,
    consumeRateLimit: input.deps.consumeRateLimit,
  });
}

export async function resolveGoogleEmailOtpSessionForAuthService(input: {
  readonly deps: GoogleEmailOtpOperationsInput;
  readonly request: {
    providerSubject?: string | GoogleProviderSubject;
    sub?: string;
    email?: string | VerifiedGoogleEmail;
    accountMode?: unknown;
    appSessionVersion?: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    restartRegistrationOffer?: unknown;
  };
}): Promise<GoogleEmailOtpResolutionResult> {
  return await resolveGoogleEmailOtpSessionWithDeps({
    request: input.request,
    identityStore: input.deps.identityStore,
    registrationAttemptStore: input.deps.registrationAttemptStore,
    walletEnrollmentStore: input.deps.walletEnrollmentStore,
    deriveHostedWalletId: async (request) =>
      await deriveHostedOidcWalletId({
        env: input.deps,
        ...request,
      }),
    isHostedHmacReadableWalletId: (walletId) =>
      isHostedHmacReadableWalletId({ config: input.deps.config, walletId }),
  });
}

export async function completeGoogleEmailOtpRegistrationAttemptForAuthService(input: {
  readonly deps: GoogleEmailOtpOperationsInput;
  readonly request: {
    registrationAttemptId?: unknown;
    walletId?: unknown;
  };
}): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
  return await completeGoogleEmailOtpRegistrationAttemptWithStore({
    registrationAttemptStore: input.deps.registrationAttemptStore,
    identityStore: input.deps.identityStore,
    registrationAttemptId: input.request.registrationAttemptId,
    walletId: input.request.walletId,
    nowMs: Date.now(),
  });
}

export async function validateGoogleEmailOtpRegistrationCandidateWalletForAuthService(input: {
  readonly deps: GoogleEmailOtpOperationsInput;
  readonly request: {
    registrationAttemptId: string;
    walletId: string;
    appSessionVersion: string;
    providerSubject: string;
  };
}): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
  return await validateGoogleEmailOtpRegistrationCandidateWalletWithStore({
    registrationAttemptStore: input.deps.registrationAttemptStore,
    registrationAttemptId: input.request.registrationAttemptId,
    walletId: input.request.walletId,
    appSessionVersion: input.request.appSessionVersion,
    providerSubject: input.request.providerSubject,
    nowMs: Date.now(),
  });
}

export async function recordGoogleEmailOtpRegistrationAttemptPublicKeyForAuthService(input: {
  readonly deps: GoogleEmailOtpOperationsInput;
  readonly request: {
    registrationAttemptId?: unknown;
    walletId?: unknown;
    finalizedPublicKey?: unknown;
  };
}): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
  return await recordGoogleEmailOtpRegistrationAttemptPublicKeyWithStore({
    registrationAttemptStore: input.deps.registrationAttemptStore,
    registrationAttemptId: input.request.registrationAttemptId,
    walletId: input.request.walletId,
    finalizedPublicKey: input.request.finalizedPublicKey,
    nowMs: Date.now(),
  });
}

export async function failGoogleEmailOtpRegistrationAttemptForAuthService(input: {
  readonly deps: GoogleEmailOtpOperationsInput;
  readonly request: {
    registrationAttemptId?: unknown;
    walletId?: unknown;
    failureCode?: unknown;
  };
}): Promise<void> {
  await failGoogleEmailOtpRegistrationAttemptWithStore({
    registrationAttemptStore: input.deps.registrationAttemptStore,
    registrationAttemptId: input.request.registrationAttemptId,
    walletId: input.request.walletId,
    failureCode: input.request.failureCode,
    nowMs: Date.now(),
  });
}

export async function cleanupGoogleEmailOtpDevRegistrationStateForAuthService(input: {
  readonly deps: GoogleEmailOtpOperationsInput;
  readonly request: {
    providerSubject?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    nowMs?: unknown;
  };
}): Promise<
  | {
      ok: true;
      providerSubject: string;
      expiredRegistrationAttemptsDeleted: number;
      linkedWalletId?: string;
      orphanedWalletMappingRemoved: boolean;
      orphanedWalletMappingSkippedReason?:
        | 'no_linked_wallet'
        | 'wallet_id_mismatch'
        | 'not_relayer_subaccount'
        | 'active_email_otp_enrollment'
        | 'mismatched_email_otp_enrollment';
    }
  | { ok: false; code: string; message: string }
> {
  return await cleanupGoogleEmailOtpDevRegistrationStateWithStores({
    registrationAttemptStore: input.deps.registrationAttemptStore,
    identityStore: input.deps.identityStore,
    walletEnrollmentStore: input.deps.walletEnrollmentStore,
    isProductionEnvironment: input.deps.isProductionEnvironment,
    isHostedHmacReadableWalletId: (walletId) =>
      isHostedHmacReadableWalletId({ config: input.deps.config, walletId }),
    providerSubject: input.request.providerSubject,
    walletId: input.request.walletId,
    orgId: input.request.orgId,
    nowMs: input.request.nowMs,
  });
}
