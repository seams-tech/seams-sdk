import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  parseGoogleProviderSubject,
  parseOrgId,
  parseVerifiedGoogleEmail,
} from '@shared/utils/domainIds';
import type { ThresholdRuntimePolicyScope } from '../types';
import type {
  EmailOtpRegistrationAttemptStore,
  EmailOtpWalletEnrollmentRecord,
  EmailOtpWalletEnrollmentStore,
  GoogleEmailOtpRegistrationAttemptRecord,
  GoogleEmailOtpRegistrationOfferCandidateRecord,
  NonEmptyGoogleEmailOtpRegistrationOfferCandidates,
  PendingGoogleEmailOtpRegistrationAttemptRecord,
} from '../EmailOtpStores';
import type { IdentityStore } from '../IdentityStore';
import { readActiveEmailOtpEnrollmentWithStore } from './emailOtpEnrollment';
import { randomOpaqueId } from './bytes';

export type GoogleEmailOtpResolutionMode =
  | 'existing_wallet'
  | 'register_started'
  | 'wallet_id_collision'
  | 'registration_incomplete'
  | 'stale_identity_mapping';

export type GoogleEmailOtpRegistrationOfferCandidate = {
  candidateId: string;
  walletId: string;
};

export type GoogleEmailOtpRegistrationOffer = {
  offerId: string;
  selectedCandidateId: string;
  candidates: readonly [
    GoogleEmailOtpRegistrationOfferCandidate,
    ...GoogleEmailOtpRegistrationOfferCandidate[],
  ];
};

export type GoogleEmailOtpResolutionResult =
  | {
      ok: true;
      mode: 'existing_wallet';
      walletId: string;
      providerSubject: string;
      email?: string;
      hasEmailOtpEnrollment: true;
    }
  | {
      ok: true;
      mode: 'register_started';
      walletId: string;
      providerSubject: string;
      email: string;
      registrationAttemptId: string;
      expiresAtMs: number;
      offer: GoogleEmailOtpRegistrationOffer;
    }
  | {
      ok: false;
      mode: 'wallet_id_collision' | 'registration_incomplete' | 'stale_identity_mapping';
      code: 'wallet_id_collision' | 'registration_incomplete' | 'stale_identity_mapping';
      walletId?: string;
      providerSubject: string;
      email?: string;
      message: string;
    };

export type GoogleEmailOtpRegistrationRateLimitRequest = {
  providerSubject?: unknown;
  email?: unknown;
  accountMode?: unknown;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  clientIp?: string;
  appSessionUserId?: string;
  restartRegistrationOffer?: unknown;
};

export type GoogleEmailOtpRegistrationRateLimitResult =
  | { ok: true }
  | {
      ok: false;
      code: 'invalid_body' | 'rate_limited';
      message: string;
      retryAfterMs?: number;
      resetAtMs?: number;
    };

export type GoogleEmailOtpRegistrationRateLimitConsumer = (input: {
  scope: 'googleRegistrationAttempt';
  action:
    | 'google_email_otp_registration_create'
    | 'google_email_otp_registration_offer_restart';
  userId?: string;
  providerSubject: string;
  orgId: string;
  clientIp?: string;
}) => Promise<GoogleEmailOtpRegistrationRateLimitResult>;

export type GoogleEmailOtpSessionResolveRequest = {
  providerSubject?: string;
  sub?: string;
  email?: string;
  accountMode?: unknown;
  appSessionVersion?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  restartRegistrationOffer?: unknown;
};

export type GoogleEmailOtpHostedWalletDeriver = (input: {
  providerSubject: string;
  sub?: string;
  email?: string;
  authProvider: string;
  walletIdDerivationNonce?: string;
  collisionCounter?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
}) => Promise<string>;

export type GoogleEmailOtpHostedWalletPredicate = (walletId: string) => boolean;

export async function cleanupGoogleEmailOtpRegistrationAttemptsWithStore(input: {
  readonly registrationAttemptStore: EmailOtpRegistrationAttemptStore;
  readonly nowMs: number;
}): Promise<void> {
  await input.registrationAttemptStore.deleteExpired(input.nowMs);
}

export async function consumeGoogleEmailOtpRegistrationAttemptRateLimitWithDeps(input: {
  readonly request: GoogleEmailOtpRegistrationRateLimitRequest;
  readonly consumeRateLimit: GoogleEmailOtpRegistrationRateLimitConsumer;
}): Promise<GoogleEmailOtpRegistrationRateLimitResult> {
  const accountMode = toOptionalTrimmedString(input.request.accountMode)?.toLowerCase();
  if (accountMode !== 'register') return { ok: true };
  const providerSubject = parseGoogleProviderSubject(input.request.providerSubject);
  if (!providerSubject.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: providerSubject.error.message,
    };
  }
  const email = parseVerifiedGoogleEmail(input.request.email);
  if (!email.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: email.error.message,
    };
  }
  const orgId = parseOrgId(input.request.runtimePolicyScope?.orgId);
  if (!orgId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: orgId.error.message,
    };
  }
  const restartOffer = isTruthyBoundaryFlag(input.request.restartRegistrationOffer);
  return await input.consumeRateLimit({
    scope: 'googleRegistrationAttempt',
    action: restartOffer
      ? 'google_email_otp_registration_offer_restart'
      : 'google_email_otp_registration_create',
    userId: toOptionalTrimmedString(input.request.appSessionUserId),
    providerSubject: providerSubject.value,
    orgId: orgId.value,
    clientIp: toOptionalTrimmedString(input.request.clientIp),
  });
}

export async function resolveGoogleEmailOtpSessionWithDeps(input: {
  readonly request: GoogleEmailOtpSessionResolveRequest;
  readonly identityStore: IdentityStore;
  readonly registrationAttemptStore: EmailOtpRegistrationAttemptStore;
  readonly walletEnrollmentStore: EmailOtpWalletEnrollmentStore;
  readonly deriveHostedWalletId: GoogleEmailOtpHostedWalletDeriver;
  readonly isHostedHmacReadableWalletId: GoogleEmailOtpHostedWalletPredicate;
}): Promise<GoogleEmailOtpResolutionResult> {
  const providerSubject = toOptionalTrimmedString(
    input.request.providerSubject ?? input.request.sub,
  );
  if (!providerSubject || !providerSubject.startsWith('google:')) {
    throw new Error('Cannot resolve Google Email OTP session without Google provider subject');
  }
  const accountMode = toOptionalTrimmedString(input.request.accountMode)?.toLowerCase();
  if (accountMode !== 'register' && accountMode !== 'login') {
    throw new Error('Google Email OTP accountMode must be register or login');
  }
  const email = toOptionalTrimmedString(input.request.email)?.toLowerCase() || '';
  const orgId = toOptionalTrimmedString(input.request.runtimePolicyScope?.orgId) || '';
  if (!orgId) {
    throw new Error('Google Email OTP requires orgId tenant scope');
  }
  const appSessionVersion = toOptionalTrimmedString(input.request.appSessionVersion);
  if (accountMode === 'register' && !appSessionVersion) {
    throw new Error('Google Email OTP registration requires appSessionVersion');
  }

  if (accountMode === 'login') {
    return await resolveGoogleEmailOtpLoginSession({
      request: {
        providerSubject,
        email,
        orgId,
      },
      identityStore: input.identityStore,
      walletEnrollmentStore: input.walletEnrollmentStore,
      isHostedHmacReadableWalletId: input.isHostedHmacReadableWalletId,
    });
  }

  return await resolveGoogleEmailOtpRegistrationSession({
    request: {
      providerSubject,
      email,
      orgId,
      appSessionVersion,
      runtimePolicyScope: input.request.runtimePolicyScope,
      restartRegistrationOffer: isTruthyBoundaryFlag(input.request.restartRegistrationOffer),
    },
    identityStore: input.identityStore,
    registrationAttemptStore: input.registrationAttemptStore,
    walletEnrollmentStore: input.walletEnrollmentStore,
    deriveHostedWalletId: input.deriveHostedWalletId,
    isHostedHmacReadableWalletId: input.isHostedHmacReadableWalletId,
  });
}

export async function completeGoogleEmailOtpRegistrationAttemptWithStore(input: {
  readonly registrationAttemptStore: EmailOtpRegistrationAttemptStore;
  readonly identityStore: IdentityStore;
  readonly registrationAttemptId?: unknown;
  readonly walletId?: unknown;
  readonly nowMs: number;
}): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
  const registrationAttemptId = toOptionalTrimmedString(input.registrationAttemptId);
  if (!registrationAttemptId) return { ok: true };
  const walletId = toOptionalTrimmedString(input.walletId);
  const attempt = await input.registrationAttemptStore.get(registrationAttemptId);
  if (!attempt) {
    return {
      ok: false,
      code: 'registration_incomplete',
      message: 'Google Email OTP registration attempt expired or was not found',
    };
  }
  if (attempt.expiresAtMs <= input.nowMs) {
    await input.registrationAttemptStore.put({
      ...attempt,
      state: 'expired',
      updatedAtMs: input.nowMs,
    });
    return {
      ok: false,
      code: 'registration_incomplete',
      message: 'Google Email OTP registration attempt expired',
    };
  }
  if (walletId !== attempt.walletId) {
    return {
      ok: false,
      code: 'wallet_identity_mismatch',
      message: 'registrationAttemptId does not match walletId',
    };
  }
  if (attempt.state !== 'started' && attempt.state !== 'key_finalized') {
    return {
      ok: false,
      code: 'registration_incomplete',
      message: 'Google Email OTP registration attempt is no longer active',
    };
  }
  const linked = await input.identityStore.linkSubjectToUserId({
    userId: attempt.walletId,
    subject: `wallet:${attempt.providerSubject}`,
    allowMoveIfSoleIdentity: true,
  });
  if (!linked.ok) {
    await input.registrationAttemptStore.put({
      ...attempt,
      state: 'failed',
      failureCode: linked.code,
      updatedAtMs: input.nowMs,
    });
    return {
      ok: false,
      code: linked.code,
      message: linked.message,
    };
  }
  await input.registrationAttemptStore.put({
    ...attempt,
    state: 'active',
    updatedAtMs: input.nowMs,
  });
  return { ok: true };
}

export async function validateGoogleEmailOtpRegistrationCandidateWalletWithStore(input: {
  readonly registrationAttemptStore: EmailOtpRegistrationAttemptStore;
  readonly registrationAttemptId: string;
  readonly walletId: string;
  readonly appSessionVersion: string;
  readonly providerSubject: string;
  readonly nowMs: number;
}): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
  const registrationAttemptId = toOptionalTrimmedString(input.registrationAttemptId);
  const walletId = toOptionalTrimmedString(input.walletId);
  const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
  const providerSubject = toOptionalTrimmedString(input.providerSubject);
  if (!registrationAttemptId || !walletId || !appSessionVersion || !providerSubject) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Google Email OTP registration candidate validation requires signed session scope',
    };
  }
  const attempt = await input.registrationAttemptStore.get(registrationAttemptId);
  if (!attempt) {
    return {
      ok: false,
      code: 'registration_attempt_missing',
      message: 'Google Email OTP registration attempt expired or was not found',
    };
  }
  if (attempt.expiresAtMs <= input.nowMs) {
    await input.registrationAttemptStore.put({
      ...attempt,
      state: 'expired',
      updatedAtMs: input.nowMs,
    });
    return {
      ok: false,
      code: 'registration_attempt_expired',
      message: 'Google Email OTP registration attempt expired',
    };
  }
  if (attempt.providerSubject !== providerSubject) {
    return {
      ok: false,
      code: 'challenge_subject_mismatch',
      message: 'Email OTP registration attempt does not match the provider subject',
    };
  }
  if (attempt.appSessionVersion !== appSessionVersion) {
    return {
      ok: false,
      code: 'app_session_version_mismatch',
      message: 'Google Email OTP registration attempt does not match the app session',
    };
  }
  if (attempt.state !== 'started' && attempt.state !== 'key_finalized') {
    return {
      ok: false,
      code: 'registration_incomplete',
      message: 'Google Email OTP registration attempt is no longer active',
    };
  }
  const candidate = findGoogleEmailOtpOfferCandidateByWalletId({
    candidates: attempt.offerCandidates,
    walletId,
  });
  if (!candidate) {
    return {
      ok: false,
      code: 'wallet_identity_mismatch',
      message: 'walletId is not an active Google Email OTP registration candidate',
    };
  }
  return { ok: true };
}

export async function recordGoogleEmailOtpRegistrationAttemptPublicKeyWithStore(input: {
  readonly registrationAttemptStore: EmailOtpRegistrationAttemptStore;
  readonly registrationAttemptId?: unknown;
  readonly walletId?: unknown;
  readonly finalizedPublicKey?: unknown;
  readonly nowMs: number;
}): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
  const registrationAttemptId = toOptionalTrimmedString(input.registrationAttemptId);
  if (!registrationAttemptId) return { ok: true };
  const walletId = toOptionalTrimmedString(input.walletId);
  const finalizedPublicKey = toOptionalTrimmedString(input.finalizedPublicKey);
  const attempt = await input.registrationAttemptStore.get(registrationAttemptId);
  if (!attempt) {
    return {
      ok: false,
      code: 'registration_incomplete',
      message: 'Google Email OTP registration attempt expired or was not found',
    };
  }
  if (attempt.expiresAtMs <= input.nowMs) {
    await input.registrationAttemptStore.put({
      ...attempt,
      state: 'expired',
      updatedAtMs: input.nowMs,
    });
    return {
      ok: false,
      code: 'registration_incomplete',
      message: 'Google Email OTP registration attempt expired',
    };
  }
  if (walletId !== attempt.walletId) {
    return {
      ok: false,
      code: 'wallet_identity_mismatch',
      message: 'registrationAttemptId does not match walletId',
    };
  }
  if (
    attempt.state !== 'started' &&
    attempt.state !== 'key_finalized' &&
    attempt.state !== 'active'
  ) {
    return {
      ok: false,
      code: 'registration_incomplete',
      message: 'Google Email OTP registration attempt is no longer active',
    };
  }
  if (attempt.state === 'started') {
    if (!finalizedPublicKey) {
      await input.registrationAttemptStore.put({
        ...attempt,
        updatedAtMs: input.nowMs,
      });
    } else {
      await input.registrationAttemptStore.put({
        ...attempt,
        state: 'key_finalized',
        finalizedPublicKey,
        updatedAtMs: input.nowMs,
      });
    }
    return { ok: true };
  }
  await input.registrationAttemptStore.put({
    ...attempt,
    ...(finalizedPublicKey ? { finalizedPublicKey } : {}),
    updatedAtMs: input.nowMs,
  });
  return { ok: true };
}

export async function failGoogleEmailOtpRegistrationAttemptWithStore(input: {
  readonly registrationAttemptStore: EmailOtpRegistrationAttemptStore;
  readonly registrationAttemptId?: unknown;
  readonly walletId?: unknown;
  readonly failureCode?: unknown;
  readonly nowMs: number;
}): Promise<void> {
  const registrationAttemptId = toOptionalTrimmedString(input.registrationAttemptId);
  if (!registrationAttemptId) return;
  const attempt = await input.registrationAttemptStore.get(registrationAttemptId);
  if (!attempt) return;
  const walletId = toOptionalTrimmedString(input.walletId);
  if (walletId && walletId !== attempt.walletId) return;
  await input.registrationAttemptStore.put({
    ...attempt,
    state: 'failed',
    failureCode: toOptionalTrimmedString(input.failureCode) || 'failed',
    updatedAtMs: input.nowMs,
  });
}

export async function cleanupGoogleEmailOtpDevRegistrationStateWithStores(input: {
  readonly registrationAttemptStore: EmailOtpRegistrationAttemptStore;
  readonly identityStore: IdentityStore;
  readonly walletEnrollmentStore: EmailOtpWalletEnrollmentStore;
  readonly isProductionEnvironment: boolean;
  readonly isHostedHmacReadableWalletId: GoogleEmailOtpHostedWalletPredicate;
  readonly providerSubject?: unknown;
  readonly walletId?: unknown;
  readonly orgId?: unknown;
  readonly nowMs?: unknown;
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
  if (input.isProductionEnvironment) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Google Email OTP dev cleanup is not available',
    };
  }

  const providerSubject = toOptionalTrimmedString(input.providerSubject);
  if (!providerSubject || !providerSubject.startsWith('google:')) {
    return { ok: false, code: 'invalid_body', message: 'Missing Google provider subject' };
  }

  const requestedWalletId = toOptionalTrimmedString(input.walletId);
  const requestedOrgId = toOptionalTrimmedString(input.orgId);
  const nowMsRaw = typeof input.nowMs === 'number' ? input.nowMs : Number(input.nowMs);
  const nowMs = Number.isFinite(nowMsRaw) && nowMsRaw > 0 ? Math.floor(nowMsRaw) : Date.now();
  const expiredRegistrationAttemptsDeleted =
    await input.registrationAttemptStore.deleteExpired(nowMs);

  const subject = `wallet:${providerSubject}`;
  const linkedWalletId = await input.identityStore.getUserIdBySubject(subject);
  if (!linkedWalletId) {
    return {
      ok: true,
      providerSubject,
      expiredRegistrationAttemptsDeleted,
      orphanedWalletMappingRemoved: false,
      orphanedWalletMappingSkippedReason: 'no_linked_wallet',
    };
  }

  if (requestedWalletId && requestedWalletId !== linkedWalletId) {
    return {
      ok: true,
      providerSubject,
      expiredRegistrationAttemptsDeleted,
      linkedWalletId,
      orphanedWalletMappingRemoved: false,
      orphanedWalletMappingSkippedReason: 'wallet_id_mismatch',
    };
  }

  if (!input.isHostedHmacReadableWalletId(linkedWalletId)) {
    return {
      ok: true,
      providerSubject,
      expiredRegistrationAttemptsDeleted,
      linkedWalletId,
      orphanedWalletMappingRemoved: false,
      orphanedWalletMappingSkippedReason: 'not_relayer_subaccount',
    };
  }

  const activeEnrollment = await input.walletEnrollmentStore.get(linkedWalletId);
  if (activeEnrollment) {
    const enrollmentMatchesProvider = activeEnrollment.providerUserId === providerSubject;
    const enrollmentMatchesOrg = !requestedOrgId || activeEnrollment.orgId === requestedOrgId;
    if (enrollmentMatchesProvider && enrollmentMatchesOrg) {
      return {
        ok: true,
        providerSubject,
        expiredRegistrationAttemptsDeleted,
        linkedWalletId,
        orphanedWalletMappingRemoved: false,
        orphanedWalletMappingSkippedReason: 'active_email_otp_enrollment',
      };
    }
  }
  const deleted = await input.identityStore.deleteSubjectLinkForDevCleanup({
    userId: linkedWalletId,
    subject,
  });
  if (!deleted.ok && deleted.code !== 'not_found') return deleted;

  return {
    ok: true,
    providerSubject,
    expiredRegistrationAttemptsDeleted,
    linkedWalletId,
    orphanedWalletMappingRemoved: deleted.ok,
  };
}

type GoogleEmailOtpLoginResolutionRequest = {
  providerSubject: string;
  email: string;
  orgId: string;
};

type GoogleEmailOtpRegistrationResolutionRequest = {
  providerSubject: string;
  email: string;
  orgId: string;
  appSessionVersion: string;
  restartRegistrationOffer: boolean;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

async function resolveGoogleEmailOtpLoginSession(input: {
  readonly request: GoogleEmailOtpLoginResolutionRequest;
  readonly identityStore: IdentityStore;
  readonly walletEnrollmentStore: EmailOtpWalletEnrollmentStore;
  readonly isHostedHmacReadableWalletId: GoogleEmailOtpHostedWalletPredicate;
}): Promise<GoogleEmailOtpResolutionResult> {
  const wallet = `wallet:${input.request.providerSubject}`;
  const linkedWalletId = await input.identityStore.getUserIdBySubject(wallet);
  const hostedLinkedWalletId =
    linkedWalletId && input.isHostedHmacReadableWalletId(linkedWalletId) ? linkedWalletId : null;

  if (hostedLinkedWalletId) {
    const enrollment = await readActiveEmailOtpEnrollmentWithStore({
      walletEnrollmentStore: input.walletEnrollmentStore,
      request: {
        walletId: hostedLinkedWalletId,
        orgId: input.request.orgId,
        providerUserId: input.request.providerSubject,
      },
    });
    if (enrollment.ok) {
      return {
        ok: true,
        mode: 'existing_wallet',
        walletId: hostedLinkedWalletId,
        providerSubject: input.request.providerSubject,
        ...(input.request.email ? { email: input.request.email } : {}),
        hasEmailOtpEnrollment: true,
      };
    }
    if (!isGoogleEmailOtpEnrollmentLookupMiss(enrollment.code)) {
      const error = new Error(enrollment.message) as Error & { code?: string };
      error.code = enrollment.code;
      throw error;
    }
  }

  const discovered = await getGoogleEmailOtpEnrollmentBySubject({
    walletEnrollmentStore: input.walletEnrollmentStore,
    providerSubject: input.request.providerSubject,
    orgId: input.request.orgId,
    isHostedHmacReadableWalletId: input.isHostedHmacReadableWalletId,
  });
  if (!discovered) {
    if (linkedWalletId) {
      const stale = googleEmailOtpStaleIdentityMapping({
        providerSubject: input.request.providerSubject,
        linkedWalletId,
        ...(input.request.email ? { email: input.request.email } : {}),
      });
      const error = new Error(stale.message) as Error & { code?: string };
      error.code = stale.code;
      throw error;
    }
    const error = new Error('Email OTP enrollment not found') as Error & { code?: string };
    error.code = 'not_found';
    throw error;
  }
  const repaired = await repairGoogleEmailOtpWalletLink({
    identityStore: input.identityStore,
    providerSubject: input.request.providerSubject,
    walletId: discovered.walletId,
  });
  if (!repaired.ok) {
    const error = new Error(repaired.message) as Error & { code?: string };
    error.code = repaired.code;
    throw error;
  }
  return {
    ok: true,
    mode: 'existing_wallet',
    walletId: discovered.walletId,
    providerSubject: input.request.providerSubject,
    ...(input.request.email ? { email: input.request.email } : {}),
    hasEmailOtpEnrollment: true,
  };
}

async function resolveGoogleEmailOtpRegistrationSession(input: {
  readonly request: GoogleEmailOtpRegistrationResolutionRequest;
  readonly identityStore: IdentityStore;
  readonly registrationAttemptStore: EmailOtpRegistrationAttemptStore;
  readonly walletEnrollmentStore: EmailOtpWalletEnrollmentStore;
  readonly deriveHostedWalletId: GoogleEmailOtpHostedWalletDeriver;
  readonly isHostedHmacReadableWalletId: GoogleEmailOtpHostedWalletPredicate;
}): Promise<GoogleEmailOtpResolutionResult> {
  if (!input.request.email) {
    throw new Error('Email is required to register a Google Email OTP wallet id');
  }
  const discoveredExistingEnrollment = await getGoogleEmailOtpEnrollmentBySubject({
    walletEnrollmentStore: input.walletEnrollmentStore,
    providerSubject: input.request.providerSubject,
    orgId: input.request.orgId,
    isHostedHmacReadableWalletId: input.isHostedHmacReadableWalletId,
  });
  if (discoveredExistingEnrollment && !input.request.restartRegistrationOffer) {
    return await resolveRegistrationForExistingEnrollment({
      identityStore: input.identityStore,
      providerSubject: input.request.providerSubject,
      email: input.request.email,
      enrollment: discoveredExistingEnrollment,
    });
  }

  const wallet = `wallet:${input.request.providerSubject}`;
  const linkedWalletId = await input.identityStore.getUserIdBySubject(wallet);
  if (linkedWalletId && !input.request.restartRegistrationOffer) {
    return googleEmailOtpStaleIdentityMapping({
      providerSubject: input.request.providerSubject,
      linkedWalletId,
      email: input.request.email,
    });
  }

  const now = Date.now();
  await input.registrationAttemptStore.abandonStartedBySubjectEmailExceptAppSession({
    providerSubject: input.request.providerSubject,
    email: input.request.email,
    orgId: input.request.orgId,
    appSessionVersion: input.request.appSessionVersion,
    ...(input.request.runtimePolicyScope
      ? { runtimePolicyScope: input.request.runtimePolicyScope }
      : {}),
    nowMs: now,
    failureCode: 'app_session_version_replaced',
  });

  const startedAttempt = await findStartedGoogleEmailOtpRegistrationAttempt({
    registrationAttemptStore: input.registrationAttemptStore,
    providerSubject: input.request.providerSubject,
    email: input.request.email,
    orgId: input.request.orgId,
    appSessionVersion: input.request.appSessionVersion,
    runtimePolicyScope: input.request.runtimePolicyScope,
    isHostedHmacReadableWalletId: input.isHostedHmacReadableWalletId,
  });
  if (startedAttempt) {
    if (input.request.restartRegistrationOffer) {
      await input.registrationAttemptStore.put({
        ...startedAttempt,
        state: 'abandoned',
        failureCode: 'offer_restarted_by_user',
        updatedAtMs: Date.now(),
      });
    } else {
      return registrationAttemptStartedResponse({
        attempt: startedAttempt,
        providerSubject: input.request.providerSubject,
        email: input.request.email,
      });
    }
  }

  return await createGoogleEmailOtpRegistrationOffer({
    request: input.request,
    identityStore: input.identityStore,
    registrationAttemptStore: input.registrationAttemptStore,
    walletEnrollmentStore: input.walletEnrollmentStore,
    deriveHostedWalletId: input.deriveHostedWalletId,
  });
}

async function resolveRegistrationForExistingEnrollment(input: {
  readonly identityStore: IdentityStore;
  readonly providerSubject: string;
  readonly email: string;
  readonly enrollment: EmailOtpWalletEnrollmentRecord;
}): Promise<GoogleEmailOtpResolutionResult> {
  const repaired = await repairGoogleEmailOtpWalletLink({
    identityStore: input.identityStore,
    providerSubject: input.providerSubject,
    walletId: input.enrollment.walletId,
  });
  if (!repaired.ok) {
    return {
      ok: false,
      mode: 'registration_incomplete',
      code: 'registration_incomplete',
      walletId: input.enrollment.walletId,
      providerSubject: input.providerSubject,
      email: input.email,
      message: repaired.message,
    };
  }
  return {
    ok: true,
    mode: 'existing_wallet',
    walletId: input.enrollment.walletId,
    providerSubject: input.providerSubject,
    email: input.email,
    hasEmailOtpEnrollment: true,
  };
}

async function createGoogleEmailOtpRegistrationOffer(input: {
  readonly request: GoogleEmailOtpRegistrationResolutionRequest;
  readonly identityStore: IdentityStore;
  readonly registrationAttemptStore: EmailOtpRegistrationAttemptStore;
  readonly walletEnrollmentStore: EmailOtpWalletEnrollmentStore;
  readonly deriveHostedWalletId: GoogleEmailOtpHostedWalletDeriver;
}): Promise<GoogleEmailOtpResolutionResult> {
  const nowMs = Date.now();
  const authProvider = 'google_oidc';
  const walletIdDerivationNonce = randomOpaqueId(18);
  const offerCandidates: GoogleEmailOtpRegistrationOfferCandidateRecord[] = [];
  for (let attempt = 0; attempt < 30 && offerCandidates.length < 5; attempt += 1) {
    const candidate = await input.deriveHostedWalletId({
      providerSubject: input.request.providerSubject,
      email: input.request.email,
      authProvider,
      walletIdDerivationNonce,
      ...(input.request.runtimePolicyScope
        ? { runtimePolicyScope: input.request.runtimePolicyScope }
        : {}),
      ...(attempt ? { collisionCounter: attempt } : {}),
    });
    const inUseByLiveAttempt = await input.registrationAttemptStore.hasLiveStartedWalletAttempt({
      walletId: candidate,
      nowMs,
    });
    const inUseByEnrollment = await input.walletEnrollmentStore.get(candidate);
    if (inUseByEnrollment || inUseByLiveAttempt) continue;
    const existingSubjects = await input.identityStore.listSubjectsByUserId(candidate);
    if (hasDifferentWalletIdentityLink(existingSubjects, `wallet:${input.request.providerSubject}`)) {
      continue;
    }
    offerCandidates.push({
      candidateId: randomOpaqueId(18),
      walletId: candidate,
      collisionCounter: attempt,
    });
  }
  const [selectedCandidate, ...remainingOfferCandidates] = offerCandidates;
  if (!selectedCandidate) {
    return {
      ok: false,
      mode: 'registration_incomplete',
      code: 'registration_incomplete',
      providerSubject: input.request.providerSubject,
      email: input.request.email,
      message: 'Unable to allocate a fresh Google Email OTP registration attempt',
    };
  }

  const nonEmptyOfferCandidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates = [
    selectedCandidate,
    ...remainingOfferCandidates,
  ];
  const walletId = selectedCandidate.walletId;
  const offerId = randomOpaqueId(18);
  const attempt = await createGoogleEmailOtpRegistrationAttempt({
    registrationAttemptStore: input.registrationAttemptStore,
    providerSubject: input.request.providerSubject,
    email: input.request.email,
    walletId,
    offerId,
    offerCandidates: nonEmptyOfferCandidates,
    selectedCandidateId: selectedCandidate.candidateId,
    appSessionVersion: input.request.appSessionVersion,
    authProvider,
    walletIdDerivationNonce,
    collisionCounter: selectedCandidate.collisionCounter,
    runtimePolicyScope: input.request.runtimePolicyScope,
  });
  return registrationAttemptStartedResponse({
    attempt,
    providerSubject: input.request.providerSubject,
    email: input.request.email,
  });
}

async function createGoogleEmailOtpRegistrationAttempt(input: {
  readonly registrationAttemptStore: EmailOtpRegistrationAttemptStore;
  readonly providerSubject: string;
  readonly email: string;
  readonly walletId: string;
  readonly offerId: string;
  readonly offerCandidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates;
  readonly selectedCandidateId: string;
  readonly appSessionVersion: string;
  readonly authProvider: string;
  readonly walletIdDerivationNonce: string;
  readonly collisionCounter: number;
  readonly runtimePolicyScope?: ThresholdRuntimePolicyScope;
}): Promise<PendingGoogleEmailOtpRegistrationAttemptRecord> {
  const now = Date.now();
  await cleanupGoogleEmailOtpRegistrationAttemptsWithStore({
    registrationAttemptStore: input.registrationAttemptStore,
    nowMs: now,
  });
  const attempt: GoogleEmailOtpRegistrationAttemptRecord = {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: randomOpaqueId(18),
    providerSubject: input.providerSubject,
    email: input.email,
    walletId: input.walletId,
    offerId: input.offerId,
    offerCandidates: input.offerCandidates,
    selectedCandidateId: input.selectedCandidateId,
    appSessionVersion: input.appSessionVersion,
    authProvider: input.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: input.walletIdDerivationNonce,
    collisionCounter: input.collisionCounter,
    state: 'started',
    createdAtMs: now,
    updatedAtMs: now,
    expiresAtMs: now + 30 * 60 * 1000,
    ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
  };
  await input.registrationAttemptStore.put(attempt);
  return attempt;
}

async function findStartedGoogleEmailOtpRegistrationAttempt(input: {
  readonly registrationAttemptStore: EmailOtpRegistrationAttemptStore;
  readonly providerSubject: string;
  readonly email: string;
  readonly orgId: string;
  readonly appSessionVersion: string;
  readonly runtimePolicyScope?: ThresholdRuntimePolicyScope;
  readonly isHostedHmacReadableWalletId: GoogleEmailOtpHostedWalletPredicate;
}): Promise<PendingGoogleEmailOtpRegistrationAttemptRecord | null> {
  const now = Date.now();
  await cleanupGoogleEmailOtpRegistrationAttemptsWithStore({
    registrationAttemptStore: input.registrationAttemptStore,
    nowMs: now,
  });
  const attempt = await input.registrationAttemptStore.findStartedBySubjectEmail({
    providerSubject: input.providerSubject,
    email: input.email,
    orgId: input.orgId,
    appSessionVersion: input.appSessionVersion,
    ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
    nowMs: now,
  });
  if (!attempt) return null;
  if (!input.isHostedHmacReadableWalletId(attempt.walletId)) {
    await input.registrationAttemptStore.put({
      ...attempt,
      state: 'failed',
      failureCode: 'non_hmac_readable_wallet_id',
      updatedAtMs: now,
    });
    return null;
  }
  const refreshedAttempt = { ...attempt, updatedAtMs: now };
  await input.registrationAttemptStore.put(refreshedAttempt);
  return refreshedAttempt;
}

async function getGoogleEmailOtpEnrollmentBySubject(input: {
  readonly walletEnrollmentStore: EmailOtpWalletEnrollmentStore;
  readonly providerSubject: string;
  readonly orgId: string;
  readonly isHostedHmacReadableWalletId: GoogleEmailOtpHostedWalletPredicate;
}): Promise<EmailOtpWalletEnrollmentRecord | null> {
  const providerSubject = toOptionalTrimmedString(input.providerSubject);
  const orgId = toOptionalTrimmedString(input.orgId);
  if (!providerSubject || !orgId) return null;

  const enrollment = await input.walletEnrollmentStore.getByProviderUserId({
    providerUserId: providerSubject,
    orgId,
  });
  if (
    !enrollment ||
    enrollment.providerUserId !== providerSubject ||
    enrollment.orgId !== orgId ||
    !input.isHostedHmacReadableWalletId(enrollment.walletId)
  ) {
    return null;
  }
  return enrollment;
}

async function repairGoogleEmailOtpWalletLink(input: {
  readonly identityStore: IdentityStore;
  readonly providerSubject: string;
  readonly walletId: string;
}): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
  const linked = await input.identityStore.linkSubjectToUserId({
    userId: input.walletId,
    subject: `wallet:${input.providerSubject}`,
    allowMoveIfSoleIdentity: true,
  });
  if (!linked.ok) {
    return {
      ok: false,
      code: linked.code,
      message: linked.message,
    };
  }
  return { ok: true };
}

function isGoogleEmailOtpEnrollmentLookupMiss(code: string): boolean {
  return (
    code === 'not_found' ||
    code === 'provider_identity_mismatch' ||
    code === 'tenant_scope_mismatch'
  );
}

function googleEmailOtpStaleIdentityMapping(input: {
  readonly providerSubject: string;
  readonly linkedWalletId: string;
  readonly email?: string;
}): {
  ok: false;
  mode: 'stale_identity_mapping';
  code: 'stale_identity_mapping';
  walletId: string;
  providerSubject: string;
  email?: string;
  message: string;
} {
  return {
    ok: false,
    mode: 'stale_identity_mapping',
    code: 'stale_identity_mapping',
    walletId: input.linkedWalletId,
    providerSubject: input.providerSubject,
    ...(input.email ? { email: input.email } : {}),
    message:
      'Google Email OTP identity mapping is stale. Clear the stale identity mapping with the dev cleanup route before registering this Google account.',
  };
}

function registrationAttemptStartedResponse(input: {
  readonly attempt: PendingGoogleEmailOtpRegistrationAttemptRecord;
  readonly providerSubject: string;
  readonly email: string;
}): GoogleEmailOtpResolutionResult {
  return {
    ok: true,
    mode: 'register_started',
    walletId: input.attempt.walletId,
    providerSubject: input.providerSubject,
    email: input.email,
    registrationAttemptId: input.attempt.attemptId,
    expiresAtMs: input.attempt.expiresAtMs,
    offer: googleEmailOtpRegistrationOfferResponse(input.attempt),
  };
}

function googleEmailOtpRegistrationOfferResponse(
  attempt: PendingGoogleEmailOtpRegistrationAttemptRecord,
): GoogleEmailOtpRegistrationOffer {
  const [firstOfferCandidate, ...remainingOfferCandidates] = attempt.offerCandidates;
  const remainingCandidates = googleEmailOtpRegistrationOfferCandidateResponses(
    remainingOfferCandidates,
  );
  return {
    offerId: attempt.offerId,
    selectedCandidateId: attempt.selectedCandidateId,
    candidates: [
      googleEmailOtpRegistrationOfferCandidateResponse(firstOfferCandidate),
      ...remainingCandidates,
    ],
  };
}

function googleEmailOtpRegistrationOfferCandidateResponses(
  candidates: readonly GoogleEmailOtpRegistrationOfferCandidateRecord[],
): GoogleEmailOtpRegistrationOfferCandidate[] {
  const out: GoogleEmailOtpRegistrationOfferCandidate[] = [];
  for (const candidate of candidates) {
    out.push(googleEmailOtpRegistrationOfferCandidateResponse(candidate));
  }
  return out;
}

function googleEmailOtpRegistrationOfferCandidateResponse(
  candidate: GoogleEmailOtpRegistrationOfferCandidateRecord,
): GoogleEmailOtpRegistrationOfferCandidate {
  return {
    candidateId: candidate.candidateId,
    walletId: candidate.walletId,
  };
}

function findGoogleEmailOtpOfferCandidateByWalletId(input: {
  readonly candidates: readonly GoogleEmailOtpRegistrationOfferCandidateRecord[];
  readonly walletId: string;
}): GoogleEmailOtpRegistrationOfferCandidateRecord | null {
  for (const candidate of input.candidates) {
    if (candidate.walletId === input.walletId) return candidate;
  }
  return null;
}

function hasDifferentWalletIdentityLink(
  subjects: readonly string[],
  expectedWalletSubject: string,
): boolean {
  for (const subject of subjects) {
    if (subject.startsWith('wallet:') && subject !== expectedWalletSubject) return true;
  }
  return false;
}

function isTruthyBoundaryFlag(value: unknown): boolean {
  return value === true || String(value || '').trim().toLowerCase() === 'true';
}
