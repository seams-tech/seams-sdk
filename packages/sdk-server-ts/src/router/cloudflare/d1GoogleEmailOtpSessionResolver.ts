import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import {
  parseGoogleProviderSubject,
  parseOrgId,
  parseVerifiedGoogleEmail,
} from '@shared/utils/domainIds';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  deriveHostedNearAccountId,
  isHostedHmacReadableRelayerWalletId,
} from '../../core/hostedAccountIds';
import type {
  EmailOtpWalletEnrollmentRecord,
  GoogleEmailOtpRegistrationOfferCandidateRecord,
  NonEmptyGoogleEmailOtpRegistrationOfferCandidates,
} from '../../core/EmailOtpStores';
import type {
  IdentityStore,
  LinkIdentityResult,
  UnlinkIdentityResult,
} from '../../core/IdentityStore';
import type { CloudflareRouterApiAuthService } from '../authServicePort';
import type { CloudflareD1EmailOtpEnrollmentStore } from './d1EmailOtpEnrollmentStore';
import type { CloudflareD1EmailOtpRateLimitStore } from './d1EmailOtpRateLimitStore';
import type { CloudflareD1GoogleEmailOtpRegistrationAttemptStore } from './d1GoogleEmailOtpRegistrationAttemptStore';
import {
  googleEmailOtpStaleIdentityMapping,
  hasDifferentWalletIdentitySubject,
} from './d1IdentityRecords';
import {
  abandonedGoogleEmailOtpRegistrationAttemptRecord,
  activeGoogleEmailOtpRegistrationAttemptRecord,
  expiredGoogleEmailOtpRegistrationAttemptRecord,
  failedGoogleEmailOtpRegistrationAttemptWithCode,
  googleEmailOtpRegistrationOfferForResponse,
  requireRuntimePolicyScope,
} from './d1GoogleEmailOtpRegistrationRecords';
import {
  parseD1BoundaryWalletId,
  parseD1BoundaryWalletIdResult,
} from './d1RouterApiAuthBoundary';
import { requireD1RouterApiAuthScopeString } from './d1RouterApiAuthConfig';

type ResolveGoogleEmailOtpSessionInput = Parameters<
  CloudflareRouterApiAuthService['resolveGoogleEmailOtpSession']
>[0];
type ResolveGoogleEmailOtpSessionResult = Awaited<
  ReturnType<CloudflareRouterApiAuthService['resolveGoogleEmailOtpSession']>
>;
type CleanupGoogleEmailOtpDevRegistrationStateInput = Parameters<
  CloudflareRouterApiAuthService['cleanupGoogleEmailOtpDevRegistrationState']
>[0];
type CleanupGoogleEmailOtpDevRegistrationStateResult = Awaited<
  ReturnType<CloudflareRouterApiAuthService['cleanupGoogleEmailOtpDevRegistrationState']>
>;
type ConsumeGoogleEmailOtpRegistrationAttemptRateLimitInput = Parameters<
  CloudflareRouterApiAuthService['consumeGoogleEmailOtpRegistrationAttemptRateLimit']
>[0];
type ConsumeGoogleEmailOtpRegistrationAttemptRateLimitResult = Awaited<
  ReturnType<CloudflareRouterApiAuthService['consumeGoogleEmailOtpRegistrationAttemptRateLimit']>
>;

type GoogleEmailOtpIdentityLinker = (input: {
  readonly userId: string;
  readonly subject: string;
  readonly allowMoveIfSoleIdentity?: boolean;
}) => Promise<LinkIdentityResult>;

type CompleteGoogleEmailOtpRegistrationAttemptResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: string; readonly message: string };

export class CloudflareD1GoogleEmailOtpSessionResolver {
  private readonly accountIdDerivationSecret: unknown;
  private readonly emailOtpEnrollments: CloudflareD1EmailOtpEnrollmentStore;
  private readonly emailOtpRateLimits: CloudflareD1EmailOtpRateLimitStore;
  private readonly identityStore: IdentityStore;
  private readonly linkIdentity: GoogleEmailOtpIdentityLinker;
  private readonly production: boolean;
  private readonly registrationAttempts: CloudflareD1GoogleEmailOtpRegistrationAttemptStore;
  private readonly relayerAccount: unknown;

  constructor(input: {
    readonly accountIdDerivationSecret: unknown;
    readonly emailOtpEnrollments: CloudflareD1EmailOtpEnrollmentStore;
    readonly emailOtpRateLimits: CloudflareD1EmailOtpRateLimitStore;
    readonly identityStore: IdentityStore;
    readonly linkIdentity: GoogleEmailOtpIdentityLinker;
    readonly production: boolean;
    readonly registrationAttempts: CloudflareD1GoogleEmailOtpRegistrationAttemptStore;
    readonly relayerAccount: unknown;
  }) {
    this.accountIdDerivationSecret = input.accountIdDerivationSecret;
    this.emailOtpEnrollments = input.emailOtpEnrollments;
    this.emailOtpRateLimits = input.emailOtpRateLimits;
    this.identityStore = input.identityStore;
    this.linkIdentity = input.linkIdentity;
    this.production = input.production;
    this.registrationAttempts = input.registrationAttempts;
    this.relayerAccount = input.relayerAccount;
  }

  async resolve(
    input: ResolveGoogleEmailOtpSessionInput,
  ): Promise<ResolveGoogleEmailOtpSessionResult> {
    const providerSubject = parseGoogleProviderSubject(input.providerSubject ?? input.sub);
    if (!providerSubject.ok) {
      throw new Error('Cannot resolve Google Email OTP session without Google provider subject');
    }
    const accountMode = toOptionalTrimmedString(input.accountMode)?.toLowerCase();
    if (accountMode !== 'register' && accountMode !== 'login') {
      throw new Error('Google Email OTP accountMode must be register or login');
    }
    const email = toOptionalTrimmedString(input.email)?.toLowerCase() || '';
    const runtimePolicyScope = requireRuntimePolicyScope(input.runtimePolicyScope);
    const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
    if (accountMode === 'register' && !appSessionVersion) {
      throw new Error('Google Email OTP registration requires appSessionVersion');
    }
    const restartRegistrationOffer = isTrueFlag(input.restartRegistrationOffer);
    const identitySubject = `wallet:${providerSubject.value}`;
    const linkedWalletId = parseD1BoundaryWalletId(
      await this.identityStore.getUserIdBySubject(identitySubject),
    );
    const linkedIsHostedHmacReadableWallet = Boolean(
      linkedWalletId && this.isHostedHmacReadableRelayerWallet(linkedWalletId),
    );

    if (accountMode === 'login') {
      return await this.resolveLoginSession({
        providerSubject: providerSubject.value,
        email,
        orgId: runtimePolicyScope.orgId,
        linkedWalletId,
        linkedIsHostedHmacReadableWallet,
      });
    }

    if (!email) {
      throw new Error('Email is required to register a Google Email OTP wallet id');
    }
    return await this.resolveRegistrationSession({
      providerSubject: providerSubject.value,
      email,
      orgId: runtimePolicyScope.orgId,
      appSessionVersion: appSessionVersion || '',
      runtimePolicyScope,
      restartRegistrationOffer,
      identitySubject,
      linkedWalletId,
    });
  }

  async cleanupDevRegistrationState(
    input: CleanupGoogleEmailOtpDevRegistrationStateInput,
  ): Promise<CleanupGoogleEmailOtpDevRegistrationStateResult> {
    if (this.production) {
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

    const requestedWalletId = parseD1BoundaryWalletId(input.walletId);
    const requestedOrgId = toOptionalTrimmedString(input.orgId);
    const nowMs = cleanupNowMs(input.nowMs);
    const expiredRegistrationAttemptsDeleted =
      await this.registrationAttempts.cleanupExpired(nowMs);
    const subject = `wallet:${providerSubject}`;
    const linkedWalletId = parseD1BoundaryWalletId(
      await this.identityStore.getUserIdBySubject(subject),
    );

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
    if (!this.isHostedHmacReadableRelayerWallet(linkedWalletId)) {
      return {
        ok: true,
        providerSubject,
        expiredRegistrationAttemptsDeleted,
        linkedWalletId,
        orphanedWalletMappingRemoved: false,
        orphanedWalletMappingSkippedReason: 'not_relayer_subaccount',
      };
    }

    const activeEnrollment = await this.emailOtpEnrollments.readEnrollment(linkedWalletId);
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

    const deleted = await this.identityStore.deleteSubjectLinkForDevCleanup({
      userId: linkedWalletId,
      subject,
    });
    if (!deleted.ok && deleted.code !== 'not_found') {
      return devCleanupIdentityDeleteFailure(deleted);
    }
    return {
      ok: true,
      providerSubject,
      expiredRegistrationAttemptsDeleted,
      linkedWalletId,
      orphanedWalletMappingRemoved: deleted.ok,
    };
  }

  async consumeRegistrationAttemptRateLimit(
    input: ConsumeGoogleEmailOtpRegistrationAttemptRateLimitInput,
  ): Promise<ConsumeGoogleEmailOtpRegistrationAttemptRateLimitResult> {
    const accountMode = toOptionalTrimmedString(input.accountMode)?.toLowerCase();
    if (accountMode !== 'register') return { ok: true };
    const providerSubject = parseGoogleProviderSubject(input.providerSubject);
    if (!providerSubject.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: providerSubject.error.message,
      };
    }
    const email = parseVerifiedGoogleEmail(input.email);
    if (!email.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: email.error.message,
      };
    }
    const orgId = parseOrgId(input.runtimePolicyScope?.orgId);
    if (!orgId.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: orgId.error.message,
      };
    }
    const restartOffer = isTrueFlag(input.restartRegistrationOffer);
    return await this.emailOtpRateLimits.consume({
      scope: 'googleRegistrationAttempt',
      action: restartOffer
        ? 'google_email_otp_registration_offer_restart'
        : 'google_email_otp_registration_create',
      userId: toOptionalTrimmedString(input.appSessionUserId),
      providerSubject: providerSubject.value,
      orgId: orgId.value,
      clientIp: toOptionalTrimmedString(input.clientIp),
    });
  }

  async completeRegistrationAttempt(input: {
    readonly registrationAttemptId?: unknown;
    readonly walletId?: unknown;
  }): Promise<CompleteGoogleEmailOtpRegistrationAttemptResult> {
    const registrationAttemptId = toOptionalTrimmedString(input.registrationAttemptId);
    if (!registrationAttemptId) return { ok: true };
    const walletId = parseD1BoundaryWalletIdResult(input.walletId);
    if (!walletId.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: walletId.code === 'missing' ? 'Missing walletId' : 'Invalid walletId',
      };
    }
    const attempt = await this.registrationAttempts.read(registrationAttemptId);
    if (!attempt) {
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt expired or was not found',
      };
    }
    if (attempt.expiresAtMs <= Date.now()) {
      await this.registrationAttempts.put(
        expiredGoogleEmailOtpRegistrationAttemptRecord({
          record: attempt,
          updatedAtMs: Date.now(),
        }),
      );
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt expired',
      };
    }
    if (walletId.value !== attempt.walletId) {
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
    const linked = await this.linkIdentity({
      userId: attempt.walletId,
      subject: `wallet:${attempt.providerSubject}`,
      allowMoveIfSoleIdentity: true,
    });
    if (!linked.ok) {
      await this.registrationAttempts.put(
        failedGoogleEmailOtpRegistrationAttemptWithCode({
          record: attempt,
          failureCode: linked.code,
          updatedAtMs: Date.now(),
        }),
      );
      return { ok: false, code: linked.code, message: linked.message };
    }
    await this.registrationAttempts.put(
      activeGoogleEmailOtpRegistrationAttemptRecord({
        record: attempt,
        updatedAtMs: Date.now(),
      }),
    );
    return { ok: true };
  }

  private async resolveLoginSession(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly linkedWalletId: string | null;
    readonly linkedIsHostedHmacReadableWallet: boolean;
  }): Promise<ResolveGoogleEmailOtpSessionResult> {
    if (input.linkedWalletId && input.linkedIsHostedHmacReadableWallet) {
      const enrollment = await this.readActiveEnrollment({
        walletId: input.linkedWalletId,
        orgId: input.orgId,
        providerUserId: input.providerSubject,
      });
      if (enrollment.ok) {
        return {
          ok: true,
          mode: 'existing_wallet',
          walletId: input.linkedWalletId,
          providerSubject: input.providerSubject,
          ...(input.email ? { email: input.email } : {}),
          hasEmailOtpEnrollment: true,
        };
      }
      if (!isGoogleEmailOtpEnrollmentLookupMiss(enrollment.code)) {
        throw codedError(enrollment.code, enrollment.message);
      }
    }

    const discovered = await this.getEnrollmentBySubject({
      providerSubject: input.providerSubject,
      orgId: input.orgId,
    });
    if (!discovered) {
      if (input.linkedWalletId) {
        const stale = googleEmailOtpStaleIdentityMapping({
          providerSubject: input.providerSubject,
          linkedWalletId: input.linkedWalletId,
          ...(input.email ? { email: input.email } : {}),
        });
        throw codedError(stale.code, stale.message);
      }
      throw codedError('not_found', 'Email OTP enrollment not found');
    }

    const repaired = await this.repairWalletLink({
      providerSubject: input.providerSubject,
      walletId: discovered.walletId,
    });
    if (!repaired.ok) throw codedError(repaired.code, repaired.message);
    return {
      ok: true,
      mode: 'existing_wallet',
      walletId: discovered.walletId,
      providerSubject: input.providerSubject,
      ...(input.email ? { email: input.email } : {}),
      hasEmailOtpEnrollment: true,
    };
  }

  private async resolveRegistrationSession(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope: RuntimePolicyScope;
    readonly restartRegistrationOffer: boolean;
    readonly identitySubject: string;
    readonly linkedWalletId: string | null;
  }): Promise<ResolveGoogleEmailOtpSessionResult> {
    const discoveredExistingEnrollment = await this.getEnrollmentBySubject({
      providerSubject: input.providerSubject,
      orgId: input.orgId,
    });
    if (discoveredExistingEnrollment && !input.restartRegistrationOffer) {
      const repaired = await this.repairWalletLink({
        providerSubject: input.providerSubject,
        walletId: discoveredExistingEnrollment.walletId,
      });
      if (!repaired.ok) {
        return {
          ok: false,
          mode: 'registration_incomplete',
          code: 'registration_incomplete',
          walletId: discoveredExistingEnrollment.walletId,
          providerSubject: input.providerSubject,
          email: input.email,
          message: repaired.message,
        };
      }
      return {
        ok: true,
        mode: 'existing_wallet',
        walletId: discoveredExistingEnrollment.walletId,
        providerSubject: input.providerSubject,
        email: input.email,
        hasEmailOtpEnrollment: true,
      };
    }
    if (input.linkedWalletId && !input.restartRegistrationOffer) {
      return googleEmailOtpStaleIdentityMapping({
        providerSubject: input.providerSubject,
        linkedWalletId: input.linkedWalletId,
        email: input.email,
      });
    }

    const nowMs = Date.now();
    await this.registrationAttempts.abandonStartedExceptAppSession({
      providerSubject: input.providerSubject,
      email: input.email,
      orgId: input.orgId,
      appSessionVersion: input.appSessionVersion,
      runtimePolicyScope: input.runtimePolicyScope,
      nowMs,
      failureCode: 'app_session_version_replaced',
    });

    let startedAttempt = await this.registrationAttempts.findStarted({
      providerSubject: input.providerSubject,
      email: input.email,
      orgId: input.orgId,
      appSessionVersion: input.appSessionVersion,
      runtimePolicyScope: input.runtimePolicyScope,
    });
    if (startedAttempt && !this.isHostedHmacReadableRelayerWallet(startedAttempt.walletId)) {
      await this.registrationAttempts.failNonHmacReadableWallet({
        record: startedAttempt,
        updatedAtMs: Date.now(),
      });
      startedAttempt = null;
    }
    if (startedAttempt) {
      if (input.restartRegistrationOffer) {
        await this.registrationAttempts.put(
          abandonedGoogleEmailOtpRegistrationAttemptRecord({
            record: startedAttempt,
            failureCode: 'offer_restarted_by_user',
            updatedAtMs: Date.now(),
          }),
        );
      } else {
        return {
          ok: true,
          mode: 'register_started',
          walletId: startedAttempt.walletId,
          providerSubject: input.providerSubject,
          email: input.email,
          registrationAttemptId: startedAttempt.attemptId,
          expiresAtMs: startedAttempt.expiresAtMs,
          offer: googleEmailOtpRegistrationOfferForResponse(startedAttempt),
        };
      }
    }

    return await this.createFreshRegistrationAttempt(input);
  }

  private async createFreshRegistrationAttempt(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope: RuntimePolicyScope;
    readonly identitySubject: string;
  }): Promise<ResolveGoogleEmailOtpSessionResult> {
    const nowMs = Date.now();
    const authProvider = 'google_oidc';
    const walletIdDerivationNonce = secureRandomBase64Url(
      18,
      'google email otp wallet derivation nonces',
    );
    const offerCandidates: GoogleEmailOtpRegistrationOfferCandidateRecord[] = [];
    for (let attempt = 0; attempt < 30 && offerCandidates.length < 5; attempt += 1) {
      const walletId = await this.deriveHostedWalletId({
        providerSubject: input.providerSubject,
        email: input.email,
        authProvider,
        runtimePolicyScope: input.runtimePolicyScope,
        walletIdDerivationNonce,
        collisionCounter: attempt,
      });
      const inUseByLiveAttempt = await this.registrationAttempts.hasLiveStartedWalletAttempt({
        walletId,
        nowMs,
      });
      if (inUseByLiveAttempt) continue;
      const inUseByEnrollment = await this.emailOtpEnrollments.readEnrollment(walletId);
      if (inUseByEnrollment) continue;
      const existingSubjects = await this.identityStore.listSubjectsByUserId(walletId);
      if (
        hasDifferentWalletIdentitySubject({
          subjects: existingSubjects,
          expectedIdentitySubject: input.identitySubject,
        })
      ) {
        continue;
      }
      offerCandidates.push({
        candidateId: secureRandomBase64Url(18, 'google email otp offer candidate ids'),
        walletId,
        collisionCounter: attempt,
      });
    }

    const selectedCandidate = offerCandidates[0];
    if (!selectedCandidate) {
      return {
        ok: false,
        mode: 'registration_incomplete',
        code: 'registration_incomplete',
        providerSubject: input.providerSubject,
        email: input.email,
        message: 'Unable to allocate a fresh Google Email OTP registration attempt',
      };
    }
    const nonEmptyOfferCandidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates = [
      selectedCandidate,
      ...offerCandidates.slice(1),
    ];
    const attempt = await this.registrationAttempts.create({
      providerSubject: input.providerSubject,
      email: input.email,
      walletId: selectedCandidate.walletId,
      offerId: secureRandomBase64Url(18, 'google email otp offer ids'),
      offerCandidates: nonEmptyOfferCandidates,
      selectedCandidateId: selectedCandidate.candidateId,
      appSessionVersion: input.appSessionVersion,
      authProvider,
      walletIdDerivationNonce,
      collisionCounter: selectedCandidate.collisionCounter,
      runtimePolicyScope: input.runtimePolicyScope,
    });
    return {
      ok: true,
      mode: 'register_started',
      walletId: attempt.walletId,
      providerSubject: input.providerSubject,
      email: input.email,
      registrationAttemptId: attempt.attemptId,
      expiresAtMs: attempt.expiresAtMs,
      offer: googleEmailOtpRegistrationOfferForResponse(attempt),
    };
  }

  private isHostedHmacReadableRelayerWallet(walletId: string): boolean {
    return isHostedHmacReadableRelayerWalletId({
      walletId,
      relayerAccount: this.relayerAccount,
    });
  }

  private async deriveHostedWalletId(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly authProvider: string;
    readonly runtimePolicyScope: RuntimePolicyScope;
    readonly walletIdDerivationNonce: string;
    readonly collisionCounter: number;
  }): Promise<string> {
    return await deriveHostedNearAccountId({
      accountIdDerivationSecret: requireD1RouterApiAuthScopeString(
        this.accountIdDerivationSecret,
        'ACCOUNT_ID_DERIVATION_SECRET',
      ),
      relayerAccount: requireD1RouterApiAuthScopeString(this.relayerAccount, 'relayerAccount'),
      projectId: input.runtimePolicyScope.projectId,
      envId: input.runtimePolicyScope.envId,
      authProvider: input.authProvider,
      providerSubject: input.providerSubject,
      verifiedEmail: input.email,
      walletIdDerivationNonce: input.walletIdDerivationNonce,
      ...(input.collisionCounter > 0 ? { collisionCounter: input.collisionCounter } : {}),
    });
  }

  private async getEnrollmentBySubject(input: {
    readonly providerSubject: string;
    readonly orgId: string;
  }): Promise<EmailOtpWalletEnrollmentRecord | null> {
    const enrollment = await this.emailOtpEnrollments.readEnrollmentByProviderUserId({
      providerUserId: input.providerSubject,
      orgId: input.orgId,
    });
    if (
      !enrollment ||
      enrollment.providerUserId !== input.providerSubject ||
      enrollment.orgId !== input.orgId ||
      !this.isHostedHmacReadableRelayerWallet(enrollment.walletId)
    ) {
      return null;
    }
    return enrollment;
  }

  private async repairWalletLink(input: {
    readonly providerSubject: string;
    readonly walletId: string;
  }): Promise<LinkIdentityResult> {
    return await this.linkIdentity({
      userId: input.walletId,
      subject: `wallet:${input.providerSubject}`,
      allowMoveIfSoleIdentity: true,
    });
  }

  private async readActiveEnrollment(input: {
    readonly walletId: string;
    readonly orgId: string;
    readonly providerUserId: string;
  }): Promise<
    | { readonly ok: true; readonly enrollment: EmailOtpWalletEnrollmentRecord }
    | { readonly ok: false; readonly code: string; readonly message: string }
  > {
    const enrollment = await this.emailOtpEnrollments.readEnrollment(input.walletId);
    if (!enrollment) {
      return { ok: false, code: 'not_found', message: 'Email OTP enrollment not found' };
    }
    if (enrollment.orgId !== input.orgId) {
      return {
        ok: false,
        code: 'tenant_scope_mismatch',
        message: 'Email OTP enrollment does not match the requested orgId',
      };
    }
    if (enrollment.providerUserId !== input.providerUserId) {
      return {
        ok: false,
        code: 'provider_identity_mismatch',
        message: 'Email OTP enrollment does not belong to the requested provider identity',
      };
    }
    return { ok: true, enrollment };
  }
}

function isTrueFlag(input: unknown): boolean {
  return (
    input === true ||
    String(input || '')
      .trim()
      .toLowerCase() === 'true'
  );
}

function cleanupNowMs(input: unknown): number {
  const raw = typeof input === 'number' ? input : Number(input);
  return Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : Date.now();
}

function isGoogleEmailOtpEnrollmentLookupMiss(code: string): boolean {
  return (
    code === 'not_found' ||
    code === 'provider_identity_mismatch' ||
    code === 'tenant_scope_mismatch'
  );
}

function codedError(code: string, message: string): Error & { code: string } {
  const error = new Error(message) as Error & { code: string };
  error.code = code;
  return error;
}

function devCleanupIdentityDeleteFailure(
  input: UnlinkIdentityResult & { readonly ok: false },
): Extract<CleanupGoogleEmailOtpDevRegistrationStateResult, { readonly ok: false }> {
  return { ok: false, code: input.code, message: input.message };
}
