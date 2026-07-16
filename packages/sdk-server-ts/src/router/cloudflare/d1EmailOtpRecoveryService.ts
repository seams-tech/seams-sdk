import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import { EMAIL_OTP_RECOVERY_KEY_COUNT } from '@shared/utils/emailOtpRecoveryKey';
import type {
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  EmailOtpWalletEnrollmentRecord,
} from '../../core/EmailOtpStores';
import {
  validateSecp256k1PublicKey33,
  verifySecp256k1RecoverableSignatureAgainstPublicKey33,
} from '../../core/ThresholdService/evmCryptoWasm';
import type {
  RouterApiEmailOtpRouteService,
  RouterApiWalletUnlockService,
} from '../authServicePort';
import { CloudflareD1EmailOtpChallengeStore } from './d1EmailOtpChallengeStore';
import { CloudflareD1EmailOtpChallengeVerifier } from './d1EmailOtpChallengeVerifier';
import { CloudflareD1EmailOtpEnrollmentStore } from './d1EmailOtpEnrollmentStore';
import { CloudflareD1EmailOtpGrantStore } from './d1EmailOtpGrantStore';
import { CloudflareD1EmailOtpRateLimitStore } from './d1EmailOtpRateLimitStore';
import { CloudflareD1EmailOtpRecoveryEscrowStore } from './d1EmailOtpRecoveryEscrowStore';
import { isRecordValue, parseD1BoundaryWalletIdResult } from './d1RouterApiAuthBoundary';
import {
  activeEmailOtpRecoveryEscrow,
  activeEmailOtpRecoveryRotationEscrowRecord,
  bytesEqual,
  clampedEmailOtpUnlockTtlMs,
  countActiveEmailOtpRecoveryEscrows,
  decodeFixedBase64Url,
  emailOtpGrantRecord,
  emailOtpRecoveryEscrowMatchesEnrollment,
  emailOtpUnlockChallengeRecord,
  invalidRecoveryRotationBody,
  recoveryRotationBindingMismatch,
  redactEmailOtpRecoveryChallengeEscrow,
  revokedEmailOtpRecoveryEscrowRecord,
  type EmailOtpRecoveryRotationHash,
} from './d1EmailOtpRecords';

type ReadActiveEmailOtpEnrollmentInput =
  Parameters<RouterApiEmailOtpRouteService['readActiveEmailOtpEnrollment']>[0];
type ReadActiveEmailOtpEnrollmentResult = Awaited<
  ReturnType<RouterApiEmailOtpRouteService['readActiveEmailOtpEnrollment']>
>;
type ReadEmailOtpEnrollmentInput =
  Parameters<RouterApiEmailOtpRouteService['readEmailOtpEnrollment']>[0];
type ReadEmailOtpEnrollmentResult = Awaited<
  ReturnType<RouterApiEmailOtpRouteService['readEmailOtpEnrollment']>
>;
type IsEmailOtpStrongAuthRequiredInput =
  Parameters<RouterApiEmailOtpRouteService['isEmailOtpStrongAuthRequired']>[0];
type IsEmailOtpStrongAuthRequiredResult = Awaited<
  ReturnType<RouterApiEmailOtpRouteService['isEmailOtpStrongAuthRequired']>
>;
type MarkEmailOtpStrongAuthSatisfiedInput =
  Parameters<RouterApiEmailOtpRouteService['markEmailOtpStrongAuthSatisfied']>[0];
type MarkEmailOtpStrongAuthSatisfiedResult = Awaited<
  ReturnType<RouterApiEmailOtpRouteService['markEmailOtpStrongAuthSatisfied']>
>;
type GetEmailOtpRecoveryCodeStatusInput =
  Parameters<RouterApiEmailOtpRouteService['getEmailOtpRecoveryCodeStatus']>[0];
type GetEmailOtpRecoveryCodeStatusResult = Awaited<
  ReturnType<RouterApiEmailOtpRouteService['getEmailOtpRecoveryCodeStatus']>
>;
type VerifyEmailOtpDeviceRecoveryChallengeInput =
  Parameters<RouterApiEmailOtpRouteService['verifyEmailOtpDeviceRecoveryChallenge']>[0];
type VerifyEmailOtpDeviceRecoveryChallengeResult =
  Awaited<ReturnType<RouterApiEmailOtpRouteService['verifyEmailOtpDeviceRecoveryChallenge']>>;
type CreateEmailOtpUnlockChallengeInput =
  Parameters<RouterApiWalletUnlockService['createEmailOtpUnlockChallenge']>[0];
type CreateEmailOtpUnlockChallengeResult = Awaited<
  ReturnType<RouterApiWalletUnlockService['createEmailOtpUnlockChallenge']>
>;
type VerifyEmailOtpUnlockProofInput =
  Parameters<RouterApiWalletUnlockService['verifyEmailOtpUnlockProof']>[0];
type VerifyEmailOtpUnlockProofResult = Awaited<
  ReturnType<RouterApiWalletUnlockService['verifyEmailOtpUnlockProof']>
>;
type ConsumeEmailOtpGrantInput =
  Parameters<RouterApiEmailOtpRouteService['consumeEmailOtpGrant']>[0];
type ConsumeEmailOtpGrantResult = Awaited<
  ReturnType<RouterApiEmailOtpRouteService['consumeEmailOtpGrant']>
>;
type ConsumeEmailOtpRecoveryKeyInput =
  Parameters<RouterApiEmailOtpRouteService['consumeEmailOtpRecoveryKey']>[0];
type ConsumeEmailOtpRecoveryKeyResult = Awaited<
  ReturnType<RouterApiEmailOtpRouteService['consumeEmailOtpRecoveryKey']>
>;
type RotateEmailOtpRecoveryKeysInput =
  Parameters<RouterApiEmailOtpRouteService['rotateEmailOtpRecoveryKeys']>[0];
type RotateEmailOtpRecoveryKeysResult = Awaited<
  ReturnType<RouterApiEmailOtpRouteService['rotateEmailOtpRecoveryKeys']>
>;
type RecordEmailOtpRecoveryKeyAttemptFailureInput =
  Parameters<RouterApiEmailOtpRouteService['recordEmailOtpRecoveryKeyAttemptFailure']>[0];
type RecordEmailOtpRecoveryKeyAttemptFailureResult =
  Awaited<ReturnType<RouterApiEmailOtpRouteService['recordEmailOtpRecoveryKeyAttemptFailure']>>;

type NormalizedRecoveryCodeStatusInput = {
  readonly userId: string;
  readonly walletId: string;
  readonly orgId: string;
};

type NormalizedEmailOtpEnrollmentReadInput = {
  readonly walletId: string;
  readonly orgId: string;
};

type NormalizedActiveEmailOtpEnrollmentReadInput = NormalizedEmailOtpEnrollmentReadInput & {
  readonly providerUserId: string | undefined;
};

type NormalizedEmailOtpStrongAuthInput = {
  readonly walletId: string;
};

type NormalizedUnlockChallengeInput = {
  readonly walletId: string;
  readonly orgId: string;
  readonly ttlMs: number;
};

type NormalizedUnlockProofInput = {
  readonly walletId: string;
  readonly orgId: string;
  readonly challengeId: string;
  readonly publicKeyB64u: string;
  readonly signatureB64u: string;
};

type NormalizedGrantConsumptionInput = {
  readonly loginGrant: string;
  readonly userId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly clientIp: string | undefined;
};

type NormalizedRecoveryGrantInput = {
  readonly recoveryConsumeGrant: string;
  readonly userId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly clientIp: string | undefined;
};

type NormalizedRecoveryKeyConsumptionInput = NormalizedRecoveryGrantInput & {
  readonly recoveryKeyId: string;
};

type NormalizedRecoveryRotationInput = {
  readonly userId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly enrollmentId: string;
  readonly enrollmentSealKeyVersion: string;
  readonly rawEscrows: readonly unknown[];
};

type ParseResult<TValue, TResult> =
  | {
      readonly ok: true;
      readonly value: TValue;
    }
  | {
      readonly ok: false;
      readonly result: TResult;
    };

type InvalidBodyResult = {
  readonly ok: false;
  readonly code: 'invalid_body';
  readonly message: string;
};

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

function normalizeEmailOtpEnrollmentReadInput(
  input: ReadEmailOtpEnrollmentInput,
): ParseResult<NormalizedEmailOtpEnrollmentReadInput, InvalidBodyResult> {
  const walletId = parseD1BoundaryWalletIdResult(input.walletId);
  const orgId = toOptionalTrimmedString(input.orgId);
  if (!walletId.ok) {
    return {
      ok: false,
      result: invalidEmailOtpEnrollmentReadBody(
        walletId.code === 'missing' ? 'Missing walletId' : 'Invalid walletId',
      ),
    };
  }
  if (!orgId) return { ok: false, result: invalidEmailOtpEnrollmentReadBody('Missing orgId') };
  return { ok: true, value: { walletId: walletId.value, orgId } };
}

function normalizeActiveEmailOtpEnrollmentReadInput(
  input: ReadActiveEmailOtpEnrollmentInput,
): ParseResult<NormalizedActiveEmailOtpEnrollmentReadInput, InvalidBodyResult> {
  const walletId = parseD1BoundaryWalletIdResult(input.walletId);
  const orgId = toOptionalTrimmedString(input.orgId);
  const providerUserId = toOptionalTrimmedString(input.providerUserId);
  if (!walletId.ok) {
    return {
      ok: false,
      result: invalidActiveEmailOtpEnrollmentReadBody(
        walletId.code === 'missing' ? 'Missing walletId' : 'Invalid walletId',
      ),
    };
  }
  if (!orgId) {
    return { ok: false, result: invalidActiveEmailOtpEnrollmentReadBody('Missing orgId') };
  }
  return { ok: true, value: { walletId: walletId.value, orgId, providerUserId } };
}

function normalizeEmailOtpStrongAuthInput(
  input: IsEmailOtpStrongAuthRequiredInput | MarkEmailOtpStrongAuthSatisfiedInput,
): ParseResult<NormalizedEmailOtpStrongAuthInput, InvalidBodyResult> {
  const walletId = parseD1BoundaryWalletIdResult(input.walletId);
  if (!walletId.ok) {
    return {
      ok: false,
      result: invalidEmailOtpStrongAuthBody(
        walletId.code === 'missing' ? 'Missing walletId' : 'Invalid walletId',
      ),
    };
  }
  return { ok: true, value: { walletId: walletId.value } };
}

function invalidEmailOtpEnrollmentReadBody(message: string): InvalidBodyResult {
  return { ok: false, code: 'invalid_body', message };
}

function invalidActiveEmailOtpEnrollmentReadBody(message: string): InvalidBodyResult {
  return { ok: false, code: 'invalid_body', message };
}

function invalidEmailOtpStrongAuthBody(message: string): InvalidBodyResult {
  return { ok: false, code: 'invalid_body', message };
}

function emailOtpEnrollmentTenantMismatch(): ReadEmailOtpEnrollmentResult {
  return {
    ok: false,
    code: 'tenant_scope_mismatch',
    message: 'Email OTP enrollment does not match the requested orgId',
  };
}

export class CloudflareD1EmailOtpRecoveryService {
  private readonly challengeVerifier: CloudflareD1EmailOtpChallengeVerifier;
  private readonly emailOtpChallenges: CloudflareD1EmailOtpChallengeStore;
  private readonly emailOtpEnrollments: CloudflareD1EmailOtpEnrollmentStore;
  private readonly emailOtpGrants: CloudflareD1EmailOtpGrantStore;
  private readonly emailOtpRateLimits: CloudflareD1EmailOtpRateLimitStore;
  private readonly emailOtpRecoveryEscrows: CloudflareD1EmailOtpRecoveryEscrowStore;
  private readonly grantTtlMs: number;
  private readonly sha256Bytes: EmailOtpRecoveryRotationHash;

  constructor(input: {
    readonly challengeVerifier: CloudflareD1EmailOtpChallengeVerifier;
    readonly emailOtpChallenges: CloudflareD1EmailOtpChallengeStore;
    readonly emailOtpEnrollments: CloudflareD1EmailOtpEnrollmentStore;
    readonly emailOtpGrants: CloudflareD1EmailOtpGrantStore;
    readonly emailOtpRateLimits: CloudflareD1EmailOtpRateLimitStore;
    readonly emailOtpRecoveryEscrows: CloudflareD1EmailOtpRecoveryEscrowStore;
    readonly grantTtlMs: number;
    readonly sha256Bytes: EmailOtpRecoveryRotationHash;
  }) {
    this.challengeVerifier = input.challengeVerifier;
    this.emailOtpChallenges = input.emailOtpChallenges;
    this.emailOtpEnrollments = input.emailOtpEnrollments;
    this.emailOtpGrants = input.emailOtpGrants;
    this.emailOtpRateLimits = input.emailOtpRateLimits;
    this.emailOtpRecoveryEscrows = input.emailOtpRecoveryEscrows;
    this.grantTtlMs = input.grantTtlMs;
    this.sha256Bytes = input.sha256Bytes;
  }

  async readEmailOtpEnrollment(
    input: ReadEmailOtpEnrollmentInput,
  ): Promise<ReadEmailOtpEnrollmentResult> {
    const parsed = normalizeEmailOtpEnrollmentReadInput(input);
    if (!parsed.ok) return parsed.result;

    const enrollment = await this.emailOtpEnrollments.readEnrollment(parsed.value.walletId);
    if (!enrollment) {
      return { ok: false, code: 'not_found', message: 'Email OTP enrollment not found' };
    }
    if (enrollment.orgId !== parsed.value.orgId) return emailOtpEnrollmentTenantMismatch();
    return { ok: true, enrollment };
  }

  async readActiveEmailOtpEnrollment(
    input: ReadActiveEmailOtpEnrollmentInput,
  ): Promise<ReadActiveEmailOtpEnrollmentResult> {
    const parsed = normalizeActiveEmailOtpEnrollmentReadInput(input);
    if (!parsed.ok) return parsed.result;

    const enrollment = await this.readEmailOtpEnrollment({
      walletId: parsed.value.walletId,
      orgId: parsed.value.orgId,
    });
    if (!enrollment.ok) return enrollment;
    if (
      parsed.value.providerUserId &&
      enrollment.enrollment.providerUserId !== parsed.value.providerUserId
    ) {
      return {
        ok: false,
        code: 'provider_identity_mismatch',
        message: 'Email OTP enrollment does not match the requested provider user',
      };
    }
    return enrollment;
  }

  async isEmailOtpStrongAuthRequired(
    input: IsEmailOtpStrongAuthRequiredInput,
  ): Promise<IsEmailOtpStrongAuthRequiredResult> {
    const parsed = normalizeEmailOtpStrongAuthInput(input);
    if (!parsed.ok) return parsed.result;

    const enrollment = await this.emailOtpEnrollments.readEnrollment(parsed.value.walletId);
    if (!enrollment) return { ok: true, required: false, walletId: parsed.value.walletId };
    const authState = await this.emailOtpEnrollments.readAuthStateForEnrollment(enrollment);
    if (!authState.ok) return authState;
    const state = authState.state;
    if (!state) return { ok: true, required: false, walletId: parsed.value.walletId };
    const lastEmailOtpLoginAtMs =
      typeof state.lastEmailOtpLoginAtMs === 'number' ? state.lastEmailOtpLoginAtMs : undefined;
    const lastStrongAuthAtMs =
      typeof state.lastStrongAuthAtMs === 'number' ? state.lastStrongAuthAtMs : undefined;
    return {
      ok: true,
      required: Boolean(
        lastEmailOtpLoginAtMs &&
        (!lastStrongAuthAtMs || lastEmailOtpLoginAtMs > lastStrongAuthAtMs),
      ),
      walletId: parsed.value.walletId,
      ...(lastEmailOtpLoginAtMs ? { lastEmailOtpLoginAtMs } : {}),
      ...(lastStrongAuthAtMs ? { lastStrongAuthAtMs } : {}),
    };
  }

  async markEmailOtpStrongAuthSatisfied(
    input: MarkEmailOtpStrongAuthSatisfiedInput,
  ): Promise<MarkEmailOtpStrongAuthSatisfiedResult> {
    const parsed = normalizeEmailOtpStrongAuthInput(input);
    if (!parsed.ok) return parsed.result;

    const enrollment = await this.emailOtpEnrollments.readEnrollment(parsed.value.walletId);
    if (!enrollment) return { ok: true, walletId: parsed.value.walletId };
    const nowMs = Date.now();
    await this.emailOtpEnrollments.putAuthStateForEnrollment(enrollment, {
      lastStrongAuthAtMs: nowMs,
    });
    return { ok: true, walletId: parsed.value.walletId, lastStrongAuthAtMs: nowMs };
  }

  async getEmailOtpRecoveryCodeStatus(
    input: GetEmailOtpRecoveryCodeStatusInput,
  ): Promise<GetEmailOtpRecoveryCodeStatusResult> {
    try {
      const parsed = normalizeRecoveryCodeStatusInput(input);
      if (!parsed.ok) return parsed.result;

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId: parsed.value.walletId,
        orgId: parsed.value.orgId,
        providerUserId: parsed.value.userId,
      });
      if (!enrollment.ok) {
        if (enrollment.code === 'not_found') {
          return emailOtpRecoveryNotEnrolledStatus(parsed.value.walletId);
        }
        return enrollment;
      }

      const records = await this.emailOtpRecoveryEscrows.listForEnrollment(enrollment.enrollment);
      const summary = summarizeEmailOtpRecoveryCodes(records);
      return {
        ok: true,
        status:
          summary.activeRecoveryCodeCount === EMAIL_OTP_RECOVERY_KEY_COUNT ? 'ready' : 'incomplete',
        walletId: parsed.value.walletId,
        enrollmentId: enrollment.enrollment.enrollmentId,
        enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
        expectedRecoveryCodeCount: EMAIL_OTP_RECOVERY_KEY_COUNT,
        activeRecoveryCodeCount: summary.activeRecoveryCodeCount,
        consumedRecoveryCodeCount: summary.consumedRecoveryCodeCount,
        revokedRecoveryCodeCount: summary.revokedRecoveryCodeCount,
        totalRecoveryCodeCount: records.length,
        issuedAtMs: summary.issuedAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to read Email OTP recovery-code status',
      };
    }
  }

  async verifyEmailOtpDeviceRecoveryChallenge(
    input: VerifyEmailOtpDeviceRecoveryChallengeInput,
  ): Promise<VerifyEmailOtpDeviceRecoveryChallengeResult> {
    const verified = await this.challengeVerifier.verifyExisting({
      ...input,
      action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    if (!verified.ok) return verified;

    const activeRecoveryWrappedEnrollmentEscrows = await this.listActiveRecoveryEscrows(
      verified.enrollment,
    );
    if (activeRecoveryWrappedEnrollmentEscrows.length <= 0) {
      return recoveryWrappedEscrowsMissing();
    }

    const issuedAtMs = Date.now();
    const recoveryConsumeGrantExpiresAtMs = issuedAtMs + this.grantTtlMs;
    const recoveryConsumeGrant = secureRandomBase64Url(24, 'email otp device recovery grants');
    await this.emailOtpGrants.put(
      emailOtpGrantRecord({
        grantToken: recoveryConsumeGrant,
        userId: verified.userId,
        walletId: verified.walletId,
        orgId: verified.orgId,
        challengeId: verified.challengeId,
        sessionHash: verified.sessionHash,
        appSessionVersion: verified.appSessionVersion,
        action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
        issuedAtMs,
        expiresAtMs: recoveryConsumeGrantExpiresAtMs,
      }),
    );

    return {
      ok: true,
      challengeId: verified.challengeId,
      otpChannel: verified.otpChannel,
      recoveryConsumeGrant,
      recoveryConsumeGrantExpiresAtMs,
      recoveryWrappedEnrollmentEscrows: activeRecoveryWrappedEnrollmentEscrows.map(
        redactEmailOtpRecoveryChallengeEscrow,
      ),
      enrollment: {
        walletId: verified.enrollment.walletId,
        providerUserId: verified.enrollment.providerUserId,
        orgId: verified.enrollment.orgId,
        enrollmentId: verified.enrollment.enrollmentId,
        enrollmentVersion: verified.enrollment.enrollmentVersion,
        enrollmentSealKeyVersion: verified.enrollment.enrollmentSealKeyVersion,
        signingRootId: verified.enrollment.signingRootId,
        signingRootVersion: verified.enrollment.signingRootVersion,
        recoveryWrappedEnrollmentEscrowCount:
          verified.enrollment.recoveryWrappedEnrollmentEscrowCount,
      },
    };
  }

  async createEmailOtpUnlockChallenge(
    input: CreateEmailOtpUnlockChallengeInput,
  ): Promise<CreateEmailOtpUnlockChallengeResult> {
    try {
      const parsed = normalizeUnlockChallengeInput(input);
      if (!parsed.ok) return parsed.result;

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId: parsed.value.walletId,
        orgId: parsed.value.orgId,
      });
      if (!enrollment.ok) return enrollment;

      const nowMs = Date.now();
      const challengeId = secureRandomBase64Url(16, 'email otp unlock challenge ids');
      const challengeB64u = secureRandomBase64Url(32, 'email otp unlock challenges');
      const expiresAtMs = nowMs + parsed.value.ttlMs;
      await this.emailOtpChallenges.putUnlock(
        emailOtpUnlockChallengeRecord({
          challengeId,
          walletId: enrollment.enrollment.walletId,
          userId: enrollment.enrollment.providerUserId,
          orgId: enrollment.enrollment.orgId,
          challengeB64u,
          createdAtMs: nowMs,
          expiresAtMs,
        }),
      );
      return {
        ok: true,
        walletId: enrollment.enrollment.walletId,
        challengeId,
        challengeB64u,
        expiresAtMs,
        unlockKeyVersion: enrollment.enrollment.unlockKeyVersion,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create Email OTP unlock challenge',
      };
    }
  }

  async verifyEmailOtpUnlockProof(
    input: VerifyEmailOtpUnlockProofInput,
  ): Promise<VerifyEmailOtpUnlockProofResult> {
    try {
      const parsed = normalizeUnlockProofInput(input);
      if (!parsed.ok) return parsed.result;

      const challenge = await this.emailOtpChallenges.consumeUnlock(parsed.value.challengeId);
      if (!challenge || Date.now() > challenge.expiresAtMs) {
        return emailOtpUnlockProofRejected(
          'challenge_expired_or_invalid',
          'Email OTP unlock challenge expired or invalid',
        );
      }
      if (challenge.walletId !== parsed.value.walletId) {
        return emailOtpUnlockProofRejected(
          'challenge_binding_mismatch',
          'Email OTP unlock challenge is not valid for this walletId',
        );
      }

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId: parsed.value.walletId,
        orgId: parsed.value.orgId,
      });
      if (!enrollment.ok) {
        return emailOtpUnlockProofRejected(enrollment.code, enrollment.message);
      }
      if (
        challenge.userId !== enrollment.enrollment.providerUserId ||
        challenge.orgId !== enrollment.enrollment.orgId
      ) {
        return emailOtpUnlockProofRejected(
          'challenge_binding_mismatch',
          'Email OTP unlock challenge is not valid for this enrollment',
        );
      }

      const publicKey = decodeFixedBase64Url(parsed.value.publicKeyB64u, 33);
      if (!publicKey) {
        return emailOtpUnlockProofRejected(
          'invalid_body',
          'unlockProof.publicKey must decode to 33 bytes',
        );
      }
      try {
        await validateSecp256k1PublicKey33(publicKey);
      } catch {
        return emailOtpUnlockProofRejected(
          'invalid_body',
          'unlockProof.publicKey is not a valid secp256k1 public key',
        );
      }

      const signature = decodeFixedBase64Url(parsed.value.signatureB64u, 65);
      if (!signature) {
        return emailOtpUnlockProofRejected(
          'invalid_body',
          'unlockProof.signature must decode to 65 bytes',
        );
      }
      const enrolledPublicKey = decodeFixedBase64Url(
        enrollment.enrollment.clientUnlockPublicKeyB64u,
        33,
      );
      if (!enrolledPublicKey || !bytesEqual(enrolledPublicKey, publicKey)) {
        return emailOtpUnlockProofRejected(
          'invalid_unlock_proof',
          'unlockProof.publicKey does not match the enrolled clientUnlockPublicKeyB64u',
        );
      }
      const challengeDigest = decodeFixedBase64Url(challenge.challengeB64u, 32);
      if (!challengeDigest) {
        return emailOtpUnlockProofRejected(
          'internal',
          'Stored unlock challenge digest must decode to 32 bytes',
        );
      }
      try {
        await verifySecp256k1RecoverableSignatureAgainstPublicKey33(
          challengeDigest,
          signature,
          publicKey,
        );
      } catch {
        return emailOtpUnlockProofRejected(
          'invalid_unlock_proof',
          'unlockProof.signature did not verify against unlockProof.publicKey',
        );
      }

      await this.emailOtpEnrollments.putAuthStateForEnrollment(enrollment.enrollment, {
        lastEmailOtpLoginAtMs: Date.now(),
      });
      return {
        ok: true,
        verified: true,
        userId: enrollment.enrollment.walletId,
        walletId: enrollment.enrollment.walletId,
        providerUserId: enrollment.enrollment.providerUserId,
        orgId: enrollment.enrollment.orgId,
        unlockKeyVersion: enrollment.enrollment.unlockKeyVersion,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to verify Email OTP unlock proof',
      };
    }
  }

  async consumeEmailOtpGrant(
    input: ConsumeEmailOtpGrantInput,
  ): Promise<ConsumeEmailOtpGrantResult> {
    try {
      const parsed = normalizeGrantConsumptionInput(input);
      if (!parsed.ok) return parsed.result;

      const rateLimit = await this.emailOtpRateLimits.consume({
        scope: 'grant',
        userId: parsed.value.userId,
        walletId: parsed.value.walletId,
        orgId: parsed.value.orgId,
        clientIp: parsed.value.clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const record = await this.emailOtpGrants.consume(parsed.value.loginGrant);
      if (!record || Date.now() > record.expiresAtMs) return emailOtpGrantInvalidOrExpired();
      if (record.action !== WALLET_EMAIL_OTP_ACTIONS.unseal) {
        return emailOtpGrantInvalidOrExpired();
      }
      if (emailOtpGrantBindingMismatch(record, parsed.value)) {
        return emailOtpRecoveryGrantBindingMismatchResult();
      }

      return {
        ok: true,
        challengeId: record.challengeId,
        otpChannel: EMAIL_OTP_CHANNEL,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to consume Email OTP grant',
      };
    }
  }

  async consumeEmailOtpRecoveryKey(
    input: ConsumeEmailOtpRecoveryKeyInput,
  ): Promise<ConsumeEmailOtpRecoveryKeyResult> {
    try {
      const parsed = normalizeRecoveryKeyConsumptionInput(input);
      if (!parsed.ok) return parsed.result;

      const rateLimit = await this.emailOtpRateLimits.consume({
        scope: 'grant',
        userId: parsed.value.userId,
        walletId: parsed.value.walletId,
        orgId: parsed.value.orgId,
        clientIp: parsed.value.clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const grantRecord = await this.emailOtpGrants.consume(parsed.value.recoveryConsumeGrant);
      if (!grantRecord || Date.now() > grantRecord.expiresAtMs) {
        return emailOtpRecoveryConsumeGrantInvalidOrExpired();
      }
      if (grantRecord.action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery) {
        return emailOtpRecoveryConsumeGrantInvalidOrExpired();
      }
      if (emailOtpRecoveryGrantBindingMismatch(grantRecord, parsed.value)) {
        return emailOtpRecoveryGrantBindingMismatchResult();
      }

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId: parsed.value.walletId,
        orgId: parsed.value.orgId,
        providerUserId: parsed.value.userId,
      });
      if (!enrollment.ok) return enrollment;

      const recoveryRecord = await this.emailOtpRecoveryEscrows.read({
        walletId: parsed.value.walletId,
        recoveryKeyId: parsed.value.recoveryKeyId,
      });
      if (!recoveryRecord || recoveryRecord.recoveryKeyStatus !== 'active') {
        return recoveryKeyNotActive();
      }
      if (
        !emailOtpRecoveryEscrowMatchesEnrollment({
          escrow: recoveryRecord,
          enrollment: enrollment.enrollment,
        })
      ) {
        return {
          ok: false,
          code: 'recovery_key_binding_mismatch',
          message: 'Recovery key is not valid for this Email OTP enrollment',
        };
      }

      const consumedAtMs = Date.now();
      const consumedRecord = await this.emailOtpRecoveryEscrows.consume({
        record: recoveryRecord,
        consumedAtMs,
      });
      if (!consumedRecord) return recoveryKeyNotActive();
      await this.emailOtpEnrollments.putAuthStateForEnrollment(enrollment.enrollment, {
        lastStrongAuthAtMs: consumedAtMs,
      });
      const activeRecoveryWrappedEnrollmentEscrowCount =
        await this.countActiveRecoveryEscrowsForEnrollment(enrollment.enrollment);

      return {
        ok: true,
        walletId: parsed.value.walletId,
        recoveryKeyId: parsed.value.recoveryKeyId,
        consumedAtMs,
        activeRecoveryWrappedEnrollmentEscrowCount,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to consume Email OTP recovery key',
      };
    }
  }

  async rotateEmailOtpRecoveryKeys(
    input: RotateEmailOtpRecoveryKeysInput,
  ): Promise<RotateEmailOtpRecoveryKeysResult> {
    try {
      const parsed = normalizeRecoveryRotationInput(input);
      if (!parsed.ok) return parsed.result;

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId: parsed.value.walletId,
        orgId: parsed.value.orgId,
        providerUserId: parsed.value.userId,
      });
      if (!enrollment.ok) return enrollment;
      if (
        enrollment.enrollment.enrollmentId !== parsed.value.enrollmentId ||
        enrollment.enrollment.enrollmentSealKeyVersion !== parsed.value.enrollmentSealKeyVersion
      ) {
        return recoveryRotationBindingMismatch();
      }

      const authState = await this.emailOtpEnrollments.readAuthStateForEnrollment(
        enrollment.enrollment,
      );
      if (!authState.ok) return authState;
      const lastStrongAuthAtMs =
        typeof authState.state?.lastStrongAuthAtMs === 'number'
          ? authState.state.lastStrongAuthAtMs
          : 0;
      const issuedAtMs = Date.now();
      const freshAuthExpiresAtMs = lastStrongAuthAtMs + this.grantTtlMs;
      if (!lastStrongAuthAtMs || issuedAtMs > freshAuthExpiresAtMs) {
        return {
          ok: false,
          code: 'fresh_auth_required',
          message: 'Fresh account authentication is required to rotate recovery codes',
        };
      }

      const nextActiveRecords = await this.buildRotatedRecoveryEscrows({
        rawEscrows: parsed.value.rawEscrows,
        enrollment: enrollment.enrollment,
        issuedAtMs,
      });
      if (!nextActiveRecords.ok) return nextActiveRecords.result;

      const existingRecords = await this.emailOtpRecoveryEscrows.listForEnrollment(
        enrollment.enrollment,
      );
      const revokedRecords = revokedActiveRecoveryEscrows(existingRecords, issuedAtMs);
      await this.emailOtpRecoveryEscrows.putMany([...revokedRecords, ...nextActiveRecords.records]);
      const updatedRecords = await this.emailOtpRecoveryEscrows.listForEnrollment(
        enrollment.enrollment,
      );
      const activeRecoveryCodeCount = countActiveEmailOtpRecoveryEscrows(updatedRecords);
      if (activeRecoveryCodeCount !== EMAIL_OTP_RECOVERY_KEY_COUNT) {
        return {
          ok: false,
          code: 'internal',
          message: `Email OTP recovery-code rotation left ${activeRecoveryCodeCount} active codes; expected ${EMAIL_OTP_RECOVERY_KEY_COUNT}`,
        };
      }
      return {
        ok: true,
        walletId: parsed.value.walletId,
        enrollmentId: parsed.value.enrollmentId,
        enrollmentSealKeyVersion: parsed.value.enrollmentSealKeyVersion,
        activeRecoveryCodeCount,
        revokedRecoveryCodeCount: revokedRecords.length,
        totalRecoveryCodeCount: updatedRecords.length,
        issuedAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to rotate Email OTP recovery codes',
      };
    }
  }

  async recordEmailOtpRecoveryKeyAttemptFailure(
    input: RecordEmailOtpRecoveryKeyAttemptFailureInput,
  ): Promise<RecordEmailOtpRecoveryKeyAttemptFailureResult> {
    try {
      const parsed = normalizeRecoveryGrantInput(input, invalidRecoveryAttemptBody);
      if (!parsed.ok) return parsed.result;

      const grantRecord = await this.emailOtpGrants.read(parsed.value.recoveryConsumeGrant);
      if (!grantRecord || Date.now() > grantRecord.expiresAtMs) {
        if (grantRecord) await this.emailOtpGrants.delete(parsed.value.recoveryConsumeGrant);
        return emailOtpRecoveryConsumeGrantInvalidOrExpired();
      }
      if (grantRecord.action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery) {
        return emailOtpRecoveryConsumeGrantInvalidOrExpired();
      }
      if (emailOtpRecoveryGrantBindingMismatch(grantRecord, parsed.value)) {
        return emailOtpRecoveryGrantBindingMismatchResult();
      }

      const rateLimit = await this.emailOtpRateLimits.consume({
        scope: 'recoveryKeyAttempt',
        action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
        userId: parsed.value.userId,
        walletId: parsed.value.walletId,
        orgId: parsed.value.orgId,
        clientIp: parsed.value.clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId: parsed.value.walletId,
        orgId: parsed.value.orgId,
        providerUserId: parsed.value.userId,
      });
      if (!enrollment.ok) return enrollment;

      const activeRecoveryWrappedEnrollmentEscrowCount =
        await this.countActiveRecoveryEscrowsForEnrollment(enrollment.enrollment);
      if (activeRecoveryWrappedEnrollmentEscrowCount <= 0) {
        return recoveryWrappedEscrowsMissing();
      }

      return {
        ok: true,
        walletId: parsed.value.walletId,
        recordedAtMs: Date.now(),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to record Email OTP recovery-key failure',
      };
    }
  }

  private async listActiveRecoveryEscrows(
    enrollment: EmailOtpWalletEnrollmentRecord,
  ): Promise<
    Extract<
      EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
      { readonly recoveryKeyStatus: 'active' }
    >[]
  > {
    const records = await this.emailOtpRecoveryEscrows.listForEnrollment(enrollment);
    const activeRecords: Extract<
      EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
      { readonly recoveryKeyStatus: 'active' }
    >[] = [];
    for (const record of records) {
      if (activeEmailOtpRecoveryEscrow(record)) activeRecords.push(record);
    }
    return activeRecords;
  }

  private async countActiveRecoveryEscrowsForEnrollment(
    enrollment: EmailOtpWalletEnrollmentRecord,
  ): Promise<number> {
    const records = await this.listActiveRecoveryEscrows(enrollment);
    return records.length;
  }

  private async buildRotatedRecoveryEscrows(input: {
    readonly rawEscrows: readonly unknown[];
    readonly enrollment: EmailOtpWalletEnrollmentRecord;
    readonly issuedAtMs: number;
  }): Promise<
    | {
        readonly ok: true;
        readonly records: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[];
      }
    | {
        readonly ok: false;
        readonly result: RotateEmailOtpRecoveryKeysResult;
      }
  > {
    const recoveryKeyIds = new Set<string>();
    const nonceB64us = new Set<string>();
    const records: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] = [];
    for (const rawEscrow of input.rawEscrows) {
      const nextRecord = await activeEmailOtpRecoveryRotationEscrowRecord({
        raw: rawEscrow,
        enrollment: input.enrollment,
        issuedAtMs: input.issuedAtMs,
        recoveryKeyIds,
        nonceB64us,
        sha256Bytes: this.sha256Bytes,
      });
      if (!nextRecord.ok) return nextRecord;
      records.push(nextRecord.record);
    }
    return { ok: true, records };
  }
}

function normalizeRecoveryCodeStatusInput(
  input: GetEmailOtpRecoveryCodeStatusInput,
): ParseResult<NormalizedRecoveryCodeStatusInput, GetEmailOtpRecoveryCodeStatusResult> {
  const userId = toOptionalTrimmedString(input.userId);
  const walletId = parseD1BoundaryWalletIdResult(input.walletId);
  const orgId = toOptionalTrimmedString(input.orgId);
  if (!userId) return invalidRecoveryCodeStatusBody('Missing userId');
  if (!walletId.ok) {
    return invalidRecoveryCodeStatusBody(
      walletId.code === 'missing' ? 'Missing walletId' : 'Invalid walletId',
    );
  }
  if (!orgId) return invalidRecoveryCodeStatusBody('Missing orgId');
  return { ok: true, value: { userId, walletId: walletId.value, orgId } };
}

function normalizeUnlockChallengeInput(
  input: CreateEmailOtpUnlockChallengeInput,
): ParseResult<NormalizedUnlockChallengeInput, CreateEmailOtpUnlockChallengeResult> {
  const walletId = parseD1BoundaryWalletIdResult(input.walletId);
  const orgId = toOptionalTrimmedString(input.orgId);
  if (!walletId.ok) {
    return invalidUnlockChallengeBody(
      walletId.code === 'missing' ? 'Missing walletId' : 'Invalid walletId',
    );
  }
  if (!orgId) return invalidUnlockChallengeBody('Missing orgId');
  return {
    ok: true,
    value: {
      walletId: walletId.value,
      orgId,
      ttlMs: clampedEmailOtpUnlockTtlMs(input.ttlMs ?? input.ttl_ms),
    },
  };
}

function normalizeUnlockProofInput(
  input: VerifyEmailOtpUnlockProofInput,
): ParseResult<NormalizedUnlockProofInput, VerifyEmailOtpUnlockProofResult> {
  const walletId = parseD1BoundaryWalletIdResult(input.walletId);
  const orgId = toOptionalTrimmedString(input.orgId);
  const challengeId = toOptionalTrimmedString(input.challengeId);
  const unlockProof = isRecordValue(input.unlockProof) ? input.unlockProof : null;
  if (!walletId.ok) {
    return invalidUnlockProofBody(
      walletId.code === 'missing' ? 'Missing walletId' : 'Invalid walletId',
    );
  }
  if (!orgId) return invalidUnlockProofBody('Missing orgId');
  if (!challengeId) return invalidUnlockProofBody('Missing challengeId');
  if (!unlockProof) return invalidUnlockProofBody('unlockProof is required');

  const publicKeyB64u = toOptionalTrimmedString(unlockProof.publicKey);
  const signatureB64u = toOptionalTrimmedString(unlockProof.signature);
  if (!publicKeyB64u) return invalidUnlockProofBody('unlockProof.publicKey is required');
  if (!signatureB64u) return invalidUnlockProofBody('unlockProof.signature is required');
  return {
    ok: true,
    value: { walletId: walletId.value, orgId, challengeId, publicKeyB64u, signatureB64u },
  };
}

function normalizeGrantConsumptionInput(
  input: ConsumeEmailOtpGrantInput,
): ParseResult<NormalizedGrantConsumptionInput, ConsumeEmailOtpGrantResult> {
  const loginGrant = toOptionalTrimmedString(input.loginGrant);
  const userId = toOptionalTrimmedString(input.userId);
  const walletId = parseD1BoundaryWalletIdResult(input.walletId);
  const orgId = toOptionalTrimmedString(input.orgId);
  const otpChannel = toOptionalTrimmedString(input.otpChannel);
  const clientIp = toOptionalTrimmedString(input.clientIp);
  if (!loginGrant) return invalidGrantConsumptionBody('Missing loginGrant');
  if (!userId) return invalidGrantConsumptionBody('Missing userId');
  if (!walletId.ok) {
    return invalidGrantConsumptionBody(
      walletId.code === 'missing' ? 'Missing walletId' : 'Invalid walletId',
    );
  }
  if (!orgId) return invalidGrantConsumptionBody('Missing orgId');
  if (otpChannel !== EMAIL_OTP_CHANNEL) {
    return invalidGrantConsumptionBody('otpChannel must be email_otp');
  }
  return {
    ok: true,
    value: {
      loginGrant,
      userId,
      walletId: walletId.value,
      orgId,
      clientIp,
    },
  };
}

function normalizeRecoveryKeyConsumptionInput(
  input: ConsumeEmailOtpRecoveryKeyInput,
): ParseResult<NormalizedRecoveryKeyConsumptionInput, ConsumeEmailOtpRecoveryKeyResult> {
  const grant = normalizeRecoveryGrantInput(input, invalidRecoveryKeyGrantBody);
  if (!grant.ok) return grant;
  const recoveryKeyId = toOptionalTrimmedString(input.recoveryKeyId);
  if (!recoveryKeyId) return invalidRecoveryKeyConsumptionBody('Missing recoveryKeyId');
  return { ok: true, value: { ...grant.value, recoveryKeyId } };
}

function normalizeRecoveryGrantInput<TResult>(
  input: RecordEmailOtpRecoveryKeyAttemptFailureInput | ConsumeEmailOtpRecoveryKeyInput,
  invalidBody: (message: string) => ParseResult<NormalizedRecoveryGrantInput, TResult>,
): ParseResult<NormalizedRecoveryGrantInput, TResult> {
  const recoveryConsumeGrant = toOptionalTrimmedString(input.recoveryConsumeGrant);
  const userId = toOptionalTrimmedString(input.userId);
  const walletId = parseD1BoundaryWalletIdResult(input.walletId);
  const orgId = toOptionalTrimmedString(input.orgId);
  const clientIp = toOptionalTrimmedString(input.clientIp);
  if (!recoveryConsumeGrant) return invalidBody('Missing recoveryConsumeGrant');
  if (!userId) return invalidBody('Missing userId');
  if (!walletId.ok) {
    return invalidBody(walletId.code === 'missing' ? 'Missing walletId' : 'Invalid walletId');
  }
  if (!orgId) return invalidBody('Missing orgId');
  return {
    ok: true,
    value: {
      recoveryConsumeGrant,
      userId,
      walletId: walletId.value,
      orgId,
      clientIp,
    },
  };
}

function normalizeRecoveryRotationInput(
  input: RotateEmailOtpRecoveryKeysInput,
): ParseResult<NormalizedRecoveryRotationInput, RotateEmailOtpRecoveryKeysResult> {
  const userId = toOptionalTrimmedString(input.userId);
  const walletId = parseD1BoundaryWalletIdResult(input.walletId);
  const orgId = toOptionalTrimmedString(input.orgId);
  const enrollmentId = toOptionalTrimmedString(input.enrollmentId);
  const enrollmentSealKeyVersion = toOptionalTrimmedString(input.enrollmentSealKeyVersion);
  if (!userId) return { ok: false, result: invalidRecoveryRotationBody('Missing userId') };
  if (!walletId.ok) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody(
        walletId.code === 'missing' ? 'Missing walletId' : 'Invalid walletId',
      ),
    };
  }
  if (!orgId) return { ok: false, result: invalidRecoveryRotationBody('Missing orgId') };
  if (!enrollmentId) {
    return { ok: false, result: invalidRecoveryRotationBody('Missing enrollmentId') };
  }
  if (!enrollmentSealKeyVersion) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody('Missing enrollmentSealKeyVersion'),
    };
  }
  const rawEscrows = Array.isArray(input.recoveryWrappedEnrollmentEscrows)
    ? input.recoveryWrappedEnrollmentEscrows
    : [];
  if (rawEscrows.length !== EMAIL_OTP_RECOVERY_KEY_COUNT) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody(
        `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
      ),
    };
  }
  return {
    ok: true,
    value: {
      userId,
      walletId: walletId.value,
      orgId,
      enrollmentId,
      enrollmentSealKeyVersion,
      rawEscrows,
    },
  };
}

function summarizeEmailOtpRecoveryCodes(
  records: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[],
): {
  readonly activeRecoveryCodeCount: number;
  readonly consumedRecoveryCodeCount: number;
  readonly revokedRecoveryCodeCount: number;
  readonly issuedAtMs: number | null;
} {
  let activeRecoveryCodeCount = 0;
  let consumedRecoveryCodeCount = 0;
  let revokedRecoveryCodeCount = 0;
  let issuedAtMs: number | null = null;
  for (const record of records) {
    const recoveryKeyStatus = record.recoveryKeyStatus;
    switch (recoveryKeyStatus) {
      case 'active':
        activeRecoveryCodeCount += 1;
        break;
      case 'consumed':
        consumedRecoveryCodeCount += 1;
        break;
      case 'revoked':
        revokedRecoveryCodeCount += 1;
        break;
      default:
        assertNeverRecoveryKeyStatus(recoveryKeyStatus);
    }
    issuedAtMs = issuedAtMs === null ? record.issuedAtMs : Math.min(issuedAtMs, record.issuedAtMs);
  }
  return {
    activeRecoveryCodeCount,
    consumedRecoveryCodeCount,
    revokedRecoveryCodeCount,
    issuedAtMs,
  };
}

function revokedActiveRecoveryEscrows(
  records: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[],
  revokedAtMs: number,
): EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] {
  const revokedRecords: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] = [];
  for (const record of records) {
    if (!activeEmailOtpRecoveryEscrow(record)) continue;
    revokedRecords.push(revokedEmailOtpRecoveryEscrowRecord({ record, revokedAtMs }));
  }
  return revokedRecords;
}

function emailOtpGrantBindingMismatch(
  record: {
    readonly userId: string;
    readonly walletId: string;
    readonly otpChannel: typeof EMAIL_OTP_CHANNEL;
    readonly orgId?: string;
  },
  input: NormalizedGrantConsumptionInput,
): boolean {
  return (
    record.userId !== input.userId ||
    record.walletId !== input.walletId ||
    record.otpChannel !== EMAIL_OTP_CHANNEL ||
    record.orgId !== input.orgId
  );
}

function emailOtpRecoveryGrantBindingMismatch(
  record: {
    readonly userId: string;
    readonly walletId: string;
    readonly otpChannel: typeof EMAIL_OTP_CHANNEL;
    readonly orgId?: string;
  },
  input: NormalizedRecoveryGrantInput,
): boolean {
  return (
    record.userId !== input.userId ||
    record.walletId !== input.walletId ||
    record.otpChannel !== EMAIL_OTP_CHANNEL ||
    record.orgId !== input.orgId
  );
}

function invalidRecoveryCodeStatusBody(
  message: string,
): ParseResult<NormalizedRecoveryCodeStatusInput, GetEmailOtpRecoveryCodeStatusResult> {
  return { ok: false, result: { ok: false, code: 'invalid_body', message } };
}

function invalidUnlockChallengeBody(
  message: string,
): ParseResult<NormalizedUnlockChallengeInput, CreateEmailOtpUnlockChallengeResult> {
  return { ok: false, result: { ok: false, code: 'invalid_body', message } };
}

function invalidUnlockProofBody(
  message: string,
): ParseResult<NormalizedUnlockProofInput, VerifyEmailOtpUnlockProofResult> {
  return { ok: false, result: { ok: false, verified: false, code: 'invalid_body', message } };
}

function invalidGrantConsumptionBody(
  message: string,
): ParseResult<NormalizedGrantConsumptionInput, ConsumeEmailOtpGrantResult> {
  return { ok: false, result: { ok: false, code: 'invalid_body', message } };
}

function invalidRecoveryAttemptBody(
  message: string,
): ParseResult<NormalizedRecoveryGrantInput, RecordEmailOtpRecoveryKeyAttemptFailureResult> {
  return { ok: false, result: { ok: false, code: 'invalid_body', message } };
}

function invalidRecoveryKeyGrantBody(
  message: string,
): ParseResult<NormalizedRecoveryGrantInput, ConsumeEmailOtpRecoveryKeyResult> {
  return { ok: false, result: { ok: false, code: 'invalid_body', message } };
}

function invalidRecoveryKeyConsumptionBody(
  message: string,
): ParseResult<NormalizedRecoveryKeyConsumptionInput, ConsumeEmailOtpRecoveryKeyResult> {
  return { ok: false, result: { ok: false, code: 'invalid_body', message } };
}

function emailOtpRecoveryNotEnrolledStatus(walletId: string): GetEmailOtpRecoveryCodeStatusResult {
  return {
    ok: true,
    status: 'not_enrolled',
    walletId,
    enrollmentId: '',
    enrollmentSealKeyVersion: '',
    expectedRecoveryCodeCount: EMAIL_OTP_RECOVERY_KEY_COUNT,
    activeRecoveryCodeCount: 0,
    consumedRecoveryCodeCount: 0,
    revokedRecoveryCodeCount: 0,
    totalRecoveryCodeCount: 0,
    issuedAtMs: null,
  };
}

function recoveryWrappedEscrowsMissing(): {
  readonly ok: false;
  readonly code: 'recovery_wrapped_escrows_missing';
  readonly message: string;
} {
  return {
    ok: false,
    code: 'recovery_wrapped_escrows_missing',
    message: 'No active Email OTP recovery-wrapped enrollment escrows are available',
  };
}

function emailOtpGrantInvalidOrExpired(): ConsumeEmailOtpGrantResult {
  return {
    ok: false,
    code: 'login_grant_invalid_or_expired',
    message: 'Login grant is invalid or expired',
  };
}

function emailOtpRecoveryConsumeGrantInvalidOrExpired(): {
  readonly ok: false;
  readonly code: 'recovery_consume_grant_invalid_or_expired';
  readonly message: string;
} {
  return {
    ok: false,
    code: 'recovery_consume_grant_invalid_or_expired',
    message: 'Recovery consume grant is invalid or expired',
  };
}

function emailOtpRecoveryGrantBindingMismatchResult(): {
  readonly ok: false;
  readonly code: 'recovery_grant_binding_mismatch';
  readonly message: string;
} {
  return {
    ok: false,
    code: 'recovery_grant_binding_mismatch',
    message: 'Recovery grant is not valid for the current Email OTP authority',
  };
}

function recoveryKeyNotActive(): {
  readonly ok: false;
  readonly code: 'recovery_key_not_active';
  readonly message: string;
} {
  return {
    ok: false,
    code: 'recovery_key_not_active',
    message: 'Recovery key is not active',
  };
}

function emailOtpUnlockProofRejected(
  code: string,
  message: string,
): VerifyEmailOtpUnlockProofResult {
  return {
    ok: false,
    verified: false,
    code,
    message,
  };
}

function assertNeverRecoveryKeyStatus(value: never): never {
  throw new Error(`Unhandled Email OTP recovery key status: ${String(value)}`);
}
