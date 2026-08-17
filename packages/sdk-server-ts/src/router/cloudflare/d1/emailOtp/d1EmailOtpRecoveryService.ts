import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import type { EmailOtpWalletEnrollmentRecord } from '../../../../core/EmailOtpStores';
import {
  validateSecp256k1PublicKey33,
  verifySecp256k1RecoverableSignatureAgainstPublicKey33,
} from '../../../../core/ThresholdService/evmCryptoWasm';
import type {
  RouterApiEmailOtpRouteService,
  RouterApiWalletUnlockService,
} from '../../../framework/authServicePort';
import { CloudflareD1EmailOtpChallengeStore } from './d1EmailOtpChallengeStore';
import { CloudflareD1EmailOtpChallengeVerifier } from './d1EmailOtpChallengeVerifier';
import { CloudflareD1EmailOtpEnrollmentStore } from './d1EmailOtpEnrollmentStore';
import { CloudflareD1EmailOtpGrantStore } from './d1EmailOtpGrantStore';
import { CloudflareD1EmailOtpRateLimitStore } from './d1EmailOtpRateLimitStore';
import { isRecordValue, parseD1BoundaryWalletIdResult } from '../auth/d1RouterApiAuthBoundary';
import {
  bytesEqual,
  clampedEmailOtpUnlockTtlMs,
  decodeFixedBase64Url,
  emailOtpGrantRecord,
  emailOtpUnlockChallengeRecord,
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
type NormalizedEmailOtpEnrollmentReadInput = {
  readonly walletId: string;
  readonly orgId: string;
};

type NormalizedActiveEmailOtpEnrollmentReadInput = NormalizedEmailOtpEnrollmentReadInput & {
  readonly providerUserId: string | undefined;
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
  input: MarkEmailOtpStrongAuthSatisfiedInput,
): ParseResult<{ readonly walletId: string }, InvalidBodyResult> {
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
  private readonly grantTtlMs: number;

  constructor(input: {
    readonly challengeVerifier: CloudflareD1EmailOtpChallengeVerifier;
    readonly emailOtpChallenges: CloudflareD1EmailOtpChallengeStore;
    readonly emailOtpEnrollments: CloudflareD1EmailOtpEnrollmentStore;
    readonly emailOtpGrants: CloudflareD1EmailOtpGrantStore;
    readonly emailOtpRateLimits: CloudflareD1EmailOtpRateLimitStore;
    readonly grantTtlMs: number;
  }) {
    this.challengeVerifier = input.challengeVerifier;
    this.emailOtpChallenges = input.emailOtpChallenges;
    this.emailOtpEnrollments = input.emailOtpEnrollments;
    this.emailOtpGrants = input.emailOtpGrants;
    this.emailOtpRateLimits = input.emailOtpRateLimits;
    this.grantTtlMs = input.grantTtlMs;
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
    const walletId = input.subject.walletId;
    const enrollment = await this.emailOtpEnrollments.readEnrollment(walletId);
    if (!enrollment) return { ok: true, required: false, walletId };
    const authState = await this.emailOtpEnrollments.readAuthStateForEnrollment(enrollment);
    if (!authState.ok) return authState;
    const state = authState.state;
    if (!state) return { ok: true, required: false, walletId };
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
      walletId,
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
        enrollmentId: enrollment.enrollment.enrollmentId,
        enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
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
        return emailOtpGrantInvalidOrExpired();
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

  async consumeEmailOtpWalletRecoveryBootstrap(
    input: Parameters<
      RouterApiEmailOtpRouteService['consumeEmailOtpWalletRecoveryBootstrap']
    >[0],
  ): Promise<
    Awaited<ReturnType<RouterApiEmailOtpRouteService['consumeEmailOtpWalletRecoveryBootstrap']>>
  > {
    const recoveryBootstrapGrant = toOptionalTrimmedString(input.recoveryBootstrapGrant);
    const walletId = toOptionalTrimmedString(input.walletId);
    const orgId = toOptionalTrimmedString(input.orgId);
    if (!recoveryBootstrapGrant || !walletId || !orgId) {
      return { ok: false, code: 'invalid_body', message: 'recovery bootstrap grant is incomplete' };
    }
    const record = await this.emailOtpGrants.consume(recoveryBootstrapGrant);
    if (
      !record ||
      record.action !== WALLET_EMAIL_OTP_ACTIONS.recoveryBootstrap ||
      record.walletId !== walletId ||
      record.orgId !== orgId ||
      Date.now() > record.expiresAtMs
    ) {
      return {
        ok: false,
        code: 'recovery_bootstrap_grant_invalid_or_expired',
        message: 'Recovery bootstrap grant is invalid or expired',
      };
    }
    return {
      ok: true,
      walletId: record.walletId,
      providerUserId: record.userId,
      orgId: record.orgId || orgId,
      challengeId: record.challengeId,
      grantExpiresAtMs: record.expiresAtMs,
    };
  }
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
  const walletId = parseD1BoundaryWalletIdResult(input.subject.walletId);
  const userId =
    input.subject.kind === 'authorization_session'
      ? input.subject.principalId
      : input.subject.providerSubject;
  const orgId =
    input.subject.kind === 'authorization_session'
      ? input.subject.tenantId
      : input.subject.orgId;
  const otpChannel = toOptionalTrimmedString(input.otpChannel);
  const clientIp = toOptionalTrimmedString(input.clientIp);
  if (!loginGrant) return invalidGrantConsumptionBody('Missing loginGrant');
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

function emailOtpGrantInvalidOrExpired(): ConsumeEmailOtpGrantResult {
  return {
    ok: false,
    code: 'grant_invalid_or_expired',
    message: 'Email OTP grant is invalid or expired',
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
