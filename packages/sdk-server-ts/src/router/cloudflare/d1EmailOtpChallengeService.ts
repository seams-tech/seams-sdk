import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import type {
  RouterApiEmailOtpRouteService,
} from '../authServicePort';
import { emailOtpGrantRecord, maskEmail, parseEmailOtpLoginOperation } from './d1EmailOtpRecords';
import type { CloudflareD1EmailOtpChallengeIssuer } from './d1EmailOtpChallengeIssuer';
import type { CloudflareD1EmailOtpChallengeStore } from './d1EmailOtpChallengeStore';
import type { CloudflareD1EmailOtpChallengeVerifier } from './d1EmailOtpChallengeVerifier';
import type { CloudflareD1EmailOtpGrantStore } from './d1EmailOtpGrantStore';
import type { CloudflareD1EmailOtpRegistrationEnrollmentFinalizer } from './d1EmailOtpRegistrationEnrollmentFinalizer';
import type { CloudflareD1GoogleEmailOtpRegistrationAttemptStore } from './d1GoogleEmailOtpRegistrationAttemptStore';

type CreateEmailOtpChallengeInput =
  Parameters<RouterApiEmailOtpRouteService['createEmailOtpChallenge']>[0];
type CreateEmailOtpChallengeResult = Awaited<
  ReturnType<RouterApiEmailOtpRouteService['createEmailOtpChallenge']>
>;
type CreateEmailOtpEnrollmentChallengeInput =
  Parameters<RouterApiEmailOtpRouteService['createEmailOtpEnrollmentChallenge']>[0];
type CreateEmailOtpEnrollmentChallengeResult =
  Awaited<ReturnType<RouterApiEmailOtpRouteService['createEmailOtpEnrollmentChallenge']>>;
type CreateEmailOtpDeviceRecoveryChallengeInput =
  Parameters<RouterApiEmailOtpRouteService['createEmailOtpDeviceRecoveryChallenge']>[0];
type CreateEmailOtpDeviceRecoveryChallengeResult =
  Awaited<ReturnType<RouterApiEmailOtpRouteService['createEmailOtpDeviceRecoveryChallenge']>>;
type VerifyEmailOtpChallengeInput =
  Parameters<RouterApiEmailOtpRouteService['verifyEmailOtpChallenge']>[0];
type VerifyEmailOtpChallengeResult = Awaited<
  ReturnType<RouterApiEmailOtpRouteService['verifyEmailOtpChallenge']>
>;
type VerifyEmailOtpEnrollmentInput =
  Parameters<RouterApiEmailOtpRouteService['verifyEmailOtpEnrollment']>[0];
type VerifyEmailOtpEnrollmentResult = Awaited<
  ReturnType<RouterApiEmailOtpRouteService['verifyEmailOtpEnrollment']>
>;
type ReadEmailOtpOutboxEntryInput =
  Parameters<RouterApiEmailOtpRouteService['readEmailOtpOutboxEntry']>[0];
type ReadEmailOtpOutboxEntryResult = Awaited<
  ReturnType<RouterApiEmailOtpRouteService['readEmailOtpOutboxEntry']>
>;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

export class CloudflareD1EmailOtpChallengeService {
  private readonly challenges: CloudflareD1EmailOtpChallengeStore;
  private readonly devOutboxEnabled: boolean;
  private readonly finalizer: CloudflareD1EmailOtpRegistrationEnrollmentFinalizer;
  private readonly grantTtlMs: number;
  private readonly grants: CloudflareD1EmailOtpGrantStore;
  private readonly issuer: CloudflareD1EmailOtpChallengeIssuer;
  private readonly registrationAttempts: CloudflareD1GoogleEmailOtpRegistrationAttemptStore;
  private readonly verifier: CloudflareD1EmailOtpChallengeVerifier;

  constructor(input: {
    readonly challenges: CloudflareD1EmailOtpChallengeStore;
    readonly devOutboxEnabled: boolean;
    readonly finalizer: CloudflareD1EmailOtpRegistrationEnrollmentFinalizer;
    readonly grantTtlMs: number;
    readonly grants: CloudflareD1EmailOtpGrantStore;
    readonly issuer: CloudflareD1EmailOtpChallengeIssuer;
    readonly registrationAttempts: CloudflareD1GoogleEmailOtpRegistrationAttemptStore;
    readonly verifier: CloudflareD1EmailOtpChallengeVerifier;
  }) {
    this.challenges = input.challenges;
    this.devOutboxEnabled = input.devOutboxEnabled;
    this.finalizer = input.finalizer;
    this.grantTtlMs = input.grantTtlMs;
    this.grants = input.grants;
    this.issuer = input.issuer;
    this.registrationAttempts = input.registrationAttempts;
    this.verifier = input.verifier;
  }

  async createEmailOtpChallenge(
    input: CreateEmailOtpChallengeInput,
  ): Promise<CreateEmailOtpChallengeResult> {
    const operation = parseEmailOtpLoginOperation(input.operation);
    const result = await this.issuer.create({
      userId: input.userId,
      walletId: input.walletId,
      orgId: input.orgId,
      email: input.email,
      otpChannel: input.otpChannel,
      sessionHash: input.sessionHash,
      appSessionVersion: input.appSessionVersion,
      clientIp: input.clientIp,
      reuseActiveChallenge: input.reuseActiveChallenge,
      action: WALLET_EMAIL_OTP_ACTIONS.login,
      operation,
    });
    if (!result.ok) return result;
    return {
      ok: true,
      challenge: {
        challengeId: result.challenge.challengeId,
        issuedAtMs: result.challenge.issuedAtMs,
        expiresAtMs: result.challenge.expiresAtMs,
        userId: result.challenge.challengeSubjectId,
        walletId: result.challenge.walletId,
        orgId: result.challenge.orgId,
        otpChannel: result.challenge.otpChannel,
        sessionHash: result.challenge.sessionHash,
        appSessionVersion: result.challenge.appSessionVersion,
        action: WALLET_EMAIL_OTP_ACTIONS.login,
        operation,
      },
      delivery: result.delivery,
    };
  }

  async createEmailOtpEnrollmentChallenge(
    input: CreateEmailOtpEnrollmentChallengeInput,
  ): Promise<CreateEmailOtpEnrollmentChallengeResult> {
    const result = await this.issuer.create({
      userId: input.userId,
      walletId: input.walletId,
      orgId: input.orgId,
      email: input.email,
      otpChannel: input.otpChannel,
      sessionHash: input.sessionHash,
      appSessionVersion: input.appSessionVersion,
      clientIp: input.clientIp,
      action: WALLET_EMAIL_OTP_ACTIONS.registration,
      operation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
    });
    if (!result.ok) return result;
    return {
      ok: true,
      challenge: {
        challengeId: result.challenge.challengeId,
        issuedAtMs: result.challenge.issuedAtMs,
        expiresAtMs: result.challenge.expiresAtMs,
        userId: result.challenge.challengeSubjectId,
        walletId: result.challenge.walletId,
        orgId: result.challenge.orgId,
        otpChannel: result.challenge.otpChannel,
        sessionHash: result.challenge.sessionHash,
        appSessionVersion: result.challenge.appSessionVersion,
        action: WALLET_EMAIL_OTP_ACTIONS.registration,
        operation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
      },
      delivery: {
        status: result.delivery.status,
        mode: result.delivery.mode,
        emailHint: result.delivery.emailHint,
      },
    };
  }

  async createEmailOtpDeviceRecoveryChallenge(
    input: CreateEmailOtpDeviceRecoveryChallengeInput,
  ): Promise<CreateEmailOtpDeviceRecoveryChallengeResult> {
    const result = await this.issuer.create({
      userId: input.userId,
      walletId: input.walletId,
      orgId: input.orgId,
      email: input.email,
      otpChannel: input.otpChannel,
      sessionHash: input.sessionHash,
      appSessionVersion: input.appSessionVersion,
      clientIp: input.clientIp,
      action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    if (!result.ok) return result;
    return {
      ok: true,
      challenge: {
        challengeId: result.challenge.challengeId,
        issuedAtMs: result.challenge.issuedAtMs,
        expiresAtMs: result.challenge.expiresAtMs,
        userId: result.challenge.challengeSubjectId,
        walletId: result.challenge.walletId,
        orgId: result.challenge.orgId,
        otpChannel: result.challenge.otpChannel,
        sessionHash: result.challenge.sessionHash,
        appSessionVersion: result.challenge.appSessionVersion,
        action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
        operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
      },
      delivery: result.delivery,
    };
  }

  async verifyEmailOtpEnrollment(
    input: VerifyEmailOtpEnrollmentInput,
  ): Promise<VerifyEmailOtpEnrollmentResult> {
    try {
      const providerSubject = toOptionalTrimmedString(input.providerSubject);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const challengeId = toOptionalTrimmedString(input.challengeId);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
      const registrationAttemptId = toOptionalTrimmedString(
        input.googleEmailOtpRegistrationAttemptId,
      );
      if (!providerSubject) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP registration requires providerSubject',
        };
      }
      if (!walletId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP registration requires walletId',
        };
      }
      if (!orgId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP registration requires orgId',
        };
      }
      if (!challengeId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP registration requires challengeId',
        };
      }
      if (!appSessionVersion) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP registration requires appSessionVersion',
        };
      }

      const proofEmail = await this.resolveRegistrationProofEmail({
        explicitProofEmail: input.proofEmail,
        providerSubject,
        registrationAttemptId,
        walletId,
      });
      if (!proofEmail.ok) return proofEmail;

      const verified = await this.verifier.verifyRegistration({
        providerSubject,
        walletId,
        orgId,
        challengeId,
        otpCode: input.otpCode,
        otpChannel: input.otpChannel,
        sessionHash: input.sessionHash,
        appSessionVersion,
        proofEmail: proofEmail.email,
        clientIp: input.clientIp,
      });
      if (!verified.ok) return verified;

      const verifiedEmail = toOptionalTrimmedString(verified.email)?.toLowerCase() || '';
      if (!verifiedEmail) {
        return {
          ok: false,
          code: 'internal',
          message: 'Email OTP enrollment verification did not include a verified email',
        };
      }

      const persisted = await this.finalizer.persistVerifiedEnrollment({
        walletId: verified.walletId,
        orgId: verified.orgId,
        authSubjectId: verified.challengeSubjectId,
        verifiedEmail,
        material: input,
        registrationAttemptId,
        nowMs: Date.now(),
      });
      if (!persisted.ok) return persisted;
      return {
        ok: true,
        walletId: verified.walletId,
        otpChannel: verified.otpChannel,
        enrollment: persisted.enrollment,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to verify Email OTP enrollment',
      };
    }
  }

  async verifyEmailOtpChallenge(
    input: VerifyEmailOtpChallengeInput,
  ): Promise<VerifyEmailOtpChallengeResult> {
    const operation = parseEmailOtpLoginOperation(input.operation);
    const verified = await this.verifier.verifyExisting({
      userId: input.userId,
      walletId: input.walletId,
      orgId: input.orgId,
      challengeId: input.challengeId,
      otpCode: input.otpCode,
      otpChannel: input.otpChannel,
      sessionHash: input.sessionHash,
      appSessionVersion: input.appSessionVersion,
      clientIp: input.clientIp,
      action: WALLET_EMAIL_OTP_ACTIONS.login,
      operation,
    });
    if (!verified.ok) return verified;

    const issuedAtMs = Date.now();
    const grantExpiresAtMs = issuedAtMs + this.grantTtlMs;
    const loginGrant = secureRandomBase64Url(24, 'email otp login grants');
    await this.grants.put(
      emailOtpGrantRecord({
        grantToken: loginGrant,
        userId: verified.userId,
        walletId: verified.walletId,
        orgId: verified.orgId,
        challengeId: verified.challengeId,
        sessionHash: verified.sessionHash,
        appSessionVersion: verified.appSessionVersion,
        action: WALLET_EMAIL_OTP_ACTIONS.unseal,
        issuedAtMs,
        expiresAtMs: grantExpiresAtMs,
      }),
    );

    return {
      ok: true,
      challengeId: verified.challengeId,
      loginGrant,
      grantExpiresAtMs,
      otpChannel: EMAIL_OTP_CHANNEL,
    };
  }

  async readEmailOtpOutboxEntry(
    input: ReadEmailOtpOutboxEntryInput,
  ): Promise<ReadEmailOtpOutboxEntryResult> {
    if (!this.devOutboxEnabled) {
      return { ok: false, code: 'not_found', message: 'Email OTP dev outbox is not enabled' };
    }
    const challengeId = toOptionalTrimmedString(input.challengeId);
    const userId = toOptionalTrimmedString(input.userId);
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    const record = challengeId
      ? await this.challenges.read(challengeId)
      : await this.challenges.readLatestActiveForSubjectWallet({
          challengeSubjectId: userId,
          walletId,
          nowMs: Date.now(),
        });
    if (!record || record.challengeSubjectId !== userId || record.walletId !== walletId) {
      return { ok: false, code: 'not_found', message: 'Email OTP outbox entry was not found' };
    }
    if (Date.now() > record.expiresAtMs) {
      await this.challenges.delete(challengeId);
      return { ok: false, code: 'not_found', message: 'Email OTP outbox entry expired' };
    }
    return {
      ok: true,
      challengeId: record.challengeId,
      walletId,
      userId,
      otpChannel: EMAIL_OTP_CHANNEL,
      emailHint: maskEmail(record.email),
      otpCode: record.otpCode,
      expiresAtMs: record.expiresAtMs,
    };
  }

  private async resolveRegistrationProofEmail(input: {
    readonly explicitProofEmail: unknown;
    readonly providerSubject: string;
    readonly registrationAttemptId: string | undefined;
    readonly walletId: string;
  }): Promise<{ ok: true; email: string } | { ok: false; code: string; message: string }> {
    let proofEmail = toOptionalTrimmedString(input.explicitProofEmail)?.toLowerCase() || '';
    if (!input.registrationAttemptId) {
      if (proofEmail) return { ok: true, email: proofEmail };
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP registration requires proofEmail',
      };
    }

    const attempt = await this.registrationAttempts.read(input.registrationAttemptId);
    if (!attempt) {
      return {
        ok: false,
        code: 'registration_attempt_missing',
        message: 'Google Email OTP registration attempt expired or was not found',
      };
    }
    if (attempt.providerSubject !== input.providerSubject) {
      return {
        ok: false,
        code: 'challenge_subject_mismatch',
        message: 'Email OTP registration attempt does not match the provider subject',
      };
    }
    if (attempt.expiresAtMs <= Date.now()) {
      return {
        ok: false,
        code: 'registration_attempt_expired',
        message: 'Google Email OTP registration attempt expired',
      };
    }
    if (attempt.walletId !== input.walletId) {
      return {
        ok: false,
        code: 'wallet_identity_mismatch',
        message: 'registrationAttemptId does not match walletId',
      };
    }
    proofEmail = attempt.email.toLowerCase();
    return { ok: true, email: proofEmail };
  }
}
