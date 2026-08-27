import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  parseProviderSubject,
  parseVerifiedGoogleEmail,
  type WalletId,
} from '@shared/utils/domainIds';
import type {
  CloudflareD1EmailOtpChallengeIssuer,
} from '../emailOtp/d1EmailOtpChallengeIssuer';
import type {
  CloudflareD1EmailOtpChallengeVerifier,
} from '../emailOtp/d1EmailOtpChallengeVerifier';
import type { CloudflareD1EmailOtpEnrollmentStore } from '../emailOtp/d1EmailOtpEnrollmentStore';
import type { CloudflareD1EmailOtpServerSealRuntime } from '../emailOtp/d1EmailOtpServerSealRuntime';
import type { CloudflareD1OidcVerificationService } from '../oidc/d1OidcVerificationService';
import { hashEmailOtpOperationBinding } from '../../../domains/emailOtp/emailOtpSessionRouteHelpers';
import { sealEmailOtpFactorSecretForWorker } from '../../../domains/emailOtp/emailOtpRouteHandlers';
import type { EmailOtpChallengeDelivery } from '../../../framework/authServicePort';
import type {
  OtpIssuedWalletRecoveryGoogleEmailOtpAttempt,
  OtpVerifiedWalletRecoveryGoogleEmailOtpAttempt,
  WalletRecoveryGoogleEmailOtpFinalizationInput,
  WalletRecoveryGoogleEmailOtpTargetEnrollmentV1,
  WalletRecoveryGoogleEmailOtpAttemptRecord,
} from './d1WalletRecoveryGoogleEmailOtpRecords';
import {
  markWalletRecoveryGoogleEmailOtpAttemptIssued,
  markWalletRecoveryGoogleEmailOtpAttemptVerified,
  walletRecoveryGoogleEmailOtpFinalizationInput,
} from './d1WalletRecoveryGoogleEmailOtpRecords';
import type { CloudflareD1WalletRecoveryGoogleEmailOtpAttemptStore } from './d1WalletRecoveryGoogleEmailOtpAttemptStore';

type GoogleVerificationResult = Awaited<
  ReturnType<CloudflareD1OidcVerificationService['verifyGoogleLoginForRecovery']>
>;

type GoogleRecoveryFailure = {
  readonly ok: false;
  readonly code: string;
  readonly message: string;
};

export type WalletRecoveryGoogleEmailOtpChallengeResult =
  | {
      readonly ok: true;
      readonly recoveryOperationId: string;
      readonly walletId: WalletId;
      readonly reservationId: string;
      readonly challengeId: string;
      readonly verifiedEmail: string;
      readonly delivery: EmailOtpChallengeDelivery;
      readonly expiresAtMs: number;
    }
  | GoogleRecoveryFailure;

export type WalletRecoveryGoogleEmailOtpFactorReleaseResult =
  | {
      readonly ok: true;
      readonly kind: 'email_otp_factor_release_v1';
      readonly recovery: WalletRecoveryGoogleEmailOtpFinalizationInput;
      readonly enrollment: {
        readonly kind: 'existing';
        readonly enrollmentId: string;
        readonly enrollmentSealKeyVersion: string;
      };
      readonly serverEphemeralPublicKey65B64u: string;
      readonly nonce12B64u: string;
      readonly ciphertextB64u: string;
    }
  | {
      readonly ok: true;
      readonly kind: 'wallet_recovery_google_email_otp_new_enrollment_v1';
      readonly recovery: WalletRecoveryGoogleEmailOtpFinalizationInput;
      readonly enrollment: {
        readonly kind: 'create';
        readonly providerSubject: string;
        readonly verifiedEmail: string;
      };
    }
  | GoogleRecoveryFailure;

export type WalletRecoveryGoogleEmailOtpVerificationResult =
  | {
      readonly ok: true;
      readonly recovery: WalletRecoveryGoogleEmailOtpFinalizationInput;
      readonly attempt: OtpVerifiedWalletRecoveryGoogleEmailOtpAttempt;
    }
  | GoogleRecoveryFailure;

type GoogleIdentity = {
  readonly providerSubject: string;
  readonly verifiedEmail: string;
};

/**
 * Recovery-scoped Google and Email OTP coordinator. It owns only the
 * recovery operation binding; Google verification, OTP issuance/consumption,
 * and factor unsealing stay in their existing services.
 */
export class CloudflareD1WalletRecoveryGoogleEmailOtpService {
  private readonly attempts: CloudflareD1WalletRecoveryGoogleEmailOtpAttemptStore;
  private readonly google: Pick<
    CloudflareD1OidcVerificationService,
    'verifyGoogleLoginForRecovery'
  >;
  private readonly issuer: Pick<CloudflareD1EmailOtpChallengeIssuer, 'create'>;
  private readonly verifier: Pick<
    CloudflareD1EmailOtpChallengeVerifier,
    'verifyRecoveryBootstrap'
  >;
  private readonly enrollments: Pick<CloudflareD1EmailOtpEnrollmentStore, 'readEnrollment'>;
  private readonly serverSeal: Pick<
    CloudflareD1EmailOtpServerSealRuntime,
    'removeEmailOtpServerSeal'
  >;
  private readonly orgId: string;
  private readonly nowMs: () => number;

  constructor(input: {
    readonly attempts: CloudflareD1WalletRecoveryGoogleEmailOtpAttemptStore;
    readonly google: Pick<
      CloudflareD1OidcVerificationService,
      'verifyGoogleLoginForRecovery'
    >;
    readonly issuer: Pick<CloudflareD1EmailOtpChallengeIssuer, 'create'>;
    readonly verifier: Pick<
      CloudflareD1EmailOtpChallengeVerifier,
      'verifyRecoveryBootstrap'
    >;
    readonly enrollments: Pick<CloudflareD1EmailOtpEnrollmentStore, 'readEnrollment'>;
    readonly serverSeal: Pick<
      CloudflareD1EmailOtpServerSealRuntime,
      'removeEmailOtpServerSeal'
    >;
    readonly orgId: string;
    readonly nowMs?: () => number;
  }) {
    this.attempts = input.attempts;
    this.google = input.google;
    this.issuer = input.issuer;
    this.verifier = input.verifier;
    this.enrollments = input.enrollments;
    this.serverSeal = input.serverSeal;
    this.orgId = input.orgId;
    this.nowMs = input.nowMs ?? Date.now;
  }

  async persistPrepared(input: {
    readonly attempt: WalletRecoveryGoogleEmailOtpAttemptRecord;
  }): Promise<{ readonly kind: 'stored'; readonly version: string } | { readonly kind: 'conflict' }> {
    return await this.attempts.create(input.attempt);
  }

  async readAttempt(
    recoveryOperationId: Parameters<CloudflareD1WalletRecoveryGoogleEmailOtpAttemptStore['read']>[0],
  ) {
    return await this.attempts.read(recoveryOperationId);
  }

  /** Verifies the Google token and issues the recovery-bound OTP. */
  async verifyGoogle(input: {
    readonly recoveryOperationId: Parameters<CloudflareD1WalletRecoveryGoogleEmailOtpAttemptStore['read']>[0];
    readonly reservationId: string;
    readonly idToken: unknown;
    readonly requestOrigin: string | null;
    readonly clientIp?: unknown;
  }): Promise<WalletRecoveryGoogleEmailOtpChallengeResult> {
    const stored = await this.attempts.read(input.recoveryOperationId);
    if (stored.kind !== 'present') return recoveryAttemptUnavailable();
    const attempt = stored.value;
    if (
      attempt.orgId !== this.orgId ||
      String(attempt.reservationId) !== input.reservationId ||
      attempt.expiresAtMs <= this.nowMs() ||
      (attempt.state !== 'prepared' && attempt.state !== 'otp_issued')
    ) {
      return recoveryAttemptUnavailable();
    }

    const verified = await this.google.verifyGoogleLoginForRecovery({ idToken: input.idToken });
    const identity = parseGoogleIdentity(verified);
    if (!identity.ok) return identity;

    const enrollment = await this.enrollments.readEnrollment(String(attempt.walletId));
    const targetEnrollment = resolveTargetEnrollment({
      enrollment,
      orgId: attempt.orgId,
      identity,
      anchor: attempt.continuityAnchor,
    });
    if ('ok' in targetEnrollment) return targetEnrollment;

    const ownerProofBindingDigest = await recoveryOwnerProofBindingDigest({
      attempt,
      identity,
    });
    const issued = await this.issuer.create({
      userId: identity.providerSubject,
      walletId: String(attempt.walletId),
      orgId: attempt.orgId,
      email: identity.verifiedEmail,
      otpChannel: EMAIL_OTP_CHANNEL,
      ownerProofBindingDigest,
      requestOrigin: input.requestOrigin,
      clientIp: input.clientIp,
      reuseActiveChallenge: true,
      action: WALLET_EMAIL_OTP_ACTIONS.recoveryBootstrap,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    if (!issued.ok) return issued;

    const next = markWalletRecoveryGoogleEmailOtpAttemptIssued({
      attempt: attempt.state === 'prepared' ? attempt : preparedAttemptFromIssued(attempt),
      providerSubject: identity.providerSubject,
      verifiedEmail: identity.verifiedEmail,
      challengeId: issued.challenge.challengeId,
      ownerProofBindingDigest,
      targetEnrollment,
    });
    const updated = await this.attempts.update(next, stored.version);
    if (updated.kind === 'conflict') return recoveryAttemptConflict();
    return {
      ok: true,
      recoveryOperationId: String(attempt.recoveryOperationId),
      walletId: attempt.walletId,
      reservationId: String(attempt.reservationId),
      challengeId: issued.challenge.challengeId,
      verifiedEmail: identity.verifiedEmail,
      delivery: issued.delivery,
      expiresAtMs: issued.challenge.expiresAtMs,
    };
  }

  /** Consumes the recovery-bound OTP; factor release is a separate retryable gate. */
  async verifyOtp(input: {
    readonly recoveryOperationId: Parameters<CloudflareD1WalletRecoveryGoogleEmailOtpAttemptStore['read']>[0];
    readonly reservationId: string;
    readonly challengeId: string;
    readonly otpCode: unknown;
    readonly clientIp?: unknown;
  }): Promise<WalletRecoveryGoogleEmailOtpVerificationResult> {
    const stored = await this.attempts.read(input.recoveryOperationId);
    if (stored.kind !== 'present') return recoveryAttemptUnavailable();
    const attempt = stored.value;
    if (
      attempt.state !== 'otp_issued' ||
      attempt.orgId !== this.orgId ||
      String(attempt.reservationId) !== input.reservationId ||
      attempt.challengeId !== input.challengeId ||
      attempt.expiresAtMs <= this.nowMs()
    ) {
      return recoveryAttemptUnavailable();
    }
    const verified = await this.verifier.verifyRecoveryBootstrap({
      providerSubject: attempt.providerSubject,
      walletId: String(attempt.walletId),
      orgId: attempt.orgId,
      challengeId: input.challengeId,
      otpCode: input.otpCode,
      otpChannel: EMAIL_OTP_CHANNEL,
      ownerProofBindingDigest: attempt.ownerProofBindingDigest,
      proofEmail: attempt.verifiedEmail,
      clientIp: input.clientIp,
      action: WALLET_EMAIL_OTP_ACTIONS.recoveryBootstrap,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    if (!verified.ok) return verified;
    const next = markWalletRecoveryGoogleEmailOtpAttemptVerified(attempt);
    const updated = await this.attempts.update(next, stored.version);
    if (updated.kind === 'conflict') return recoveryAttemptConflict();
    return {
      ok: true,
      recovery: walletRecoveryGoogleEmailOtpFinalizationInput(next),
      attempt: next,
    };
  }

  /** Releases existing Email material, or returns authorization to create the first enrollment. */
  async releaseFactor(input: {
    readonly recoveryOperationId: Parameters<CloudflareD1WalletRecoveryGoogleEmailOtpAttemptStore['read']>[0];
    readonly reservationId: string;
    readonly workerEphemeralPublicKey65B64u?: unknown;
  }): Promise<WalletRecoveryGoogleEmailOtpFactorReleaseResult> {
    const stored = await this.attempts.read(input.recoveryOperationId);
    if (stored.kind !== 'present' || stored.value.state !== 'otp_verified') {
      return recoveryAttemptUnavailable();
    }
    const attempt = stored.value;
    if (
      attempt.orgId !== this.orgId ||
      String(attempt.reservationId) !== input.reservationId ||
      attempt.expiresAtMs <= this.nowMs()
    ) {
      return recoveryAttemptUnavailable();
    }
    const recovery = walletRecoveryGoogleEmailOtpFinalizationInput(attempt);
    if (attempt.targetEnrollment.kind === 'create') {
      return {
        ok: true,
        kind: 'wallet_recovery_google_email_otp_new_enrollment_v1',
        recovery,
        enrollment: attempt.targetEnrollment,
      };
    }
    const workerEphemeralPublicKey65B64u = nonEmpty(input.workerEphemeralPublicKey65B64u);
    if (!workerEphemeralPublicKey65B64u) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP recovery factor release key is required',
      };
    }
    const enrollment = await this.enrollments.readEnrollment(String(attempt.walletId));
    if (
      !enrollment ||
      enrollment.orgId !== attempt.orgId ||
      enrollment.providerUserId !== attempt.providerSubject ||
      enrollment.verifiedEmail !== attempt.verifiedEmail ||
      enrollment.enrollmentId !== attempt.targetEnrollment.enrollmentId ||
      enrollment.enrollmentSealKeyVersion !== attempt.targetEnrollment.enrollmentSealKeyVersion
    ) {
      return {
        ok: false,
        code: 'recovery_conflict',
        message: 'Email OTP recovery enrollment changed after verification',
      };
    }
    const unsealed = await this.serverSeal.removeEmailOtpServerSeal({
      wrappedCiphertext: enrollment.serverSealedFactorCiphertextB64u,
    });
    if (!unsealed.ok) return unsealed;
    if (unsealed.enrollmentSealKeyVersion !== enrollment.enrollmentSealKeyVersion) {
      return {
        ok: false,
        code: 'recovery_conflict',
        message: 'Email OTP recovery enrollment seal changed after verification',
      };
    }
    const sealed = await sealEmailOtpFactorSecretForWorker({
      factorSecret32B64u: unsealed.ciphertext,
      workerEphemeralPublicKey65B64u,
      walletId: String(attempt.walletId),
      enrollmentId: enrollment.enrollmentId,
      enrollmentSealKeyVersion: enrollment.enrollmentSealKeyVersion,
      challengeId: attempt.challengeId,
    });
    if (!sealed.ok) return sealed;
    return {
      ok: true,
      kind: 'email_otp_factor_release_v1',
      recovery,
      enrollment: {
        kind: 'existing',
        enrollmentId: enrollment.enrollmentId,
        enrollmentSealKeyVersion: enrollment.enrollmentSealKeyVersion,
      },
      serverEphemeralPublicKey65B64u: sealed.serverEphemeralPublicKey65B64u,
      nonce12B64u: sealed.nonce12B64u,
      ciphertextB64u: sealed.ciphertextB64u,
    };
  }
}

function parseGoogleIdentity(
  result: GoogleVerificationResult,
): { readonly ok: true } & GoogleIdentity | GoogleRecoveryFailure {
  if (!result.ok || result.verified !== true) {
    return {
      ok: false,
      code: result.code || 'not_verified',
      message: result.message || 'Google verification failed',
    };
  }
  const providerSubject = parseProviderSubject(result.providerSubject);
  const email = parseVerifiedGoogleEmail(result.email);
  if (!providerSubject.ok || !email.ok || result.emailVerified !== true) {
    return {
      ok: false,
      code: 'provider_identity_mismatch',
      message: 'Google verification did not provide a verified identity email',
    };
  }
  return {
    ok: true,
    providerSubject: providerSubject.value,
    verifiedEmail: email.value,
  };
}

function resolveTargetEnrollment(input: {
  readonly enrollment: Awaited<ReturnType<CloudflareD1EmailOtpEnrollmentStore['readEnrollment']>>;
  readonly orgId: string;
  readonly identity: GoogleIdentity;
  readonly anchor: {
    readonly envelope: {
      readonly kind: 'passkey' | 'email_otp';
      readonly enrollmentId?: string;
      readonly enrollmentSealKeyVersion?: string;
    };
  };
}): WalletRecoveryGoogleEmailOtpTargetEnrollmentV1 | GoogleRecoveryFailure {
  if (input.enrollment) {
    if (
      input.enrollment.orgId !== input.orgId ||
      input.enrollment.providerUserId !== input.identity.providerSubject ||
      input.enrollment.verifiedEmail !== input.identity.verifiedEmail
    ) {
      return {
        ok: false,
        code: 'provider_identity_mismatch',
        message: 'Google identity does not match the wallet Email enrollment',
      };
    }
    if (
      input.anchor.envelope.kind === 'email_otp' &&
      (input.anchor.envelope.enrollmentId !== input.enrollment.enrollmentId ||
        input.anchor.envelope.enrollmentSealKeyVersion !==
          input.enrollment.enrollmentSealKeyVersion)
    ) {
      return {
        ok: false,
        code: 'recovery_conflict',
        message: 'Wallet Email custody enrollment changed after preparation',
      };
    }
    return {
      kind: 'existing',
      enrollmentId: input.enrollment.enrollmentId,
      enrollmentSealKeyVersion: input.enrollment.enrollmentSealKeyVersion,
    };
  }
  if (input.anchor.envelope.kind === 'email_otp') {
    return {
      ok: false,
      code: 'recovery_conflict',
      message: 'Wallet Email custody enrollment is missing after preparation',
    };
  }
  return {
    kind: 'create',
    providerSubject: input.identity.providerSubject,
    verifiedEmail: input.identity.verifiedEmail,
  };
}

async function recoveryOwnerProofBindingDigest(input: {
  readonly attempt: Extract<WalletRecoveryGoogleEmailOtpAttemptRecord, { readonly state: 'prepared' | 'otp_issued' }>;
  readonly identity: GoogleIdentity;
}): Promise<DigestB64u> {
  const operationFingerprintDigest = parseDigestB64u(
    await sha256Base64Url({
      version: 'wallet_recovery_google_email_otp_binding_v1',
      recoveryOperationId: String(input.attempt.recoveryOperationId),
      walletId: String(input.attempt.walletId),
      reservationId: String(input.attempt.reservationId),
      targetDeviceId: String(input.attempt.targetDeviceId),
      targetAuthorityId: String(input.attempt.targetAuthorityId),
      targetWalletAuthMethodId: String(input.attempt.targetWalletAuthMethodId),
      providerSubject: input.identity.providerSubject,
      verifiedEmail: input.identity.verifiedEmail,
    }),
  );
  return parseDigestB64u(
    await hashEmailOtpOperationBinding({
      walletId: String(input.attempt.walletId),
      providerUserId: input.identity.providerSubject,
      orgId: input.attempt.orgId,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
      requestOrigin: null,
      audience: null,
      authorityRef: {
        kind: 'wallet_recovery',
        recoveryOperationId: String(input.attempt.recoveryOperationId),
        targetAuthorityId: String(input.attempt.targetAuthorityId),
        targetDeviceId: String(input.attempt.targetDeviceId),
        targetWalletAuthMethodId: String(input.attempt.targetWalletAuthMethodId),
      },
      operationFingerprintDigest,
    }),
  );
}

async function sha256Base64Url(value: Record<string, string>): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(value)));
}

function preparedAttemptFromIssued(
  attempt: OtpIssuedWalletRecoveryGoogleEmailOtpAttempt,
): Extract<WalletRecoveryGoogleEmailOtpAttemptRecord, { readonly state: 'prepared' }> {
  return {
    version: attempt.version,
    walletId: attempt.walletId,
    orgId: attempt.orgId,
    reservationId: attempt.reservationId,
    recoveryOperationId: attempt.recoveryOperationId,
    targetDeviceId: attempt.targetDeviceId,
    targetAuthorityId: attempt.targetAuthorityId,
    targetWalletAuthMethodId: attempt.targetWalletAuthMethodId,
    target: attempt.target,
    continuityAnchor: attempt.continuityAnchor,
    recoverySetVersion: attempt.recoverySetVersion,
    keyManifestDigestB64u: attempt.keyManifestDigestB64u,
    state: 'prepared',
    createdAtMs: attempt.createdAtMs,
    expiresAtMs: attempt.expiresAtMs,
  };
}

function nonEmpty(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function recoveryAttemptUnavailable(): GoogleRecoveryFailure {
  return {
    ok: false,
    code: 'recovery_attempt_unavailable',
    message: 'Wallet recovery operation is unavailable',
  };
}

function recoveryAttemptConflict(): GoogleRecoveryFailure {
  return {
    ok: false,
    code: 'recovery_conflict',
    message: 'Wallet recovery operation changed; retry recovery',
  };
}
