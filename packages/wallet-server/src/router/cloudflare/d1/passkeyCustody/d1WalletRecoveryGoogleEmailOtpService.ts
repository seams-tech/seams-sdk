import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8, sha256HexUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  buildActiveWalletAuthorityV1,
  buildFullOwnerPermissionsV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  replaceActiveWalletAuthorityEd25519MaterialActivationV1,
  type ActiveWalletAuthorityV1,
  type WalletSignerActivationSetV1,
} from '@shared/authorization';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import {
  consumeReservedRecoveryCode,
  type RecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import type { WalletRecoveryEnvelopeSetRecord } from '@shared/wallet-recovery';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import type { EmailOtpWalletEnrollmentRecord } from '../../../../core/EmailOtpStores';
import type { D1WalletStore } from '../../../../core/d1WalletStore';
import type { D1WalletAuthorityStore } from '../wallet/d1WalletAuthorityStore';
import type { CloudflareD1PasskeyCustodyEnvelopeStore } from './d1PasskeyCustodyEnvelopeStore';
import type {
  CloudflareD1WalletCustodyCommitStore,
  WalletRecoveryEmailEnrollmentCommit,
} from './d1WalletCustodyCommitStore';
import type { CloudflareD1EmailOtpRegistrationEnrollmentFinalizer } from '../emailOtp/d1EmailOtpRegistrationEnrollmentFinalizer';
import type { EmailOtpEnrollmentMaterialBoundaryInput } from '../emailOtp/d1EmailOtpRecords';
import type { WebAuthnRecoveryContinuityAnchorRecord } from '../webauthn/d1WebAuthnRecords';
import {
  buildWalletRecoveryEcdsaPossessionChallengesV1,
  resolveWalletRecoveryKeyManifestV1,
  verifyWalletRecoveryKeyActivationsV1,
  type WalletRecoveryEcdsaMaterialPossessionProofInputV1,
  type WalletRecoveryKeyManifestV1,
} from '../../../domains/passkeyCustody/walletRecoveryKeyManifest';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type { PasskeyCustodyEnvelopeLocator } from './d1PasskeyCustodyEnvelopeStore';
import {
  parseWalletAuthorityBindingDigest,
  parseProviderSubject,
  parseVerifiedGoogleEmail,
  type WalletId,
} from '@shared/utils/domainIds';
import type { CloudflareD1EmailOtpChallengeIssuer } from '../emailOtp/d1EmailOtpChallengeIssuer';
import type { CloudflareD1EmailOtpChallengeVerifier } from '../emailOtp/d1EmailOtpChallengeVerifier';
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

type ActiveEmailOtpWalletAuthMethodRecordV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly kind: 'email_otp'; readonly status: 'active' }
>;

export type WalletRecoveryGoogleEmailOtpFinalizationEnrollment =
  | {
      readonly kind: 'existing';
      readonly enrollmentId: string;
      readonly enrollmentSealKeyVersion: string;
      readonly material?: never;
    }
  | {
      readonly kind: 'create';
      readonly providerSubject: string;
      readonly verifiedEmail: string;
      readonly material: EmailOtpEnrollmentMaterialBoundaryInput;
    };

export type WalletRecoveryGoogleEmailOtpFinalizationDependencies = {
  readonly envelopeStore: CloudflareD1PasskeyCustodyEnvelopeStore;
  readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
  readonly walletAuthorityStore: Pick<D1WalletAuthorityStore, 'readById'>;
  readonly walletStore: D1WalletStore;
  readonly enrollmentFinalizer: Pick<
    CloudflareD1EmailOtpRegistrationEnrollmentFinalizer,
    'prepareLinkedDeviceEnrollment'
  >;
};

export type WalletRecoveryGoogleEmailOtpFinalizationResult =
  | {
      readonly kind: 'promoted';
      readonly storeVersion: string;
      readonly authority: ActiveWalletAuthorityV1;
      readonly authMethod: ActiveEmailOtpWalletAuthMethodRecordV2;
      readonly enrollment: EmailOtpWalletEnrollmentRecord;
    }
  | { readonly kind: 'conflict'; readonly reason: string }
  | { readonly kind: 'refused'; readonly reason: string }
  | { readonly kind: 'envelope_rejected'; readonly reason: string }
  | { readonly kind: 'enrollment_rejected'; readonly reason: string };

export type WalletRecoveryGoogleEmailOtpFinalizationRequest =
  | {
      readonly kind: 'finalize';
      readonly recovery: WalletRecoveryGoogleEmailOtpFinalizationInput;
      readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
      readonly emailOtpEnrollment: WalletRecoveryGoogleEmailOtpFinalizationEnrollment;
      readonly ecdsaMaterialPossessionProofs: readonly WalletRecoveryEcdsaMaterialPossessionProofInputV1[];
      readonly dependencies: WalletRecoveryGoogleEmailOtpFinalizationDependencies;
    }
  | {
      readonly kind: 'replay';
      readonly recovery: WalletRecoveryGoogleEmailOtpFinalizationInput;
      readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
      readonly dependencies: WalletRecoveryGoogleEmailOtpFinalizationDependencies;
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
  private readonly verifier: Pick<CloudflareD1EmailOtpChallengeVerifier, 'verifyRecoveryBootstrap'>;
  private readonly enrollments: Pick<CloudflareD1EmailOtpEnrollmentStore, 'readEnrollment'>;
  private readonly serverSeal: Pick<
    CloudflareD1EmailOtpServerSealRuntime,
    'removeEmailOtpServerSeal'
  >;
  private readonly orgId: string;
  private readonly nowMs: () => number;

  constructor(input: {
    readonly attempts: CloudflareD1WalletRecoveryGoogleEmailOtpAttemptStore;
    readonly google: Pick<CloudflareD1OidcVerificationService, 'verifyGoogleLoginForRecovery'>;
    readonly issuer: Pick<CloudflareD1EmailOtpChallengeIssuer, 'create'>;
    readonly verifier: Pick<CloudflareD1EmailOtpChallengeVerifier, 'verifyRecoveryBootstrap'>;
    readonly enrollments: Pick<CloudflareD1EmailOtpEnrollmentStore, 'readEnrollment'>;
    readonly serverSeal: Pick<CloudflareD1EmailOtpServerSealRuntime, 'removeEmailOtpServerSeal'>;
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
  }): Promise<
    { readonly kind: 'stored'; readonly version: string } | { readonly kind: 'conflict' }
  > {
    return await this.attempts.create(input.attempt);
  }

  async readAttempt(
    recoveryOperationId: Parameters<
      CloudflareD1WalletRecoveryGoogleEmailOtpAttemptStore['read']
    >[0],
  ) {
    return await this.attempts.read(recoveryOperationId);
  }

  /** Verifies the Google token and issues the recovery-bound OTP. */
  async verifyGoogle(input: {
    readonly recoveryOperationId: Parameters<
      CloudflareD1WalletRecoveryGoogleEmailOtpAttemptStore['read']
    >[0];
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
    readonly recoveryOperationId: Parameters<
      CloudflareD1WalletRecoveryGoogleEmailOtpAttemptStore['read']
    >[0];
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
    readonly recoveryOperationId: Parameters<
      CloudflareD1WalletRecoveryGoogleEmailOtpAttemptStore['read']
    >[0];
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

  /**
   * Completes the verified Google/Email recovery by installing a fresh target
   * authority and Email method. The durable commit owns every write; this
   * coordinator only resolves the continuity anchor and target envelope.
   */
  async finalizeRecovery(
    input: WalletRecoveryGoogleEmailOtpFinalizationRequest,
  ): Promise<WalletRecoveryGoogleEmailOtpFinalizationResult> {
    const recovery = input.recovery;
    if (recovery.orgId !== this.orgId) {
      return recoveryFinalizationRefused('recovery operation tenant changed');
    }
    const stored = await this.attempts.read(recovery.recoveryOperationId);
    if (stored.kind === 'missing') {
      return { kind: 'conflict', reason: 'the recovery operation is unavailable or incomplete' };
    }
    if (stored.value.state === 'finalized') {
      if (
        alphabetizeStringify(walletRecoveryGoogleEmailOtpFinalizationInput(stored.value)) !==
        alphabetizeStringify(recovery)
      ) {
        return recoveryAttemptConflictForFinalization();
      }
      const currentEnrollment = await this.enrollments.readEnrollment(String(recovery.walletId));
      if (!currentEnrollment) {
        return { kind: 'conflict', reason: 'the recovery operation is unavailable or incomplete' };
      }
      return await replayGoogleEmailOtpRecovery({
        recovery,
        replacementEnvelope: input.replacementEnvelope,
        enrollment: currentEnrollment,
        dependencies: input.dependencies,
      });
    }
    if (input.kind === 'replay') {
      return recoveryAttemptUnavailableForFinalization();
    }
    const enrollmentInput = validateFinalizationEnrollment({
      recovery,
      enrollment: input.emailOtpEnrollment,
    });
    if (!enrollmentInput.ok) return enrollmentInput;
    if (stored.value.state !== 'otp_verified') {
      return recoveryAttemptUnavailableForFinalization();
    }
    const attempt = stored.value;
    if (
      attempt.orgId !== this.orgId ||
      alphabetizeStringify(walletRecoveryGoogleEmailOtpFinalizationInput(attempt)) !==
        alphabetizeStringify(recovery) ||
      attempt.expiresAtMs <= this.nowMs()
    ) {
      return recoveryAttemptConflictForFinalization();
    }

    let manifest: WalletRecoveryKeyManifestV1;
    try {
      manifest = await resolveWalletRecoveryKeyManifestV1({
        registry: input.dependencies.walletStore,
        walletId: recovery.walletId,
      });
    } catch (error: unknown) {
      return recoveryFinalizationRefused(
        error instanceof Error ? error.message : 'wallet recovery key manifest unavailable',
      );
    }
    const continuity = await readGoogleEmailRecoveryContinuityAnchor({
      walletId: recovery.walletId,
      anchor: attempt.continuityAnchor,
      manifest,
      envelopeStore: input.dependencies.envelopeStore,
      walletCustodyCommits: input.dependencies.walletCustodyCommits,
      walletAuthorityStore: input.dependencies.walletAuthorityStore,
    });
    if (continuity.kind === 'rejected') {
      return recoveryFinalizationRefused(continuity.reason);
    }

    try {
      const ecdsaPossessionChallenges = await buildWalletRecoveryEcdsaPossessionChallengesV1({
        manifest,
        walletId: recovery.walletId,
        reservationId: String(recovery.reservationId),
        replacementId: String(recovery.recoveryOperationId),
        sourceAuthorityDigestB64u: googleEmailRecoveryAuthorityDigest(
          attempt.continuityAnchor.authority,
        ),
        challengeB64u: String(recovery.recoveryOperationId),
        expiresAtMs: attempt.expiresAtMs,
      });
      const ecdsaActivationReceipts = manifest.entries.flatMap((entry) =>
        entry.kind === 'evm_family_ecdsa'
          ? [{ keySetId: entry.keySetId, activationReceipt: entry.activationReceipt }]
          : [],
      );
      const activationVerification = await verifyWalletRecoveryKeyActivationsV1({
        registry: input.dependencies.walletStore,
        walletId: recovery.walletId,
        recoveryCorrelationId: String(recovery.reservationId),
        replacementId: String(recovery.recoveryOperationId),
        authorityRef: continuity.authorityRef,
        ecdsaPossessionChallenges: [...ecdsaPossessionChallenges.values()],
        ecdsaActivationReceipts,
        ecdsaMaterialPossessionProofs: input.ecdsaMaterialPossessionProofs,
        nowMs: this.nowMs(),
      });
      if (activationVerification.kind !== 'verified') {
        return recoveryFinalizationRefused(activationVerification.reason);
      }
    } catch (error: unknown) {
      return recoveryFinalizationRefused(
        error instanceof Error ? error.message : 'wallet recovery activation unavailable',
      );
    }

    let authority: ActiveWalletAuthorityV1;
    try {
      authority = await buildGoogleEmailRecoveryAuthority({
        recovery,
        continuityAuthority: continuity.authority,
        manifest,
        nowMs: this.nowMs(),
      });
    } catch (error: unknown) {
      return recoveryFinalizationRefused(
        error instanceof Error ? error.message : 'wallet recovery activation unavailable',
      );
    }

    const enrollment = await prepareGoogleEmailRecoveryEnrollment({
      recovery,
      enrollment: enrollmentInput,
      enrollmentFinalizer: input.dependencies.enrollmentFinalizer,
      enrollments: this.enrollments,
      nowMs: this.nowMs(),
    });
    if (!enrollment.ok) return enrollment;

    const replacementError = validateGoogleEmailRecoveryEnvelope({
      recovery,
      replacementEnvelope: input.replacementEnvelope,
      enrollment: enrollment.enrollment,
    });
    if (replacementError) {
      return { kind: 'envelope_rejected', reason: replacementError };
    }

    const walletAuthMethod = buildGoogleEmailRecoveryAuthMethod({
      recovery,
      walletAuthorityId: authority.authorityId,
      emailHashHex: await sha256HexUtf8(recovery.verifiedEmail),
      nowMs: this.nowMs(),
    });
    const storedRecoverySet = await input.dependencies.walletCustodyCommits.readRecoveryEnvelopeSet(
      recovery.walletId,
    );
    if (!storedRecoverySet || storedRecoverySet.storeVersion !== attempt.recoverySetVersion) {
      return recoveryAttemptConflictForFinalization();
    }
    const reservedIndex = storedRecoverySet.record.manifestKekWraps.findIndex(
      (wrap) =>
        wrap.lifecycle.state === 'reserved' &&
        wrap.lifecycle.reservationId === recovery.reservationId,
    );
    const selected = storedRecoverySet.record.manifestKekWraps[reservedIndex];
    if (reservedIndex < 0 || !selected || selected.lifecycle.state !== 'reserved') {
      return recoveryAttemptUnavailableForFinalization();
    }
    const locator =
      await input.dependencies.walletCustodyCommits.readRecoveryCodeLocatorByRecoveryKey({
        walletId: recovery.walletId,
        recoveryKeyId: selected.recoveryKeyId,
      });
    if (!locator) return recoveryAttemptUnavailableForFinalization();
    const consumed = consumeReservedRecoveryCode({
      lifecycle: selected.lifecycle,
      reservationId: recovery.reservationId,
      nowMs: this.nowMs(),
    });
    if (!consumed.ok || consumed.lifecycle.state !== 'consumed') {
      return recoveryAttemptUnavailableForFinalization();
    }
    const consumedRecoverySet = buildGoogleEmailConsumedRecoverySet({
      record: storedRecoverySet.record,
      reservedIndex,
      consumedLifecycle: consumed.lifecycle,
      nowMs: this.nowMs(),
    });
    const committed =
      await input.dependencies.walletCustodyCommits.commitRecoveryGoogleEmailOtpAuthorityInstall({
        recovery,
        recoveryAttemptStoreVersion: stored.version,
        continuityAuthority: continuity.authority,
        authority,
        recoverySet: consumedRecoverySet,
        expectedRecoverySetVersion: storedRecoverySet.storeVersion,
        replacementEnvelope: input.replacementEnvelope,
        recoveryKeyId: selected.recoveryKeyId,
        walletAuthMethod,
        enrollmentCommit: enrollment.commit,
      });
    if (committed.kind === 'conflict') {
      return { kind: 'conflict', reason: 'the recovery state changed during finalization' };
    }
    if (committed.kind === 'inconsistent') {
      return { kind: 'enrollment_rejected', reason: committed.reason };
    }
    return {
      kind: 'promoted',
      storeVersion: committed.envelopeStoreVersion,
      authority,
      authMethod: walletAuthMethod,
      enrollment: enrollment.enrollment,
    };
  }
}

type ValidatedGoogleEmailRecoveryEnrollment =
  | {
      readonly ok: true;
      readonly enrollment: WalletRecoveryGoogleEmailOtpFinalizationEnrollment;
    }
  | { readonly ok: false; readonly kind: 'enrollment_rejected'; readonly reason: string };

function validateFinalizationEnrollment(input: {
  readonly recovery: WalletRecoveryGoogleEmailOtpFinalizationInput;
  readonly enrollment: WalletRecoveryGoogleEmailOtpFinalizationEnrollment;
}): ValidatedGoogleEmailRecoveryEnrollment {
  if (input.recovery.targetEnrollment.kind !== input.enrollment.kind) {
    return {
      ok: false,
      kind: 'enrollment_rejected',
      reason: 'recovery Email enrollment target changed',
    };
  }
  switch (input.enrollment.kind) {
    case 'existing':
      if (
        input.recovery.targetEnrollment.kind !== 'existing' ||
        input.recovery.targetEnrollment.enrollmentId !== input.enrollment.enrollmentId ||
        input.recovery.targetEnrollment.enrollmentSealKeyVersion !==
          input.enrollment.enrollmentSealKeyVersion
      ) {
        return {
          ok: false,
          kind: 'enrollment_rejected',
          reason: 'recovery Email enrollment reference changed',
        };
      }
      return { ok: true, enrollment: input.enrollment };
    case 'create':
      if (
        input.recovery.targetEnrollment.kind !== 'create' ||
        input.recovery.targetEnrollment.providerSubject !== input.enrollment.providerSubject ||
        input.recovery.targetEnrollment.verifiedEmail !== input.enrollment.verifiedEmail
      ) {
        return {
          ok: false,
          kind: 'enrollment_rejected',
          reason: 'recovery Email enrollment identity changed',
        };
      }
      return { ok: true, enrollment: input.enrollment };
  }
}

type PreparedGoogleEmailRecoveryEnrollment =
  | {
      readonly ok: true;
      readonly enrollment: EmailOtpWalletEnrollmentRecord;
      readonly commit: WalletRecoveryEmailEnrollmentCommit;
    }
  | { readonly ok: false; readonly kind: 'enrollment_rejected'; readonly reason: string };

async function prepareGoogleEmailRecoveryEnrollment(input: {
  readonly recovery: WalletRecoveryGoogleEmailOtpFinalizationInput;
  readonly enrollment: ValidatedGoogleEmailRecoveryEnrollment & { readonly ok: true };
  readonly enrollmentFinalizer: Pick<
    CloudflareD1EmailOtpRegistrationEnrollmentFinalizer,
    'prepareLinkedDeviceEnrollment'
  >;
  readonly enrollments: Pick<CloudflareD1EmailOtpEnrollmentStore, 'readEnrollment'>;
  readonly nowMs: number;
}): Promise<PreparedGoogleEmailRecoveryEnrollment> {
  const recovery = input.recovery;
  const enrollmentInput = input.enrollment.enrollment;
  switch (enrollmentInput.kind) {
    case 'existing': {
      const existing = await input.enrollments.readEnrollment(String(recovery.walletId));
      if (
        !existing ||
        existing.walletId !== recovery.walletId ||
        existing.orgId !== recovery.orgId ||
        existing.providerUserId !== recovery.providerSubject ||
        existing.verifiedEmail !== recovery.verifiedEmail ||
        existing.enrollmentId !== enrollmentInput.enrollmentId ||
        existing.enrollmentSealKeyVersion !== enrollmentInput.enrollmentSealKeyVersion
      ) {
        return {
          ok: false,
          kind: 'enrollment_rejected',
          reason: 'Email OTP recovery enrollment changed after verification',
        };
      }
      return {
        ok: true,
        enrollment: existing,
        commit: { kind: 'existing', enrollment: existing, statements: [] },
      };
    }
    case 'create': {
      const prepared = await input.enrollmentFinalizer.prepareLinkedDeviceEnrollment({
        walletId: String(recovery.walletId),
        orgId: recovery.orgId,
        authSubjectId: recovery.providerSubject,
        verifiedEmail: recovery.verifiedEmail,
        material: enrollmentInput.material,
        nowMs: input.nowMs,
      });
      if (!prepared.ok) {
        return { ok: false, kind: 'enrollment_rejected', reason: prepared.message };
      }
      return {
        ok: true,
        enrollment: prepared.enrollment,
        commit: {
          kind: 'create',
          enrollment: prepared.enrollment,
          statements: prepared.statements,
        },
      };
    }
  }
}

function validateGoogleEmailRecoveryEnvelope(input: {
  readonly recovery: WalletRecoveryGoogleEmailOtpFinalizationInput;
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly enrollment: EmailOtpWalletEnrollmentRecord;
}): string | null {
  const envelope = input.replacementEnvelope;
  if (
    envelope.walletId !== input.recovery.walletId ||
    envelope.binding.kind !== 'wallet_custody_seed_v1' ||
    envelope.factor.kind !== 'email_otp' ||
    envelope.lifecycle.state !== 'active' ||
    Number(envelope.envelopeRevision) !== 1 ||
    envelope.ownership.kind !== 'method_bound' ||
    envelope.ownership.walletAuthMethodId !== input.recovery.targetWalletAuthMethodId ||
    envelope.factor.enrollmentId !== input.enrollment.enrollmentId ||
    envelope.factor.enrollmentSealKeyVersion !== input.enrollment.enrollmentSealKeyVersion
  ) {
    return 'the replacement Email OTP envelope is not bound to this recovery target';
  }
  return null;
}

type GoogleEmailRecoveryContinuityRead =
  | {
      readonly kind: 'ready';
      readonly authority: ActiveWalletAuthorityV1;
      readonly authorityRef: WalletAuthAuthorityRef;
    }
  | { readonly kind: 'rejected'; readonly reason: string };

async function readGoogleEmailRecoveryContinuityAnchor(input: {
  readonly walletId: WalletId;
  readonly anchor: WebAuthnRecoveryContinuityAnchorRecord;
  readonly manifest: WalletRecoveryKeyManifestV1;
  readonly envelopeStore: CloudflareD1PasskeyCustodyEnvelopeStore;
  readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
  readonly walletAuthorityStore: Pick<D1WalletAuthorityStore, 'readById'>;
}): Promise<GoogleEmailRecoveryContinuityRead> {
  const authority = await input.walletAuthorityStore.readById(input.anchor.authority.authorityId);
  const expectedAuthority = authority
    ? await googleEmailRecoveryContinuityAuthorityAfterActivation({
        authority: input.anchor.authority,
        manifest: input.manifest,
        updatedAtMs: authority.updatedAtMs,
      })
    : null;
  if (
    !authority ||
    !expectedAuthority ||
    authority.state !== 'active' ||
    authority.walletId !== input.walletId ||
    alphabetizeStringify(authority) !== alphabetizeStringify(expectedAuthority)
  ) {
    return { kind: 'rejected', reason: 'the recovery continuity authority changed' };
  }
  const method = await input.walletCustodyCommits.readWalletAuthMethodById(
    input.anchor.method.walletAuthMethodId,
  );
  if (
    !method ||
    method.status !== 'active' ||
    method.walletId !== input.walletId ||
    alphabetizeStringify(method) !== alphabetizeStringify(input.anchor.method)
  ) {
    return { kind: 'rejected', reason: 'the recovery continuity method changed' };
  }
  const envelopeLookup = await input.envelopeStore.lookupEnvelope(
    googleEmailContinuityEnvelopeLocator(input.anchor),
  );
  if (
    envelopeLookup.kind !== 'active' ||
    !googleEmailContinuityEnvelopeMatchesAnchor(envelopeLookup.envelope, input.anchor)
  ) {
    return { kind: 'rejected', reason: 'the recovery continuity envelope changed' };
  }
  const authorityDigest = parseWalletAuthorityBindingDigest(
    String(input.anchor.authority.authorityDigestB64u),
  );
  if (!authorityDigest.ok) {
    return { kind: 'rejected', reason: 'the recovery continuity authority changed' };
  }
  return {
    kind: 'ready',
    authority,
    authorityRef: {
      kind: 'wallet_auth_authority_ref',
      walletId: input.walletId,
      authorityDigest: authorityDigest.value,
      walletAuthMethodId: input.anchor.method.walletAuthMethodId,
    },
  };
}

async function googleEmailRecoveryContinuityAuthorityAfterActivation(input: {
  readonly authority: ActiveWalletAuthorityV1;
  readonly manifest: WalletRecoveryKeyManifestV1;
  readonly updatedAtMs: number;
}): Promise<ActiveWalletAuthorityV1> {
  const signerActivations = googleEmailRecoverySignerActivations({
    continuity: input.authority.signerActivations,
    manifest: input.manifest,
  });
  const ed25519 = signerActivations.ed25519;
  if (!ed25519) return input.authority;
  return await replaceActiveWalletAuthorityEd25519MaterialActivationV1({
    authority: input.authority,
    materialActivation: ed25519.materialActivation,
    updatedAtMs: input.updatedAtMs,
  });
}

function googleEmailRecoveryAuthorityDigest(authority: ActiveWalletAuthorityV1) {
  const parsed = parseWalletAuthorityBindingDigest(String(authority.authorityDigestB64u));
  if (!parsed.ok) throw new Error('wallet recovery authority digest is invalid');
  return parsed.value;
}

function googleEmailContinuityEnvelopeLocator(
  anchor: WebAuthnRecoveryContinuityAnchorRecord,
): PasskeyCustodyEnvelopeLocator {
  switch (anchor.envelope.kind) {
    case 'passkey':
      return {
        walletId: anchor.envelope.walletId,
        envelopeId: anchor.envelope.envelopeId,
        factor: {
          kind: 'passkey',
          rpId: anchor.envelope.rpId,
          credentialIdB64u: anchor.envelope.credentialIdB64u,
        },
      };
    case 'email_otp':
      return {
        walletId: anchor.envelope.walletId,
        envelopeId: anchor.envelope.envelopeId,
        factor: {
          kind: 'email_otp',
          enrollmentId: anchor.envelope.enrollmentId,
          enrollmentSealKeyVersion: anchor.envelope.enrollmentSealKeyVersion,
        },
      };
  }
}

function googleEmailContinuityEnvelopeMatchesAnchor(
  envelope: PasskeyCustodyEnvelopeRecord,
  anchor: WebAuthnRecoveryContinuityAnchorRecord,
): boolean {
  if (
    envelope.lifecycle.state !== 'active' ||
    envelope.walletId !== anchor.envelope.walletId ||
    envelope.envelopeId !== anchor.envelope.envelopeId ||
    envelope.binding.kind !== 'wallet_custody_seed_v1' ||
    envelope.ownership.kind !== 'method_bound' ||
    envelope.ownership.walletAuthMethodId !== anchor.method.walletAuthMethodId ||
    envelope.envelopeRevision !== anchor.envelope.envelopeRevision ||
    envelope.updatedAtMs !== anchor.envelope.updatedAtMs
  ) {
    return false;
  }
  switch (anchor.envelope.kind) {
    case 'passkey':
      return (
        envelope.factor.kind === 'passkey' &&
        envelope.factor.rpId === anchor.envelope.rpId &&
        envelope.factor.credentialIdB64u === anchor.envelope.credentialIdB64u
      );
    case 'email_otp':
      return (
        envelope.factor.kind === 'email_otp' &&
        envelope.factor.enrollmentId === anchor.envelope.enrollmentId &&
        envelope.factor.enrollmentSealKeyVersion === anchor.envelope.enrollmentSealKeyVersion
      );
  }
}

async function buildGoogleEmailRecoveryAuthority(input: {
  readonly recovery: WalletRecoveryGoogleEmailOtpFinalizationInput;
  readonly continuityAuthority: ActiveWalletAuthorityV1;
  readonly manifest: WalletRecoveryKeyManifestV1;
  readonly nowMs: number;
}): Promise<ActiveWalletAuthorityV1> {
  const signerActivations = googleEmailRecoverySignerActivations({
    continuity: input.continuityAuthority.signerActivations,
    manifest: input.manifest,
  });
  const signerActivationSetDigestB64u =
    await computeWalletSignerActivationSetDigestB64u(signerActivations);
  const draft: ActiveWalletAuthorityV1 = {
    kind: 'wallet_authority_v1',
    authorityId: input.recovery.targetAuthorityId,
    walletId: input.recovery.walletId,
    principal: {
      kind: 'owner_device',
      deviceId: input.recovery.targetDeviceId,
    },
    provenance: {
      kind: 'wallet_recovery',
      recoveryOperationId: input.recovery.recoveryOperationId,
      continuityAuthorityId: input.continuityAuthority.authorityId,
    },
    permissions: buildFullOwnerPermissionsV1(),
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: input.continuityAuthority.authorityDigestB64u,
    revocationEpoch: 0,
    createdAtMs: input.nowMs,
    updatedAtMs: input.nowMs,
    state: 'active',
    activatedAtMs: input.nowMs,
  };
  return buildActiveWalletAuthorityV1({
    kind: draft.kind,
    authorityId: draft.authorityId,
    walletId: draft.walletId,
    principal: draft.principal,
    provenance: draft.provenance,
    permissions: draft.permissions,
    signerActivations: draft.signerActivations,
    signerActivationSetDigestB64u: draft.signerActivationSetDigestB64u,
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(draft),
    revocationEpoch: draft.revocationEpoch,
    createdAtMs: draft.createdAtMs,
    updatedAtMs: draft.updatedAtMs,
    state: draft.state,
    activatedAtMs: draft.activatedAtMs,
  });
}

function googleEmailRecoverySignerActivations(input: {
  readonly continuity: WalletSignerActivationSetV1;
  readonly manifest: WalletRecoveryKeyManifestV1;
}): WalletSignerActivationSetV1 {
  const continuityEd25519 = input.continuity.ed25519;
  if (!continuityEd25519) return input.continuity;
  const entries = input.manifest.entries.filter(
    (entry) =>
      entry.kind === 'near_ed25519' &&
      entry.registeredPublicKeyB64u === continuityEd25519.signer.registeredPublicKeyB64u &&
      entry.recoveryBasis.capabilityKind === 'recovery',
  );
  if (entries.length !== 1 || entries[0]?.kind !== 'near_ed25519') {
    throw new Error('wallet recovery has no exact fresh Ed25519 activation');
  }
  const ed25519 = {
    kind: 'wallet_ed25519_signer_activation_v1' as const,
    signer: continuityEd25519.signer,
    materialActivation: routerAbMpcMaterialActivationRefFromWire(
      entries[0].recoveryBasis.activeMaterialActivation,
    ),
  };
  const continuityEcdsa = input.continuity.ecdsa;
  if (!continuityEcdsa) {
    return {
      kind: 'wallet_signer_activation_set_v1',
      keyFamilies: ['ed25519'],
      ed25519,
    };
  }
  return {
    kind: 'wallet_signer_activation_set_v1',
    keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
    ed25519,
    ecdsa: continuityEcdsa,
  };
}

function buildGoogleEmailRecoveryAuthMethod(input: {
  readonly recovery: WalletRecoveryGoogleEmailOtpFinalizationInput;
  readonly walletAuthorityId: WalletAuthMethodRecordV2['walletAuthorityId'];
  readonly emailHashHex: string;
  readonly nowMs: number;
}): ActiveEmailOtpWalletAuthMethodRecordV2 {
  const method = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: input.recovery.targetWalletAuthMethodId,
    walletId: input.recovery.walletId,
    walletAuthorityId: input.walletAuthorityId,
    kind: 'email_otp',
    status: 'active',
    emailHashHex: input.emailHashHex,
    registrationAuthorityId: input.recovery.challengeId,
    createdAtMs: input.nowMs,
    updatedAtMs: input.nowMs,
    activatedAtMs: input.nowMs,
  });
  if (method.kind !== 'email_otp' || method.status !== 'active') {
    throw new Error('recovery Email method builder returned an invalid branch');
  }
  return method;
}

function buildGoogleEmailConsumedRecoverySet(input: {
  readonly record: WalletRecoveryEnvelopeSetRecord;
  readonly reservedIndex: number;
  readonly consumedLifecycle: Extract<
    WalletRecoveryEnvelopeSetRecord['manifestKekWraps'][number]['lifecycle'],
    { readonly state: 'consumed' }
  >;
  readonly nowMs: number;
}): WalletRecoveryEnvelopeSetRecord {
  const manifestKekWraps = input.record.manifestKekWraps.map((wrap, index) => {
    if (index !== input.reservedIndex) return wrap;
    return {
      recoveryKeyId: wrap.recoveryKeyId,
      nonceB64u: wrap.nonceB64u,
      wrappedManifestKekB64u: wrap.wrappedManifestKekB64u,
      aadHashB64u: wrap.aadHashB64u,
      lifecycle: input.consumedLifecycle,
    };
  });
  return {
    kind: 'wallet_recovery_envelope_set_v1',
    walletId: input.record.walletId,
    manifestKekWraps,
    entries: input.record.entries,
    issuedAtMs: input.record.issuedAtMs,
    updatedAtMs: input.nowMs,
  };
}

async function replayGoogleEmailOtpRecovery(input: {
  readonly recovery: WalletRecoveryGoogleEmailOtpFinalizationInput;
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly enrollment: EmailOtpWalletEnrollmentRecord;
  readonly dependencies: WalletRecoveryGoogleEmailOtpFinalizationDependencies;
}): Promise<WalletRecoveryGoogleEmailOtpFinalizationResult> {
  const replay = await input.dependencies.walletCustodyCommits.resolveRecoveryGoogleEmailOtpReplay({
    recovery: input.recovery,
    replacementEnvelope: input.replacementEnvelope,
    enrollment: input.enrollment,
  });
  if (replay.kind === 'conflict') {
    return { kind: 'conflict', reason: 'the recovery operation is unavailable or incomplete' };
  }
  if (replay.kind === 'inconsistent') {
    return { kind: 'enrollment_rejected', reason: replay.reason };
  }
  const [authority, method] = await Promise.all([
    input.dependencies.walletAuthorityStore.readById(input.recovery.targetAuthorityId),
    input.dependencies.walletCustodyCommits.readWalletAuthMethodById(
      input.recovery.targetWalletAuthMethodId,
    ),
  ]);
  if (
    !authority ||
    authority.state !== 'active' ||
    !method ||
    method.kind !== 'email_otp' ||
    method.status !== 'active'
  ) {
    return { kind: 'conflict', reason: 'the recovery commit projection is unavailable' };
  }
  return {
    kind: 'promoted',
    storeVersion: replay.envelopeStoreVersion,
    authority,
    authMethod: method,
    enrollment: input.enrollment,
  };
}

function parseGoogleIdentity(
  result: GoogleVerificationResult,
): ({ readonly ok: true } & GoogleIdentity) | GoogleRecoveryFailure {
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
  readonly attempt: Extract<
    WalletRecoveryGoogleEmailOtpAttemptRecord,
    { readonly state: 'prepared' | 'otp_issued' }
  >;
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

function recoveryFinalizationRefused(
  reason: string,
): Extract<WalletRecoveryGoogleEmailOtpFinalizationResult, { readonly kind: 'refused' }> {
  return { kind: 'refused', reason };
}

function recoveryAttemptUnavailableForFinalization(): Extract<
  WalletRecoveryGoogleEmailOtpFinalizationResult,
  { readonly kind: 'refused' }
> {
  return {
    kind: 'refused',
    reason: 'wallet recovery operation is unavailable',
  };
}

function recoveryAttemptConflictForFinalization(): Extract<
  WalletRecoveryGoogleEmailOtpFinalizationResult,
  { readonly kind: 'conflict' }
> {
  return {
    kind: 'conflict',
    reason: 'wallet recovery operation changed; retry recovery',
  };
}
