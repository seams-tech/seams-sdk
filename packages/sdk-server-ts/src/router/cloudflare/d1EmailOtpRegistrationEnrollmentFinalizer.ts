import { EMAIL_OTP_RECOVERY_KEY_COUNT } from '@shared/utils/emailOtpRecoveryKey';
import { sha256Bytes } from '@shared/utils/digests';
import type { RegistrationAuthority, WalletId } from '@shared/utils/registrationIntent';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  EmailOtpAuthStateRecord,
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  EmailOtpWalletEnrollmentRecord,
} from '../../core/EmailOtpStores';
import type {
  WalletRegistrationFinalizeRequest
} from '../../core/registrationContracts';
import { validateSecp256k1PublicKey33 } from '../../core/ThresholdService/ethSignerWasm';
import type { CloudflareD1EmailOtpEnrollmentStore } from './d1EmailOtpEnrollmentStore';
import type { CloudflareD1EmailOtpRecoveryEscrowStore } from './d1EmailOtpRecoveryEscrowStore';
import type { CloudflareD1GoogleEmailOtpSessionResolver } from './d1GoogleEmailOtpSessionResolver';
import {
  activeEmailOtpRecoveryEscrow,
  emailOtpRecoveryEscrowWithUpdatedAt,
  validateEmailOtpEnrollmentMaterial,
  type EmailOtpEnrollmentMaterialBoundaryInput,
} from './d1EmailOtpRecords';

type FinalizeWalletRegistrationInput = WalletRegistrationFinalizeRequest;

type D1EmailOtpRegistrationEnrollmentPersistence =
  | {
      readonly providerEnrollmentMove: 'none';
      readonly previousProviderWalletId?: never;
      readonly enrollment: EmailOtpWalletEnrollmentRecord;
      readonly recoveryWrappedEnrollmentEscrows: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[];
      readonly existingAuthState: EmailOtpAuthStateRecord | null;
    }
  | {
      readonly providerEnrollmentMove: 'delete_previous';
      readonly previousProviderWalletId: string;
      readonly enrollment: EmailOtpWalletEnrollmentRecord;
      readonly recoveryWrappedEnrollmentEscrows: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[];
      readonly existingAuthState: EmailOtpAuthStateRecord | null;
    };

type D1EmailOtpRegistrationFinalizeEnrollmentResult =
  | {
      readonly ok: true;
      readonly persistence?: D1EmailOtpRegistrationEnrollmentPersistence;
    }
  | {
      readonly ok: false;
      readonly code: string;
      readonly message: string;
    };

type D1EmailOtpRegistrationEnrollmentBuildResult =
  | {
      readonly ok: true;
      readonly persistence: D1EmailOtpRegistrationEnrollmentPersistence;
    }
  | {
      readonly ok: false;
      readonly code: string;
      readonly message: string;
    };

type D1EmailOtpRegistrationEnrollmentPersistResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: string; readonly message: string };

type D1EmailOtpVerifiedRegistrationEnrollmentPersistResult =
  | {
      readonly ok: true;
      readonly enrollment: {
        readonly createdAtMs: number;
        readonly updatedAtMs: number;
        readonly enrollmentSealKeyVersion: string;
        readonly unlockKeyVersion: string;
      };
    }
  | {
      readonly ok: false;
      readonly code: string;
      readonly message: string;
    };

function safeInteger(raw: unknown): number | null {
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : null;
}

function recoveryEscrowsWithUpdatedAt(input: {
  readonly records: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[];
  readonly updatedAtMs: number;
}): EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] {
  const records: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] = [];
  for (const record of input.records) {
    records.push(emailOtpRecoveryEscrowWithUpdatedAt({ record, updatedAtMs: input.updatedAtMs }));
  }
  return records;
}

function countActiveRecoveryEscrows(
  records: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[],
): number {
  let count = 0;
  for (const record of records) {
    if (activeEmailOtpRecoveryEscrow(record)) count += 1;
  }
  return count;
}

export class CloudflareD1EmailOtpRegistrationEnrollmentFinalizer {
  private readonly emailOtpEnrollments: CloudflareD1EmailOtpEnrollmentStore;
  private readonly emailOtpRecoveryEscrows: CloudflareD1EmailOtpRecoveryEscrowStore;
  private readonly googleEmailOtpSessions: CloudflareD1GoogleEmailOtpSessionResolver;

  constructor(input: {
    readonly emailOtpEnrollments: CloudflareD1EmailOtpEnrollmentStore;
    readonly emailOtpRecoveryEscrows: CloudflareD1EmailOtpRecoveryEscrowStore;
    readonly googleEmailOtpSessions: CloudflareD1GoogleEmailOtpSessionResolver;
  }) {
    this.emailOtpEnrollments = input.emailOtpEnrollments;
    this.emailOtpRecoveryEscrows = input.emailOtpRecoveryEscrows;
    this.googleEmailOtpSessions = input.googleEmailOtpSessions;
  }

  async prepareRegistrationFinalize(input: {
    readonly authority: RegistrationAuthority;
    readonly request: Pick<
      FinalizeWalletRegistrationInput,
      'emailOtpEnrollment' | 'emailOtpBackupAck'
    >;
    readonly walletId: WalletId;
    readonly orgId: string;
    readonly nowMs: number;
  }): Promise<D1EmailOtpRegistrationFinalizeEnrollmentResult> {
    if (input.authority.kind !== 'email_otp') {
      if (input.request.emailOtpEnrollment || input.request.emailOtpBackupAck) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP enrollment material is only valid for Email OTP registration',
        };
      }
      return { ok: true };
    }
    if (!input.request.emailOtpEnrollment) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP registration finalize requires emailOtpEnrollment',
      };
    }
    const backupAck = input.request.emailOtpBackupAck;
    if (!backupAck) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP registration finalize requires emailOtpBackupAck',
      };
    }
    if (
      input.authority.walletId !== input.walletId ||
      input.authority.finalWalletId !== input.walletId ||
      input.authority.orgId !== input.orgId
    ) {
      return {
        ok: false,
        code: 'authority_binding_mismatch',
        message: 'Email OTP registration authority does not match finalize scope',
      };
    }
    const backupOfferId = toOptionalTrimmedString(backupAck.offerId);
    const backupCandidateId = toOptionalTrimmedString(backupAck.candidateId);
    if (
      input.authority.proofKind === 'google_sso_registration' &&
      (backupOfferId !== input.authority.googleEmailOtpRegistrationOfferId ||
        backupCandidateId !== input.authority.googleEmailOtpRegistrationCandidateId)
    ) {
      return {
        ok: false,
        code: 'backup_ack_binding_mismatch',
        message: 'Email OTP recovery-code backup acknowledgement does not match the offer',
      };
    }
    if (
      input.authority.proofKind !== 'google_sso_registration' &&
      (backupOfferId || backupCandidateId)
    ) {
      return {
        ok: false,
        code: 'backup_ack_binding_mismatch',
        message: 'Email OTP recovery-code backup acknowledgement has unexpected offer metadata',
      };
    }
    const recoveryCodesIssuedAtMs = safeInteger(backupAck.recoveryCodesIssuedAtMs);
    const acknowledgedAtMs = safeInteger(backupAck.acknowledgedAtMs);
    if (recoveryCodesIssuedAtMs === null || acknowledgedAtMs === null) {
      return {
        ok: false,
        code: 'backup_ack_invalid',
        message: 'Email OTP recovery-code backup acknowledgement timestamps are invalid',
      };
    }
    if (acknowledgedAtMs < recoveryCodesIssuedAtMs) {
      return {
        ok: false,
        code: 'backup_ack_invalid',
        message: 'Email OTP recovery-code backup acknowledgement predates code issuance',
      };
    }
    const enrollment = await this.buildPersistence({
      walletId: input.walletId,
      orgId: input.orgId,
      authSubjectId: input.authority.providerSubject,
      verifiedEmail: input.authority.email,
      material: input.request.emailOtpEnrollment,
      nowMs: input.nowMs,
    });
    if (!enrollment.ok) return enrollment;
    const firstEscrow = enrollment.persistence.recoveryWrappedEnrollmentEscrows[0];
    if (!firstEscrow || firstEscrow.issuedAtMs !== recoveryCodesIssuedAtMs) {
      return {
        ok: false,
        code: 'backup_ack_binding_mismatch',
        message:
          'Email OTP recovery-code backup acknowledgement timestamp does not match enrollment',
      };
    }
    return enrollment;
  }

  async persistPrepared(
    persistence: D1EmailOtpRegistrationEnrollmentPersistence,
  ): Promise<D1EmailOtpRegistrationEnrollmentPersistResult> {
    if (persistence.providerEnrollmentMove === 'delete_previous') {
      await this.emailOtpEnrollments.deleteEnrollment(persistence.previousProviderWalletId);
    }
    await this.emailOtpEnrollments.putEnrollment(persistence.enrollment);
    await this.emailOtpRecoveryEscrows.putMany(persistence.recoveryWrappedEnrollmentEscrows);
    const records = await this.emailOtpRecoveryEscrows.listForEnrollment(persistence.enrollment);
    const activeRecoveryWrappedEnrollmentEscrowCount = countActiveRecoveryEscrows(records);
    if (activeRecoveryWrappedEnrollmentEscrowCount !== EMAIL_OTP_RECOVERY_KEY_COUNT) {
      return {
        ok: false,
        code: 'internal',
        message: `Email OTP enrollment persisted ${activeRecoveryWrappedEnrollmentEscrowCount} active recovery-wrapped escrows; expected ${EMAIL_OTP_RECOVERY_KEY_COUNT}`,
      };
    }
    await this.emailOtpEnrollments.resetAuthStateForEnrollment({
      enrollment: persistence.enrollment,
      existingState: persistence.existingAuthState,
      updatedAtMs: persistence.enrollment.updatedAtMs,
    });
    return { ok: true };
  }

  async persistVerifiedEnrollment(input: {
    readonly walletId: string;
    readonly orgId: string;
    readonly authSubjectId: string;
    readonly verifiedEmail: string;
    readonly material: EmailOtpEnrollmentMaterialBoundaryInput;
    readonly registrationAttemptId?: string;
    readonly nowMs: number;
  }): Promise<D1EmailOtpVerifiedRegistrationEnrollmentPersistResult> {
    const canonicalWalletExists = await this.emailOtpEnrollments.signerWalletExists(input.walletId);
    if (!canonicalWalletExists) {
      return {
        ok: false,
        code: 'wallet_registration_incomplete',
        message:
          'Email OTP enrollment requires an existing canonical wallet. New wallet registration must finalize through /wallets/register/finalize.',
      };
    }
    const prepared = await this.buildPersistence(input);
    if (!prepared.ok) return prepared;
    const persisted = await this.persistPrepared(prepared.persistence);
    if (!persisted.ok) return persisted;
    const completedRegistration = await this.googleEmailOtpSessions.completeRegistrationAttempt({
      registrationAttemptId: input.registrationAttemptId,
      walletId: input.walletId,
    });
    if (!completedRegistration.ok) return completedRegistration;
    return {
      ok: true,
      enrollment: {
        createdAtMs: prepared.persistence.enrollment.createdAtMs,
        updatedAtMs: prepared.persistence.enrollment.updatedAtMs,
        enrollmentSealKeyVersion: prepared.persistence.enrollment.enrollmentSealKeyVersion,
        unlockKeyVersion: prepared.persistence.enrollment.unlockKeyVersion,
      },
    };
  }

  private async buildPersistence(input: {
    readonly walletId: string;
    readonly orgId: string;
    readonly authSubjectId: string;
    readonly verifiedEmail: string;
    readonly material: EmailOtpEnrollmentMaterialBoundaryInput;
    readonly nowMs: number;
  }): Promise<D1EmailOtpRegistrationEnrollmentBuildResult> {
    const enrollmentMaterial = await validateEmailOtpEnrollmentMaterial({
      material: input.material,
      sha256Bytes,
      validateSecp256k1PublicKey33,
    });
    if (!enrollmentMaterial.ok) return enrollmentMaterial;
    const orgId = toOptionalTrimmedString(input.orgId) || '';
    const walletId = toOptionalTrimmedString(input.walletId) || '';
    const authSubjectId = toOptionalTrimmedString(input.authSubjectId) || '';
    const verifiedEmail = toOptionalTrimmedString(input.verifiedEmail)?.toLowerCase() || '';
    if (!orgId || !walletId || !authSubjectId || !verifiedEmail) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP registration enrollment requires wallet, org, and email identity',
      };
    }
    const existing = await this.emailOtpEnrollments.readEnrollment(walletId);
    const existingAuthState = await this.emailOtpEnrollments.readAuthState(walletId);
    const enrollmentScope = enrollmentMaterial.recoveryWrappedEnrollmentEscrows[0];
    if (!enrollmentScope) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
      };
    }
    for (const record of enrollmentMaterial.recoveryWrappedEnrollmentEscrows) {
      if (
        record.walletId !== walletId ||
        record.userId !== authSubjectId ||
        record.authSubjectId !== authSubjectId ||
        record.enrollmentSealKeyVersion !== enrollmentMaterial.enrollmentSealKeyVersion ||
        record.recoveryKeyStatus !== 'active'
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrow metadata does not match registration',
        };
      }
    }
    const enrollment: EmailOtpWalletEnrollmentRecord = {
      version: 'email_otp_wallet_enrollment_v1',
      walletId,
      providerUserId: authSubjectId,
      orgId,
      verifiedEmail,
      enrollmentId: enrollmentScope.enrollmentId,
      enrollmentVersion: enrollmentScope.enrollmentVersion,
      enrollmentSealKeyVersion: enrollmentMaterial.enrollmentSealKeyVersion,
      signingRootId: enrollmentScope.signingRootId,
      signingRootVersion: enrollmentScope.signingRootVersion,
      recoveryWrappedEnrollmentEscrowCount:
        enrollmentMaterial.recoveryWrappedEnrollmentEscrows.length,
      clientUnlockPublicKeyB64u: enrollmentMaterial.clientUnlockPublicKeyB64u,
      unlockKeyVersion: enrollmentMaterial.unlockKeyVersion,
      thresholdEcdsaClientVerifyingShareB64u:
        enrollmentMaterial.thresholdEcdsaClientVerifyingShareB64u,
      createdAtMs: existing?.createdAtMs ?? input.nowMs,
      updatedAtMs: input.nowMs,
    };
    const existingProviderEnrollment =
      await this.emailOtpEnrollments.readEnrollmentByProviderUserId({
        providerUserId: enrollment.providerUserId,
        orgId: enrollment.orgId,
      });
    const recoveryWrappedEnrollmentEscrows = recoveryEscrowsWithUpdatedAt({
      records: enrollmentMaterial.recoveryWrappedEnrollmentEscrows,
      updatedAtMs: input.nowMs,
    });
    if (existingProviderEnrollment && existingProviderEnrollment.walletId !== enrollment.walletId) {
      return {
        ok: true,
        persistence: {
          providerEnrollmentMove: 'delete_previous',
          previousProviderWalletId: existingProviderEnrollment.walletId,
          enrollment,
          recoveryWrappedEnrollmentEscrows,
          existingAuthState,
        },
      };
    }
    return {
      ok: true,
      persistence: {
        providerEnrollmentMove: 'none',
        enrollment,
        recoveryWrappedEnrollmentEscrows,
        existingAuthState,
      },
    };
  }
}
