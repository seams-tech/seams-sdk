import {
  EMAIL_OTP_INITIAL_ENROLLMENT_VERSION,
  emailOtpDeviceEnrollmentId,
} from '@shared/utils/emailOtpDomain';
import type { RegistrationAuthority, WalletId } from '@shared/utils/registrationIntent';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  EmailOtpAuthStateRecord,
  EmailOtpWalletEnrollmentRecord,
} from '../../../../core/EmailOtpStores';
import type { WalletRegistrationFinalizeRequest } from '../../../../core/registrationContracts';
import type { D1PreparedStatementLike } from '../../../../storage/tenantRoute';
import { validateSecp256k1PublicKey33 } from '../../../../core/ThresholdService/evmCryptoWasm';
import type { CloudflareD1EmailOtpEnrollmentStore } from './d1EmailOtpEnrollmentStore';
import type { CloudflareD1GoogleEmailOtpSessionResolver } from './d1GoogleEmailOtpSessionResolver';
import {
  validateEmailOtpEnrollmentMaterial,
  type EmailOtpEnrollmentMaterialBoundaryInput,
} from './d1EmailOtpRecords';

type FinalizeWalletRegistrationInput = WalletRegistrationFinalizeRequest;

export type D1EmailOtpRegistrationEnrollmentPersistence =
  | {
      readonly providerEnrollmentMove: 'none';
      readonly previousProviderWalletId?: never;
      readonly enrollment: EmailOtpWalletEnrollmentRecord;
      readonly existingAuthState: EmailOtpAuthStateRecord | null;
    }
  | {
      readonly providerEnrollmentMove: 'delete_previous';
      readonly previousProviderWalletId: string;
      readonly enrollment: EmailOtpWalletEnrollmentRecord;
      readonly existingAuthState: EmailOtpAuthStateRecord | null;
    };

export type D1EmailOtpRegistrationCommitPlan = {
  readonly kind: 'd1_email_otp_registration_commit_plan_v1';
  readonly statements: readonly D1PreparedStatementLike[];
};

type EnrollmentResult =
  | { readonly ok: true; readonly persistence?: D1EmailOtpRegistrationEnrollmentPersistence }
  | { readonly ok: false; readonly code: string; readonly message: string };

type BuildResult =
  | { readonly ok: true; readonly persistence: D1EmailOtpRegistrationEnrollmentPersistence }
  | { readonly ok: false; readonly code: string; readonly message: string };

export class CloudflareD1EmailOtpRegistrationEnrollmentFinalizer {
  private readonly emailOtpEnrollments: CloudflareD1EmailOtpEnrollmentStore;
  private readonly googleEmailOtpSessions: CloudflareD1GoogleEmailOtpSessionResolver;

  constructor(input: {
    readonly emailOtpEnrollments: CloudflareD1EmailOtpEnrollmentStore;
    readonly googleEmailOtpSessions: CloudflareD1GoogleEmailOtpSessionResolver;
  }) {
    this.emailOtpEnrollments = input.emailOtpEnrollments;
    this.googleEmailOtpSessions = input.googleEmailOtpSessions;
  }

  async prepareRegistrationFinalize(input: {
    readonly authority: RegistrationAuthority;
    readonly request: Pick<FinalizeWalletRegistrationInput, 'emailOtpEnrollment'>;
    readonly walletId: WalletId;
    readonly orgId: string;
    readonly nowMs: number;
  }): Promise<EnrollmentResult> {
    if (input.authority.kind !== 'email_otp') {
      return input.request.emailOtpEnrollment
        ? {
            ok: false,
            code: 'invalid_body',
            message: 'Email OTP enrollment material is only valid for Email OTP registration',
          }
        : { ok: true };
    }
    if (!input.request.emailOtpEnrollment) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP registration finalize requires emailOtpEnrollment',
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
    return await this.buildPersistence({
      walletId: input.walletId,
      orgId: input.orgId,
      authSubjectId: input.authority.providerSubject,
      verifiedEmail: input.authority.email,
      material: input.request.emailOtpEnrollment,
      nowMs: input.nowMs,
    });
  }

  async persistPrepared(
    persistence: D1EmailOtpRegistrationEnrollmentPersistence,
  ): Promise<{ readonly ok: true }> {
    if (persistence.providerEnrollmentMove === 'delete_previous') {
      await this.emailOtpEnrollments.deleteEnrollment(persistence.previousProviderWalletId);
    }
    await this.emailOtpEnrollments.putEnrollment(persistence.enrollment);
    await this.emailOtpEnrollments.resetAuthStateForEnrollment({
      enrollment: persistence.enrollment,
      existingState: persistence.existingAuthState,
      updatedAtMs: persistence.enrollment.updatedAtMs,
    });
    return { ok: true };
  }

  prepareRegistrationCommitPlan(
    persistence: D1EmailOtpRegistrationEnrollmentPersistence,
  ): D1EmailOtpRegistrationCommitPlan {
    const statements: D1PreparedStatementLike[] = [];
    if (persistence.providerEnrollmentMove === 'delete_previous') {
      statements.push(
        this.emailOtpEnrollments.prepareDeleteEnrollmentStatement(
          persistence.previousProviderWalletId,
        ),
      );
    }
    statements.push(
      this.emailOtpEnrollments.preparePutEnrollmentStatement(persistence.enrollment),
      this.emailOtpEnrollments.prepareResetAuthStateForEnrollment({
        enrollment: persistence.enrollment,
        existingState: persistence.existingAuthState,
        updatedAtMs: persistence.enrollment.updatedAtMs,
      }).statement,
    );
    return { kind: 'd1_email_otp_registration_commit_plan_v1', statements };
  }

  async persistVerifiedEnrollment(input: {
    readonly walletId: string;
    readonly orgId: string;
    readonly authSubjectId: string;
    readonly verifiedEmail: string;
    readonly material: EmailOtpEnrollmentMaterialBoundaryInput;
    readonly registrationAttemptId?: string;
    readonly nowMs: number;
  }) {
    if (!(await this.emailOtpEnrollments.signerWalletExists(input.walletId))) {
      return {
        ok: false as const,
        code: 'wallet_registration_incomplete',
        message: 'Email OTP enrollment requires a canonical wallet',
      };
    }
    const prepared = await this.buildPersistence(input);
    if (!prepared.ok) return prepared;
    await this.persistPrepared(prepared.persistence);
    const completed = await this.googleEmailOtpSessions.completeRegistrationAttempt({
      registrationAttemptId: input.registrationAttemptId,
      walletId: input.walletId,
    });
    if (!completed.ok) return completed;
    const enrollment = prepared.persistence.enrollment;
    return {
      ok: true as const,
      enrollment: {
        createdAtMs: enrollment.createdAtMs,
        updatedAtMs: enrollment.updatedAtMs,
        enrollmentSealKeyVersion: enrollment.enrollmentSealKeyVersion,
        unlockKeyVersion: enrollment.unlockKeyVersion,
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
  }): Promise<BuildResult> {
    const material = await validateEmailOtpEnrollmentMaterial({
      material: input.material,
      validateSecp256k1PublicKey33,
    });
    if (!material.ok) return material;
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
    const enrollment: EmailOtpWalletEnrollmentRecord = {
      version: 'email_otp_wallet_enrollment_v1',
      walletId,
      providerUserId: authSubjectId,
      orgId,
      verifiedEmail,
      enrollmentId: emailOtpDeviceEnrollmentId(walletId, authSubjectId),
      enrollmentVersion: EMAIL_OTP_INITIAL_ENROLLMENT_VERSION,
      enrollmentSealKeyVersion: material.enrollmentSealKeyVersion,
      clientUnlockPublicKeyB64u: material.clientUnlockPublicKeyB64u,
      unlockKeyVersion: material.unlockKeyVersion,
      serverSealedFactorCiphertextB64u: material.serverSealedFactorCiphertextB64u,
      createdAtMs: existing?.createdAtMs ?? input.nowMs,
      updatedAtMs: input.nowMs,
    };
    const previous = await this.emailOtpEnrollments.readEnrollmentByProviderUserId({
      providerUserId: enrollment.providerUserId,
      orgId: enrollment.orgId,
    });
    return previous && previous.walletId !== enrollment.walletId
      ? {
          ok: true,
          persistence: {
            providerEnrollmentMove: 'delete_previous',
            previousProviderWalletId: previous.walletId,
            enrollment,
            existingAuthState,
          },
        }
      : {
          ok: true,
          persistence: { providerEnrollmentMove: 'none', enrollment, existingAuthState },
        };
  }
}
