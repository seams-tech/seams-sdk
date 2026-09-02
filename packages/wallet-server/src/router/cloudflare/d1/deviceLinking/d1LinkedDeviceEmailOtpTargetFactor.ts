/**
 * Refactor 103 Phase 6.2 — the D1 composition behind the linked-device Email
 * OTP challenge routes and the approval-time base-factor provenance reader.
 *
 * Everything identity-bearing is resolved server-side: the destination comes
 * from the wallet's active verified enrollment, the base factor from the
 * canonical wallet auth-method store, and the target authority identity
 * from the enrollment identity. Device 2 supplies only the code it received
 * and its worker's ephemeral recipient key. Challenges reuse the Refactor 100
 * issuer, verifier, rate limits, and lockouts under the dedicated
 * `wallet_email_otp_device_link` purpose, bound by a digest over the whole
 * device-link context.
 */
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceEmailOtpFactorReleaseEnvelopeV1,
  LinkedDeviceEmailOtpBaseFactorRequestV1,
  LinkedDeviceEmailOtpBaseFactorResolutionV1,
  LinkedDeviceEmailOtpVerificationGrantV1,
  LinkedDeviceTargetPreparationV1,
  LinkedDeviceEmailOtpEnrollmentSelectionV1,
} from '@shared/device-linking/contracts';
import { computeLinkedDeviceTargetPreparationDigestV1 } from '@shared/device-linking/digests';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { sha256HexUtf8 } from '@shared/utils/digests';
import type {
  WalletAuthMethodId,
  WalletId,
  VerifiedEmailAddress,
} from '@shared/utils/domainIds';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_DEVICE_LINK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import {
  computeLinkedDeviceEmailOtpAuthorityDigestV1,
  computeLinkedDeviceEmailOtpChallengeBindingDigestV1,
  computeLinkedDeviceEmailOtpGrantTokenDigestV1,
  linkedDeviceEmailOtpDescriptorCredentialIdV1,
  linkedDeviceEmailOtpGrantAdmitsUseV1,
  parseLinkedDeviceEmailOtpGrantRecordV1,
} from '../../../../core/deviceLinking/linkedDeviceEmailOtpGrant';
import type { LinkedDeviceSessionRecordV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type { D1WalletAuthorityStore } from '../wallet/d1WalletAuthorityStore';
import type { EmailOtpWalletEnrollmentRecord } from '../../../../core/EmailOtpStores';
import { sealEmailOtpFactorSecretForWorker } from '../../../domains/emailOtp/emailOtpRouteHandlers';
import type { DeviceLinkingEmailOtpTargetFactorProviderV1 } from '../../../transport/fetch/routes/deviceLinking';
import type {
  LinkedDeviceEmailOtpGrantRegistrationPortV1,
  VerifiedLinkedDeviceEmailOtpGrantV1,
} from './d1LinkedDeviceTargetCredentialProvider';
import type {
  CloudflareD1EmailOtpChallengeIssuer,
  EmailOtpChallengeIssueResult,
} from '../emailOtp/d1EmailOtpChallengeIssuer';
import type { CloudflareD1EmailOtpChallengeVerifier } from '../emailOtp/d1EmailOtpChallengeVerifier';
import type { CloudflareD1EmailOtpEnrollmentStore } from '../emailOtp/d1EmailOtpEnrollmentStore';
import type { CloudflareD1EmailOtpServerSealRuntime } from '../emailOtp/d1EmailOtpServerSealRuntime';
import { type D1LinkedDeviceEmailOtpGrantStoreV1 } from './d1LinkedDeviceEmailOtpGrantStore';

const DEFAULT_GRANT_TTL_MS = 5 * 60 * 1_000;
const DEFAULT_RESEND_COOLDOWN_MS = 30 * 1_000;

type ResolvedBaseFactorV1 = {
  readonly enrollment: EmailOtpWalletEnrollmentRecord;
  readonly emailHashHex: string;
  readonly registrationAuthorityId: string;
  readonly baseWalletAuthMethodId: WalletAuthMethodId;
  readonly maskedEmailHint: string;
};

type ResolvedChallengeContextV1 =
  | {
      readonly kind: 'existing_enrollment';
      readonly resolved: ResolvedBaseFactorV1;
      readonly targetEmail: VerifiedEmailAddress;
      readonly enrollment: Extract<
        LinkedDeviceEmailOtpEnrollmentSelectionV1,
        { readonly kind: 'existing_enrollment' }
      >;
      readonly targetPreparationDigestB64u: ReturnType<typeof parseDigestB64u>;
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly authorityDigestB64u: ReturnType<typeof parseDigestB64u>;
      readonly bindingDigestB64u: string;
    }
  | {
      readonly kind: 'new_enrollment';
      readonly targetEmail: VerifiedEmailAddress;
      readonly enrollment: Extract<
        LinkedDeviceEmailOtpEnrollmentSelectionV1,
        { readonly kind: 'new_enrollment' }
      >;
      readonly targetPreparationDigestB64u: ReturnType<typeof parseDigestB64u>;
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly authorityDigestB64u: ReturnType<typeof parseDigestB64u>;
      readonly bindingDigestB64u: string;
      readonly providerUserId: string;
      readonly orgId: string;
    };

type SentEmailOtpChallengeV1 = Extract<
  NonNullable<
    Extract<
      LinkedDeviceSessionRecordV1,
      { readonly targetFactor: { readonly kind: 'email_otp' } }
    >['emailOtpChallenge']
  >,
  { readonly state: 'sent' }
>;

function resolveSentEmailOtpChallengeV1(
  session: LinkedDeviceSessionRecordV1,
  challengeId: string,
): SentEmailOtpChallengeV1 | null {
  if (
    session.state.state !== 'awaiting_target_factor' ||
    session.targetFactor?.kind !== 'email_otp'
  ) {
    return null;
  }
  const challenge = session.emailOtpChallenge;
  if (!challenge || challenge.state !== 'sent' || challenge.challengeId !== challengeId) {
    return null;
  }
  return challenge;
}

export type D1LinkedDeviceEmailOtpTargetFactorOptionsV1 = {
  readonly issuer: Pick<CloudflareD1EmailOtpChallengeIssuer, 'create'>;
  readonly verifier: Pick<
    CloudflareD1EmailOtpChallengeVerifier,
    'verifyExisting' | 'verifyRegistration'
  >;
  readonly enrollments: Pick<CloudflareD1EmailOtpEnrollmentStore, 'readEnrollment'>;
  readonly orgId: string;
  readonly walletAuthMethods: {
    listForWalletV2(input: { readonly walletId: string }): Promise<WalletAuthMethodRecordV2[]>;
  };
  readonly walletAuthorities: Pick<D1WalletAuthorityStore, 'readById'>;
  readonly serverSeal: Pick<CloudflareD1EmailOtpServerSealRuntime, 'removeEmailOtpServerSeal'>;
  readonly grants: Pick<
    D1LinkedDeviceEmailOtpGrantStoreV1,
    'issueV1' | 'readByIdV1' | 'buildConsumeStatementsV1'
  >;
  readonly grantTtlMs?: number;
  readonly resendCooldownMs?: number;
};

export type LinkedDeviceEmailOtpTargetEnrollmentResolutionV1 =
  | {
      readonly kind: 'existing_enrollment';
      readonly targetEmail: VerifiedEmailAddress;
    }
  | {
      readonly kind: 'new_enrollment';
      readonly targetEmail: VerifiedEmailAddress;
    }
  | {
      readonly kind: 'conflict';
      readonly message: string;
    };

export class D1LinkedDeviceEmailOtpTargetFactorV1 implements DeviceLinkingEmailOtpTargetFactorProviderV1 {
  private readonly options: D1LinkedDeviceEmailOtpTargetFactorOptionsV1;
  private readonly grantTtlMs: number;
  private readonly resendCooldownMs: number;

  constructor(options: D1LinkedDeviceEmailOtpTargetFactorOptionsV1) {
    this.options = options;
    this.grantTtlMs = requirePositiveMs(options.grantTtlMs ?? DEFAULT_GRANT_TTL_MS, 'grantTtlMs');
    this.resendCooldownMs = requirePositiveMs(
      options.resendCooldownMs ?? DEFAULT_RESEND_COOLDOWN_MS,
      'resendCooldownMs',
    );
  }

  async resolveTargetEnrollmentV1(input: {
    readonly walletId: WalletId;
    readonly targetEmail: VerifiedEmailAddress;
  }): Promise<LinkedDeviceEmailOtpTargetEnrollmentResolutionV1> {
    const enrollment = await this.options.enrollments.readEnrollment(String(input.walletId));
    if (!enrollment) {
      return { kind: 'new_enrollment', targetEmail: input.targetEmail };
    }
    if (enrollment.verifiedEmail !== input.targetEmail) {
      return {
        kind: 'conflict',
        message: 'target Email OTP address conflicts with the wallet enrollment',
      };
    }
    const candidates = await this.listEligibleBaseFactorsV1(input.walletId);
    return candidates.length > 0
      ? { kind: 'existing_enrollment', targetEmail: input.targetEmail }
      : { kind: 'new_enrollment', targetEmail: input.targetEmail };
  }

  async resolveBaseFactorSelectionV1(input: {
    readonly walletId: WalletId;
    readonly request: LinkedDeviceEmailOtpBaseFactorRequestV1;
  }): Promise<LinkedDeviceEmailOtpBaseFactorResolutionV1> {
    const candidates = await this.listEligibleBaseFactorsV1(input.walletId);
    if (input.request.kind === 'select') {
      const selected = candidates.find(
        (candidate) => candidate.baseWalletAuthMethodId === input.request.baseWalletAuthMethodId,
      );
      return selected
        ? {
            kind: 'selected',
            choice: {
              baseWalletAuthMethodId: selected.baseWalletAuthMethodId,
              maskedEmailHint: selected.maskedEmailHint,
            },
          }
        : { kind: 'unavailable', reason: 'no_active_email_otp_base_factor' };
    }
    if (candidates.length === 0) {
      return { kind: 'unavailable', reason: 'no_active_email_otp_base_factor' };
    }
    const choices = candidates.map((candidate) => ({
      baseWalletAuthMethodId: candidate.baseWalletAuthMethodId,
      maskedEmailHint: candidate.maskedEmailHint,
    }));
    if (choices.length === 1) {
      return { kind: 'selected', choice: choices[0]! };
    }
    return { kind: 'selection_required', choices: [choices[0]!, ...choices.slice(1)] };
  }

  async startChallengeV1(
    input:
      | {
          readonly session: LinkedDeviceSessionRecordV1;
          readonly approval: LinkedDeviceApprovalV1;
          readonly preparation: LinkedDeviceTargetPreparationV1;
          readonly resend: false;
          readonly requestedAtMs: number;
        }
      | {
          readonly session: LinkedDeviceSessionRecordV1;
          readonly approval: LinkedDeviceApprovalV1;
          readonly preparation: LinkedDeviceTargetPreparationV1;
          readonly resend: true;
          readonly requestedAtMs: number;
        },
  ): Promise<
    | {
        readonly kind: 'sent';
        readonly challengeId: string;
        readonly maskedEmailHint: string;
        readonly expiresAtMs: number;
        readonly resendAvailableAtMs: number;
      }
    | { readonly kind: 'refused'; readonly code: string; readonly message: string }
  > {
    const context = await this.resolveChallengeContextV1(input.approval, input.preparation);
    if (context.kind === 'refused') return context;
    let issued: EmailOtpChallengeIssueResult;
    if (context.kind === 'new_enrollment') {
      issued = await this.options.issuer.create({
        userId: context.providerUserId,
        email: context.targetEmail,
        walletId: String(input.approval.walletId),
        orgId: context.orgId,
        otpChannel: EMAIL_OTP_CHANNEL,
        ownerProofBindingDigest: context.bindingDigestB64u,
        action: WALLET_EMAIL_OTP_ACTIONS.registration,
        operation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
        // A fresh start reuses an outstanding challenge instead of racing it;
        // an explicit resend, arriving after the route's cooldown gate, mints anew.
        reuseActiveChallenge: !input.resend,
      });
    } else {
      issued = await this.options.issuer.create({
        userId: context.resolved.enrollment.providerUserId,
        walletId: String(input.approval.walletId),
        orgId: context.resolved.enrollment.orgId,
        otpChannel: EMAIL_OTP_CHANNEL,
        ownerProofBindingDigest: context.bindingDigestB64u,
        action: WALLET_EMAIL_OTP_ACTIONS.deviceLink,
        operation: WALLET_EMAIL_OTP_DEVICE_LINK_OPERATION,
        reuseActiveChallenge: !input.resend,
      });
    }
    if (!issued.ok) {
      return { kind: 'refused', code: issued.code, message: issued.message };
    }
    return {
      kind: 'sent',
      challengeId: issued.challenge.challengeId,
      // Resolved first: the issuer's delivery hint is the masked form shared
      // with every other Email OTP surface, and this branch shows the address
      // in full (see resolveBaseFactorV1).
      maskedEmailHint:
        (context.kind === 'existing_enrollment' ? context.resolved.maskedEmailHint : '') ||
        issued.delivery.emailHint,
      expiresAtMs: issued.challenge.expiresAtMs,
      resendAvailableAtMs: issued.challenge.issuedAtMs + this.resendCooldownMs,
    };
  }

  async verifyChallengeV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly challengeId: string;
    readonly otpCode: string;
    readonly requestedAtMs: number;
  }): Promise<
    | {
        readonly kind: 'verified';
        readonly grant: LinkedDeviceEmailOtpVerificationGrantV1;
        readonly factorRelease: LinkedDeviceEmailOtpFactorReleaseEnvelopeV1 | null;
      }
    | { readonly kind: 'refused'; readonly code: string; readonly message: string }
  > {
    const context = await this.resolveChallengeContextV1(input.approval, input.preparation);
    if (context.kind === 'refused') return context;
    const challenge = resolveSentEmailOtpChallengeV1(input.session, input.challengeId);
    if (!challenge) {
      return {
        kind: 'refused',
        code: 'release_recipient_missing',
        message: 'the link session has no worker recipient for this challenge',
      };
    }
    if (context.kind === 'new_enrollment') {
      return await this.verifyNewEnrollmentChallengeV1({ input, context, challenge });
    }
    const recipientKey = challenge.workerEphemeralPublicKey65B64u;
    const verified = await this.options.verifier.verifyExisting({
      userId: context.resolved.enrollment.providerUserId,
      walletId: String(input.approval.walletId),
      orgId: context.resolved.enrollment.orgId,
      challengeId: input.challengeId,
      otpCode: input.otpCode,
      otpChannel: EMAIL_OTP_CHANNEL,
      ownerProofBindingDigest: context.bindingDigestB64u,
      action: WALLET_EMAIL_OTP_ACTIONS.deviceLink,
      operation: WALLET_EMAIL_OTP_DEVICE_LINK_OPERATION,
    });
    if (!verified.ok) {
      return { kind: 'refused', code: verified.code, message: verified.message };
    }
    const issuedAtMs = input.requestedAtMs;
    // The grant must not outlive the artifacts it authorizes against.
    const expiresAtMs = Math.min(
      issuedAtMs + this.grantTtlMs,
      input.approval.expiresAtMs,
      input.preparation.expiresAtMs,
    );
    if (expiresAtMs <= issuedAtMs) {
      return {
        kind: 'refused',
        code: 'enrollment_expired',
        message: 'linked-device enrollment has no remaining lifetime for a grant',
      };
    }
    const grantId = randomTokenB64u(16);
    const grantToken = randomTokenB64u(32);
    const grantRecord = parseLinkedDeviceEmailOtpGrantRecordV1({
      kind: 'linked_device_email_otp_grant_record_v1',
      grantId,
      grantTokenDigestB64u: await computeLinkedDeviceEmailOtpGrantTokenDigestV1(grantToken),
      walletId: input.approval.walletId,
      linkSessionId: input.approval.linkSessionId,
      enrollmentId: input.approval.enrollmentId,
      deviceId: input.approval.deviceId,
      targetFactor: { kind: 'email_otp' },
      targetPreparationDigestB64u: context.targetPreparationDigestB64u,
      targetEmail: context.targetEmail,
      enrollment: { kind: 'existing_enrollment' },
      emailHashHex: context.resolved.emailHashHex,
      registrationAuthorityId: context.resolved.registrationAuthorityId,
      providerUserId: context.resolved.enrollment.providerUserId,
      baseWalletAuthMethodId: context.resolved.baseWalletAuthMethodId,
      walletAuthMethodId: context.walletAuthMethodId,
      authorityDigestB64u: context.authorityDigestB64u,
      challengeId: verified.challengeId,
      state: { kind: 'issued' },
      issuedAtMs,
      expiresAtMs,
    });
    // Release the existing factor material to the worker recipient key the
    // authenticated link-session device supplied. The AAD names the verified
    // challenge, so this ciphertext is useless outside this exact completion.
    const unsealed = await this.options.serverSeal.removeEmailOtpServerSeal({
      wrappedCiphertext: context.resolved.enrollment.serverSealedFactorCiphertextB64u,
    });
    if (!unsealed.ok) {
      return { kind: 'refused', code: unsealed.code, message: unsealed.message };
    }
    if (
      unsealed.enrollmentSealKeyVersion !== context.resolved.enrollment.enrollmentSealKeyVersion
    ) {
      return {
        kind: 'refused',
        code: 'scope_mismatch',
        message: 'Email OTP factor release seal key version changed',
      };
    }
    const sealed = await sealEmailOtpFactorSecretForWorker({
      factorSecret32B64u: unsealed.ciphertext,
      workerEphemeralPublicKey65B64u: recipientKey,
      walletId: String(input.approval.walletId),
      enrollmentId: context.resolved.enrollment.enrollmentId,
      enrollmentSealKeyVersion: context.resolved.enrollment.enrollmentSealKeyVersion,
      challengeId: verified.challengeId,
    });
    if (!sealed.ok) {
      return { kind: 'refused', code: sealed.code, message: sealed.message };
    }
    await this.options.grants.issueV1(grantRecord);
    return {
      kind: 'verified',
      grant: {
        kind: 'linked_device_email_otp_verification_grant_v1',
        grantId,
        grantToken,
        challengeId: verified.challengeId,
        linkSessionId: input.approval.linkSessionId,
        walletId: input.approval.walletId,
        enrollmentId: input.approval.enrollmentId,
        deviceId: input.approval.deviceId,
        targetPreparationDigestB64u: context.targetPreparationDigestB64u,
        targetEmail: context.targetEmail,
        enrollment: { kind: 'existing_enrollment' },
        baseWalletAuthMethodId: context.resolved.baseWalletAuthMethodId,
        emailHashHex: context.resolved.emailHashHex,
        registrationAuthorityId: context.resolved.registrationAuthorityId,
        providerUserId: context.resolved.enrollment.providerUserId,
        authorityDigestB64u: context.authorityDigestB64u,
        issuedAtMs,
        expiresAtMs,
      },
      factorRelease: {
        kind: 'email_otp_factor_release_v1',
        challengeId: verified.challengeId,
        enrollmentId: context.resolved.enrollment.enrollmentId,
        enrollmentSealKeyVersion: context.resolved.enrollment.enrollmentSealKeyVersion,
        serverEphemeralPublicKey65B64u: sealed.serverEphemeralPublicKey65B64u,
        nonce12B64u: sealed.nonce12B64u,
        ciphertextB64u: sealed.ciphertextB64u,
      },
    };
  }

  private async verifyNewEnrollmentChallengeV1(input: {
    readonly input: {
      readonly session: LinkedDeviceSessionRecordV1;
      readonly approval: LinkedDeviceApprovalV1;
      readonly preparation: LinkedDeviceTargetPreparationV1;
      readonly challengeId: string;
      readonly otpCode: string;
      readonly requestedAtMs: number;
    };
    readonly context: Extract<ResolvedChallengeContextV1, { readonly kind: 'new_enrollment' }>;
    readonly challenge: SentEmailOtpChallengeV1;
  }): Promise<
    | {
        readonly kind: 'verified';
        readonly grant: LinkedDeviceEmailOtpVerificationGrantV1;
        readonly factorRelease: null;
      }
    | { readonly kind: 'refused'; readonly code: string; readonly message: string }
  > {
    const verified = await this.options.verifier.verifyRegistration({
      providerSubject: input.context.providerUserId,
      walletId: String(input.input.approval.walletId),
      orgId: input.context.orgId,
      challengeId: input.input.challengeId,
      otpCode: input.input.otpCode,
      otpChannel: EMAIL_OTP_CHANNEL,
      ownerProofBindingDigest: input.context.bindingDigestB64u,
      proofEmail: input.context.targetEmail,
    });
    if (!verified.ok) {
      return { kind: 'refused', code: verified.code, message: verified.message };
    }
    if (
      verified.email !== input.context.targetEmail ||
      verified.challengeSubjectId !== input.context.providerUserId ||
      verified.challengeId !== input.challenge.challengeId
    ) {
      return {
        kind: 'refused',
        code: 'scope_mismatch',
        message: 'Email OTP registration challenge identity changed',
      };
    }
    const issuedAtMs = input.input.requestedAtMs;
    const expiresAtMs = Math.min(
      issuedAtMs + this.grantTtlMs,
      input.input.approval.expiresAtMs,
      input.input.preparation.expiresAtMs,
    );
    if (expiresAtMs <= issuedAtMs) {
      return {
        kind: 'refused',
        code: 'enrollment_expired',
        message: 'linked-device enrollment has no remaining lifetime for a grant',
      };
    }
    const grantId = randomTokenB64u(16);
    const grantToken = randomTokenB64u(32);
    const emailHashHex = await sha256HexUtf8(input.context.targetEmail);
    const grantRecord = parseLinkedDeviceEmailOtpGrantRecordV1({
      kind: 'linked_device_email_otp_grant_record_v1',
      grantId,
      grantTokenDigestB64u: await computeLinkedDeviceEmailOtpGrantTokenDigestV1(grantToken),
      walletId: input.input.approval.walletId,
      linkSessionId: input.input.approval.linkSessionId,
      enrollmentId: input.input.approval.enrollmentId,
      deviceId: input.input.approval.deviceId,
      targetFactor: { kind: 'email_otp' },
      targetPreparationDigestB64u: input.context.targetPreparationDigestB64u,
      targetEmail: input.context.targetEmail,
      enrollment: { kind: 'new_enrollment' },
      emailHashHex,
      registrationAuthorityId: verified.challengeId,
      providerUserId: input.context.providerUserId,
      walletAuthMethodId: input.context.walletAuthMethodId,
      authorityDigestB64u: input.context.authorityDigestB64u,
      challengeId: verified.challengeId,
      state: { kind: 'issued' },
      issuedAtMs,
      expiresAtMs,
    });
    await this.options.grants.issueV1(grantRecord);
    return {
      kind: 'verified',
      grant: {
        kind: 'linked_device_email_otp_verification_grant_v1',
        grantId,
        grantToken,
        challengeId: verified.challengeId,
        linkSessionId: input.input.approval.linkSessionId,
        walletId: input.input.approval.walletId,
        enrollmentId: input.input.approval.enrollmentId,
        deviceId: input.input.approval.deviceId,
        targetPreparationDigestB64u: input.context.targetPreparationDigestB64u,
        targetEmail: input.context.targetEmail,
        enrollment: { kind: 'new_enrollment' },
        emailHashHex,
        registrationAuthorityId: verified.challengeId,
        providerUserId: input.context.providerUserId,
        authorityDigestB64u: input.context.authorityDigestB64u,
        issuedAtMs,
        expiresAtMs,
      },
      factorRelease: null,
    };
  }

  async verifyRegistrationGrantV1(
    input: Parameters<LinkedDeviceEmailOtpGrantRegistrationPortV1['verifyRegistrationGrantV1']>[0],
  ): Promise<
    | { readonly kind: 'verified'; readonly grant: VerifiedLinkedDeviceEmailOtpGrantV1 }
    | { readonly kind: 'rejected'; readonly message: string }
  > {
    const wireGrant = input.registration.emailOtpVerificationGrant;
    if (input.registration.targetFactor.kind !== 'email_otp' || !wireGrant) {
      return { kind: 'rejected', message: 'Email OTP verification grant is missing' };
    }
    const durable = await this.options.grants.readByIdV1(wireGrant.grantId);
    if (!durable || !linkedDeviceEmailOtpGrantAdmitsUseV1(durable, input.requestedAtMs)) {
      return { kind: 'rejected', message: 'Email OTP verification grant is unavailable' };
    }
    const tokenDigest = await computeLinkedDeviceEmailOtpGrantTokenDigestV1(wireGrant.grantToken);
    if (!isEmailOtpTargetPreparationV1(input.preparation)) {
      return { kind: 'rejected', message: 'Email OTP target preparation is unavailable' };
    }
    const commonIdentityMatches =
      tokenDigest === durable.grantTokenDigestB64u &&
      durable.walletId === input.preparation.walletId &&
      durable.linkSessionId === input.preparation.linkSessionId &&
      durable.enrollmentId === input.preparation.enrollmentId &&
      durable.deviceId === input.preparation.deviceId &&
      durable.walletAuthMethodId === input.preparation.walletAuthMethodId &&
      durable.targetPreparationDigestB64u === input.registration.targetPreparationDigestB64u &&
      durable.targetEmail === input.preparation.targetEmail &&
      durable.targetEmail === wireGrant.targetEmail &&
      durable.enrollment.kind === input.preparation.enrollment.kind &&
      durable.enrollment.kind === wireGrant.enrollment.kind &&
      durable.authorityDigestB64u === wireGrant.authorityDigestB64u &&
      durable.challengeId === wireGrant.challengeId &&
      durable.issuedAtMs === wireGrant.issuedAtMs &&
      durable.expiresAtMs === wireGrant.expiresAtMs &&
      durable.targetEmail === wireGrant.targetEmail &&
      durable.emailHashHex === wireGrant.emailHashHex &&
      durable.registrationAuthorityId === wireGrant.registrationAuthorityId &&
      durable.providerUserId === wireGrant.providerUserId;
    if (!commonIdentityMatches) {
      return { kind: 'rejected', message: 'Email OTP verification grant identity changed' };
    }
    if (input.preparation.enrollment.kind === 'new_enrollment') {
      if (input.registration.emailOtpEnrollment === undefined) {
        return { kind: 'rejected', message: 'new Email OTP enrollment material is missing' };
      }
      if (durable.baseWalletAuthMethodId !== undefined || wireGrant.baseWalletAuthMethodId !== undefined) {
        return { kind: 'rejected', message: 'new Email OTP grant cannot carry a base factor' };
      }
      if (durable.targetEmail !== wireGrant.targetEmail) {
        return { kind: 'rejected', message: 'Email OTP target email changed' };
      }
      const existingEnrollment = await this.options.enrollments.readEnrollment(
        String(input.preparation.walletId),
      );
      if (existingEnrollment) {
        return { kind: 'rejected', message: 'wallet already has an Email OTP enrollment' };
      }
      return {
        kind: 'verified',
        grant: {
          grantId: durable.grantId,
          targetEmail: durable.targetEmail,
          enrollment: { kind: 'new_enrollment' },
          providerUserId: durable.providerUserId,
          authorityDigestB64u: durable.authorityDigestB64u,
          descriptorCredentialIdB64u: await linkedDeviceEmailOtpDescriptorCredentialIdV1(
            durable.walletAuthMethodId,
          ),
        },
      };
    }
    const baseWalletAuthMethodId = input.preparation.baseWalletAuthMethodId;
    if (!baseWalletAuthMethodId) {
      return { kind: 'rejected', message: 'existing Email OTP base factor is missing' };
    }
    const baseFactor = await this.resolveBaseFactorV1(
      input.preparation.walletId,
      baseWalletAuthMethodId,
    );
    if (
      !baseFactor ||
      durable.baseWalletAuthMethodId !== baseFactor.baseWalletAuthMethodId ||
      durable.baseWalletAuthMethodId !== wireGrant.baseWalletAuthMethodId ||
      baseFactor.emailHashHex !== wireGrant.emailHashHex ||
      baseFactor.registrationAuthorityId !== wireGrant.registrationAuthorityId ||
      baseFactor.enrollment.providerUserId !== wireGrant.providerUserId ||
      baseFactor.enrollment.verifiedEmail !== input.preparation.targetEmail
    ) {
      return { kind: 'rejected', message: 'Email OTP verification grant identity changed' };
    }
    return {
      kind: 'verified',
      grant: {
        grantId: durable.grantId,
        targetEmail: durable.targetEmail,
        enrollment: { kind: 'existing_enrollment' },
        providerUserId: durable.providerUserId,
        baseWalletAuthMethodId: durable.baseWalletAuthMethodId,
        authorityDigestB64u: durable.authorityDigestB64u,
        descriptorCredentialIdB64u: await linkedDeviceEmailOtpDescriptorCredentialIdV1(
          durable.walletAuthMethodId,
        ),
      },
    };
  }

  async buildCompletionStatementsV1(
    input: Parameters<
      LinkedDeviceEmailOtpGrantRegistrationPortV1['buildCompletionStatementsV1']
    >[0],
  ) {
    return this.options.grants.buildConsumeStatementsV1({
      grantId: input.grant.grantId,
      consumedAtMs: input.consumedAtMs,
    });
  }

  private async resolveChallengeContextV1(
    approval: LinkedDeviceApprovalV1,
    preparation: LinkedDeviceTargetPreparationV1,
  ): Promise<
    | ResolvedChallengeContextV1
    | { readonly kind: 'refused'; readonly code: string; readonly message: string }
  > {
    if (approval.targetFactor.kind !== 'email_otp') {
      return {
        kind: 'refused',
        code: 'wrong_target_factor',
        message: 'approved target factor is not email OTP',
      };
    }
    if (preparation.targetFactor.kind !== 'email_otp') {
      return {
        kind: 'refused',
        code: 'wrong_target_factor',
        message: 'target preparation is not email OTP',
      };
    }
    const targetEmail = approval.targetFactor.targetEmail;
    const enrollment = approval.targetFactor.enrollment;
    if (
      !targetEmail ||
      !enrollment ||
      !preparation.targetEmail ||
      !preparation.enrollment ||
      targetEmail !== preparation.targetEmail ||
      enrollment.kind !== preparation.enrollment.kind
    ) {
      return {
        kind: 'refused',
        code: 'target_changed',
        message: 'approved Email OTP target changed',
      };
    }
    const targetPreparationDigestB64u = parseDigestB64u(
      await computeLinkedDeviceTargetPreparationDigestV1(preparation),
    );
    const walletAuthMethodId = preparation.walletAuthMethodId;
    if (enrollment.kind === 'existing_enrollment') {
      const baseWalletAuthMethodId = preparation.baseWalletAuthMethodId;
      if (!baseWalletAuthMethodId || !approval.targetFactor.baseWalletAuthMethodId) {
        return {
          kind: 'refused',
          code: 'base_factor_unavailable',
          message: 'approved Email OTP base factor is missing',
        };
      }
      if (approval.targetFactor.baseWalletAuthMethodId !== baseWalletAuthMethodId) {
        return {
          kind: 'refused',
          code: 'base_factor_changed',
          message: 'approved Email OTP base factor changed',
        };
      }
      const resolved = await this.resolveBaseFactorV1(approval.walletId, baseWalletAuthMethodId);
      if (!resolved || resolved.enrollment.verifiedEmail !== targetEmail) {
        return {
          kind: 'refused',
          code: 'base_factor_unavailable',
          message: 'wallet has no active verified Email OTP factor for the target address',
        };
      }
      const authorityDigestB64u = await computeLinkedDeviceEmailOtpAuthorityDigestV1({
        walletId: approval.walletId,
        enrollmentId: approval.enrollmentId,
        deviceId: approval.deviceId,
        walletAuthMethodId,
        targetEmail,
        enrollment: { kind: 'existing_enrollment' },
        baseWalletAuthMethodId: resolved.baseWalletAuthMethodId,
      });
      const bindingDigestB64u = await computeLinkedDeviceEmailOtpChallengeBindingDigestV1({
        walletId: approval.walletId,
        linkSessionId: approval.linkSessionId,
        enrollmentId: approval.enrollmentId,
        deviceId: approval.deviceId,
        targetPreparationDigestB64u,
        targetEmail,
        enrollment: { kind: 'existing_enrollment' },
        baseWalletAuthMethodId: resolved.baseWalletAuthMethodId,
        walletAuthMethodId,
      });
      return {
        kind: 'existing_enrollment',
        resolved,
        targetEmail,
        enrollment: { kind: 'existing_enrollment' },
        targetPreparationDigestB64u,
        walletAuthMethodId,
        authorityDigestB64u,
        bindingDigestB64u,
      };
    }
    if (preparation.baseWalletAuthMethodId || approval.targetFactor.baseWalletAuthMethodId) {
      return {
        kind: 'refused',
        code: 'base_factor_changed',
        message: 'new Email OTP enrollment cannot carry an existing base factor',
      };
    }
    const existingEnrollment = await this.options.enrollments.readEnrollment(
      String(approval.walletId),
    );
    if (existingEnrollment) {
      return {
        kind: 'refused',
        code: 'target_enrollment_exists',
        message: 'wallet already has an Email OTP enrollment',
      };
    }
    const providerUserId = String(targetEmail);
    const authorityDigestB64u = await computeLinkedDeviceEmailOtpAuthorityDigestV1({
      walletId: approval.walletId,
      enrollmentId: approval.enrollmentId,
      deviceId: approval.deviceId,
      walletAuthMethodId,
      targetEmail,
      enrollment: { kind: 'new_enrollment' },
    });
    const bindingDigestB64u = await computeLinkedDeviceEmailOtpChallengeBindingDigestV1({
      walletId: approval.walletId,
      linkSessionId: approval.linkSessionId,
      enrollmentId: approval.enrollmentId,
      deviceId: approval.deviceId,
      targetPreparationDigestB64u,
      targetEmail,
      enrollment: { kind: 'new_enrollment' },
      walletAuthMethodId,
    });
    return {
      kind: 'new_enrollment',
      targetEmail,
      enrollment: { kind: 'new_enrollment' },
      targetPreparationDigestB64u,
      walletAuthMethodId,
      authorityDigestB64u,
      bindingDigestB64u,
      providerUserId,
      orgId: this.options.orgId,
    };
  }

  private async listEligibleBaseFactorsV1(walletId: WalletId): Promise<ResolvedBaseFactorV1[]> {
    const enrollment = await this.options.enrollments.readEnrollment(String(walletId));
    if (!enrollment || !enrollment.serverSealedFactorCiphertextB64u) return [];
    const emailHashHex = await sha256HexUtf8(enrollment.verifiedEmail);
    const methods = await this.options.walletAuthMethods.listForWalletV2({
      walletId: String(walletId),
    });
    const active = methods.filter(
      (method) => method.kind === 'email_otp' && method.status === 'active',
    );
    const candidates: ResolvedBaseFactorV1[] = [];
    for (const factor of active) {
      if (factor.kind !== 'email_otp' || factor.emailHashHex !== emailHashHex) continue;
      const authority = await this.options.walletAuthorities.readById(factor.walletAuthorityId);
      if (!authority || authority.state !== 'active' || authority.walletId !== walletId) continue;
      candidates.push({
        enrollment,
        emailHashHex,
        registrationAuthorityId: factor.registrationAuthorityId,
        baseWalletAuthMethodId: factor.walletAuthMethodId,
        maskedEmailHint: enrollment.verifiedEmail.trim().toLowerCase(),
      });
    }
    return candidates.sort((left, right) =>
      String(left.baseWalletAuthMethodId).localeCompare(String(right.baseWalletAuthMethodId)),
    );
  }

  private async resolveBaseFactorV1(
    walletId: WalletId,
    baseWalletAuthMethodId: WalletAuthMethodId,
  ): Promise<ResolvedBaseFactorV1 | null> {
    const candidates = await this.listEligibleBaseFactorsV1(walletId);
    return (
      candidates.find((candidate) => candidate.baseWalletAuthMethodId === baseWalletAuthMethodId) ??
      null
    );
  }
}

function isEmailOtpTargetPreparationV1(
  preparation: LinkedDeviceTargetPreparationV1,
): preparation is Extract<
  LinkedDeviceTargetPreparationV1,
  { readonly targetFactor: { readonly kind: 'email_otp' } }
> {
  return preparation.targetFactor.kind === 'email_otp';
}

export function linkedDeviceEmailOtpGrantRegistrationPortV1(
  provider: D1LinkedDeviceEmailOtpTargetFactorV1,
): LinkedDeviceEmailOtpGrantRegistrationPortV1 {
  return {
    verifyRegistrationGrantV1: (input) => provider.verifyRegistrationGrantV1(input),
    buildCompletionStatementsV1: (input) => provider.buildCompletionStatementsV1(input),
  };
}

function requirePositiveMs(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value;
}

function randomTokenB64u(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}
