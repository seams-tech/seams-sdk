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
  LinkedDeviceEmailOtpVerificationGrantV1,
  LinkedDeviceTargetPreparationV1,
} from '@shared/device-linking/contracts';
import { computeLinkedDeviceTargetPreparationDigestV1 } from '@shared/device-linking/digests';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { sha256HexUtf8 } from '@shared/utils/digests';
import type { WalletAuthMethodId, WalletId } from '@shared/utils/domainIds';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_DEVICE_LINK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import {
  walletAuthMethodRecordId,
  type WalletAuthMethodRecord,
} from '@shared/utils/registrationIntent';
import {
  computeLinkedDeviceEmailOtpAuthorityDigestV1,
  computeLinkedDeviceEmailOtpChallengeBindingDigestV1,
  computeLinkedDeviceEmailOtpGrantTokenDigestV1,
  parseLinkedDeviceEmailOtpGrantRecordV1,
} from '../../../../core/deviceLinking/linkedDeviceEmailOtpGrant';
import type {
  LinkedDeviceEmailOtpBaseFactorReaderV1,
  LinkedDeviceSessionRecordV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import type { EmailOtpWalletEnrollmentRecord } from '../../../../core/EmailOtpStores';
import { sealEmailOtpFactorSecretForWorker } from '../../../domains/emailOtp/emailOtpRouteHandlers';
import type { DeviceLinkingEmailOtpTargetFactorProviderV1 } from '../../../transport/fetch/routes/deviceLinking';
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
  readonly verifier: Pick<CloudflareD1EmailOtpChallengeVerifier, 'verifyExisting'>;
  readonly enrollments: Pick<CloudflareD1EmailOtpEnrollmentStore, 'readEnrollment'>;
  readonly walletAuthMethods: {
    listForWallet(input: { readonly walletId: string }): Promise<WalletAuthMethodRecord[]>;
  };
  readonly serverSeal: Pick<CloudflareD1EmailOtpServerSealRuntime, 'removeEmailOtpServerSeal'>;
  readonly grants: D1LinkedDeviceEmailOtpGrantStoreV1;
  readonly grantTtlMs?: number;
  readonly resendCooldownMs?: number;
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

  /**
   * Approval-time provenance: the one active verified base factor for this
   * wallet, or nothing. `null` refuses the approval outright — an `email_otp`
   * enrollment cannot be approved against a wallet without the factor.
   */
  async readActiveEmailOtpBaseFactorV1(input: { readonly walletId: WalletId }): Promise<{
    readonly baseWalletAuthMethodId: WalletAuthMethodId;
    readonly maskedEmailHint: string;
  } | null> {
    const resolved = await this.resolveBaseFactorV1(input.walletId);
    if (!resolved) return null;
    return {
      baseWalletAuthMethodId: resolved.baseWalletAuthMethodId,
      maskedEmailHint: resolved.maskedEmailHint,
    };
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
    const issued: EmailOtpChallengeIssueResult = await this.options.issuer.create({
      userId: context.resolved.enrollment.providerUserId,
      walletId: String(input.approval.walletId),
      orgId: context.resolved.enrollment.orgId,
      otpChannel: EMAIL_OTP_CHANNEL,
      ownerProofBindingDigest: context.bindingDigestB64u,
      action: WALLET_EMAIL_OTP_ACTIONS.deviceLink,
      operation: WALLET_EMAIL_OTP_DEVICE_LINK_OPERATION,
      // A fresh start reuses an outstanding challenge instead of racing it; an
      // explicit resend, arriving after the route's cooldown gate, mints anew.
      reuseActiveChallenge: !input.resend,
    });
    if (!issued.ok) {
      return { kind: 'refused', code: issued.code, message: issued.message };
    }
    return {
      kind: 'sent',
      challengeId: issued.challenge.challengeId,
      // Resolved first: the issuer's delivery hint is the masked form shared
      // with every other Email OTP surface, and this branch shows the address
      // in full (see resolveBaseFactorV1).
      maskedEmailHint: context.resolved.maskedEmailHint || issued.delivery.emailHint,
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
        readonly factorRelease: LinkedDeviceEmailOtpFactorReleaseEnvelopeV1;
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

  private async resolveChallengeContextV1(
    approval: LinkedDeviceApprovalV1,
    preparation: LinkedDeviceTargetPreparationV1,
  ): Promise<
    | {
        readonly kind: 'resolved';
        readonly resolved: ResolvedBaseFactorV1;
        readonly targetPreparationDigestB64u: ReturnType<typeof parseDigestB64u>;
        readonly walletAuthMethodId: WalletAuthMethodId;
        readonly authorityDigestB64u: ReturnType<typeof parseDigestB64u>;
        readonly bindingDigestB64u: string;
      }
    | { readonly kind: 'refused'; readonly code: string; readonly message: string }
  > {
    if (approval.targetFactor.kind !== 'email_otp') {
      return {
        kind: 'refused',
        code: 'wrong_target_factor',
        message: 'approved target factor is not email OTP',
      };
    }
    const resolved = await this.resolveBaseFactorV1(approval.walletId);
    if (!resolved) {
      return {
        kind: 'refused',
        code: 'base_factor_unavailable',
        message: 'wallet has no active verified Email OTP factor',
      };
    }
    const targetPreparationDigestB64u = parseDigestB64u(
      await computeLinkedDeviceTargetPreparationDigestV1(preparation),
    );
    const walletAuthMethodId = preparation.walletAuthMethodId;
    const authorityDigestB64u = await computeLinkedDeviceEmailOtpAuthorityDigestV1({
      walletId: approval.walletId,
      enrollmentId: approval.enrollmentId,
      deviceId: approval.deviceId,
      walletAuthMethodId,
      baseWalletAuthMethodId: resolved.baseWalletAuthMethodId,
    });
    const bindingDigestB64u = await computeLinkedDeviceEmailOtpChallengeBindingDigestV1({
      walletId: approval.walletId,
      linkSessionId: approval.linkSessionId,
      enrollmentId: approval.enrollmentId,
      deviceId: approval.deviceId,
      targetPreparationDigestB64u,
      baseWalletAuthMethodId: resolved.baseWalletAuthMethodId,
      walletAuthMethodId,
    });
    return {
      kind: 'resolved',
      resolved,
      targetPreparationDigestB64u,
      walletAuthMethodId,
      authorityDigestB64u,
      bindingDigestB64u,
    };
  }

  private async resolveBaseFactorV1(walletId: WalletId): Promise<ResolvedBaseFactorV1 | null> {
    const enrollment = await this.options.enrollments.readEnrollment(String(walletId));
    if (!enrollment) return null;
    const emailHashHex = await sha256HexUtf8(enrollment.verifiedEmail);
    const methods = await this.options.walletAuthMethods.listForWallet({
      walletId: String(walletId),
    });
    const active = methods.filter(
      (method) => method.kind === 'email_otp' && method.status === 'active',
    );
    // Exactly one active factor, and it must be the enrollment's destination.
    // Anything else is an inconsistent wallet, which fails closed.
    if (active.length !== 1) return null;
    const factor = active[0];
    if (!factor || factor.kind !== 'email_otp' || factor.emailHashHex !== emailHashHex) {
      return null;
    }
    const baseWalletAuthMethodId = walletAuthMethodRecordId(factor);
    return {
      enrollment,
      emailHashHex,
      registrationAuthorityId: factor.registrationAuthorityId,
      baseWalletAuthMethodId,
      // The linked-device flow shows the address in full: device 2 has already
      // scanned device 1's code, so masking hides the one fact the user needs
      // to confirm the code is going somewhere they can read. The field keeps
      // its `maskedEmailHint` name because it is a shared wire field; only this
      // branch fills it with the verified address. Every other Email OTP
      // surface still masks, through `maskEmail` in the delivery runtime.
      //
      // Normalized, not raw: device 1 claims this same value from its local
      // account identity, and the provenance check compares the two as
      // strings. The mask helpers both trimmed and lower-cased internally, so
      // removing them without restating that here would make the comparison
      // sensitive to stored casing for the first time.
      maskedEmailHint: enrollment.verifiedEmail.trim().toLowerCase(),
    };
  }
}

/** The provenance reader the session service consumes at approval time. */
export function linkedDeviceEmailOtpBaseFactorReaderV1(
  provider: D1LinkedDeviceEmailOtpTargetFactorV1,
): LinkedDeviceEmailOtpBaseFactorReaderV1 {
  return {
    readActiveEmailOtpBaseFactorV1: (input) => provider.readActiveEmailOtpBaseFactorV1(input),
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
