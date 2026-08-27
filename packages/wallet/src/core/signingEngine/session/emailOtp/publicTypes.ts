import type { WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import { normalizeThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import {
  parseWalletAuthorityV1,
  type ActiveWalletAuthorityV1,
} from '@shared/authorization/walletAuthority';
import {
  parseMpcMaterialActivationRef,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import {
  parseWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';

export type EmailOtpUnlockEd25519Identity = {
  readonly materialActivation: MpcMaterialActivationRef;
  readonly nearAccountId: string;
  readonly signerSlot: number;
  readonly operationalPublicKey: string;
  readonly thresholdSessionId: string;
  readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
};

export type EmailOtpUnlockEd25519Selection =
  | {
      readonly kind: 'present';
    } & EmailOtpUnlockEd25519Identity
  | {
      readonly kind: 'absent';
    };

export type EmailOtpChallengeDeliveryStatus = 'sent' | 'reused';

export type EmailOtpChallengeDelivery =
  | {
      kind: 'provider';
      status: EmailOtpChallengeDeliveryStatus;
      emailHint: string;
      otpCode?: never;
    }
  | {
      kind: 'demo_code_response';
      status: EmailOtpChallengeDeliveryStatus;
      emailHint: string;
      otpCode: string;
    }
  | {
      kind: 'provider_and_demo_code';
      status: EmailOtpChallengeDeliveryStatus;
      emailHint: string;
      otpCode: string;
    };

export type DemoEmailOtpCodeResponse = Extract<EmailOtpChallengeDelivery, { otpCode: string }>;

export type EmailOtpUnlockSignerSelection =
  | {
      readonly kind: 'ecdsa';
      readonly keyHandle: string;
      readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
      readonly ed25519: EmailOtpUnlockEd25519Selection;
    }
  | {
      readonly kind: 'ed25519_only';
    } & EmailOtpUnlockEd25519Identity;

export function parseEmailOtpUnlockEd25519Identity(
  record: Record<string, unknown>,
): EmailOtpUnlockEd25519Identity {
  const materialActivation = parseMpcMaterialActivationRef(record.materialActivation);
  if (!materialActivation.ok) {
    throw new Error('Email OTP Ed25519 material activation is invalid');
  }
  const nearAccountId = String(record.nearAccountId || '').trim();
  const operationalPublicKey = String(record.operationalPublicKey || '').trim();
  const thresholdSessionId = String(record.thresholdSessionId || '').trim();
  const signerSlot = Number(record.signerSlot);
  if (!nearAccountId || !operationalPublicKey || !thresholdSessionId) {
    throw new Error('Email OTP Ed25519 signer identity is incomplete');
  }
  if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
    throw new Error('Email OTP Ed25519 signer slot is invalid');
  }
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(record.runtimePolicyScope);
  if (!runtimePolicyScope) {
    throw new Error('Email OTP Ed25519 runtime policy scope is invalid');
  }
  return {
    materialActivation: materialActivation.value,
    nearAccountId,
    signerSlot,
    operationalPublicKey,
    thresholdSessionId,
    runtimePolicyScope,
  };
}

export function parseEmailOtpUnlockEd25519Selection(
  raw: unknown,
): EmailOtpUnlockEd25519Selection {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('Email OTP Ed25519 signer selection must be an object');
  }
  const record = raw as Record<string, unknown>;
  if (record.kind === 'absent') return { kind: 'absent' };
  if (record.kind !== 'present') {
    throw new Error('Email OTP Ed25519 signer selection kind is invalid');
  }
  return { kind: 'present', ...parseEmailOtpUnlockEd25519Identity(record) };
}

export type EmailOtpVerifiedAuthorityProjection = {
  readonly kind: 'email_otp_verified_authority_projection_v1';
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: Extract<
    WalletAuthMethodRecordV2,
    { readonly kind: 'email_otp'; readonly status: 'active' }
  >;
};

export function parseEmailOtpVerifiedAuthorityProjection(
  raw: unknown,
): EmailOtpVerifiedAuthorityProjection {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('Email OTP verified authority projection must be an object');
  }
  const record = raw as Record<string, unknown>;
  if (record.kind !== 'email_otp_verified_authority_projection_v1') {
    throw new Error('Email OTP verified authority projection kind is invalid');
  }
  const authority = parseWalletAuthorityV1(record.authority);
  const authMethod = parseWalletAuthMethodRecordV2(record.authMethod);
  if (
    !authority.ok ||
    authority.value.state !== 'active' ||
    !authMethod ||
    authMethod.kind !== 'email_otp' ||
    authMethod.status !== 'active' ||
    authority.value.walletId !== authMethod.walletId ||
    authority.value.authorityId !== authMethod.walletAuthorityId
  ) {
    throw new Error('Email OTP verified authority projection is invalid');
  }
  return {
    kind: 'email_otp_verified_authority_projection_v1',
    authority: authority.value,
    authMethod,
  };
}

export type EmailOtpTransactionSigningChallenge = {
  challengeId: string;
  emailHint: string;
  delivery: EmailOtpChallengeDelivery;
};

export type EmailOtpEnrollmentResult = {
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
  serverSealedFactorCiphertextB64u: string;
  clientUnlockPublicKeyB64u: string;
  unlockKeyVersion: string;
};

export type GoogleEmailOtpProviderResolution =
  | {
      mode: 'existing_wallet';
      walletId: string;
      providerSubject: string;
      email: string;
      hasEmailOtpEnrollment: true;
    }
  | {
      mode: 'register_started';
      walletId: string;
      providerSubject: string;
      email: string;
      registrationAttemptId: string;
      expiresAtMs: number;
      offer: {
        offerId: string;
        selectedCandidateId: string;
        candidates: readonly [
          { candidateId: string; walletId: string },
          ...{ candidateId: string; walletId: string }[],
        ];
      };
    };
