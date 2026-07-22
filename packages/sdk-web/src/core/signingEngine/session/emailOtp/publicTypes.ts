import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { EmailOtpRecoveryCodeSet } from '@shared/utils/emailOtpRecoveryKey';
import type { WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';

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

export type DemoEmailOtpCodeResponse = Extract<
  EmailOtpChallengeDelivery,
  { otpCode: string }
>;

export type EmailOtpEnrollmentResult = {
  thresholdEcdsaClientVerifyingShareB64u: string;
  recoveryKeys: EmailOtpRecoveryCodeSet;
  recoveryCodesIssuedAtMs: number;
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
  clientUnlockPublicKeyB64u: string;
  unlockKeyVersion: string;
};

export type EmailOtpRecoveryCodeBackupStatus = {
  status: 'active';
  walletId: string;
  enrollmentId: string;
  recoveryCodeCount: number;
  issuedAtMs: number;
  storedAtMs: number;
  activeRecoveryCodeCountAtBackup: number;
};

export type EmailOtpRecoveryCodeLifecycleStatus = 'ready' | 'incomplete' | 'not_enrolled';

export type EmailOtpRecoveryCodeStatus = {
  status: EmailOtpRecoveryCodeLifecycleStatus;
  walletId: string;
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
  expectedRecoveryCodeCount: number;
  activeRecoveryCodeCount: number;
  consumedRecoveryCodeCount: number;
  revokedRecoveryCodeCount: number;
  totalRecoveryCodeCount: number;
  issuedAtMs: number | null;
};

export type EmailOtpRecoveryCodeRotationMaterial = {
  walletId: string;
  userId: string;
  providerUserId: string;
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  recoveryKeys: EmailOtpRecoveryCodeSet;
  recoveryCodesIssuedAtMs: number;
  activeRecoveryCodeCount: number;
  revokedRecoveryCodeCount: number;
  totalRecoveryCodeCount: number;
};

export type EmailOtpDeviceEnrollmentRestoreResult = {
  walletId: string;
  userId: string;
  providerUserId: string;
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  recoveryKeyId: string;
  activeRecoveryWrappedEnrollmentEscrowCount: number;
};

export type EmailOtpDeviceEnrollmentRemoveResult = {
  walletId: string;
  providerUserId: string;
  enrollmentId: string;
  removed: true;
};

export type GoogleEmailOtpSessionExchangeResult = {
  jwt?: string;
  session: {
    userId: string;
    walletId: string;
    email?: string;
    name?: string;
    googleEmailOtpResolution?: {
      mode: 'existing_wallet' | 'register_started';
      registrationAttemptId?: string;
      expiresAt?: string;
      expiresAtMs?: number;
      loginChallenge?:
        | {
            delivery: EmailOtpChallengeDelivery;
            challengeId: string;
            emailHint?: string;
            expiresAt?: string;
            expiresAtMs?: number;
          }
        | {
            delivery: 'rate_limited';
            retryAfterMs?: number;
            resetAtMs?: number;
          };
      offer?: {
        offerId: string;
        selectedCandidateId: string;
        candidates: readonly [
          { candidateId: string; walletId: string },
          ...{ candidateId: string; walletId: string }[],
        ];
      };
    };
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  };
};
