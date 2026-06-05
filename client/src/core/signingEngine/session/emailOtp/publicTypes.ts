import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { EmailOtpRecoveryCodeSet } from '@shared/utils/emailOtpRecoveryKey';
import type { WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';

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
  acknowledgedAtMs: number;
  activeRecoveryCodeCountAtAcknowledgement: number;
};

export type EmailOtpRecoveryCodeLifecycleStatus =
  | 'ready'
  | 'pending_backup'
  | 'incomplete'
  | 'not_enrolled';

export type EmailOtpRecoveryCodeStatus = {
  status: EmailOtpRecoveryCodeLifecycleStatus;
  walletId: string;
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
  expectedRecoveryCodeCount: number;
  activeRecoveryCodeCount: number;
  pendingBackupRecoveryCodeCount: number;
  consumedRecoveryCodeCount: number;
  revokedRecoveryCodeCount: number;
  abandonedRecoveryCodeCount: number;
  totalRecoveryCodeCount: number;
  issuedAtMs: number | null;
  acknowledgedAtMs: number | null;
};

export type EmailOtpDeviceEnrollmentRestoreResult = {
  walletId: string;
  userId: string;
  authSubjectId: string;
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  recoveryKeyId: string;
  activeRecoveryWrappedEnrollmentEscrowCount: number;
};

export type EmailOtpDeviceEnrollmentRemoveResult = {
  walletId: string;
  authSubjectId: string;
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
    };
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  };
};
