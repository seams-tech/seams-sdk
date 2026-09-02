import type { WalletId } from '@shared/utils/domainIds';
import type { WalletRecoveryTargetV1 } from '@shared/wallet-recovery/walletRecoveryTarget';
import type { EmailOtpChallengeDelivery } from '@/core/signingEngine/session/emailOtp/publicTypes';

export type HostedRecoveryTargetKind = WalletRecoveryTargetV1['kind'];

export type HostedRecoveryFailure =
  | { readonly kind: 'dismissed' }
  | { readonly kind: 'consumed' }
  | { readonly kind: 'refused' }
  | { readonly kind: 'retryable_conflict' }
  | { readonly kind: 'transport_uncertain' };

type HostedRecoveryPreparedCommon = {
  readonly kind: 'hosted_recovery_prepared';
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
};

export type HostedRecoveryPrepared =
  | (HostedRecoveryPreparedCommon & {
      readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'passkey' }>;
    })
  | (HostedRecoveryPreparedCommon & {
      readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'google_email_otp' }>;
    });

export type HostedRecoveryCredentialCreated = {
  readonly kind: 'hosted_recovery_credential_created';
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
  readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'passkey' }>;
};

export type HostedRecoveryGoogleVerified = {
  readonly kind: 'hosted_recovery_google_verified';
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
  readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'google_email_otp' }>;
  readonly challengeId: string;
  readonly delivery: EmailOtpChallengeDelivery;
  readonly expiresAtMs: number;
};

export type HostedRecoveryEmailOtpVerified = {
  readonly kind: 'hosted_recovery_email_otp_verified';
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
  readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'google_email_otp' }>;
  readonly challengeId: string;
};

export type HostedRecoveryFinalizationOperation =
  | HostedRecoveryCredentialCreated
  | HostedRecoveryEmailOtpVerified;

export type HostedRecoveryPort = {
  targetFor(kind: HostedRecoveryTargetKind): WalletRecoveryTargetV1;

  prepare(input: {
    readonly recoveryCode: string;
    readonly target: WalletRecoveryTargetV1;
    readonly signal: AbortSignal;
  }): Promise<HostedRecoveryPrepared | HostedRecoveryFailure>;

  createPasskey(
    operation: HostedRecoveryPrepared,
  ): Promise<HostedRecoveryCredentialCreated | HostedRecoveryFailure>;

  verifyGoogle(
    operation: HostedRecoveryPrepared,
    idToken: string,
  ): Promise<HostedRecoveryGoogleVerified | HostedRecoveryFailure>;

  verifyEmailOtp(
    operation: HostedRecoveryGoogleVerified,
    input: { readonly challengeId: string; readonly otpCode: string },
  ): Promise<HostedRecoveryEmailOtpVerified | HostedRecoveryFailure>;

  finalize(
    operation: HostedRecoveryFinalizationOperation,
  ): Promise<
    { readonly kind: 'ready_for_sign_in'; readonly walletId: WalletId } | HostedRecoveryFailure
  >;

  cancel(
    operation:
      | HostedRecoveryPrepared
      | HostedRecoveryCredentialCreated
      | HostedRecoveryGoogleVerified
      | HostedRecoveryEmailOtpVerified,
  ): Promise<void>;
};
