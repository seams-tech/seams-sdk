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

export type DemoEmailOtpCodeResponse = Extract<EmailOtpChallengeDelivery, { otpCode: string }>;

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

export type GoogleEmailOtpProviderResolution = {
  mode: 'existing_wallet';
  walletId: string;
  providerSubject: string;
  email?: string;
  hasEmailOtpEnrollment: true;
} | {
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
