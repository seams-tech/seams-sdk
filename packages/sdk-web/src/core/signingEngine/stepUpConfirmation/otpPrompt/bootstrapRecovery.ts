export type EmailOtpBootstrapRecovery = {
  challengeId: string;
  enrollmentSealKeyVersion: string;
  unlockChallengeId: string;
  unlockChallengeB64u: string;
  clientUnlockPublicKeyB64u: string;
  unlockSignatureB64u: string;
  thresholdEd25519RecoveryCodeSecret32B64u?: string;
};
