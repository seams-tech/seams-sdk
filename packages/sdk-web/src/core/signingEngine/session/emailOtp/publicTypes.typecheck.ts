import type {
  EmailOtpEnrollmentResult,
  EmailOtpRecoveryCodeRotationMaterial,
} from './publicTypes';
import type { EmailOtpRecoveryCodeSet } from '@shared/utils/emailOtpRecoveryKey';

declare const rawRecoveryKeys: string[];
declare const parsedRecoveryKeys: EmailOtpRecoveryCodeSet;

// @ts-expect-error raw string arrays must be normalized into a fixed recovery-code set.
const invalidRecoveryCodeSet: EmailOtpRecoveryCodeSet = rawRecoveryKeys;
void invalidRecoveryCodeSet;

declare const rawWorkerEnrollmentOutput: {
  thresholdEcdsaClientVerifyingShareB64u: string;
  recoveryKeys: string[];
  recoveryCodesIssuedAtMs: number;
  challengeId: string;
  otpChannel: 'email';
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
  clientUnlockPublicKeyB64u: string;
  unlockKeyVersion: string;
};

// @ts-expect-error worker enrollment output must pass through the recovery-code parser.
const invalidEnrollmentFromRawOutput: EmailOtpEnrollmentResult = rawWorkerEnrollmentOutput;
void invalidEnrollmentFromRawOutput;

const broadSpreadWorkerEnrollmentOutput = {
  ...rawWorkerEnrollmentOutput,
};

// @ts-expect-error broad spreads cannot forge parsed Email OTP enrollment results.
const invalidEnrollmentFromBroadSpread: EmailOtpEnrollmentResult =
  broadSpreadWorkerEnrollmentOutput;
void invalidEnrollmentFromBroadSpread;

declare const rawWorkerRotationOutput: {
  walletId: string;
  userId: string;
  authSubjectId: string;
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  signingRootId: string;
  signingRootVersion: string;
  recoveryKeys: string[];
  recoveryCodesIssuedAtMs: number;
  activeRecoveryCodeCount: number;
  revokedRecoveryCodeCount: number;
  totalRecoveryCodeCount: number;
};

const broadSpreadWorkerRotationOutput = {
  ...rawWorkerRotationOutput,
};

// @ts-expect-error broad spreads cannot forge parsed Email OTP recovery-code rotations.
const invalidRotationFromBroadSpread: EmailOtpRecoveryCodeRotationMaterial =
  broadSpreadWorkerRotationOutput;
void invalidRotationFromBroadSpread;

const invalidRotationWithSigningRoot: EmailOtpRecoveryCodeRotationMaterial = {
  walletId: 'wallet-1',
  userId: 'user-1',
  providerUserId: 'subject-1',
  enrollmentId: 'enrollment-1',
  enrollmentVersion: 'v1',
  enrollmentSealKeyVersion: 'seal-v1',
  recoveryKeys: parsedRecoveryKeys,
  recoveryCodesIssuedAtMs: 1,
  activeRecoveryCodeCount: 1,
  revokedRecoveryCodeCount: 0,
  totalRecoveryCodeCount: 1,
  // @ts-expect-error rotation material must not expose signing-root identity.
  signingRootId: 'root-1',
};
void invalidRotationWithSigningRoot;
