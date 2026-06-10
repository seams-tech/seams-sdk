import type {
  EmailOtpEnrollmentResult,
  EmailOtpRecoveryCodeRotationMaterial,
} from './publicTypes';
import type { EmailOtpRecoveryCodeSet } from '@shared/utils/emailOtpRecoveryKey';

declare const rawRecoveryKeys: string[];

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
