import type { EmailOtpEnrollmentResult } from './publicTypes';
import type { EmailOtpRecoveryCodeSet } from '@shared/utils/emailOtpRecoveryKey';

declare const rawRecoveryKeys: string[];

// @ts-expect-error raw string arrays must be normalized into a fixed recovery-code set.
const invalidRecoveryCodeSet: EmailOtpRecoveryCodeSet = rawRecoveryKeys;
void invalidRecoveryCodeSet;

declare const rawWorkerEnrollmentOutput: {
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
