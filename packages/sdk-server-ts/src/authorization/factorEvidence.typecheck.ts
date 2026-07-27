import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  buildVerifiedEmailOtpFactorResult,
  buildVerifiedPasskeyFactorResult,
} from './factorEvidence';

type EmailOtpFactorInput = Parameters<typeof buildVerifiedEmailOtpFactorResult>[0];
type PasskeyFactorInput = Parameters<typeof buildVerifiedPasskeyFactorResult>[0];

declare const missingOtpReceipt: Omit<EmailOtpFactorInput, 'verificationReceiptDigest'>;
declare const passkeyWithOtpReceipt: Omit<PasskeyFactorInput, 'assertionDigest'> & {
  readonly verificationReceiptDigest: DigestB64u;
};

// @ts-expect-error verified Email OTP evidence requires a consumed verification receipt
buildVerifiedEmailOtpFactorResult(missingOtpReceipt);

// @ts-expect-error a Passkey assertion digest cannot be replaced by an OTP receipt
buildVerifiedPasskeyFactorResult(passkeyWithOtpReceipt);
