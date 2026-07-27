import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { AuthorizationService } from './service';
import {
  buildVerifiedEmailOtpFactorResult,
  buildVerifiedPasskeyFactorResult,
  type VerifiedGrantEvidenceSet,
} from './factorEvidence';

type EmailOtpFactorInput = Parameters<typeof buildVerifiedEmailOtpFactorResult>[0];
type PasskeyFactorInput = Parameters<typeof buildVerifiedPasskeyFactorResult>[0];

declare const missingOtpReceipt: Omit<EmailOtpFactorInput, 'verificationReceiptDigest'>;
declare const passkeyWithOtpReceipt: Omit<PasskeyFactorInput, 'assertionDigest'> & {
  readonly verificationReceiptDigest: DigestB64u;
};
type StructuralEvidenceSet = {
  readonly [K in keyof VerifiedGrantEvidenceSet]: VerifiedGrantEvidenceSet[K];
};
declare const structuralEvidenceSet: StructuralEvidenceSet;
declare const service: AuthorizationService;

// @ts-expect-error verified Email OTP evidence requires a consumed verification receipt
buildVerifiedEmailOtpFactorResult(missingOtpReceipt);

// @ts-expect-error a Passkey assertion digest cannot be replaced by an OTP receipt
buildVerifiedPasskeyFactorResult(passkeyWithOtpReceipt);

// @ts-expect-error verified evidence sets retain nominal post-verification proof
const forgedEvidenceSet: VerifiedGrantEvidenceSet = structuralEvidenceSet;

// @ts-expect-error the service exposes no generic verified-evidence persistence bypass
service.recordVerifiedEvidenceSet(forgedEvidenceSet);

void forgedEvidenceSet;
