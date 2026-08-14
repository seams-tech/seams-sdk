import type { AuthorizationService } from './service';
import {
  buildVerifiedWalletOperationEmailOtpFactorResult,
  buildVerifiedWalletOperationPasskeyFactorResult,
  buildVerifiedOwnerProof,
  buildVerifiedWalletSessionPasskeyFactorResult,
  type VerifiedAuthorizationEvidenceSet,
} from './factorEvidence';

type WalletEmailOtpFactorInput = Parameters<
  typeof buildVerifiedWalletOperationEmailOtpFactorResult
>[0];
type WalletPasskeyFactorInput = Parameters<
  typeof buildVerifiedWalletOperationPasskeyFactorResult
>[0];
type WalletFactorForbiddenKey =
  | 'sessionId'
  | 'deviceId'
  | 'appSessionVersion'
  | 'walletSessionId'
  | 'quotaId';
type WalletFactorsRejectSessionFields =
  Extract<
    keyof WalletEmailOtpFactorInput | keyof WalletPasskeyFactorInput,
    WalletFactorForbiddenKey
  > extends never
    ? true
    : false;

type StructuralEvidenceSet = {
  readonly [K in keyof VerifiedAuthorizationEvidenceSet]: VerifiedAuthorizationEvidenceSet[K];
};
declare const structuralEvidenceSet: StructuralEvidenceSet;
declare const service: AuthorizationService;
const walletFactorsRejectSessionFields: WalletFactorsRejectSessionFields = true;
type WalletSessionFactorInput = Parameters<
  typeof buildVerifiedWalletSessionPasskeyFactorResult
>[0];
type WalletSessionFactorRejectsSessionFields = Extract<
  keyof WalletSessionFactorInput,
  WalletFactorForbiddenKey
> extends never
  ? true
  : false;
const walletSessionFactorRejectsSessionFields: WalletSessionFactorRejectsSessionFields = true;

// @ts-expect-error verified evidence sets retain nominal post-verification proof
const forgedEvidenceSet: VerifiedAuthorizationEvidenceSet = structuralEvidenceSet;

// @ts-expect-error the service exposes no generic verified-evidence persistence bypass
service.recordVerifiedEvidenceSet(forgedEvidenceSet);

void forgedEvidenceSet;
void walletFactorsRejectSessionFields;
void walletSessionFactorRejectsSessionFields;

const forgedOwnerProofInput = {
  purpose: 'wallet_session' as const,
  proofId: 'proof',
  factor: { kind: 'verified_wallet_session_passkey_factor' as const },
};
// @ts-expect-error owner proofs are created from verified factors, never browser-shaped fields.
buildVerifiedOwnerProof(forgedOwnerProofInput);
