import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { listStoredThresholdEcdsaSessionRecordsForWallet } from '@/core/signingEngine/session/persistence/records';
import {
  selectEmailOtpEcdsaRecordForEd25519Signing,
  type EmailOtpCompanionSessionAttachResult,
  type EmailOtpEcdsaRecordForEd25519SigningSelectionResult,
} from './companionSessions';

declare const walletId: WalletId;
declare const listRecords: typeof listStoredThresholdEcdsaSessionRecordsForWallet;
declare const signingGrantId: string;
declare const selectionResult: EmailOtpEcdsaRecordForEd25519SigningSelectionResult;

void selectEmailOtpEcdsaRecordForEd25519Signing({
  kind: 'latest_wallet_record',
  walletId,
  listThresholdEcdsaSessionRecordsForWallet: listRecords,
});

void selectEmailOtpEcdsaRecordForEd25519Signing({
  kind: 'signing_grant_exact',
  walletId,
  signingGrantId,
  listThresholdEcdsaSessionRecordsForWallet: listRecords,
});

// @ts-expect-error Exact companion selection requires signingGrantId.
void selectEmailOtpEcdsaRecordForEd25519Signing({
  kind: 'signing_grant_exact',
  walletId,
  listThresholdEcdsaSessionRecordsForWallet: listRecords,
});

void selectEmailOtpEcdsaRecordForEd25519Signing({
  kind: 'latest_wallet_record',
  // @ts-expect-error Email OTP ECDSA companion selection requires WalletId.
  walletId: 'alice.testnet',
  listThresholdEcdsaSessionRecordsForWallet: listRecords,
});

function assertNeverEmailOtpEcdsaRecordSelection(
  result: never,
): never {
  throw new Error(String((result as { kind?: unknown })?.kind || 'unknown'));
}

switch (selectionResult.kind) {
  case 'exact_match':
  case 'ambiguous':
  case 'not_found':
  case 'display_only_fallback':
    break;
  default:
    assertNeverEmailOtpEcdsaRecordSelection(selectionResult);
}

function assertNeverEmailOtpCompanionSessionAttachResult(
  result: never,
): never {
  throw new Error(String((result as { kind?: unknown })?.kind || 'unknown'));
}

declare const attachResult: EmailOtpCompanionSessionAttachResult;

switch (attachResult.kind) {
  case 'attached':
  case 'already_attached':
  case 'not_required':
  case 'missing_required_material':
  case 'failed':
    break;
  default:
    assertNeverEmailOtpCompanionSessionAttachResult(attachResult);
}

export {};
