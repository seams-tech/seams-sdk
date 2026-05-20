import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { listStoredThresholdEcdsaSessionRecordsForWallet } from '@/core/signingEngine/session/persistence/records';
import { selectEmailOtpEcdsaRecordForEd25519Signing } from './companionSessions';

declare const walletId: WalletId;
declare const listRecords: typeof listStoredThresholdEcdsaSessionRecordsForWallet;

void selectEmailOtpEcdsaRecordForEd25519Signing({
  walletId,
  listThresholdEcdsaSessionRecordsForWallet: listRecords,
});

void selectEmailOtpEcdsaRecordForEd25519Signing({
  // @ts-expect-error Email OTP ECDSA companion selection requires WalletId.
  walletId: 'alice.testnet',
  listThresholdEcdsaSessionRecordsForWallet: listRecords,
});

export {};
