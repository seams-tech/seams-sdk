import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { listWarmSessionEcdsaRecordsForWalletTarget } from './store';

declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;

void listWarmSessionEcdsaRecordsForWalletTarget({
  walletId,
  chainTarget,
});

void listWarmSessionEcdsaRecordsForWalletTarget({
  // @ts-expect-error warm-session ECDSA store lookups require WalletId.
  walletId: 'wallet.testnet',
  chainTarget,
});

export {};
