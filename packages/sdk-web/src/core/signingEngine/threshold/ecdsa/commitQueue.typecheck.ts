import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  type ThresholdEcdsaCommitQueueByKey,
  withThresholdEcdsaCommitQueue,
} from './commitQueue';

declare const queueByKey: ThresholdEcdsaCommitQueueByKey;

void withThresholdEcdsaCommitQueue({
  queueByKey,
  queueKey: 'session:tempo:tsess-1',
  walletId: toWalletId('alice.testnet'),
  enabled: true,
  task: async () => 'ok',
});

void withThresholdEcdsaCommitQueue({
  queueByKey,
  queueKey: 'session:tempo:tsess-1',
  // @ts-expect-error threshold ECDSA commit queue requires WalletId.
  walletId: 'alice.testnet',
  enabled: true,
  task: async () => 'ok',
});

export {};
