import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  type ThresholdEcdsaSigningQueueByKey,
  withThresholdEcdsaSigningQueue,
} from './signingQueue';

declare const queueByKey: ThresholdEcdsaSigningQueueByKey;

void withThresholdEcdsaSigningQueue({
  queueByKey,
  queueKey: 'wallet:alice.testnet:evm-family-ecdsa',
  walletId: toWalletId('alice.testnet'),
  enabled: true,
  task: async () => 'ok',
});

void withThresholdEcdsaSigningQueue({
  queueByKey,
  queueKey: 'wallet:alice.testnet:evm-family-ecdsa',
  // @ts-expect-error threshold ECDSA signing queue requires WalletId.
  walletId: 'alice.testnet',
  enabled: true,
  task: async () => 'ok',
});

export {};
