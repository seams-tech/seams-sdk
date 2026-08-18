import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import {
  resolveThresholdEcdsaSigningQueueKey,
  type ThresholdEcdsaSigningQueueByKey,
  withThresholdEcdsaSigningQueue,
} from './signingQueue';

declare const queueByKey: ThresholdEcdsaSigningQueueByKey;
declare const materialActivation: MpcMaterialActivationRef;
const walletId = toWalletId('alice.testnet');

void withThresholdEcdsaSigningQueue({
  queueByKey,
  queueKey: 'material:alice.testnet:capability:activation',
  walletId,
  enabled: true,
  task: async () => 'ok',
});

void withThresholdEcdsaSigningQueue({
  queueByKey,
  queueKey: 'material:alice.testnet:capability:activation',
  // @ts-expect-error threshold ECDSA signing queue requires WalletId.
  walletId: 'alice.testnet',
  enabled: true,
  task: async () => 'ok',
});

void resolveThresholdEcdsaSigningQueueKey({ materialActivation });

void resolveThresholdEcdsaSigningQueueKey({
  // @ts-expect-error queue identity requires an exact material activation.
  walletId,
});

export {};
