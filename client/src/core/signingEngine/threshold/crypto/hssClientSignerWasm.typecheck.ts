import {
  parseServerPlannedEcdsaHssContext,
  prepareThresholdEcdsaHssSessionWasm,
  type ServerPlannedEcdsaHssContext,
  type ThresholdEcdsaHssStableKeyContext,
} from './hssClientSignerWasm';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
  toEcdsaHssWalletSubjectId,
  toWalletSessionUserId,
} from '../../session/identity/emailOtpHssIdentity';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';

const serverPlannedContext = parseServerPlannedEcdsaHssContext({
  walletSessionUserId: 'wallet-user',
  subjectId: 'wallet-subject',
  chainTarget: {
    kind: 'evm',
    namespace: 'eip155',
    chainId: 11155111,
    networkSlug: 'ethereum-sepolia',
  },
  ecdsaThresholdKeyId: 'ehss-stable',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  keyPurpose: 'evm-signing',
  keyVersion: 'v1',
});
void (serverPlannedContext satisfies ServerPlannedEcdsaHssContext);

const locallyConstructedStableContext: ThresholdEcdsaHssStableKeyContext = {
  walletSessionUserId: toWalletSessionUserId('wallet-user'),
  subjectId: toEcdsaHssWalletSubjectId('wallet-subject'),
  chainTarget: {
    kind: 'evm',
    namespace: 'eip155',
    chainId: 11155111,
    networkSlug: 'ethereum-sepolia',
  },
  ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId('ehss-stable'),
  signingRootId: toEcdsaHssSigningRootId('project:dev'),
  signingRootVersion: toEcdsaHssSigningRootVersion('default'),
  keyPurpose: 'evm-signing',
  keyVersion: 'v1',
};

void ({
  ...locallyConstructedStableContext,
  // @ts-expect-error stable ECDSA HSS key context requires branded wallet session ids.
  walletSessionUserId: 'wallet-user',
} satisfies ThresholdEcdsaHssStableKeyContext);

void ({
  ...locallyConstructedStableContext,
  // @ts-expect-error stable ECDSA HSS key context requires branded ECDSA key ids.
  ecdsaThresholdKeyId: 'ehss-stable',
} satisfies ThresholdEcdsaHssStableKeyContext);

const stableContextWithWalletSigningSessionId: ThresholdEcdsaHssStableKeyContext = {
  ...locallyConstructedStableContext,
  // @ts-expect-error stable ECDSA HSS key context rejects volatile wallet session ids.
  walletSigningSessionId: 'wsess-1',
};
void stableContextWithWalletSigningSessionId;

const stableContextWithThresholdSessionId: ThresholdEcdsaHssStableKeyContext = {
  ...locallyConstructedStableContext,
  // @ts-expect-error stable ECDSA HSS key context rejects volatile threshold session ids.
  thresholdSessionId: 'tsess-1',
};
void stableContextWithThresholdSessionId;

declare const workerCtx: WorkerOperationContext;

void prepareThresholdEcdsaHssSessionWasm({
  context: serverPlannedContext,
  clientRootShare32B64u: 'client-root-share',
  workerCtx,
});

void prepareThresholdEcdsaHssSessionWasm({
  // @ts-expect-error ECDSA HSS session preparation requires server-planned prepare context.
  context: locallyConstructedStableContext,
  clientRootShare32B64u: 'client-root-share',
  workerCtx,
});
