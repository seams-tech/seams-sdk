import {
  buildThresholdEcdsaHssRoleLocalClientBootstrapWasm,
  parseServerPlannedEcdsaHssContext,
  type ServerPlannedEcdsaHssContext,
  type ThresholdEcdsaHssRoleLocalClientContext,
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

const roleLocalClientContext: ThresholdEcdsaHssRoleLocalClientContext = {
  walletSessionUserId: toWalletSessionUserId('wallet-user'),
  subjectId: toEcdsaHssWalletSubjectId('wallet-subject'),
  ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId('ehss-stable'),
  signingRootId: toEcdsaHssSigningRootId('project:dev'),
  signingRootVersion: toEcdsaHssSigningRootVersion('default'),
  keyPurpose: 'evm-signing',
  keyVersion: 'v1',
};

void ({
  ...roleLocalClientContext,
  // @ts-expect-error role-local client context excludes chain-specific HSS derivation fields.
  chainTarget: {
    kind: 'evm',
    namespace: 'eip155',
    chainId: 11155111,
    networkSlug: 'ethereum-sepolia',
  },
} satisfies ThresholdEcdsaHssRoleLocalClientContext);

declare const workerCtx: WorkerOperationContext;

async function assertRoleLocalBootstrapShape(): Promise<void> {
  const bootstrap = await buildThresholdEcdsaHssRoleLocalClientBootstrapWasm({
    context: roleLocalClientContext,
    clientRootShare32B64u: 'client-root-share',
    workerCtx,
  });
  void (bootstrap.clientCaitSithInput satisfies {
    participantId: 1;
    mappedPrivateShare32B64u: string;
    verifyingShare33B64u: string;
  });
}

void assertRoleLocalBootstrapShape;
