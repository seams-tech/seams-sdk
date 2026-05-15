import { toWalletSubjectId } from '../../interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaHssStableKeyContext } from './hssClientSignerWasm';

const validStableContext: ThresholdEcdsaHssStableKeyContext = {
  walletSessionUserId: 'wallet-user',
  subjectId: toWalletSubjectId('wallet-subject'),
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
};
void validStableContext;

const stableContextWithWalletSigningSessionId: ThresholdEcdsaHssStableKeyContext = {
  ...validStableContext,
  // @ts-expect-error stable ECDSA HSS key context rejects volatile wallet session ids.
  walletSigningSessionId: 'wsess-1',
};
void stableContextWithWalletSigningSessionId;

const stableContextWithThresholdSessionId: ThresholdEcdsaHssStableKeyContext = {
  ...validStableContext,
  // @ts-expect-error stable ECDSA HSS key context rejects volatile threshold session ids.
  thresholdSessionId: 'tsess-1',
};
void stableContextWithThresholdSessionId;
