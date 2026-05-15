import {
  toWalletSubjectId,
  walletSessionRefFromSession,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ExecuteEvmFamilyTransactionArgs,
  NearSignerCapability,
  SignTempoArgs,
} from './interfaces';

const walletSession = walletSessionRefFromSession({
  walletId: 'wallet.testnet',
  walletSessionUserId: 'wallet-user',
});
const subjectId = toWalletSubjectId('wallet-subject');
const tempoChainTarget = {
  kind: 'tempo',
  chainId: 1313,
  networkSlug: 'tempo-local',
} satisfies ThresholdEcdsaChainTarget;
const tempoRequest = {} as SignTempoArgs['request'];

const invalidSignTempoAccountIdentity: SignTempoArgs = {
  walletSession,
  // @ts-expect-error ECDSA public signing rejects account-shaped identity.
  nearAccountId: 'wallet.testnet',
  subjectId,
  request: tempoRequest,
  chainTarget: tempoChainTarget,
};
void invalidSignTempoAccountIdentity;

const invalidExecuteEvmAccountIdentity: ExecuteEvmFamilyTransactionArgs = {
  walletSession,
  // @ts-expect-error EVM-family public signing rejects account-shaped identity.
  nearAccountId: 'wallet.testnet',
  subjectId,
  request: tempoRequest,
  chainTarget: tempoChainTarget,
};
void invalidExecuteEvmAccountIdentity;

// @ts-expect-error NEAR public signing requires a NearAccountRef.
const invalidNearExecuteAction: Parameters<NearSignerCapability['executeAction']>[0] = {
  receiverId: 'contract.testnet',
  actionArgs: [],
  options: {} as Parameters<NearSignerCapability['executeAction']>[0]['options'],
};
void invalidNearExecuteAction;

export {};
