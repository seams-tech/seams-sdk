import type { EvmSignedResult } from '../../chainAdaptors/evm/evmAdapter';
import type { EvmSigningRequest } from '../../chainAdaptors/evm/types';
import type { TempoSignedResult } from '../../chainAdaptors/tempo/tempoAdapter';
import type { TempoSigningRequest } from '../../chainAdaptors/tempo/types';
import {
  type EvmEip155ChainTarget,
  type TempoChainTarget,
  type ThresholdEcdsaChainTarget,
} from '../../session/signingSession/ecdsaChainTarget';
import type {
  CreateSigningFlowEventInput,
  SigningFlowEvent,
} from '@/core/types/sdkSentEvents';

export type EvmFamilySenderSignatureAlgorithm =
  | EvmSigningRequest['senderSignatureAlgorithm']
  | TempoSigningRequest['senderSignatureAlgorithm'];

export type EvmFamilyChain = 'tempo' | 'evm';

export type TempoEcdsaSigningTarget = {
  chain: 'tempo';
  chainTarget: TempoChainTarget;
};

export type EvmEcdsaSigningTarget = {
  chain: 'evm';
  chainTarget: EvmEip155ChainTarget;
};

export type EvmFamilySigningTarget = TempoEcdsaSigningTarget | EvmEcdsaSigningTarget;

export function evmFamilySigningTargetFromExplicitTarget(args: {
  request: TempoSigningRequest | EvmSigningRequest;
  chainTarget: ThresholdEcdsaChainTarget;
}): EvmFamilySigningTarget {
  const requestChainId = Number(args.request.tx.chainId);
  if (!Number.isSafeInteger(requestChainId) || requestChainId <= 0) {
    throw new Error('[SigningEngine][ecdsa] transaction request requires a concrete chainId');
  }
  if (requestChainId !== args.chainTarget.chainId) {
    throw new Error('[SigningEngine][ecdsa] transaction request chainId does not match chainTarget');
  }
  if (args.request.chain === 'tempo' && args.chainTarget.kind !== 'tempo') {
    throw new Error('[SigningEngine][ecdsa] Tempo transaction request requires a Tempo target');
  }
  return args.chainTarget.kind === 'tempo'
    ? { chain: 'tempo', chainTarget: args.chainTarget }
    : { chain: 'evm', chainTarget: args.chainTarget };
}

export type EvmFamilyLifecycleEvent = Omit<
  CreateSigningFlowEventInput,
  'flowId' | 'accountId'
> & {
  flowId?: string;
  accountId?: string;
};

export type EvmFamilyLifecycleEventCallback = (event: SigningFlowEvent) => void;

export type EvmFamilyLifecycleArgsBase = {
  nearAccountId: string;
  signedResult: TempoSignedResult | EvmSignedResult;
  onEvent?: EvmFamilyLifecycleEventCallback;
};

export type EvmFamilyBroadcastAcceptedArgs = EvmFamilyLifecycleArgsBase & {
  txHash?: `0x${string}`;
};

export type EvmFamilyBroadcastRejectedArgs = EvmFamilyLifecycleArgsBase & {
  error?: unknown;
};

export type EvmFamilyFinalizedArgs = EvmFamilyLifecycleArgsBase & {
  txHash?: `0x${string}`;
  receiptStatus?: 'success' | 'reverted';
};

export type EvmFamilyDroppedOrReplacedArgs = EvmFamilyLifecycleArgsBase & {
  reason: 'dropped' | 'replaced';
  txHash?: `0x${string}`;
};

export type EvmFamilyReconcileLaneArgs = EvmFamilyLifecycleArgsBase;

export type EvmFamilyNonceLaneStatus = {
  chainNextNonce: string;
  unresolvedInFlightNonces: string[];
  blocked: boolean;
  blockedNonce?: string;
};
