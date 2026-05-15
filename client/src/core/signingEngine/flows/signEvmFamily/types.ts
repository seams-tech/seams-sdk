import type { EvmSignedResult } from '../../chains/evm/evmAdapter';
import type { EvmSigningRequest } from '../../chains/evm/types';
import type { TempoSignedResult } from '../../chains/tempo/tempoAdapter';
import type { TempoSigningRequest } from '../../chains/tempo/types';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  CreateSigningFlowEventInput,
  SigningFlowEvent,
} from '@/core/types/sdkSentEvents';
import type { EvmFamilyChain as EvmFamilyChainValue } from '../../interfaces/operationDeps';

export type EvmFamilySenderSignatureAlgorithm =
  | EvmSigningRequest['senderSignatureAlgorithm']
  | TempoSigningRequest['senderSignatureAlgorithm'];

export type EvmFamilyChain = EvmFamilyChainValue;

export type EvmFamilySigningTarget = ThresholdEcdsaChainTarget;

function evmFamilyRequestChainKind(
  request: TempoSigningRequest | EvmSigningRequest,
): ThresholdEcdsaChainTarget['kind'] | 'evm_compatible' {
  if (request.kind === 'tempoTransaction') return 'tempo';
  if (request.kind === 'eip1559') return 'evm_compatible';
  const requestChain = String((request as { chain?: unknown }).chain || '').trim();
  if (requestChain === 'tempo' || requestChain === 'evm') return requestChain;
  throw new Error('[SigningEngine][ecdsa] transaction request requires a concrete chain family');
}

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
  const requestChainKind = evmFamilyRequestChainKind(args.request);
  if (requestChainKind !== 'evm_compatible' && requestChainKind !== args.chainTarget.kind) {
    throw new Error('[SigningEngine][ecdsa] transaction request chain does not match chainTarget');
  }
  return args.chainTarget;
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
  walletId: string;
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
