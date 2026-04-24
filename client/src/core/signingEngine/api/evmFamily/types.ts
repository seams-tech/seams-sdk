import type { EvmSignedResult } from '../../chainAdaptors/evm/evmAdapter';
import type { EvmSigningRequest } from '../../chainAdaptors/evm/types';
import type { TempoSignedResult } from '../../chainAdaptors/tempo/tempoAdapter';
import type { TempoSigningRequest } from '../../chainAdaptors/tempo/types';
import type {
  CreateSigningFlowEventInput,
  SigningFlowEvent,
} from '@/core/types/sdkSentEvents';

export type EvmFamilySenderSignatureAlgorithm =
  | EvmSigningRequest['senderSignatureAlgorithm']
  | TempoSigningRequest['senderSignatureAlgorithm'];

export type EvmFamilyChain = 'tempo' | 'evm';

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
