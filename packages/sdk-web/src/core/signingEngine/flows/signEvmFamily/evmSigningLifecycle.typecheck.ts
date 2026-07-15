import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EvmFamilySharedEcdsaPublicIdentityOnlyState,
  EvmFamilySharedEcdsaReadyState,
  EvmFamilySharedEcdsaState,
  FutureEpochMs,
  PositiveSignatureUses,
} from './ecdsaMaterialState';
import type { VerifiedEcdsaPublicFacts } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { EvmFamilyEcdsaAuthMethod } from './ecdsaLanes';
import type { EcdsaSessionIdentity } from '../../session/warmCapabilities/ecdsaProvisionPlan';
import type { TempoSignedResult } from '../../chains/tempo/tempoAdapter';
import type { EvmFamilyBroadcastAcceptedArgs } from './types';

declare const walletId: string;
declare const authMethod: EvmFamilyEcdsaAuthMethod;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const publishedTargets: readonly ThresholdEcdsaChainTarget[];
declare const sharedPublicFacts: VerifiedEcdsaPublicFacts;
declare const identity: EcdsaSessionIdentity;
declare const remainingSignatureUses: PositiveSignatureUses;
declare const expiresAtMs: FutureEpochMs;
declare const tempoSignedResult: TempoSignedResult;

const acceptedBroadcast: EvmFamilyBroadcastAcceptedArgs = {
  walletId,
  signedResult: tempoSignedResult,
  txHash: `0x${'11'.repeat(32)}`,
};
void acceptedBroadcast;

// @ts-expect-error Broadcast acceptance requires the network transaction identity.
const acceptedBroadcastWithoutTxHash: EvmFamilyBroadcastAcceptedArgs = {
  walletId,
  signedResult: tempoSignedResult,
};
void acceptedBroadcastWithoutTxHash;

const readyState: EvmFamilySharedEcdsaReadyState = {
  kind: 'ready_to_sign',
  walletId,
  authMethod,
  sourceChainTarget: chainTarget,
  publishedTargets,
  sharedPublicFacts,
  signingGrantId: identity.signingGrantId,
  thresholdSessionId: identity.thresholdSessionId,
  remainingSignatureUses,
  expiresAtMs,
  signerMaterial: {
    kind: 'worker_handle',
    workerSessionId: 'worker-session',
  },
};
void readyState;

const publicIdentityStateWithSignerMaterial: EvmFamilySharedEcdsaPublicIdentityOnlyState = {
  kind: 'public_identity_only',
  walletId,
  authMethod,
  sourceChainTarget: chainTarget,
  publishedTargets,
  sharedPublicFacts,
  // @ts-expect-error Display-only public identity state cannot carry signer material.
  signerMaterial: {
    kind: 'worker_handle',
    workerSessionId: 'worker-session',
  },
};
void publicIdentityStateWithSignerMaterial;

// @ts-expect-error Ready ECDSA state requires signer material.
const readyStateMissingSignerMaterial: EvmFamilySharedEcdsaReadyState = {
  kind: 'ready_to_sign',
  walletId,
  authMethod,
  sourceChainTarget: chainTarget,
  publishedTargets,
  sharedPublicFacts,
  signingGrantId: identity.signingGrantId,
  thresholdSessionId: identity.thresholdSessionId,
  remainingSignatureUses,
  expiresAtMs,
};
void readyStateMissingSignerMaterial;

function assertNeverEvmFamilyState(state: never): never {
  throw new Error(String((state as { kind?: unknown })?.kind || 'unknown'));
}

declare const state: EvmFamilySharedEcdsaState;

switch (state.kind) {
  case 'unavailable':
  case 'public_identity_only':
  case 'restorable':
  case 'ready_to_sign':
  case 'ready_for_export':
    break;
  default:
    assertNeverEvmFamilyState(state);
}

export {};
