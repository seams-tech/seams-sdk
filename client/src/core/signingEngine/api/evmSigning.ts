import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { toAccountId } from '@/core/types/accountIds';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { TatchiConfigs } from '@/core/types/tatchi';
import type { EvmSigningRequest } from '../chainAdaptors/evm/types';
import type { EvmSignedResult } from '../chainAdaptors/evm/evmAdapter';
import type { TempoSigningRequest } from '../chainAdaptors/tempo/types';
import type { TempoSignedResult } from '../chainAdaptors/tempo/tempoAdapter';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../interfaces/signing';
import {
  deriveSmartAccountDeploymentTargetFromSigningRequest,
  ensureSmartAccountDeployed,
} from '../orchestration/ensureSmartAccountDeployed';
import type {
  TouchConfirmContextPort,
  TouchConfirmSigningPort,
  ThresholdPrfFirstCacheDispensePort,
  ThresholdPrfFirstCachePeekPort,
} from '../touchConfirm';
import type { SignerWorkerManagerContext } from '../workerManager';
import {
  deploySmartAccountForChain,
  resolveSmartAccountDeploymentMaxAttempts,
  resolveSmartAccountDeploymentMode,
} from '../orchestration/smartAccountDeployment';

export type EvmFamilySigningDeps = {
  indexedDB: UnifiedIndexedDBManager;
  tatchiPasskeyConfigs: TatchiConfigs;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  touchConfirmManager:
    & TouchConfirmContextPort
    & TouchConfirmSigningPort
    & ThresholdPrfFirstCachePeekPort
    & ThresholdPrfFirstCacheDispensePort;
};

type EvmFamilySigningCancelledError = Error & { code: 'cancelled' };

function createEvmFamilySigningCancelledError(): EvmFamilySigningCancelledError {
  const err = new Error('Request cancelled') as EvmFamilySigningCancelledError;
  err.code = 'cancelled';
  return err;
}

function throwIfEvmFamilySigningCancelled(shouldAbort?: () => boolean): void {
  if (typeof shouldAbort === 'function' && shouldAbort()) {
    throw createEvmFamilySigningCancelledError();
  }
}

export async function signEvmFamily(
  deps: EvmFamilySigningDeps,
  args: {
    nearAccountId: string;
    request: TempoSigningRequest | EvmSigningRequest;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
    shouldAbort?: () => boolean;
    onEvent?: (event: {
      step: number;
      phase: string;
      status: 'progress' | 'success' | 'error';
      message?: string;
      data?: unknown;
    }) => void;
  },
): Promise<TempoSignedResult | EvmSignedResult> {
  throwIfEvmFamilySigningCancelled(args.shouldAbort);

  if (args.request.chain !== 'tempo' && args.request.chain !== 'evm') {
    throw new Error('[SigningEngine] invalid request: chain must be tempo or evm');
  }
  if (args.request.senderSignatureAlgorithm === 'secp256k1' && !args.thresholdEcdsaKeyRef) {
    throw new Error('[SigningEngine] secp256k1 signing requires thresholdEcdsaKeyRef');
  }
  if (args.request.senderSignatureAlgorithm === 'secp256k1') {
    const target = deriveSmartAccountDeploymentTargetFromSigningRequest(args.request);
    const deploymentMode = resolveSmartAccountDeploymentMode(deps.tatchiPasskeyConfigs);
    try {
      await ensureSmartAccountDeployed({
        clientDB: deps.indexedDB.clientDB,
        nearAccountId: toAccountId(args.nearAccountId),
        chain: target.chain,
        chainIdCandidates: target.chainIdCandidates,
        accountModelCandidates: target.accountModelCandidates,
        maxDeployAttempts: resolveSmartAccountDeploymentMaxAttempts(deps.tatchiPasskeyConfigs),
        ...(deploymentMode === 'enforce'
          ? {
              deploy: (input) =>
                deploySmartAccountForChain(deps.tatchiPasskeyConfigs, input),
              enforce: true,
            }
          : { enforce: false }),
      });
    } catch (error: unknown) {
      const details =
        String((error as { message?: unknown })?.message || error || '').trim()
        || 'deployment failed';
      throw new Error(
        `[SigningEngine] smart-account deployment must succeed before first ${target.chain.toUpperCase()} send: ${details}`,
      );
    }
  }

  throwIfEvmFamilySigningCancelled(args.shouldAbort);

  const [{ Secp256k1Engine }, { WebAuthnP256Engine }] = await Promise.all([
    import('../signers/algorithms/secp256k1'),
    import('../signers/algorithms/webauthnP256'),
  ]);

  const signerWorkerCtx = deps.getSignerWorkerContext();
  const ctx = deps.touchConfirmManager.getContext();
  const flowArgs = {
    ctx,
    touchConfirmManager: deps.touchConfirmManager,
    workerCtx: signerWorkerCtx,
    nearAccountId: args.nearAccountId,
    onEvent: args.onEvent,
    engines: {
      secp256k1: new Secp256k1Engine({
        getRpId: () => ctx.touchIdPrompt.getRpId(),
        workerCtx: signerWorkerCtx,
        dispenseThresholdEcdsaPrfFirstForSession: (payload) =>
          deps.touchConfirmManager.dispensePrfFirstForThresholdSession(payload),
      }),
      webauthnP256: new WebAuthnP256Engine(signerWorkerCtx),
    },
    ...(args.thresholdEcdsaKeyRef
      ? { keyRefsByAlgorithm: { secp256k1: args.thresholdEcdsaKeyRef } }
      : {}),
    confirmationConfigOverride: args.confirmationConfigOverride,
  };

  if (args.request.chain === 'evm') {
    const { signEvmWithTouchConfirm } =
      await import('../orchestration/evm/evmSigningFlow');
    return await signEvmWithTouchConfirm({
      ...flowArgs,
      request: args.request,
    });
  }

  const { signTempoWithTouchConfirm } =
    await import('../orchestration/tempo/tempoSigningFlow');
  return await signTempoWithTouchConfirm({
    ...flowArgs,
    request: args.request,
  });
}
