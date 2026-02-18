import type { UnifiedIndexedDBManager } from '../../IndexedDBManager';
import { toAccountId } from '../../types/accountIds';
import type { ConfirmationConfig } from '../../types/signer-worker';
import type { TatchiConfigs } from '../../types/tatchi';
import type { TempoSigningRequest } from '../chainAdaptors/tempo/types';
import type { TempoSignedResult } from '../chainAdaptors/tempo/tempoAdapter';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../orchestration/types';
import {
  deriveSmartAccountDeploymentTargetFromTempoRequest,
  ensureSmartAccountDeployed,
} from '../orchestration/deployment/ensureSmartAccountDeployed';
import { SecureConfirmWorkerManager } from '../secureConfirm';
import type { SignerWorkerManagerContext } from '../workers/signerWorkerManager';
import {
  deploySmartAccountForChain,
  resolveSmartAccountDeploymentMaxAttempts,
  resolveSmartAccountDeploymentMode,
} from './smartAccountDeployment';

export type TempoSigningDeps = {
  indexedDB: UnifiedIndexedDBManager;
  tatchiPasskeyConfigs: TatchiConfigs;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  secureConfirmWorkerManager: SecureConfirmWorkerManager;
};

type TempoSigningCancelledError = Error & { code: 'CANCELLED' };

function createTempoSigningCancelledError(): TempoSigningCancelledError {
  const err = new Error('Request cancelled') as TempoSigningCancelledError;
  err.code = 'CANCELLED';
  return err;
}

function throwIfTempoSigningCancelled(shouldAbort?: () => boolean): void {
  if (typeof shouldAbort === 'function' && shouldAbort()) {
    throw createTempoSigningCancelledError();
  }
}

export async function signTempo(
  deps: TempoSigningDeps,
  args: {
    nearAccountId: string;
    request: TempoSigningRequest;
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
): Promise<TempoSignedResult> {
  throwIfTempoSigningCancelled(args.shouldAbort);

  if (args.request.chain !== 'tempo') {
    throw new Error('[WebAuthnManager] invalid Tempo request: chain must be tempo');
  }
  if (args.request.senderSignatureAlgorithm === 'secp256k1' && !args.thresholdEcdsaKeyRef) {
    throw new Error('[WebAuthnManager] Tempo secp256k1 signing requires thresholdEcdsaKeyRef');
  }
  if (args.request.senderSignatureAlgorithm === 'secp256k1') {
    const target = deriveSmartAccountDeploymentTargetFromTempoRequest(args.request);
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
        `[WebAuthnManager] smart-account deployment must succeed before first ${target.chain.toUpperCase()} send: ${details}`,
      );
    }
  }

  throwIfTempoSigningCancelled(args.shouldAbort);

  const [{ signTempoWithSecureConfirm }, { Secp256k1Engine }, { WebAuthnP256Engine }] =
    await Promise.all([
      import('../chainAdaptors/tempo/tempoSigningFlow'),
      import('../engines/secp256k1'),
      import('../engines/webauthnP256'),
    ]);

  const signerWorkerCtx = deps.getSignerWorkerContext();
  const ctx = deps.secureConfirmWorkerManager.getContext();
  return await signTempoWithSecureConfirm({
    ctx,
    secureConfirmWorkerManager: deps.secureConfirmWorkerManager,
    workerCtx: signerWorkerCtx,
    nearAccountId: args.nearAccountId,
    request: args.request,
    onEvent: args.onEvent,
    engines: {
      secp256k1: new Secp256k1Engine({
        getRpId: () => ctx.touchIdPrompt.getRpId(),
        workerCtx: signerWorkerCtx,
        dispenseThresholdEcdsaPrfFirstForSession: (payload) =>
          deps.secureConfirmWorkerManager.dispensePrfFirstForThresholdSession(payload),
      }),
      webauthnP256: new WebAuthnP256Engine(signerWorkerCtx),
    },
    ...(args.thresholdEcdsaKeyRef
      ? { keyRefsByAlgorithm: { secp256k1: args.thresholdEcdsaKeyRef } }
      : {}),
    confirmationConfigOverride: args.confirmationConfigOverride,
  });
}
