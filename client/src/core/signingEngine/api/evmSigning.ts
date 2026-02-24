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
  TouchConfirmSecureConfirmationPort,
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
  withThresholdEcdsaCommitQueue: <T>(args: {
    nearAccountId: string;
    enabled: boolean;
    shouldAbort?: () => boolean;
    maxQueueLength?: number;
    queueTimeoutMs?: number;
    task: () => Promise<T>;
  }) => Promise<T>;
  getThresholdEcdsaKeyRefForSigning: (args: {
    nearAccountId: string;
    chain: 'tempo' | 'evm';
  }) => ThresholdEcdsaSecp256k1KeyRef;
  touchConfirm:
    & TouchConfirmContextPort
    & TouchConfirmSigningPort
    & TouchConfirmSecureConfirmationPort
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

async function assertThresholdSigningSessionReady(args: {
  thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
  touchConfirm: ThresholdPrfFirstCachePeekPort;
}): Promise<void> {
  const thresholdSessionId = String(args.thresholdEcdsaKeyRef.thresholdSessionId || '').trim();
  if (!thresholdSessionId) {
    throw new Error('[chains] Missing threshold signingSessionId; reconnect threshold session before signing');
  }
  const peek = await args.touchConfirm.peekPrfFirstForThresholdSession({
    sessionId: thresholdSessionId,
  });
  if (!peek.ok) {
    throw new Error(
      `[chains] threshold signingSession is ${peek.code}; reconnect threshold session before signing`,
    );
  }
  if (peek.remainingUses < 1) {
    throw new Error('[chains] threshold signingSession is exhausted; reconnect threshold session before signing');
  }
}

async function ensureSmartAccountDeploymentReady(args: {
  deps: EvmFamilySigningDeps;
  nearAccountId: string;
  request: TempoSigningRequest | EvmSigningRequest;
}): Promise<void> {
  const target = deriveSmartAccountDeploymentTargetFromSigningRequest(args.request);
  const deploymentMode = resolveSmartAccountDeploymentMode(args.deps.tatchiPasskeyConfigs);
  try {
    await ensureSmartAccountDeployed({
      clientDB: args.deps.indexedDB.clientDB,
      nearAccountId: toAccountId(args.nearAccountId),
      chain: target.chain,
      chainIdCandidates: target.chainIdCandidates,
      accountModelCandidates: target.accountModelCandidates,
      maxDeployAttempts: resolveSmartAccountDeploymentMaxAttempts(args.deps.tatchiPasskeyConfigs),
      ...(deploymentMode === 'enforce'
        ? {
            deploy: (input) =>
              deploySmartAccountForChain(args.deps.tatchiPasskeyConfigs, input),
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

export async function signEvmFamily(
  deps: EvmFamilySigningDeps,
  args: {
    nearAccountId: string;
    request: TempoSigningRequest | EvmSigningRequest;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
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
  const thresholdEcdsaKeyRef = args.request.senderSignatureAlgorithm === 'secp256k1'
    ? deps.getThresholdEcdsaKeyRefForSigning({
        nearAccountId: args.nearAccountId,
        chain: args.request.chain,
      })
    : undefined;

  if (args.request.senderSignatureAlgorithm === 'secp256k1') {
    await assertThresholdSigningSessionReady({
      thresholdEcdsaKeyRef: thresholdEcdsaKeyRef!,
      touchConfirm: deps.touchConfirm,
    });
  }

  throwIfEvmFamilySigningCancelled(args.shouldAbort);

  const [{ Secp256k1Engine }, { WebAuthnP256Engine }] = await Promise.all([
    import('../signers/algorithms/secp256k1'),
    import('../signers/algorithms/webauthnP256'),
  ]);

  const signerWorkerCtx = deps.getSignerWorkerContext();
  const ctx = deps.touchConfirm.getContext();
  const flowArgs = {
    ctx,
    touchConfirm: deps.touchConfirm,
    workerCtx: signerWorkerCtx,
    nearAccountId: args.nearAccountId,
    onEvent: args.onEvent,
    engines: {
      secp256k1: new Secp256k1Engine({
        getRpId: () => ctx.touchIdPrompt.getRpId(),
        workerCtx: signerWorkerCtx,
        shouldAbort: args.shouldAbort,
        thresholdEcdsaPresignPoolPolicy: deps.tatchiPasskeyConfigs.thresholdEcdsaPresignPool,
        onThresholdEcdsaPresignRefillScheduled: ({ trigger, result }) => {
          try {
            args.onEvent?.({
              step: 4,
              phase: 'presign-refill-scheduled',
              status: 'progress',
              message: result.scheduled
                ? `Scheduled threshold presign refill (${trigger})`
                : `Skipped threshold presign refill (${trigger}): ${result.reason}`,
              data: { trigger, ...result },
            });
          } catch {}
        },
        enqueueThresholdEcdsaCommit: thresholdEcdsaKeyRef
          ? async (queueArgs) => {
              try {
                args.onEvent?.({
                  step: 4,
                  phase: 'commit-queued',
                  status: 'progress',
                  message: 'Queued for threshold signing commit',
                });
              } catch {}
              return await deps.withThresholdEcdsaCommitQueue({
                nearAccountId: queueArgs.nearAccountId,
                enabled: true,
                shouldAbort: queueArgs.shouldAbort,
                task: async () => {
                  throwIfEvmFamilySigningCancelled(queueArgs.shouldAbort);
                  await assertThresholdSigningSessionReady({
                    thresholdEcdsaKeyRef: thresholdEcdsaKeyRef,
                    touchConfirm: deps.touchConfirm,
                  });
                  try {
                    args.onEvent?.({
                      step: 4,
                      phase: 'commit-started',
                      status: 'progress',
                      message: 'Starting threshold signing commit',
                    });
                  } catch {}
                  await ensureSmartAccountDeploymentReady({
                    deps,
                    nearAccountId: args.nearAccountId,
                    request: args.request,
                  });
                  throwIfEvmFamilySigningCancelled(queueArgs.shouldAbort);
                  return await queueArgs.task();
                },
              });
            }
          : undefined,
        dispenseThresholdEcdsaPrfFirstForSession: (payload) =>
          deps.touchConfirm.dispensePrfFirstForThresholdSession(payload),
      }),
      webauthnP256: new WebAuthnP256Engine(signerWorkerCtx),
    },
    ...(thresholdEcdsaKeyRef
      ? { keyRefsByAlgorithm: { secp256k1: thresholdEcdsaKeyRef } }
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
