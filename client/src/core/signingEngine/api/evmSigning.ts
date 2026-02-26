import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { toAccountId } from '@/core/types/accountIds';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { TatchiConfigsReadonly } from '@/core/types/tatchi';
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
import {
  assertThresholdSigningSessionReady,
  isThresholdSigningSessionReady,
} from '../orchestration/shared/thresholdSigningSessionPlanner';
import type { ThresholdEcdsaSessionBootstrapResult } from '../orchestration/thresholdActivation';

export type EvmFamilySigningDeps = {
  indexedDB: UnifiedIndexedDBManager;
  tatchiPasskeyConfigs: TatchiConfigsReadonly;
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
  bootstrapThresholdEcdsaSession: (args: {
    nearAccountId: string;
    chain: 'tempo' | 'evm';
  }) => Promise<ThresholdEcdsaSessionBootstrapResult>;
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

function tryGetThresholdEcdsaKeyRefForSigning(args: {
  deps: EvmFamilySigningDeps;
  nearAccountId: string;
  chain: 'tempo' | 'evm';
}): ThresholdEcdsaSecp256k1KeyRef | null {
  try {
    return args.deps.getThresholdEcdsaKeyRefForSigning({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
    });
  } catch {
    return null;
  }
}

async function ensureThresholdEcdsaKeyRefReady(args: {
  deps: EvmFamilySigningDeps;
  nearAccountId: string;
  chain: 'tempo' | 'evm';
  keyRef: ThresholdEcdsaSecp256k1KeyRef | undefined;
  shouldAbort?: () => boolean;
  onEvent?: (event: {
    step: number;
    phase: string;
    status: 'progress' | 'success' | 'error';
    message?: string;
    data?: unknown;
  }) => void;
}): Promise<ThresholdEcdsaSecp256k1KeyRef> {
  throwIfEvmFamilySigningCancelled(args.shouldAbort);

  let resolvedKeyRef = args.keyRef
    || tryGetThresholdEcdsaKeyRefForSigning({
      deps: args.deps,
      nearAccountId: args.nearAccountId,
      chain: args.chain,
    });

  const isReady = await (async (): Promise<boolean> => {
    const sessionId = String(resolvedKeyRef?.thresholdSessionId || '').trim();
    if (!resolvedKeyRef || !sessionId) return false;
    return await isThresholdSigningSessionReady({
      touchConfirm: args.deps.touchConfirm,
      sessionId,
      usesNeeded: 1,
    });
  })();

  if (!isReady) {
    try {
      args.onEvent?.({
        step: 3,
        phase: 'threshold-session-reconnect',
        status: 'progress',
        message: args.chain === 'tempo'
          ? 'Threshold signer not ready, reconnecting Tempo signer'
          : 'Threshold signer not ready, reconnecting EVM signer',
      });
    } catch {}

    throwIfEvmFamilySigningCancelled(args.shouldAbort);
    await args.deps.bootstrapThresholdEcdsaSession({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
    });
    throwIfEvmFamilySigningCancelled(args.shouldAbort);

    resolvedKeyRef = args.deps.getThresholdEcdsaKeyRefForSigning({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
    });
  }
  if (!resolvedKeyRef) {
    throw new Error('[SigningEngine] threshold ECDSA keyRef is unavailable after reconnect');
  }

  await assertThresholdSigningSessionReady({
    touchConfirm: args.deps.touchConfirm,
    sessionId: resolvedKeyRef.thresholdSessionId,
    usesNeeded: 1,
  });

  return resolvedKeyRef;
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
  let thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef | undefined;
  if (args.request.senderSignatureAlgorithm === 'secp256k1') {
    thresholdEcdsaKeyRef = tryGetThresholdEcdsaKeyRefForSigning({
      deps,
      nearAccountId: args.nearAccountId,
      chain: args.request.chain,
    }) || undefined;
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
        thresholdEcdsaPresignPoolPolicy: deps.tatchiPasskeyConfigs.signing.thresholdEcdsa.presignPool,
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
                    touchConfirm: deps.touchConfirm,
                    sessionId: thresholdEcdsaKeyRef?.thresholdSessionId,
                    usesNeeded: 1,
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
          : async (queueArgs) =>
            await deps.withThresholdEcdsaCommitQueue({
              nearAccountId: queueArgs.nearAccountId,
              enabled: true,
              shouldAbort: queueArgs.shouldAbort,
              task: async () => {
                throwIfEvmFamilySigningCancelled(queueArgs.shouldAbort);
                await ensureSmartAccountDeploymentReady({
                  deps,
                  nearAccountId: args.nearAccountId,
                  request: args.request,
                });
                throwIfEvmFamilySigningCancelled(queueArgs.shouldAbort);
                return await queueArgs.task();
              },
            }),
        dispenseThresholdEcdsaPrfFirstForSession: (payload) =>
          deps.touchConfirm.dispensePrfFirstForThresholdSession(payload),
      }),
      webauthnP256: new WebAuthnP256Engine(signerWorkerCtx),
    },
    ...(thresholdEcdsaKeyRef
      ? { keyRefsByAlgorithm: { secp256k1: thresholdEcdsaKeyRef } }
      : {}),
    confirmationConfigOverride: args.confirmationConfigOverride,
    ...(args.request.senderSignatureAlgorithm === 'secp256k1'
      ? {
          ensureThresholdEcdsaKeyRefReady: async () => {
            const readyKeyRef = await ensureThresholdEcdsaKeyRefReady({
              deps,
              nearAccountId: args.nearAccountId,
              chain: args.request.chain,
              keyRef: thresholdEcdsaKeyRef,
              shouldAbort: args.shouldAbort,
              onEvent: args.onEvent,
            });
            thresholdEcdsaKeyRef = readyKeyRef;
            return readyKeyRef;
          },
        }
      : {}),
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
