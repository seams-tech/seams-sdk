import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { toAccountId } from '@/core/types/accountIds';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { TatchiConfigsReadonly } from '@/core/types/tatchi';
import type { EvmSigningRequest } from '../../chainAdaptors/evm/types';
import type { TempoSigningRequest } from '../../chainAdaptors/tempo/types';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import {
  deriveSmartAccountDeploymentTargetFromSigningRequest,
  ensureSmartAccountDeployed,
} from '../../orchestration/ensureSmartAccountDeployed';
import { reportSmartAccountDeploymentObservation } from '../../orchestration/reportSmartAccountDeploymentObservation';
import {
  deploySmartAccountForChain,
  resolveSmartAccountDeploymentMaxAttempts,
  resolveSmartAccountDeploymentMode,
} from '../../orchestration/smartAccountDeployment';
import { emitEvmFamilySigningEvent } from './events';
import type { EvmFamilyLifecycleEventCallback } from './types';

export type EvmFamilySmartAccountDeps = {
  indexedDB: UnifiedIndexedDBManager;
  tatchiPasskeyConfigs: TatchiConfigsReadonly;
};

export async function ensureSmartAccountDeploymentReady(args: {
  deps: EvmFamilySmartAccountDeps;
  nearAccountId: string;
  request: TempoSigningRequest | EvmSigningRequest;
  thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  onEvent?: EvmFamilyLifecycleEventCallback;
}): Promise<void> {
  const target = deriveSmartAccountDeploymentTargetFromSigningRequest(args.request);
  const deploymentMode = resolveSmartAccountDeploymentMode(args.deps.tatchiPasskeyConfigs);
  const deploymentEventData = {
    chain: target.chain,
    chainIdCandidates: target.chainIdCandidates,
    accountModelCandidates: target.accountModelCandidates,
    deploymentMode,
  };
  emitEvmFamilySigningEvent(args.onEvent, {
    phase: SigningEventPhase.STEP_04_ACCOUNT_READINESS_STARTED,
    status: 'running',
    accountId: args.nearAccountId,
    interaction: { kind: 'none', overlay: 'none' },
    data: deploymentEventData,
  });
  try {
    const deployment = await ensureSmartAccountDeployed({
      clientDB: args.deps.indexedDB.clientDB,
      nearAccountId: toAccountId(args.nearAccountId),
      chain: target.chain,
      chainIdCandidates: target.chainIdCandidates,
      accountModelCandidates: target.accountModelCandidates,
      maxDeployAttempts: resolveSmartAccountDeploymentMaxAttempts(args.deps.tatchiPasskeyConfigs),
      ...(deploymentMode === 'enforce'
        ? {
            deploy: (input) => {
              const relayerUrl = String(args.thresholdEcdsaKeyRef?.relayerUrl || '').trim();
              const thresholdSessionJwt = String(
                args.thresholdEcdsaKeyRef?.thresholdSessionJwt || '',
              ).trim();
              if (!relayerUrl || !thresholdSessionJwt) {
                return Promise.resolve({
                  ok: false,
                  code: 'missing_transport',
                  message:
                    'Missing threshold-session transport for canonical smart-account deployment',
                });
              }
              return deploySmartAccountForChain(args.deps.tatchiPasskeyConfigs, input, {
                relayerUrl,
                thresholdSessionJwt,
              });
            },
            ...(args.thresholdEcdsaKeyRef?.relayerUrl &&
            args.thresholdEcdsaKeyRef?.thresholdSessionJwt
              ? {
                  reportDeployed: async (
                    input: Parameters<
                      NonNullable<
                        Parameters<typeof ensureSmartAccountDeployed>[0]['reportDeployed']
                      >
                    >[0],
                  ) => {
                    await reportSmartAccountDeploymentObservation({
                      ...input,
                      relayerUrl: args.thresholdEcdsaKeyRef!.relayerUrl,
                      thresholdSessionJwt: args.thresholdEcdsaKeyRef!.thresholdSessionJwt!,
                    });
                  },
                }
              : {}),
            enforce: true,
          }
        : { enforce: false }),
    });
    const deploymentReady =
      deployment.status === 'deployed' || deployment.status === 'already_deployed';
    emitEvmFamilySigningEvent(args.onEvent, {
      phase: deploymentReady
        ? SigningEventPhase.STEP_04_ACCOUNT_READINESS_SUCCEEDED
        : SigningEventPhase.STEP_04_ACCOUNT_READINESS_SKIPPED,
      status: deploymentReady ? 'succeeded' : 'skipped',
      accountId: args.nearAccountId,
      interaction: { kind: 'none', overlay: 'none' },
      data: {
        ...deploymentEventData,
        deploymentStatus: deployment.status,
        attempts: deployment.attempts,
        ...(typeof deployment.chainId === 'number' ? { chainId: deployment.chainId } : {}),
        ...(deployment.accountAddress ? { accountAddress: deployment.accountAddress } : {}),
        ...(deployment.deploymentTxHash ? { deploymentTxHash: deployment.deploymentTxHash } : {}),
        ...(deployment.failureCode ? { failureCode: deployment.failureCode } : {}),
        ...(deployment.failureMessage ? { failureMessage: deployment.failureMessage } : {}),
      },
    });
  } catch (error: unknown) {
    const details =
      String((error as { message?: unknown })?.message || error || '').trim() ||
      'deployment failed';
    emitEvmFamilySigningEvent(args.onEvent, {
      phase: SigningEventPhase.FAILED,
      status: 'failed',
      accountId: args.nearAccountId,
      interaction: { kind: 'none', overlay: 'hide' },
      data: deploymentEventData,
      error: { message: details },
    });
    throw new Error(
      `[SigningEngine] smart-account deployment must succeed before first ${target.chain.toUpperCase()} send: ${details}`,
    );
  }
}
