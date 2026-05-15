import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { toAccountId } from '@/core/types/accountIds';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { EvmSigningRequest } from '../../chains/evm/types';
import type { TempoSigningRequest } from '../../chains/tempo/types';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import {
  deriveSmartAccountDeploymentTargetFromSigningRequest,
  ensureSmartAccountDeployed,
} from './smartAccountDeploymentState';
import { reportSmartAccountDeploymentObservation } from './smartAccountDeploymentObservation';
import {
  deploySmartAccountForChain,
  resolveSmartAccountDeploymentMaxAttempts,
  resolveSmartAccountDeploymentMode,
} from './smartAccountDeployment';
import { emitEvmFamilySigningEvent } from './events';
import type { EvmFamilyLifecycleEventCallback } from './types';

export type EvmFamilySmartAccountDeps = {
  indexedDB: UnifiedIndexedDBManager;
  seamsPasskeyConfigs: SeamsConfigsReadonly;
};

export async function ensureSmartAccountDeploymentReady(args: {
  deps: EvmFamilySmartAccountDeps;
  walletId: string;
  request: TempoSigningRequest | EvmSigningRequest;
  thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  onEvent?: EvmFamilyLifecycleEventCallback;
}): Promise<void> {
  const target = deriveSmartAccountDeploymentTargetFromSigningRequest(args.request);
  const deploymentMode = resolveSmartAccountDeploymentMode(args.deps.seamsPasskeyConfigs);
  const deploymentEventData = {
    chainTargets: target.chainTargetCandidates,
    accountModelCandidates: target.accountModelCandidates,
    deploymentMode,
  };
  emitEvmFamilySigningEvent(args.onEvent, {
    phase: SigningEventPhase.STEP_04_ACCOUNT_READINESS_STARTED,
    status: 'running',
    accountId: args.walletId,
    interaction: { kind: 'none', overlay: 'none' },
    data: deploymentEventData,
  });
  try {
    const deployment = await ensureSmartAccountDeployed({
      clientDB: args.deps.indexedDB.clientDB,
      walletId: toAccountId(args.walletId),
      chainTargetCandidates: target.chainTargetCandidates,
      accountModelCandidates: target.accountModelCandidates,
      maxDeployAttempts: resolveSmartAccountDeploymentMaxAttempts(args.deps.seamsPasskeyConfigs),
      ...(deploymentMode === 'enforce'
        ? {
            deploy: (input) => {
              const relayerUrl = String(args.thresholdEcdsaKeyRef?.relayerUrl || '').trim();
              const thresholdSessionAuthToken = String(
                args.thresholdEcdsaKeyRef?.thresholdSessionAuthToken || '',
              ).trim();
              if (!relayerUrl || !thresholdSessionAuthToken) {
                return Promise.resolve({
                  ok: false,
                  code: 'missing_transport',
                  message:
                    'Missing threshold-session transport for canonical smart-account deployment',
                });
              }
              return deploySmartAccountForChain(args.deps.seamsPasskeyConfigs, input, {
                relayerUrl,
                thresholdSessionAuthToken,
              });
            },
            ...(args.thresholdEcdsaKeyRef?.relayerUrl &&
            args.thresholdEcdsaKeyRef?.thresholdSessionAuthToken
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
                      thresholdSessionAuthToken: args.thresholdEcdsaKeyRef!.thresholdSessionAuthToken!,
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
      accountId: args.walletId,
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
      accountId: args.walletId,
      interaction: { kind: 'none', overlay: 'hide' },
      data: deploymentEventData,
      error: { message: details },
    });
    throw new Error(
      `[SigningEngine] smart-account deployment must succeed before first ${args.request.chain.toUpperCase()} send: ${details}`,
    );
  }
}
