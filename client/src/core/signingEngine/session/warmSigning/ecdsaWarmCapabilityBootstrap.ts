import { toAccountId } from '@/core/types/accountIds';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/types';
import type {
  ThresholdEcdsaSessionBootstrapResult,
} from '../../threshold/ecdsa/activation';
import {
  listThresholdEcdsaKeyRefsForTarget,
  type ThresholdEcdsaSessionStoreDeps,
} from '../persistence/records';
import type { BootstrapEcdsaSessionArgs, ThresholdSessionActivationDeps } from './ecdsaBootstrap';
import { ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap } from './sealedRefreshParity';
import { provisionWarmEcdsaCapability } from './ecdsaProvisioner';
import { claimWarmSessionPrfFirst } from './runtime';
import {
  provisionThresholdEcdsaSession,
  type ProvisionThresholdEcdsaSessionDeps,
} from './ecdsaSessionProvision';
import type { WarmSessionCapabilityReader } from './types';

export type BootstrapWarmEcdsaCapabilityDeps = {
  ensureSealedRefreshStartupParity: () => Promise<void>;
  queueByAccount: Map<string, Promise<void>>;
  activationDeps: ThresholdSessionActivationDeps;
  touchConfirm: UiConfirmRuntimeBridgePort;
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
  capabilityReader: WarmSessionCapabilityReader;
};

function createProvisionThresholdEcdsaSessionDeps(
  deps: BootstrapWarmEcdsaCapabilityDeps,
): ProvisionThresholdEcdsaSessionDeps {
  return {
    queueByAccount: deps.queueByAccount,
    activationDeps: deps.activationDeps,
    touchConfirm: deps.touchConfirm,
    resolveSealTransport: ({ thresholdSessionId, chainTarget }) =>
      deps.capabilityReader.resolveEcdsaSealTransportByThresholdSessionId({
        thresholdSessionId,
        chainTarget,
      }),
  };
}

export async function bootstrapWarmEcdsaCapability(
  deps: BootstrapWarmEcdsaCapabilityDeps,
  args: BootstrapEcdsaSessionArgs,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  await ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(
    deps.ensureSealedRefreshStartupParity,
    args,
  );
  const nearAccountId = toAccountId(args.nearAccountId);
  const chainTarget = args.chainTarget;
  return await provisionWarmEcdsaCapability(
    {
      getWarmSession: (warmSessionAccountId) => deps.capabilityReader.getWarmSession(warmSessionAccountId),
      listThresholdEcdsaKeyRefsForAccountTarget: ({ subjectId, chainTarget, source }) =>
        listThresholdEcdsaKeyRefsForTarget(deps.ecdsaSessions, {
          subjectId,
          chainTarget,
          ...(source ? { source } : {}),
        }),
      claimPrfFirstByThresholdSessionId: (claimArgs) =>
        claimWarmSessionPrfFirst({
          touchConfirm: deps.touchConfirm,
          thresholdSessionId: claimArgs.thresholdSessionId,
          errorContext: claimArgs.errorContext,
          uses: claimArgs.uses,
          curve: 'ecdsa',
          chainTarget: claimArgs.chainTarget || chainTarget,
          restoreBeforeClaim: async () => {
            if (claimArgs.authMethod !== 'passkey') return;
            const walletSigningSessionId = String(
              claimArgs.walletSigningSessionId || args.walletSigningSessionId || '',
            ).trim();
            if (!walletSigningSessionId) return;
            await deps.touchConfirm.restorePersistedSessionForSigning({
              walletId: nearAccountId,
              authMethod: 'passkey',
              curve: 'ecdsa',
              chainTarget,
              walletSigningSessionId,
              thresholdSessionId: claimArgs.thresholdSessionId,
              reason: 'transaction',
            });
          },
        }),
      provisionThresholdEcdsaSession: async (provisionArgs) =>
        await provisionThresholdEcdsaSession(
          createProvisionThresholdEcdsaSessionDeps(deps),
          {
            ...args,
            nearAccountId,
            chainTarget: provisionArgs.chainTarget,
            ...(provisionArgs.relayerUrl ? { relayerUrl: provisionArgs.relayerUrl } : {}),
            ...(provisionArgs.clientRootShare32
              ? { clientRootShare32: provisionArgs.clientRootShare32 }
              : {}),
            ...(provisionArgs.clientRootShare32B64u
              ? { clientRootShare32B64u: provisionArgs.clientRootShare32B64u }
              : {}),
            ...(provisionArgs.webauthnAuthentication
              ? { webauthnAuthentication: provisionArgs.webauthnAuthentication }
              : {}),
            ...(provisionArgs.ecdsaThresholdKeyId
              ? { ecdsaThresholdKeyId: provisionArgs.ecdsaThresholdKeyId }
              : {}),
            ...(provisionArgs.thresholdSessionAuth
              ? { thresholdSessionAuth: provisionArgs.thresholdSessionAuth }
              : {}),
            ...(provisionArgs.runtimePolicyScope
              ? { runtimePolicyScope: provisionArgs.runtimePolicyScope }
              : {}),
            ...(provisionArgs.runtimeScopeBootstrap
              ? { runtimeScopeBootstrap: provisionArgs.runtimeScopeBootstrap }
              : {}),
            ...(provisionArgs.operationIntent
              ? { operationIntent: provisionArgs.operationIntent }
              : {}),
            ...(provisionArgs.sessionId ? { sessionId: provisionArgs.sessionId } : {}),
            ...(provisionArgs.walletSigningSessionId
              ? { walletSigningSessionId: provisionArgs.walletSigningSessionId }
              : {}),
            ...(Array.isArray(provisionArgs.participantIds) &&
            provisionArgs.participantIds.length > 0
              ? { participantIds: provisionArgs.participantIds }
              : {}),
            ...(provisionArgs.sessionKind ? { sessionKind: provisionArgs.sessionKind } : {}),
            ...(typeof provisionArgs.ttlMs === 'number' ? { ttlMs: provisionArgs.ttlMs } : {}),
            ...(typeof provisionArgs.remainingUses === 'number'
              ? { remainingUses: provisionArgs.remainingUses }
              : {}),
            ...(provisionArgs.smartAccount ? { smartAccount: provisionArgs.smartAccount } : {}),
          },
        ),
    },
    {
      nearAccountId,
      subjectId: args.subjectId,
      chainTarget,
      source: args.source,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      participantIds: args.participantIds,
      sessionKind: args.sessionKind,
      sessionId: args.sessionId,
      walletSigningSessionId: args.walletSigningSessionId,
      thresholdSessionAuth: args.thresholdSessionAuth,
      runtimePolicyScope: args.runtimePolicyScope,
      runtimeScopeBootstrap: args.runtimeScopeBootstrap,
      clientRootShare32: args.clientRootShare32,
      clientRootShare32B64u: args.clientRootShare32B64u,
      webauthnAuthentication: args.webauthnAuthentication,
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
      smartAccount: args.smartAccount,
    },
  );
}
