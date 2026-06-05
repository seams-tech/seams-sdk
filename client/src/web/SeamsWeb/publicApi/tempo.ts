import {
  thresholdEcdsaChainTargetFromRequest,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toAccountId } from '@/core/types/accountIds';
import { toError } from '@shared/utils/errors';
import type { TempoSignerCapability, TempoSigningSurface } from '@/web/SeamsWeb/signingSurface/types';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { SeamsConfigsReadonly, ThemeName } from '@/core/types/seams';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import { executeEvmFamilyTransactionLifecycle } from '@/web/SeamsWeb/operations/tempo/executeEvmFamilyTransaction';
import { buildTempoBootstrapArgs, toSerializableTempoError } from '@/web/SeamsWeb/operations/tempo';
import type { WalletIframeCoordinator } from '@/web/SeamsWeb/walletIframe/coordinator';

function toLocalTempoBootstrapRequest(
  args: Parameters<TempoSignerCapability['bootstrapEcdsaSession']>[0],
): EcdsaBootstrapRequest {
  return {
    kind: 'reuse_warm_ecdsa_bootstrap',
    walletId: toAccountId(args.walletSession.walletId),
    chainTarget: args.chainTarget,
    source: args.source,
    relayerUrl: args.relayerUrl,
    runtimeScopeBootstrap: args.runtimeScopeBootstrap,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
  };
}

export function createTempoSignerCapability(deps: {
  signingEngine: TempoSigningSurface;
  nearClient: NearClient;
  configs: SeamsConfigsReadonly;
  getTheme: () => ThemeName;
  getWalletIframe: () => WalletIframeCoordinator;
}): TempoSignerCapability {
  const signTempo: TempoSignerCapability['signTempo'] = async (args) => {
    const walletIframe = deps.getWalletIframe();
    const chainTarget = thresholdEcdsaChainTargetFromRequest(args.chainTarget);
    const walletId = toWalletId(args.walletSession.walletId);
    if (!walletIframe.shouldUseWalletIframe()) {
      return await deps.signingEngine.signEvmFamily({
        walletSession: args.walletSession,
        request: args.request,
        chainTarget,
        confirmationConfigOverride: args.options?.confirmationConfig,
        shouldAbort: args.options?.shouldAbort,
        onEvent: args.options?.onEvent,
      });
    }
    try {
      const router = await walletIframe.requireRouter(walletId);
      return await router.signTempo({
        walletSession: args.walletSession,
        request: args.request,
        chainTarget,
        options: {
          confirmationConfig: args.options?.confirmationConfig,
          onEvent: args.options?.onEvent,
        },
      });
    } catch (error: unknown) {
      throw toError(error);
    }
  };
  const reportBroadcastAccepted: TempoSignerCapability['reportBroadcastAccepted'] = async (
    args,
  ) => {
    const walletIframe = deps.getWalletIframe();
    const walletId = toWalletId(args.walletSession.walletId);
    if (!walletIframe.shouldUseWalletIframe()) {
      await deps.signingEngine.reportTempoBroadcastAccepted({
        walletId,
        signedResult: args.signedResult,
        ...(args.txHash ? { txHash: args.txHash } : {}),
        onEvent: args.options?.onEvent,
      });
      return;
    }
    try {
      const router = await walletIframe.requireRouter(walletId);
      await router.reportTempoBroadcastAccepted({
        walletSession: args.walletSession,
        signedResult: args.signedResult,
        ...(args.txHash ? { txHash: args.txHash } : {}),
        options: {
          onEvent: args.options?.onEvent,
        },
      });
    } catch (error: unknown) {
      throw toError(error);
    }
  };
  const reportBroadcastRejected: TempoSignerCapability['reportBroadcastRejected'] = async (
    args,
  ) => {
    const walletIframe = deps.getWalletIframe();
    const walletId = toWalletId(args.walletSession.walletId);
    if (!walletIframe.shouldUseWalletIframe()) {
      await deps.signingEngine.reportTempoBroadcastRejected({
        walletId,
        signedResult: args.signedResult,
        ...(args.error !== undefined ? { error: args.error } : {}),
        onEvent: args.options?.onEvent,
      });
      return;
    }
    try {
      const router = await walletIframe.requireRouter(walletId);
      await router.reportTempoBroadcastRejected({
        walletSession: args.walletSession,
        signedResult: args.signedResult,
        ...(args.error != null ? { error: toSerializableTempoError(args.error) } : {}),
        options: {
          onEvent: args.options?.onEvent,
        },
      });
    } catch (error: unknown) {
      throw toError(error);
    }
  };
  const reportFinalized: TempoSignerCapability['reportFinalized'] = async (args) => {
    const walletIframe = deps.getWalletIframe();
    const walletId = toWalletId(args.walletSession.walletId);
    if (!walletIframe.shouldUseWalletIframe()) {
      await deps.signingEngine.reportTempoFinalized({
        walletId,
        signedResult: args.signedResult,
        ...(args.txHash ? { txHash: args.txHash } : {}),
        ...(args.receiptStatus ? { receiptStatus: args.receiptStatus } : {}),
        onEvent: args.options?.onEvent,
      });
      return;
    }
    try {
      const router = await walletIframe.requireRouter(walletId);
      await router.reportTempoFinalized({
        walletSession: args.walletSession,
        signedResult: args.signedResult,
        ...(args.txHash ? { txHash: args.txHash } : {}),
        ...(args.receiptStatus ? { receiptStatus: args.receiptStatus } : {}),
        options: {
          onEvent: args.options?.onEvent,
        },
      });
    } catch (error: unknown) {
      throw toError(error);
    }
  };
  const reportDroppedOrReplaced: TempoSignerCapability['reportDroppedOrReplaced'] = async (
    args,
  ) => {
    const walletIframe = deps.getWalletIframe();
    const walletId = toWalletId(args.walletSession.walletId);
    if (!walletIframe.shouldUseWalletIframe()) {
      await deps.signingEngine.reportTempoDroppedOrReplaced({
        walletId,
        signedResult: args.signedResult,
        reason: args.reason,
        ...(args.txHash ? { txHash: args.txHash } : {}),
        onEvent: args.options?.onEvent,
      });
      return;
    }
    try {
      const router = await walletIframe.requireRouter(walletId);
      await router.reportTempoDroppedOrReplaced({
        walletSession: args.walletSession,
        signedResult: args.signedResult,
        reason: args.reason,
        ...(args.txHash ? { txHash: args.txHash } : {}),
        options: {
          onEvent: args.options?.onEvent,
        },
      });
    } catch (error: unknown) {
      throw toError(error);
    }
  };
  const reconcileNonceLane: TempoSignerCapability['reconcileNonceLane'] = async (args) => {
    const walletIframe = deps.getWalletIframe();
    const walletId = toWalletId(args.walletSession.walletId);
    if (!walletIframe.shouldUseWalletIframe()) {
      return await deps.signingEngine.reconcileTempoNonceLane({
        walletId,
        signedResult: args.signedResult,
        onEvent: args.options?.onEvent,
      });
    }
    try {
      const router = await walletIframe.requireRouter(walletId);
      return await router.reconcileTempoNonceLane({
        walletSession: args.walletSession,
        signedResult: args.signedResult,
        options: {
          onEvent: args.options?.onEvent,
        },
      });
    } catch (error: unknown) {
      throw toError(error);
    }
  };
  const lifecycle = {
    signTempo,
    reportBroadcastAccepted,
    reportBroadcastRejected,
    reportFinalized,
    reportDroppedOrReplaced,
    reconcileNonceLane,
  };
  return {
    signTempo,
    executeEvmFamilyTransaction: async (args) => {
      const chainTarget = thresholdEcdsaChainTargetFromRequest(args.chainTarget);
      return await executeEvmFamilyTransactionLifecycle({
        lifecycle,
        chains: deps.configs.network.chains,
        input: { ...args, chainTarget },
      });
    },
    reportBroadcastAccepted,
    reportBroadcastRejected,
    reportFinalized,
    reportDroppedOrReplaced,
    reconcileNonceLane,
    bootstrapEcdsaSession: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const bootstrapArgs = buildTempoBootstrapArgs(deps.configs, args);
      if (!walletIframe.shouldUseWalletIframe()) {
        return await deps.signingEngine.bootstrapEcdsaSession(
          toLocalTempoBootstrapRequest(bootstrapArgs),
        );
      }
      const router = await walletIframe.requireRouter(toWalletId(args.walletSession.walletId));
      return await router.bootstrapEcdsaSession(bootstrapArgs);
    },
  };
}
