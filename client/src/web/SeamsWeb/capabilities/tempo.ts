import {
  thresholdEcdsaChainTargetFromRequest,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toError } from '@shared/utils/errors';
import type { TempoSignerCapability } from '../interfaces';
import { executeEvmFamilyTransactionLifecycle } from '../tempo/executeEvmFamilyTransaction';
import { buildTempoBootstrapArgs, TempoSigner, toSerializableTempoError } from '../tempo';
import type { WalletIframeCoordinator } from '../walletIframeCoordinator';

export function createTempoSignerCapability(deps: {
  getContext: () => import('../index').SeamsWebContext;
  getWalletIframe: () => WalletIframeCoordinator;
}): TempoSignerCapability {
  const tempoSigner = new TempoSigner({ getContext: deps.getContext });
  const tempoCapability: TempoSignerCapability = {
    signTempo: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const chainTarget = thresholdEcdsaChainTargetFromRequest(args.chainTarget);
      const walletId = toWalletId(args.walletSession.walletId);
      if (!walletIframe.shouldUseWalletIframe()) {
        return await tempoSigner.signTempo({ ...args, chainTarget });
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
    },
    executeEvmFamilyTransaction: async (args) => {
      const chainTarget = thresholdEcdsaChainTargetFromRequest(args.chainTarget);
      return await executeEvmFamilyTransactionLifecycle({
        capability: tempoCapability,
        chains: deps.getContext().configs.network.chains,
        input: { ...args, chainTarget },
      });
    },
    reportBroadcastAccepted: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const walletId = toWalletId(args.walletSession.walletId);
      if (!walletIframe.shouldUseWalletIframe()) {
        await tempoSigner.reportBroadcastAccepted(args);
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
    },
    reportBroadcastRejected: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const walletId = toWalletId(args.walletSession.walletId);
      if (!walletIframe.shouldUseWalletIframe()) {
        await tempoSigner.reportBroadcastRejected(args);
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
    },
    reportFinalized: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const walletId = toWalletId(args.walletSession.walletId);
      if (!walletIframe.shouldUseWalletIframe()) {
        await tempoSigner.reportFinalized(args);
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
    },
    reportDroppedOrReplaced: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const walletId = toWalletId(args.walletSession.walletId);
      if (!walletIframe.shouldUseWalletIframe()) {
        await tempoSigner.reportDroppedOrReplaced(args);
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
    },
    reconcileNonceLane: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const walletId = toWalletId(args.walletSession.walletId);
      if (!walletIframe.shouldUseWalletIframe()) {
        return await tempoSigner.reconcileNonceLane(args);
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
    },
    bootstrapEcdsaSession: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const context = deps.getContext();
      const bootstrapArgs = buildTempoBootstrapArgs(context, args);
      if (!walletIframe.shouldUseWalletIframe()) {
        return await tempoSigner.bootstrapEcdsaSession(bootstrapArgs);
      }
      const router = await walletIframe.requireRouter(toWalletId(args.walletSession.walletId));
      return await router.bootstrapEcdsaSession(bootstrapArgs);
    },
  };
  return tempoCapability;
}
