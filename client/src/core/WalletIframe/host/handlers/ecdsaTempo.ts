import type { ProgressPayload } from '../../shared/messages';
import type { HandlerDeps, HandlerMap, Req } from './types';
import { respondOk, respondOkResult } from './shared';

export function createEcdsaTempoWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION: async (
      req: Req<'PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION'>,
    ) => {
      const pm = deps.getSeamsPasskey();
      const args = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;

      const chainKind = args.chainTarget.kind;
      const result =
        chainKind === 'evm'
          ? await pm.evm.bootstrapEcdsaSession(args)
          : await pm.tempo.bootstrapEcdsaSession(args);
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_SIGN_TEMPO: async (req: Req<'PM_SIGN_TEMPO'>) => {
      const pm = deps.getSeamsPasskey();
      const { walletSession, request, chainTarget, options } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.tempo.signTempo({
        walletSession,
        request,
        chainTarget,
        options: {
          confirmationConfig: options?.confirmationConfig,
          shouldAbort: () => deps.isCancelled(req.requestId),
          onEvent: (ev) => {
            deps.postProgress(req.requestId, ev as unknown as ProgressPayload);
          },
        },
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_REPORT_TEMPO_BROADCAST_ACCEPTED: async (
      req: Req<'PM_REPORT_TEMPO_BROADCAST_ACCEPTED'>,
    ) => {
      const pm = deps.getSeamsPasskey();
      const { walletSession, signedResult, txHash } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      await pm.tempo.reportBroadcastAccepted({
        walletSession,
        signedResult,
        ...(txHash ? { txHash } : {}),
        options: {
          onEvent: (ev) => deps.postProgress(req.requestId, ev as unknown as ProgressPayload),
        },
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOk(deps, req.requestId);
    },

    PM_REPORT_TEMPO_BROADCAST_REJECTED: async (
      req: Req<'PM_REPORT_TEMPO_BROADCAST_REJECTED'>,
    ) => {
      const pm = deps.getSeamsPasskey();
      const { walletSession, signedResult, error } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      await pm.tempo.reportBroadcastRejected({
        walletSession,
        signedResult,
        ...(error ? { error } : {}),
        options: {
          onEvent: (ev) => deps.postProgress(req.requestId, ev as unknown as ProgressPayload),
        },
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOk(deps, req.requestId);
    },

    PM_REPORT_TEMPO_FINALIZED: async (req: Req<'PM_REPORT_TEMPO_FINALIZED'>) => {
      const pm = deps.getSeamsPasskey();
      const { walletSession, signedResult, txHash, receiptStatus } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      await pm.tempo.reportFinalized({
        walletSession,
        signedResult,
        ...(txHash ? { txHash } : {}),
        ...(receiptStatus ? { receiptStatus } : {}),
        options: {
          onEvent: (ev) => deps.postProgress(req.requestId, ev as unknown as ProgressPayload),
        },
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOk(deps, req.requestId);
    },

    PM_REPORT_TEMPO_DROPPED_OR_REPLACED: async (
      req: Req<'PM_REPORT_TEMPO_DROPPED_OR_REPLACED'>,
    ) => {
      const pm = deps.getSeamsPasskey();
      const { walletSession, signedResult, reason, txHash } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      await pm.tempo.reportDroppedOrReplaced({
        walletSession,
        signedResult,
        reason,
        ...(txHash ? { txHash } : {}),
        options: {
          onEvent: (ev) => deps.postProgress(req.requestId, ev as unknown as ProgressPayload),
        },
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOk(deps, req.requestId);
    },

    PM_RECONCILE_TEMPO_NONCE_LANE: async (req: Req<'PM_RECONCILE_TEMPO_NONCE_LANE'>) => {
      const pm = deps.getSeamsPasskey();
      const { walletSession, signedResult } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.tempo.reconcileNonceLane({
        walletSession,
        signedResult,
        options: {
          onEvent: (ev) => deps.postProgress(req.requestId, ev as unknown as ProgressPayload),
        },
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_PREFILL_THRESHOLD_ECDSA_PRESIGN_POOL: async (
      req: Req<'PM_PREFILL_THRESHOLD_ECDSA_PRESIGN_POOL'>,
    ) => {
      const pm = deps.getSeamsPasskey();
      const { walletSession, options } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.auth.prefillThresholdEcdsaPresignPool({
        walletSession,
        chainTarget: options.chainTarget,
        ...(typeof options.waitForPoolReady === 'boolean'
          ? { waitForPoolReady: options.waitForPoolReady }
          : {}),
        ...(typeof options.poolReadyTimeoutMs === 'number'
          ? { poolReadyTimeoutMs: options.poolReadyTimeoutMs }
          : {}),
        ...(typeof options.poolReadyPollIntervalMs === 'number'
          ? { poolReadyPollIntervalMs: options.poolReadyPollIntervalMs }
          : {}),
        ...(typeof options.minRemainingUsesBeforePrefill === 'number'
          ? { minRemainingUsesBeforePrefill: options.minRemainingUsesBeforePrefill }
          : {}),
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },
  };
}

