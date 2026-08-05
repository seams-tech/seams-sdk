import type { ProgressPayload } from '../../shared/messages';
import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOk, respondOkResult } from './shared';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import { requireTempoFeeTokenPreferenceSigningRequest } from '@/core/signingEngine/chains/tempo/feeToken';

export function createEcdsaTempoWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION: async (
      req: Req<'PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION'>,
    ) => {
      const pm = deps.getSeamsWeb();
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
      const pm = deps.getSeamsWeb();
      const { walletSession, request, chainTarget, options } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      const signOptions = {
        confirmationConfig: options?.confirmationConfig,
        shouldAbort: () => deps.isCancelled(req.requestId),
        onEvent: (ev: Parameters<typeof deps.postProgress>[1]) => {
          deps.postProgress(req.requestId, ev as unknown as ProgressPayload);
        },
      };
      let result: TempoSignedResult | EvmSignedResult;
      switch (req.payload!.operationKind) {
        case 'tempo_transaction': {
          if (request.chain !== 'tempo') {
            throw new Error('[wallet-iframe] Tempo operation requires a Tempo request');
          }
          if (chainTarget.kind !== 'tempo') {
            throw new Error('[wallet-iframe] Tempo request requires a Tempo target');
          }
          result = await pm.tempo.signTempo({
            walletSession,
            request,
            chainTarget,
            options: signOptions,
          });
          break;
        }
        case 'evm_transaction': {
          if (request.chain !== 'evm') {
            throw new Error('[wallet-iframe] EVM operation requires an EVM request');
          }
          if (chainTarget.kind !== 'evm') {
            throw new Error('[wallet-iframe] EVM request requires an EVM target');
          }
          result = await pm.evm.signTransaction({
            walletSession,
            request,
            chainTarget,
            options: signOptions,
          });
          break;
        }
        case 'tempo_fee_token_preference': {
          if (request.chain !== 'evm' || chainTarget.kind !== 'tempo') {
            throw new Error(
              '[wallet-iframe] Tempo fee-token operation requires an EVM request and Tempo target',
            );
          }
          const exactRequest = requireTempoFeeTokenPreferenceSigningRequest({
            request,
            chainTarget,
          });
          result = await pm.signTempoFeeTokenPreferenceInternal({
            walletSession,
            request: exactRequest,
            chainTarget,
            confirmationConfigOverride: signOptions.confirmationConfig,
            shouldAbort: signOptions.shouldAbort,
            onEvent: signOptions.onEvent,
          });
          break;
        }
        default:
          throw new Error('[wallet-iframe] unsupported EVM-family signing operation');
      }
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_REPORT_TEMPO_BROADCAST_ACCEPTED: async (req: Req<'PM_REPORT_TEMPO_BROADCAST_ACCEPTED'>) => {
      const pm = deps.getSeamsWeb();
      const { walletSession, signedResult, txHash } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      await pm.tempo.reportBroadcastAccepted({
        walletSession,
        signedResult,
        txHash,
        options: {
          onEvent: (ev) => deps.postProgress(req.requestId, ev as unknown as ProgressPayload),
        },
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOk(deps, req.requestId);
    },

    PM_REPORT_TEMPO_BROADCAST_REJECTED: async (req: Req<'PM_REPORT_TEMPO_BROADCAST_REJECTED'>) => {
      const pm = deps.getSeamsWeb();
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
      const pm = deps.getSeamsWeb();
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
      const pm = deps.getSeamsWeb();
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
      const pm = deps.getSeamsWeb();
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

    PM_PREFILL_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL: async (
      req: Req<'PM_PREFILL_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const { walletSession, options } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.auth.prefillRouterAbEcdsaDerivationPresignaturePool({
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
