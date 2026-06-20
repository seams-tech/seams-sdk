import { isTouchIdCancellationError } from '@shared/utils/errors';
import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOk } from './shared';

export function createExportWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_EXPORT_KEYPAIR_UI: async (req: Req<'PM_EXPORT_KEYPAIR_UI'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      try {
        await pm.keys.exportKeypairWithUI(
          payload.kind === 'near'
            ? {
                kind: 'near',
                nearAccount: payload.nearAccount,
                options: {
                  ...payload.options,
                  chain: 'near',
                  onEvent: (event) => deps.postProgress(req.requestId, event),
                },
              }
            : {
                kind: 'ecdsa',
                chainTarget: payload.chainTarget,
                walletSession: payload.walletSession,
                options: {
                  ...payload.options,
                  onEvent: (event) => deps.postProgress(req.requestId, event),
                },
              },
        );
      } catch (err: unknown) {
        if (isTouchIdCancellationError(err)) {
          if (deps.respondIfCancelled(req.requestId)) return;
          respondOk(deps, req.requestId);
          return;
        }
        throw err;
      }
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOk(deps, req.requestId);
    },

    PM_EXPORT_THRESHOLD_ED25519_SEED_FROM_HSS_REPORT_UI: async (
      req: Req<'PM_EXPORT_THRESHOLD_ED25519_SEED_FROM_HSS_REPORT_UI'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const { nearAccountId, preparedSession, finalizedReport, expectedPublicKey, variant, theme } =
        req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      try {
        await pm.keys.exportThresholdEd25519SeedFromHssReport({
          nearAccountId,
          preparedSession,
          finalizedReport,
          expectedPublicKey,
          options: {
            variant,
            theme,
            onEvent: (event) => deps.postProgress(req.requestId, event),
          },
        });
      } catch (err: unknown) {
        if (isTouchIdCancellationError(err)) {
          if (deps.respondIfCancelled(req.requestId)) return;
          respondOk(deps, req.requestId);
          return;
        }
        throw err;
      }
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOk(deps, req.requestId);
    },
  };
}

