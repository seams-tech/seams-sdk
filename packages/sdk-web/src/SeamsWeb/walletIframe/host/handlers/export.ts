import { isTouchIdCancellationError } from '@shared/utils/errors';
import {
  nearAccountRefFromAccountId,
  thresholdEcdsaChainTargetsEqual,
  walletSessionRefFromSession,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  parseExactEcdsaSigningLaneIdentity,
  parseExactEd25519SigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOk } from './shared';
import type { PMExportKeypairUiPayload } from '../../shared/messages';

function keyExportInputFromPayload(payload: PMExportKeypairUiPayload) {
  switch (payload.kind) {
    case 'near': {
      const laneIdentity = parseExactEd25519SigningLaneIdentity(payload.laneIdentity);
      if (String(laneIdentity.walletId) !== String(payload.walletSession.walletId)) {
        throw new Error('[WalletIframe] key export lane wallet does not match wallet session');
      }
      if (String(laneIdentity.nearAccountId) !== String(payload.nearAccount.accountId)) {
        throw new Error('[WalletIframe] key export lane NEAR account does not match request account');
      }
      return {
        kind: 'near' as const,
        walletSession: payload.walletSession,
        nearAccount: payload.nearAccount,
        laneIdentity,
        options: {
          ...payload.options,
          chain: 'near' as const,
        },
      };
    }
    case 'ecdsa': {
      const laneIdentity = parseExactEcdsaSigningLaneIdentity(payload.laneIdentity);
      if (String(laneIdentity.walletId) !== String(payload.walletSession.walletId)) {
        throw new Error('[WalletIframe] key export lane wallet does not match wallet session');
      }
      if (!thresholdEcdsaChainTargetsEqual(laneIdentity.chainTarget, payload.chainTarget)) {
        throw new Error('[WalletIframe] key export lane chain target does not match request target');
      }
      return {
        kind: 'ecdsa' as const,
        chainTarget: payload.chainTarget,
        walletSession: payload.walletSession,
        laneIdentity,
        options: payload.options,
      };
    }
  }
  payload satisfies never;
  throw new Error('[WalletIframe] unsupported key export payload');
}

export function createExportWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_EXPORT_KEYPAIR_UI: async (req: Req<'PM_EXPORT_KEYPAIR_UI'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      try {
        const exportInput = keyExportInputFromPayload(payload);
        switch (exportInput.kind) {
          case 'near':
            await pm.keys.exportKeypairWithUI({
              kind: 'near',
              walletSession: exportInput.walletSession,
              nearAccount: exportInput.nearAccount,
              laneIdentity: exportInput.laneIdentity,
              options: {
                ...exportInput.options,
                chain: 'near',
                onEvent: (event) => deps.postProgress(req.requestId, event),
              },
            });
            break;
          case 'ecdsa':
            await pm.keys.exportKeypairWithUI({
              kind: 'ecdsa',
              chainTarget: exportInput.chainTarget,
              walletSession: exportInput.walletSession,
              laneIdentity: exportInput.laneIdentity,
              options: {
                ...exportInput.options,
                onEvent: (event) => deps.postProgress(req.requestId, event),
              },
            });
            break;
          default:
            exportInput satisfies never;
            throw new Error('[WalletIframe] unsupported key export payload');
        }
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
      const { walletId, nearAccountId, preparedSession, finalizedReport, expectedPublicKey, variant, theme } =
        req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      try {
        await pm.keys.exportThresholdEd25519SeedFromHssReport({
          walletSession: walletSessionRefFromSession({
            walletId,
            walletSessionUserId: walletId,
          }),
          nearAccount: nearAccountRefFromAccountId(nearAccountId),
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
