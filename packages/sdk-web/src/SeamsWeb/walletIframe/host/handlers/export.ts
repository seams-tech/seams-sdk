import { isTouchIdCancellationError } from '@shared/utils/errors';
import { thresholdEcdsaChainTargetsEqual } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  parseExactEcdsaSigningLaneIdentity,
  parseExactEd25519SigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { SigningEngineExportKeypairWithUIInput } from '@/core/signingEngine/flows/recovery/keyExportFlow';
import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOk, respondOkResult } from './shared';
import type { PMExportKeypairUiPayload } from '../../shared/messages';

function keyExportInputFromPayload(
  payload: PMExportKeypairUiPayload,
): SigningEngineExportKeypairWithUIInput {
  switch (payload.kind) {
    case 'ecdsa': {
      const laneIdentity = parseExactEcdsaSigningLaneIdentity(payload.laneIdentity);
      if (String(laneIdentity.signer.walletId) !== String(payload.walletSession.walletId)) {
        throw new Error('[WalletIframe] key export lane wallet does not match wallet session');
      }
      if (!thresholdEcdsaChainTargetsEqual(laneIdentity.signer.chainTarget, payload.chainTarget)) {
        throw new Error('[WalletIframe] key export lane chain target does not match request target');
      }
      return {
        kind: 'ecdsa',
        chainTarget: payload.chainTarget,
        walletSession: payload.walletSession,
        laneIdentity,
        options: payload.options,
      };
    }
    case 'ed25519': {
      const laneIdentity = parseExactEd25519SigningLaneIdentity(payload.laneIdentity);
      const signer = laneIdentity.signer;
      if (String(signer.account.wallet.walletId) !== String(payload.walletSession.walletId)) {
        throw new Error('[WalletIframe] Ed25519 export lane wallet does not match wallet session');
      }
      if (String(signer.account.nearAccountId) !== String(payload.nearAccount.accountId)) {
        throw new Error('[WalletIframe] Ed25519 export lane does not match the NEAR account');
      }
      return {
        kind: 'ed25519',
        nearAccount: payload.nearAccount,
        walletSession: payload.walletSession,
        laneIdentity,
        options: payload.options,
      };
    }
  }
}

export function createExportWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_RESOLVE_EXACT_KEY_EXPORT_LANE: async (req: Req<'PM_RESOLVE_EXACT_KEY_EXPORT_LANE'>) => {
      const pm = deps.getSeamsWeb();
      const result = await pm.keys.resolveExactKeyExportLane(req.payload!);
      respondOkResult(deps, req.requestId, result);
    },

    PM_EXPORT_KEYPAIR_UI: async (req: Req<'PM_EXPORT_KEYPAIR_UI'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      try {
        const exportInput = keyExportInputFromPayload(payload);
        await pm.keys.exportKeypairWithUI(
          exportInput.kind === 'ecdsa'
            ? {
                kind: 'ecdsa',
                chainTarget: exportInput.chainTarget,
                walletSession: exportInput.walletSession,
                laneIdentity: exportInput.laneIdentity,
                options: {
                  ...exportInput.options,
                  onEvent: (event) => deps.postProgress(req.requestId, event),
                },
              }
            : {
                kind: 'ed25519',
                nearAccount: exportInput.nearAccount,
                walletSession: exportInput.walletSession,
                laneIdentity: exportInput.laneIdentity,
                options: {
                  ...exportInput.options,
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
  };
}
