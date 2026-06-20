import type { LoginHooksOptions } from '@/core/types/sdkSentEvents';
import type { WalletSession } from '@/core/types/seams';
import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOk, respondOkResult, withProgress } from './shared';
import {
  pmUnlockPayloadToLoginHooksOptions,
  requirePMUnlockPayload,
} from '../../shared/unlockOptions';

export function createAuthWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_UNLOCK: async (req: Req<'PM_UNLOCK'>) => {
      const pm = deps.getSeamsWeb();
      const payload = requirePMUnlockPayload(req.payload);
      const options = pmUnlockPayloadToLoginHooksOptions(payload);
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.auth.unlock(
        payload.nearAccountId,
        withProgress(deps, req.requestId, options) as LoginHooksOptions,
      );
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_LOCK: async (req: Req<'PM_LOCK'>) => {
      const pm = deps.getSeamsWeb();
      await pm.auth.lock();
      respondOk(deps, req.requestId);
    },

    PM_GET_WALLET_SESSION: async (req: Req<'PM_GET_WALLET_SESSION'>) => {
      const pm = deps.getSeamsWeb();
      const result: WalletSession = await pm.auth.getWalletSession(req.payload?.walletId);
      respondOkResult(deps, req.requestId, result);
    },

    PM_GET_RECENT_UNLOCKS: async (req: Req<'PM_GET_RECENT_UNLOCKS'>) => {
      const pm = deps.getSeamsWeb();
      const result = await pm.auth.getRecentUnlocks();
      respondOkResult(deps, req.requestId, result);
    },
  };
}
