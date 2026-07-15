import type { ActionHooksOptions, SyncAccountHooksOptions } from '@/core/types/sdkSentEvents';
import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOkResult, withProgress } from './shared';

export function createRecoveryWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_GET_RECOVERY_EMAILS: async (req: Req<'PM_GET_RECOVERY_EMAILS'>) => {
      const pm = deps.getSeamsWeb();
      const { walletId } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.recovery.getRecoveryEmails(walletId);
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_SET_RECOVERY_EMAILS: async (req: Req<'PM_SET_RECOVERY_EMAILS'>) => {
      const pm = deps.getSeamsWeb();
      const { walletId, recoveryEmails, options } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.recovery.setRecoveryEmails({
        walletId,
        recoveryEmails: Array.isArray(recoveryEmails) ? recoveryEmails : [],
        options: {
          ...withProgress(deps, req.requestId, options || {}),
        } as ActionHooksOptions,
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_SYNC_ACCOUNT_FLOW: async (req: Req<'PM_SYNC_ACCOUNT_FLOW'>) => {
      const pm = deps.getSeamsWeb();
      const { walletId } = req.payload || {};
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.recovery.syncAccount({
        ...(walletId ? { walletId } : {}),
        options: {
          ...withProgress(deps, req.requestId, {}),
        } as SyncAccountHooksOptions,
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },
  };
}
