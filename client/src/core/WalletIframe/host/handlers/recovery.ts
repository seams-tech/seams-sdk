import type { ActionHooksOptions, SyncAccountHooksOptions } from '../../../types/sdkSentEvents';
import type { HandlerDeps, HandlerMap, Req } from './types';
import { respondOk, respondOkResult, withProgress } from './shared';

export function createRecoveryWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_GET_RECOVERY_EMAILS: async (req: Req<'PM_GET_RECOVERY_EMAILS'>) => {
      const pm = deps.getSeamsPasskey();
      const { nearAccountId } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.recovery.getRecoveryEmails(nearAccountId);
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_SET_RECOVERY_EMAILS: async (req: Req<'PM_SET_RECOVERY_EMAILS'>) => {
      const pm = deps.getSeamsPasskey();
      const { nearAccountId, recoveryEmails, options } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.recovery.setRecoveryEmails({
        accountId: nearAccountId,
        recoveryEmails: Array.isArray(recoveryEmails) ? recoveryEmails : [],
        options: {
          ...withProgress(deps, req.requestId, options || {}),
        } as ActionHooksOptions,
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_SYNC_ACCOUNT_FLOW: async (req: Req<'PM_SYNC_ACCOUNT_FLOW'>) => {
      const pm = deps.getSeamsPasskey();
      const { accountId } = req.payload || {};
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.recovery.syncAccount({
        ...(accountId ? { accountId } : {}),
        options: {
          ...withProgress(deps, req.requestId, {}),
        } as SyncAccountHooksOptions,
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_START_EMAIL_RECOVERY: async (req: Req<'PM_START_EMAIL_RECOVERY'>) => {
      const pm = deps.getSeamsPasskey();
      const { accountId, options } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.recovery.startEmailRecovery({
        accountId,
        options: {
          ...withProgress(deps, req.requestId, options || {}),
        },
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_FINALIZE_EMAIL_RECOVERY: async (req: Req<'PM_FINALIZE_EMAIL_RECOVERY'>) => {
      const pm = deps.getSeamsPasskey();
      const { accountId, nearPublicKey } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      await pm.recovery.finalizeEmailRecovery({
        accountId,
        ...(nearPublicKey ? { nearPublicKey } : {}),
        options: {
          ...withProgress(deps, req.requestId, {}),
        },
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOk(deps, req.requestId);
    },

    PM_STOP_EMAIL_RECOVERY: async (req: Req<'PM_STOP_EMAIL_RECOVERY'>) => {
      const pm = deps.getSeamsPasskey();
      const { accountId, nearPublicKey } = req.payload || {};
      if (deps.respondIfCancelled(req.requestId)) return;
      await pm.recovery.cancelEmailRecovery({
        ...(accountId ? { accountId } : {}),
        ...(nearPublicKey ? { nearPublicKey } : {}),
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOk(deps, req.requestId);
    },
  };
}

