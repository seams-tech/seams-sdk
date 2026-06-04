import type { ActionHooksOptions } from '../../../types/sdkSentEvents';
import { toAccountId } from '../../../types/accountIds';
import type { HandlerDeps, HandlerMap, Req } from './types';
import { respondOk, respondOkResult, withProgress } from './shared';

export function createDeviceLinkWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_START_DEVICE2_LINKING_FLOW: async (req: Req<'PM_START_DEVICE2_LINKING_FLOW'>) => {
      const pm = deps.getSeamsWeb();
      const { ui, cameraId, accountId, signerSlot, options } = req.payload || {};
      const accountIdValue = accountId ? toAccountId(accountId) : undefined;
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.recovery.startDevice2LinkingFlow({
        ...(ui ? { ui } : {}),
        ...(cameraId ? { cameraId } : {}),
        ...(accountIdValue ? { accountId: accountIdValue } : {}),
        ...(typeof signerSlot === 'number' ? { signerSlot } : {}),
        options: {
          ...withProgress(deps, req.requestId, options || {}),
        },
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_STOP_DEVICE2_LINKING_FLOW: async (req: Req<'PM_STOP_DEVICE2_LINKING_FLOW'>) => {
      const pm = deps.getSeamsWeb();
      if (deps.respondIfCancelled(req.requestId)) return;
      await pm.recovery.stopDevice2LinkingFlow();
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOk(deps, req.requestId);
    },

    PM_LINK_DEVICE_WITH_SCANNED_QR_DATA: async (
      req: Req<'PM_LINK_DEVICE_WITH_SCANNED_QR_DATA'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const { qrData, fundingAmount, options } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.recovery.linkDeviceWithScannedQRData(qrData, {
        fundingAmount: String(fundingAmount || ''),
        ...withProgress(deps, req.requestId, options || {}),
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_HAS_PASSKEY: async (req: Req<'PM_HAS_PASSKEY'>) => {
      const pm = deps.getSeamsWeb();
      const { nearAccountId } = req.payload!;
      const ctx = pm.getContext();
      const registrationAccounts = ctx?.signingRuntime.services.registrationAccounts;
      if (registrationAccounts) {
        await registrationAccounts.getLastUser().catch(() => undefined);
        await registrationAccounts
          .nearAuthenticatorsByAccount(toAccountId(nearAccountId))
          .catch(() => undefined);
      }
      const result = await pm.auth.hasPasskeyCredential(toAccountId(nearAccountId));
      respondOkResult(deps, req.requestId, result);
    },

    PM_VIEW_ACCESS_KEYS: async (req: Req<'PM_VIEW_ACCESS_KEYS'>) => {
      const pm = deps.getSeamsWeb();
      const { accountId } = req.payload!;
      const result = await pm.viewAccessKeyList(accountId);
      respondOkResult(deps, req.requestId, result);
    },

    PM_DELETE_DEVICE_KEY: async (req: Req<'PM_DELETE_DEVICE_KEY'>) => {
      const pm = deps.getSeamsWeb();
      const { accountId, publicKeyToDelete, options } = req.payload!;
      const result = await pm.deleteDeviceKey(accountId, publicKeyToDelete, {
        ...withProgress(deps, req.requestId, options || {}),
      } as ActionHooksOptions);
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },
  };
}
