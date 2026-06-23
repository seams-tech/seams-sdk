import type { ActionHooksOptions } from '@/core/types/sdkSentEvents';
import { toAccountId } from '@/core/types/accountIds';
import {
  nearAccountRefFromAccountId,
  walletSessionRefFromSession,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOk, respondOkResult, withProgress } from './shared';

export function createDeviceLinkWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_START_DEVICE2_LINKING_FLOW: async (req: Req<'PM_START_DEVICE2_LINKING_FLOW'>) => {
      const pm = deps.getSeamsWeb();
      const { ui, cameraId, accountId, signerSlot, options } = req.payload || {};
      const accountIdValue = accountId ? toAccountId(accountId) : undefined;
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.devices.startDevice2LinkingFlow({
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
      await pm.devices.stopDevice2LinkingFlow();
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOk(deps, req.requestId);
    },

    PM_LINK_DEVICE_WITH_SCANNED_QR_DATA: async (
      req: Req<'PM_LINK_DEVICE_WITH_SCANNED_QR_DATA'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const { qrData, fundingAmount, options } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.devices.linkDeviceWithScannedQRData(qrData, {
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
      await ctx?.signingEngine.getLastUser().catch(() => undefined);
      await ctx?.signingEngine
        .nearAuthenticatorsByAccount(toAccountId(nearAccountId))
        .catch(() => undefined);
      const result = await pm.auth.hasPasskeyCredential(toAccountId(nearAccountId));
      respondOkResult(deps, req.requestId, result);
    },

    PM_VIEW_ACCESS_KEYS: async (req: Req<'PM_VIEW_ACCESS_KEYS'>) => {
      const pm = deps.getSeamsWeb();
      const { accountId } = req.payload!;
      const result = await pm.devices.viewAccessKeyList(accountId);
      respondOkResult(deps, req.requestId, result);
    },

    PM_DELETE_DEVICE_KEY: async (req: Req<'PM_DELETE_DEVICE_KEY'>) => {
      const pm = deps.getSeamsWeb();
      const { walletId, nearAccountId, publicKeyToDelete, options } = req.payload!;
      const result = await pm.devices.deleteDeviceKey({
        walletSession: walletSessionRefFromSession({
          walletId,
          walletSessionUserId: walletId,
        }),
        nearAccount: nearAccountRefFromAccountId(nearAccountId),
        publicKeyToDelete,
        options: {
          ...withProgress(deps, req.requestId, options || {}),
        } as ActionHooksOptions,
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },
  };
}
