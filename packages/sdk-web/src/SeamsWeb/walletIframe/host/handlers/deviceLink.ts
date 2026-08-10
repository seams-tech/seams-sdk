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
      const { ui, cameraId, signerSlot, options } = req.payload || {};
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.devices.startDevice2LinkingFlow({
        ...(ui ? { ui } : {}),
        ...(cameraId ? { cameraId } : {}),
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
      const { walletId } = req.payload!;
      const ctx = pm.getContext();
      await ctx?.signingEngine.getLastUser().catch(() => undefined);
      const session = await pm.auth.getWalletSession(walletId).catch(() => null);
      const nearAccountId =
        session?.appIdentity.kind === 'resolved' && session.appIdentity.nearAccountId
          ? String(session.appIdentity.nearAccountId)
          : '';
      if (nearAccountId) {
        await ctx?.signingEngine
          .nearAuthenticatorsByAccount(toAccountId(nearAccountId))
          .catch(() => undefined);
      }
      const result = await pm.auth.hasPasskeyCredential(walletId);
      respondOkResult(deps, req.requestId, result);
    },

    PM_VIEW_ACCESS_KEYS: async (req: Req<'PM_VIEW_ACCESS_KEYS'>) => {
      const pm = deps.getSeamsWeb();
      const { walletId, nearAccountId } = req.payload!;
      const result = await pm.devices.viewAccessKeyList({
        walletSession: walletSessionRefFromSession({
          walletId,
          walletSessionUserId: walletId,
        }),
        nearAccount: nearAccountRefFromAccountId(nearAccountId),
      });
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

    PM_LIST_WALLET_CREDENTIALS: async (req: Req<'PM_LIST_WALLET_CREDENTIALS'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload;
      if (!payload) throw new Error('PM_LIST_WALLET_CREDENTIALS requires a payload');
      const result = await pm.devices.listWalletCredentials({ walletId: payload.walletId });
      respondOkResult(deps, req.requestId, result);
    },

    PM_RENAME_WALLET_CREDENTIAL: async (req: Req<'PM_RENAME_WALLET_CREDENTIAL'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload;
      if (!payload) throw new Error('PM_RENAME_WALLET_CREDENTIAL requires a payload');
      const result = await pm.devices.renameWalletCredential({
        walletId: payload.walletId,
        envelopeId: payload.envelopeId,
        ...(payload.label === undefined ? {} : { label: payload.label }),
      });
      respondOkResult(deps, req.requestId, result);
    },

    PM_REVOKE_WALLET_CREDENTIAL: async (req: Req<'PM_REVOKE_WALLET_CREDENTIAL'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload;
      if (!payload) throw new Error('PM_REVOKE_WALLET_CREDENTIAL requires a payload');
      const result = await pm.devices.revokeWalletCredential({
        walletId: payload.walletId,
        rpId: payload.rpId,
        credentialIdB64u: payload.credentialIdB64u,
      });
      respondOkResult(deps, req.requestId, result);
    },
  };
}
