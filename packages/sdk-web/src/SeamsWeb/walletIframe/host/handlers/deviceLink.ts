import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOk, respondOkResult, withProgress } from './shared';
import {
  parseLinkedDeviceListRequestV1,
  parseLinkedDeviceListResultV1,
  parseLinkedDeviceRevokeRequestV1,
  parseLinkedDeviceRevokeResultV1,
  parseQrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking';

export function createDeviceLinkWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_START_DEVICE2_LINKING_FLOW: async (req: Req<'PM_START_DEVICE2_LINKING_FLOW'>) => {
      const pm = deps.getSeamsWeb();
      const { ui, cameraId, options } = req.payload || {};
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.devices.startDevice2LinkingFlow({
        ...(ui ? { ui } : {}),
        ...(cameraId ? { cameraId } : {}),
        options: {
          ...withProgress(deps, req.requestId, options || {}),
        },
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_CANCEL_DEVICE_LINKING: async (req: Req<'PM_CANCEL_DEVICE_LINKING'>) => {
      const pm = deps.getSeamsWeb();
      if (deps.respondIfCancelled(req.requestId)) return;
      await pm.devices.cancelDeviceLinking();
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOk(deps, req.requestId);
    },

    PM_SCAN_AND_LINK_DEVICE: async (req: Req<'PM_SCAN_AND_LINK_DEVICE'>) => {
      const pm = deps.getSeamsWeb();
      const { qrData, options } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      const result = await pm.devices.scanAndLinkDevice(
        parseQrLinkedDeviceSessionPayloadV4(qrData),
        withProgress(deps, req.requestId, options || {}),
      );
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_HAS_PASSKEY: async (req: Req<'PM_HAS_PASSKEY'>) => {
      const pm = deps.getSeamsWeb();
      const { walletId } = req.payload!;
      const result = await pm.auth.hasPasskeyCredential(walletId);
      respondOkResult(deps, req.requestId, result);
    },

    PM_LIST_LINKED_DEVICES: async (req: Req<'PM_LIST_LINKED_DEVICES'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload;
      if (!payload) throw new Error('PM_LIST_LINKED_DEVICES requires a payload');
      const request = parseLinkedDeviceListRequestV1({
        kind: 'linked_device_list_request_v1',
        walletId: payload.walletId,
        limit: payload.limit,
        cursor: payload.cursor,
      });
      const result = await pm.devices.listLinkedDevices({
        walletId: String(request.walletId),
        limit: request.limit,
        cursor: request.cursor,
      });
      respondOkResult(deps, req.requestId, parseLinkedDeviceListResultV1(result));
    },

    PM_REVOKE_LINKED_DEVICE: async (req: Req<'PM_REVOKE_LINKED_DEVICE'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload;
      if (!payload) throw new Error('PM_REVOKE_LINKED_DEVICE requires a payload');
      if (deps.respondIfCancelled(req.requestId)) return;
      const request = parseLinkedDeviceRevokeRequestV1({
        kind: 'linked_device_revoke_request_v1',
        walletId: payload.walletId,
        deviceId: payload.deviceId,
        requestedAtMs: payload.requestedAtMs,
      });
      const result = await pm.devices.revokeLinkedDevice({
        walletId: String(request.walletId),
        deviceId: String(request.deviceId),
        requestedAtMs: request.requestedAtMs,
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, parseLinkedDeviceRevokeResultV1(result));
    },
  };
}
