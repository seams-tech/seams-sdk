import { DeviceLinkingDomain } from '@/SeamsWeb/operations/devices/linkDevice';
import type { DeviceLinkingWebContext, DevicesCapability } from '@/SeamsWeb/signingSurface/types';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';
import { parseLinkedDeviceId, parseWalletId, type WalletId } from '@shared/utils/domainIds';
import type { LinkedDeviceId } from '@shared/signing-lanes/ids';
import type { LinkedDeviceListResultV1, LinkedDeviceRevokeResultV1 } from '@shared/device-linking';
import {
  parseLinkedDeviceListRequestV1,
  parseLinkedDeviceListResultV1,
  parseLinkedDeviceRevokeRequestV1,
  parseLinkedDeviceRevokeResultV1,
} from '@shared/device-linking';

export {
  parseLinkedDeviceListRequestV1,
  parseLinkedDeviceListResultV1,
  parseLinkedDeviceRevokeRequestV1,
  parseLinkedDeviceRevokeResultV1,
  parseLinkedDeviceSummaryV1,
} from '@shared/device-linking';
export type {
  LinkedDeviceListRequestV1,
  LinkedDeviceListResultV1,
  LinkedDeviceManagementRequestV1,
  LinkedDeviceRevokeRequestV1,
  LinkedDeviceRevokeResultV1,
  LinkedDeviceSummaryV1,
} from '@shared/device-linking';

export type LinkedDeviceManagementPortV1 = {
  listLinkedDevices(input: { readonly walletId: WalletId }): Promise<LinkedDeviceListResultV1>;
  revokeLinkedDevice(input: {
    readonly walletId: WalletId;
    readonly deviceId: LinkedDeviceId;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceRevokeResultV1>;
};

export type DevicesCapabilityDomainMethods = {
  readonly linkedDeviceManagement: LinkedDeviceManagementPortV1;
};

export function createDevicesCapability(deps: {
  readonly getContext: () => DeviceLinkingWebContext;
  readonly walletIframe: Pick<WalletIframeCoordinator, 'shouldUseWalletIframe' | 'requireRouter'>;
  readonly domain: DevicesCapabilityDomainMethods;
}): DevicesCapability {
  const deviceLinking = new DeviceLinkingDomain({
    kind: 'iframe',
    getContext: deps.getContext,
    walletIframe: deps.walletIframe,
  });
  return {
    startDevice2LinkingFlow: async (args) => await deviceLinking.startDevice2LinkingFlow(args),
    cancelDeviceLinking: async () => await deviceLinking.cancelDeviceLinking(),
    scanAndLinkDevice: async (qrData, options) =>
      await deviceLinking.scanAndLinkDevice(qrData, options),
    listLinkedDevices: async (args) => {
      const request = parseLinkedDeviceListRequestV1({
        kind: 'linked_device_list_request_v1',
        walletId: parseWalletIdForPublicCall(args.walletId),
      });
      const result = await deps.domain.linkedDeviceManagement.listLinkedDevices({
        walletId: request.walletId,
      });
      return parseLinkedDeviceListResultV1(result);
    },
    revokeLinkedDevice: async (args) => {
      const request = parseLinkedDeviceRevokeRequestV1({
        kind: 'linked_device_revoke_request_v1',
        walletId: parseWalletIdForPublicCall(args.walletId),
        deviceId: parseLinkedDeviceIdForPublicCall(args.deviceId),
        requestedAtMs: args.requestedAtMs,
      });
      const result = await deps.domain.linkedDeviceManagement.revokeLinkedDevice({
        walletId: request.walletId,
        deviceId: request.deviceId,
        requestedAtMs: request.requestedAtMs,
      });
      return parseLinkedDeviceRevokeResultV1(result);
    },
  } satisfies DevicesCapability;
}

function parseWalletIdForPublicCall(raw: string): WalletId {
  const result = parseWalletId(raw);
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function parseLinkedDeviceIdForPublicCall(raw: string): LinkedDeviceId {
  const result = parseLinkedDeviceId(raw);
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}
