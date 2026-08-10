import { DeviceLinkingDomain } from '@/SeamsWeb/operations/devices/linkDevice';
import type { DeviceLinkingFlowPortsV1 } from '@/SeamsWeb/operations/devices/deviceLinkingPorts';
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

export type DevicesCapabilityDomainMethods =
  | {
      readonly kind: 'iframe';
      readonly linkedDeviceManagement: LinkedDeviceManagementPortV1;
    }
  | {
      readonly kind: 'direct';
      readonly linkedDeviceManagement: LinkedDeviceManagementPortV1;
      readonly deviceLinkingPorts: DeviceLinkingFlowPortsV1;
    };

export function createWalletIframeLinkedDeviceManagementPortV1(deps: {
  readonly walletIframe: Pick<WalletIframeCoordinator, 'requireRouter'>;
}): LinkedDeviceManagementPortV1 {
  return {
    listLinkedDevices: async ({ walletId }) => {
      const router = await deps.walletIframe.requireRouter(walletId);
      return await router.listLinkedDevices({ walletId: String(walletId) });
    },
    revokeLinkedDevice: async ({ walletId, deviceId, requestedAtMs }) => {
      const router = await deps.walletIframe.requireRouter(walletId);
      return await router.revokeLinkedDevice({
        walletId: String(walletId),
        deviceId: String(deviceId),
        requestedAtMs,
      });
    },
  };
}

export function createDevicesCapability(deps: {
  readonly getContext: () => DeviceLinkingWebContext;
  readonly walletIframe: Pick<WalletIframeCoordinator, 'shouldUseWalletIframe' | 'requireRouter'>;
  readonly domain: DevicesCapabilityDomainMethods;
}): DevicesCapability {
  const deviceLinking =
    deps.domain.kind === 'direct'
      ? new DeviceLinkingDomain({
          kind: 'direct',
          getContext: deps.getContext,
          walletIframe: deps.walletIframe,
          ports: deps.domain.deviceLinkingPorts,
        })
      : new DeviceLinkingDomain({
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
