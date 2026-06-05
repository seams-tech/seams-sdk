import { DeviceLinkingDomain } from '@/web/SeamsWeb/operations/devices/linkDevice';
import type {
  DeviceLinkingWebContext,
  DevicesCapability,
} from '@/web/SeamsWeb/signingSurface/types';
import type { WalletIframeCoordinator } from '@/web/SeamsWeb/walletIframe/coordinator';

export type DevicesCapabilityDomainMethods = {
  viewAccessKeyList: DevicesCapability['viewAccessKeyList'];
  deleteDeviceKey: DevicesCapability['deleteDeviceKey'];
};

export function createDevicesCapability(deps: {
  getContext: () => DeviceLinkingWebContext;
  walletIframe: Pick<WalletIframeCoordinator, 'shouldUseWalletIframe' | 'requireRouter'>;
  domain: DevicesCapabilityDomainMethods;
}): DevicesCapability {
  const deviceLinking = new DeviceLinkingDomain({
    getContext: deps.getContext,
    walletIframe: deps.walletIframe,
  });
  return {
    startDevice2LinkingFlow: async (args) =>
      await deviceLinking.startDevice2LinkingFlow(args),
    stopDevice2LinkingFlow: async () => await deviceLinking.stopDevice2LinkingFlow(),
    linkDeviceWithScannedQRData: async (qrData, options) =>
      await deviceLinking.linkDeviceWithScannedQRData(qrData, options),
    viewAccessKeyList: deps.domain.viewAccessKeyList,
    deleteDeviceKey: deps.domain.deleteDeviceKey,
  } satisfies DevicesCapability;
}
