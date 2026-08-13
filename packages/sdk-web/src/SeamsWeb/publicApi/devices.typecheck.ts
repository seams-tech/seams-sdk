import type { DeviceLinkingFlowPortsV1 } from '@/SeamsWeb/operations/devices/deviceLinkingPorts';
import type { LinkedDeviceLocalStateInvalidationPortV1 } from '@/SeamsWeb/operations/devices/linkedDeviceLocalStateInvalidation';
import type { LinkedDeviceManagementPortV1, DevicesCapabilityDomainMethods } from './devices';

declare const linkedDeviceManagement: LinkedDeviceManagementPortV1;
declare const deviceLinkingPorts: DeviceLinkingFlowPortsV1;
declare const localStateInvalidation: LinkedDeviceLocalStateInvalidationPortV1;

const directDomain = {
  kind: 'direct',
  linkedDeviceManagement,
  deviceLinkingPorts,
  localStateInvalidation,
} satisfies DevicesCapabilityDomainMethods;
void directDomain;

const iframeDomain = {
  kind: 'iframe',
  linkedDeviceManagement,
} satisfies DevicesCapabilityDomainMethods;
void iframeDomain;

// @ts-expect-error direct wallet-host composition cannot omit authenticated ports.
const incompleteDirectDomain: DevicesCapabilityDomainMethods = {
  kind: 'direct',
  linkedDeviceManagement,
};
void incompleteDirectDomain;
