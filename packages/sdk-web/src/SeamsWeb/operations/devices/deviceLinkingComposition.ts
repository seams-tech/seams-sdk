import type { AuthenticatorPort } from '@/core/platform';
import type { HttpTransport } from '@/core/platform/http';
import type { LaneOperationSourcePortsV1 } from '@/core/signingEngine/session/lanes/operations/ports';
import { prepareAndCommitSourceLaneOperationV1 } from '@/core/signingEngine/session/lanes/operations/sourceLaneOperationCoordinator';
import {
  parseLinkedDeviceProvisioningDeliveriesV1,
  type LinkedDeviceProvisioningDeliveriesV1,
} from '@shared/device-linking';
import type { LaneEnrollmentManifestV1 } from '@shared/signing-lanes/rotation';
import type {
  LinkedDeviceEnrollmentId,
  LinkedDeviceId,
  LinkDeviceSessionId,
} from '@shared/signing-lanes/ids';
import type { LaneSealedHolderMaterialRepositoryV1 } from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import {
  createDeviceLinkingKeyMaterialPortV1,
  type DeviceLinkingWorkerEndpointV1,
} from './deviceLinkingWorkerChannels';
import { createDeviceLinkingLaneProvisioningPortV1 } from './deviceLinkingLaneProvisioning';
import {
  createDeviceLinkingOwnerTransportV1,
  type LinkSessionOwnerApprovalUpdatesPortV1,
  type LinkSessionOwnerAuthenticatedRequestPortV1,
} from './deviceLinkingOwnerTransport';
import { createDeviceLinkingSessionTransportPortV1 } from './deviceLinkingHttpTransport';
import { createDeviceLinkingTargetCredentialPortV1 } from './deviceLinkingTargetCredential';
import type {
  DeviceLinkingFlowPortsV1,
  DeviceLinkingOwnerAuthorizationPortV1,
} from './deviceLinkingPorts';

/** Target-ready R102 inputs are parsed before they become persisted deliveries. */
export type Device1TargetReadySourceInputV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly manifest: unknown;
  readonly children: readonly unknown[];
};

export type Device1SourcePreparationPortV1 = {
  prepareTargetReadyDeliveriesV1(
    input: Device1TargetReadySourceInputV1,
  ): Promise<LinkedDeviceProvisioningDeliveriesV1>;
};

export type Device1SourceDeliveryPersistencePortV1 = {
  persistProvisioningDeliveriesV1(input: {
    readonly manifest: LaneEnrollmentManifestV1;
    readonly deliveries: LinkedDeviceProvisioningDeliveriesV1;
  }): Promise<void>;
};

export type DeviceLinkingFlowPortsAssemblyV1 = DeviceLinkingFlowPortsV1 & {
  readonly sourcePreparation: Device1SourcePreparationPortV1;
};

export type DeviceLinkingFlowPortsAssemblyOptionsV1 = {
  readonly authenticator: AuthenticatorPort;
  readonly http: HttpTransport;
  readonly relayerUrl: string;
  readonly ownerRequest: LinkSessionOwnerAuthenticatedRequestPortV1;
  readonly ownerApprovalUpdates: LinkSessionOwnerApprovalUpdatesPortV1;
  readonly ownerAuthorization: DeviceLinkingOwnerAuthorizationPortV1;
  readonly repository: LaneSealedHolderMaterialRepositoryV1;
  readonly sourceLanePorts: LaneOperationSourcePortsV1;
  readonly sourceDeliveryPersistence: Device1SourceDeliveryPersistencePortV1;
  readonly workerEndpoint?: DeviceLinkingWorkerEndpointV1;
  readonly workerTimeoutMs?: number;
  readonly nowMs: () => number;
  readonly pollIntervalMs: number;
};

function committedDeliveryChildren(
  input: Awaited<ReturnType<typeof prepareAndCommitSourceLaneOperationV1>>,
): LinkedDeviceProvisioningDeliveriesV1['orderedChildren'] {
  const children = input.committedChildren.map((committedChild) => {
    if (committedChild.protocolCommitResult.outcome === 'conflict') {
      throw new Error('R102 source preparation returned a protocol conflict');
    }
    return {
      kind: 'linked_device_provisioning_child_v1' as const,
      job: committedChild.job,
      protocolCommitReceipt: committedChild.protocolCommitReceipt,
      holderPackage: committedChild.holderPackage,
      expectedVersion: committedChild.protocolCommitResult.version,
    };
  });
  const first = children[0];
  if (!first) throw new Error('R102 source preparation produced no child deliveries');
  return [first, ...children.slice(1)];
}

async function prepareTargetReadyDeliveriesV1(args: {
  readonly input: Device1TargetReadySourceInputV1;
  readonly sourceLanePorts: LaneOperationSourcePortsV1;
  readonly sourceDeliveryPersistence: Device1SourceDeliveryPersistencePortV1;
}): Promise<LinkedDeviceProvisioningDeliveriesV1> {
  const prepared = await prepareAndCommitSourceLaneOperationV1({
    manifest: args.input.manifest,
    children: args.input.children,
    ports: args.sourceLanePorts,
  });
  if (String(prepared.manifest.enrollmentId) !== String(args.input.enrollmentId)) {
    throw new Error('R102 source preparation enrollment does not match the target-ready input');
  }
  const deliveries = parseLinkedDeviceProvisioningDeliveriesV1({
    kind: 'linked_device_provisioning_deliveries_v1',
    linkSessionId: args.input.linkSessionId,
    enrollmentId: args.input.enrollmentId,
    deviceId: args.input.deviceId,
    orderedChildren: committedDeliveryChildren(prepared),
  });
  await args.sourceDeliveryPersistence.persistProvisioningDeliveriesV1({
    manifest: prepared.manifest,
    deliveries,
  });
  return deliveries;
}

export function createDevice1SourcePreparationPortV1(args: {
  readonly sourceLanePorts: LaneOperationSourcePortsV1;
  readonly sourceDeliveryPersistence: Device1SourceDeliveryPersistencePortV1;
}): Device1SourcePreparationPortV1 {
  return {
    prepareTargetReadyDeliveriesV1: (input) =>
      prepareTargetReadyDeliveriesV1({
        input,
        sourceLanePorts: args.sourceLanePorts,
        sourceDeliveryPersistence: args.sourceDeliveryPersistence,
      }),
  };
}

/**
 * Compose the direct browser flow from explicit trust-boundary providers.
 * Owner authorization and R102 source persistence stay injected because the
 * browser has no implicit wallet-session or Gateway authority.
 */
export function createDeviceLinkingFlowPortsV1(
  args: DeviceLinkingFlowPortsAssemblyOptionsV1,
): DeviceLinkingFlowPortsAssemblyV1 {
  const keyMaterial = createDeviceLinkingKeyMaterialPortV1({
    ...(args.workerEndpoint ? { endpoint: args.workerEndpoint } : {}),
    ...(args.workerTimeoutMs === undefined ? {} : { timeoutMs: args.workerTimeoutMs }),
  });
  const ownerTransport = createDeviceLinkingOwnerTransportV1({
    request: args.ownerRequest,
    approvalUpdates: args.ownerApprovalUpdates,
  });
  const transport = createDeviceLinkingSessionTransportPortV1({
    owner: ownerTransport,
    http: args.http,
    relayerUrl: args.relayerUrl,
    keyMaterial,
    nowMs: args.nowMs,
    pollIntervalMs: args.pollIntervalMs,
  });
  const targetCredential = createDeviceLinkingTargetCredentialPortV1({
    authenticator: args.authenticator,
    keyMaterial,
  });
  const laneProvisioning = createDeviceLinkingLaneProvisioningPortV1({
    worker: keyMaterial,
    repository: args.repository,
    nowMs: args.nowMs,
  });
  const sourcePreparation = createDevice1SourcePreparationPortV1({
    sourceLanePorts: args.sourceLanePorts,
    sourceDeliveryPersistence: args.sourceDeliveryPersistence,
  });
  return {
    transport,
    ownerAuthorization: args.ownerAuthorization,
    keyMaterial,
    targetCredential,
    laneProvisioning,
    sourcePreparation,
  };
}
