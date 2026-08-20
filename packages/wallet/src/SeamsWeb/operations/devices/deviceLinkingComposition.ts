import type { WalletCustodyCeremonyTransportPort } from '@/core/signingEngine/walletCustody/ceremonyStepRunner';
import { createDeviceLinkingEd25519ExportRootPortV1 } from './deviceLinkingEd25519ExportRoot';
import type { AuthenticatorPort } from '@/core/platform';
import type { HttpTransport } from '@/core/platform/http';
import type { LaneOperationSourcePortsV1 } from '@/core/signingEngine/session/lanes/operations/ports';
import { prepareAndCommitSourceLaneOperationV1 } from '@/core/signingEngine/session/lanes/operations/sourceLaneOperationCoordinator';
import {
  parseLinkedDeviceProvisioningDeliveriesV1,
  type LinkedDeviceProvisioningDeliveriesV1,
} from '@shared/device-linking';
import type { LaneSealedHolderMaterialRepositoryV1 } from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import type { LinkedDeviceWalletSessionRepositoryV1 } from '@/core/indexedDB/seamsWalletDB/linkedDeviceWalletSessionStore';
import type { LinkedDeviceExecutionEvidenceRepositoryV1 } from '@/core/indexedDB/seamsWalletDB/linkedDeviceExecutionEvidenceStore';
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
  Device1SourcePreparationPortV1,
  Device1TargetReadySourceInputV1,
  DeviceLinkingSessionActivationPortV1,
  DeviceLinkingFlowPortsV1,
  DeviceLinkingOwnerAuthorizationPortV1,
} from './deviceLinkingPorts';

export type {
  Device1SourcePreparationPortV1,
  Device1TargetReadySourceInputV1,
} from './deviceLinkingPorts';

export type DeviceLinkingFlowPortsAssemblyV1 = DeviceLinkingFlowPortsV1 & {
  readonly sourcePreparation: Device1SourcePreparationPortV1;
  readonly dispose: () => void;
};

export type DeviceLinkingFlowPortsAssemblyOptionsV1 = {
  readonly authenticator: AuthenticatorPort;
  readonly http: HttpTransport;
  readonly relayerUrl: string;
  readonly ownerRequest: LinkSessionOwnerAuthenticatedRequestPortV1;
  readonly ownerApprovalUpdates: LinkSessionOwnerApprovalUpdatesPortV1;
  readonly ownerAuthorization: DeviceLinkingOwnerAuthorizationPortV1;
  readonly repository: LaneSealedHolderMaterialRepositoryV1;
  readonly walletSessionRepository: Pick<
    LinkedDeviceWalletSessionRepositoryV1,
    'putExactActiveDeliveryV1'
  >;
  readonly sessionActivation: DeviceLinkingSessionActivationPortV1;
  readonly executionEvidenceRepository: Pick<
    LinkedDeviceExecutionEvidenceRepositoryV1,
    'putExactProvisionedEvidenceV1' | 'readForEnrollmentV1'
  >;
  readonly sourceLanePorts: LaneOperationSourcePortsV1;
  /** The wallet custody worker both devices drive for the export-root handoff. */
  readonly custodyCeremonyTransport: WalletCustodyCeremonyTransportPort;
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
}): Promise<LinkedDeviceProvisioningDeliveriesV1> {
  const prepared = await prepareAndCommitSourceLaneOperationV1({
    manifest: args.input.manifest,
    children: args.input.children,
    ports: args.sourceLanePorts,
  });
  if (String(prepared.manifest.enrollmentId) !== String(args.input.enrollmentId)) {
    throw new Error('R102 source preparation enrollment does not match the target-ready input');
  }
  return parseLinkedDeviceProvisioningDeliveriesV1({
    kind: 'linked_device_provisioning_deliveries_v1',
    linkSessionId: args.input.linkSessionId,
    enrollmentId: args.input.enrollmentId,
    deviceId: args.input.deviceId,
    manifest: prepared.manifest,
    orderedChildren: committedDeliveryChildren(prepared),
  });
}

export function createDevice1SourcePreparationPortV1(args: {
  readonly sourceLanePorts: LaneOperationSourcePortsV1;
}): Device1SourcePreparationPortV1 {
  return {
    prepareTargetReadyDeliveriesV1: (input) =>
      prepareTargetReadyDeliveriesV1({
        input,
        sourceLanePorts: args.sourceLanePorts,
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
  // Both devices drive the same worker port: Device 2 creates the recipient and
  // reseals, Device 1 seals to it.
  const ed25519ExportRoot = createDeviceLinkingEd25519ExportRootPortV1(
    args.custodyCeremonyTransport,
  );
  const sourcePreparation = createDevice1SourcePreparationPortV1({
    sourceLanePorts: args.sourceLanePorts,
  });
  return {
    transport,
    ownerAuthorization: args.ownerAuthorization,
    sessionActivation: args.sessionActivation,
    keyMaterial,
    targetCredential,
    ed25519ExportRoot,
    laneProvisioning,
    walletSessions: {
      putExactActiveDeliveryV1: async (delivery) => {
        await args.walletSessionRepository.putExactActiveDeliveryV1(delivery);
      },
    },
    executionEvidence: args.executionEvidenceRepository,
    sourcePreparation,
    dispose: keyMaterial.close,
  };
}
