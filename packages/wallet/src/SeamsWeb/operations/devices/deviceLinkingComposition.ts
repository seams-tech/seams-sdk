import type { WalletCustodyCeremonyTransportPort } from '@/core/signingEngine/walletCustody/ceremonyStepRunner';
import { IndexedDBManager } from '@/core/indexedDB';
import { createDeviceLinkingEd25519ExportRootPortV1 } from './deviceLinkingEd25519ExportRoot';
import type { AuthenticatorPort } from '@/core/platform';
import type { HttpTransport } from '@/core/platform/http';
import {
  createDeviceLinkingKeyMaterialPortV1,
  type DeviceLinkingWorkerEndpointV1,
} from './deviceLinkingWorkerChannels';
import {
  createDeviceLinkingOwnerTransportV1,
  type LinkSessionOwnerApprovalUpdatesPortV1,
  type LinkSessionOwnerAuthenticatedRequestPortV1,
} from './deviceLinkingOwnerTransport';
import { createDeviceLinkingSessionTransportPortV1 } from './deviceLinkingHttpTransport';
import { createDeviceLinkingTargetCredentialPortV1 } from './deviceLinkingTargetCredential';
import { createDeviceLinkingAuthorityInstallationPortV1 } from './deviceLinkingAuthorityInstallation';
import type {
  DeviceLinkingFlowPortsV1,
  DeviceLinkingOwnerAuthorizationPortV1,
  DeviceLinkingSourceContributionPortV1,
} from './deviceLinkingPorts';

export type DeviceLinkingFlowPortsAssemblyV1 = DeviceLinkingFlowPortsV1 & {
  readonly dispose: () => void;
};

export type DeviceLinkingFlowPortsAssemblyOptionsV1 = {
  readonly authenticator: AuthenticatorPort;
  readonly http: HttpTransport;
  readonly relayerUrl: string;
  readonly ownerRequest: LinkSessionOwnerAuthenticatedRequestPortV1;
  readonly ownerApprovalUpdates: LinkSessionOwnerApprovalUpdatesPortV1;
  readonly ownerAuthorization: DeviceLinkingOwnerAuthorizationPortV1;
  readonly sourceContribution: DeviceLinkingSourceContributionPortV1;
  /** The wallet custody worker both devices drive for the export-root handoff. */
  readonly custodyCeremonyTransport: WalletCustodyCeremonyTransportPort;
  readonly workerEndpoint?: DeviceLinkingWorkerEndpointV1;
  readonly workerTimeoutMs?: number;
  readonly nowMs: () => number;
  readonly pollIntervalMs: number;
};

/**
 * Compose the direct browser flow from explicit trust-boundary providers.
 * Owner authorization stays injected because the browser has no implicit
 * wallet-session or Gateway authority.
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
  });
  const authorityInstallation = createDeviceLinkingAuthorityInstallationPortV1({
    indexedDB: IndexedDBManager,
    sealing: keyMaterial,
    nowMs: args.nowMs,
  });
  // Both devices drive the same worker port: Device 2 creates the recipient and
  // reseals, Device 1 seals to it.
  const ed25519ExportRoot = createDeviceLinkingEd25519ExportRootPortV1(
    args.custodyCeremonyTransport,
  );
  return {
    transport,
    ownerAuthorization: args.ownerAuthorization,
    sourceContribution: args.sourceContribution,
    keyMaterial,
    targetCredential,
    authorityInstallation,
    readExpectedLockGenerationV1: async (walletId) => {
      const selected = await IndexedDBManager.resolveSelectedWalletAuthority(String(walletId));
      if (selected.kind === 'missing_selection') return 0;
      if (selected.kind !== 'resolved') {
        throw new Error(`selected wallet authority is unavailable: ${selected.kind}`);
      }
      return selected.selection.lockGeneration;
    },
    ed25519ExportRoot,
    dispose: keyMaterial.close,
  };
}
