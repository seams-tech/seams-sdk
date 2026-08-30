import type { WalletCustodyCeremonyTransportPort } from '@/core/signingEngine/walletCustody/ceremonyStepRunner';
import { IndexedDBManager } from '@/core/indexedDB';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
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
import {
  createDeviceLinkingSessionTransportPortV1,
  createDeviceLinkingWalletSessionAcknowledgementReplayPortV1,
} from './deviceLinkingHttpTransport';
import { createDeviceLinkingTargetCredentialPortV1 } from './deviceLinkingTargetCredential';
import {
  createDeviceLinkingAuthorityInstallationPortV1,
  type DeviceLinkingDeliveryResumePortV1,
} from './deviceLinkingAuthorityInstallation';
import {
  replayPendingDeviceLinkingAcknowledgementsV1,
  type DeviceLinkingCommittedResumeV1,
} from './deviceLinkingResume';
import type {
  DeviceLinkingFlowPortsV1,
  DeviceLinkingOwnerAuthorizationPortV1,
  DeviceLinkingSourceContributionPortV1,
  DeviceLinkingWalletSessionAcknowledgementReplayPortV1,
} from './deviceLinkingPorts';
import type {
  LocalAuthorityActivationFinalAckV1,
  WalletSessionOperationCredentialV1,
} from '@shared/device-linking';
import type { WalletAuthMethodId, WalletAuthorityId, WalletId } from '@shared/utils/domainIds';

export type DeviceLinkingFlowPortsAssemblyV1 = DeviceLinkingFlowPortsV1 & {
  readonly resumePendingAcknowledgementsV1: () => Promise<void>;
  readonly dispose: () => void;
};

type DeviceLinkingAcknowledgementExactSessionReadV1 =
  | {
      readonly kind: 'found';
      readonly operationCredential: WalletSessionOperationCredentialV1;
    }
  | { readonly kind: 'missing' };

export type DeviceLinkingAcknowledgementExactSessionReaderV1 = (input: {
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly authMethodId: WalletAuthMethodId;
}) => Promise<DeviceLinkingAcknowledgementExactSessionReadV1>;

function acknowledgementMatchesCommittedResumeV1(
  acknowledgement: LocalAuthorityActivationFinalAckV1,
  candidate: DeviceLinkingCommittedResumeV1,
): boolean {
  return (
    candidate.authorityId === acknowledgement.authorityId &&
    candidate.linkSessionId === acknowledgement.linkSessionId &&
    candidate.packageSetDigestB64u === acknowledgement.packageSetDigestB64u
  );
}

export async function resumePendingDeviceLinkingAcknowledgementsV1(input: {
  readonly installation: DeviceLinkingDeliveryResumePortV1;
  readonly transport: DeviceLinkingWalletSessionAcknowledgementReplayPortV1;
  readonly readExactSession: DeviceLinkingAcknowledgementExactSessionReaderV1;
}): Promise<void> {
  const [resumes, acknowledgements] = await Promise.all([
    input.installation.listCommittedDeliveryResumesV1(),
    input.installation.listPendingActivationAcknowledgementsV1(),
  ]);
  for (const acknowledgement of acknowledgements) {
    const resume = resumes.find(
      acknowledgementMatchesCommittedResumeV1.bind(null, acknowledgement),
    );
    if (!resume) {
      throw new Error('durable linked-device acknowledgement has no matching resume');
    }
    const exactSession = await input.readExactSession({
      walletId: resume.walletId,
      authorityId: resume.authorityId,
      authMethodId: resume.authMethodId,
    });
    if (exactSession.kind === 'missing') continue;
    await replayPendingDeviceLinkingAcknowledgementsV1({
      installation: input.installation,
      transport: input.transport,
      walletId: resume.walletId,
      authorityId: resume.authorityId,
      authMethodId: resume.authMethodId,
      operationCredential: exactSession.operationCredential,
    });
  }
}

async function readDeviceLinkingAcknowledgementExactSessionV1(input: {
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly authMethodId: WalletAuthMethodId;
}): Promise<DeviceLinkingAcknowledgementExactSessionReadV1> {
  const result = await walletSessionAuthorizations.readExactWithOperationCredential(input);
  switch (result.kind) {
    case 'found':
      return { kind: 'found', operationCredential: result.operationCredential };
    case 'missing':
      return { kind: 'missing' };
    case 'upgrade_required':
      throw new Error('Linked-device acknowledgement requires a newer client');
  }
}

export type DeviceLinkingFlowPortsAssemblyOptionsV1 = {
  readonly authenticator: AuthenticatorPort;
  readonly http: HttpTransport;
  readonly relayerUrl: string;
  readonly publishableKey: string;
  readonly projectEnvironmentId: string;
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
    publishableKey: args.publishableKey,
    projectEnvironmentId: args.projectEnvironmentId,
    keyMaterial,
    nowMs: args.nowMs,
    pollIntervalMs: args.pollIntervalMs,
  });
  const acknowledgementTransport =
    createDeviceLinkingWalletSessionAcknowledgementReplayPortV1({
      http: args.http,
      relayerUrl: args.relayerUrl,
      projectEnvironmentId: args.projectEnvironmentId,
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
    resumePendingAcknowledgementsV1: resumePendingDeviceLinkingAcknowledgementsV1.bind(null, {
      installation: authorityInstallation,
      transport: acknowledgementTransport,
      readExactSession: readDeviceLinkingAcknowledgementExactSessionV1,
    }),
    dispose: keyMaterial.close,
  };
}
