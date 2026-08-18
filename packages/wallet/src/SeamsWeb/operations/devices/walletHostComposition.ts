import type { WalletCustodyCeremonyTransportPort } from '@/core/signingEngine/walletCustody/ceremonyStepRunner';
import type { AuthenticatorPort } from '@/core/platform';
import type { HttpTransport } from '@/core/platform/http';
import type { LaneOperationSourcePortsV1 } from '@/core/signingEngine/session/lanes/operations/ports';
import type { LaneSealedHolderMaterialRepositoryV1 } from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import type { LinkedDeviceWalletSessionRepositoryV1 } from '@/core/indexedDB/seamsWalletDB/linkedDeviceWalletSessionStore';
import type { LinkedDeviceExecutionEvidenceRepositoryV1 } from '@/core/indexedDB/seamsWalletDB/linkedDeviceExecutionEvidenceStore';
import {
  parseLinkedDeviceListRequestV1,
  parseLinkedDeviceListResultV1,
  parseLinkedDeviceRevokeRequestV1,
  parseLinkedDeviceRevokeResultV1,
  type LinkedDeviceRevokeResultV1,
} from '@shared/device-linking';
import type { WalletId } from '@shared/utils/domainIds';
import type { DeviceLinkingWorkerEndpointV1 } from './deviceLinkingWorkerChannels';
import type { DeviceLinkingFlowPortsAssemblyV1 } from './deviceLinkingComposition';
import { createDeviceLinkingFlowPortsV1 } from './deviceLinkingComposition';
import type {
  LinkSessionOwnerApprovalUpdatesPortV1,
  LinkSessionOwnerAuthenticatedRequestPortV1,
} from './deviceLinkingOwnerTransport';
import type {
  DeviceLinkingOwnerAuthorizationPortV1,
  DeviceLinkingSessionActivationPortV1,
} from './deviceLinkingPorts';
import type { LinkedDeviceManagementPortV1 } from '@/SeamsWeb/publicApi/devices';
import type { WalletHostManagementRequestV1 } from './walletHostOwnerAuthority';

export const LINKED_DEVICE_MANAGEMENT_HTTP_BASE_PATH_V1 =
  '/wallet/device-linking/v1/devices' as const;

/**
 * The owner request closures are created by the wallet-host signing surface.
 * They retain the active Wallet Session credential and expose only parsed HTTP
 * boundaries to this assembly layer.
 */
export type WalletHostCompositionDependenciesV1 = {
  readonly authenticator: AuthenticatorPort;
  readonly http: HttpTransport;
  readonly relayerUrl: string;
  readonly ownerRequest: LinkSessionOwnerAuthenticatedRequestPortV1;
  readonly ownerApprovalUpdates: LinkSessionOwnerApprovalUpdatesPortV1;
  readonly ownerAuthorization: DeviceLinkingOwnerAuthorizationPortV1;
  /** The wallet custody worker both devices drive for the seed transfer. */
  readonly custodyCeremonyTransport: WalletCustodyCeremonyTransportPort;
  readonly managementRequest: WalletHostManagementRequestV1;
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
  readonly workerEndpoint?: DeviceLinkingWorkerEndpointV1;
  readonly workerTimeoutMs?: number;
  readonly nowMs: () => number;
  readonly pollIntervalMs: number;
};

export type WalletHostCompositionV1 = {
  readonly linkedDeviceManagement: LinkedDeviceManagementPortV1;
  readonly deviceLinkingPorts: DeviceLinkingFlowPortsAssemblyV1;
  readonly dispose: () => void;
};

export function createWalletHostCompositionV1(
  args: WalletHostCompositionDependenciesV1,
): WalletHostCompositionV1 {
  const deviceLinkingPorts = createDeviceLinkingFlowPortsV1(args);
  return {
    linkedDeviceManagement: createWalletHostLinkedDeviceManagementPortV1({
      request: args.managementRequest,
    }),
    deviceLinkingPorts,
    dispose: deviceLinkingPorts.dispose,
  };
}

function createWalletHostLinkedDeviceManagementPortV1(args: {
  readonly request: WalletHostManagementRequestV1;
}): LinkedDeviceManagementPortV1 {
  return {
    listLinkedDevices: async ({ walletId, limit, cursor }) => {
      const request = parseLinkedDeviceListRequestV1({
        kind: 'linked_device_list_request_v1',
        walletId,
        limit,
        cursor,
      });
      const path = `${LINKED_DEVICE_MANAGEMENT_HTTP_BASE_PATH_V1}?walletId=${encodeURIComponent(
        String(request.walletId),
      )}&limit=${encodeURIComponent(String(request.limit))}&cursor=${encodeURIComponent(
        request.cursor ?? '',
      )}`;
      const response = await args.request.request({
        method: 'GET',
        canonicalPath: path,
        walletId: request.walletId,
      });
      assertManagementSuccess(response, 'list linked devices');
      return parseLinkedDeviceListResultV1(stripOkField(response.body));
    },
    revokeLinkedDevice: async ({ walletId, deviceId, requestedAtMs }) => {
      const request = parseLinkedDeviceRevokeRequestV1({
        kind: 'linked_device_revoke_request_v1',
        walletId,
        deviceId,
        requestedAtMs,
      });
      const response = await args.request.request({
        method: 'POST',
        canonicalPath: `${LINKED_DEVICE_MANAGEMENT_HTTP_BASE_PATH_V1}/${encodeURIComponent(
          String(deviceId),
        )}/revoke`,
        body: request,
        walletId,
      });
      return parseManagementRevokeResult(response);
    },
  };
}

function parseManagementRevokeResult(response: {
  readonly status: number;
  readonly body: unknown;
}): LinkedDeviceRevokeResultV1 {
  if (response.status === 404) return parseLinkedDeviceRevokeResultV1({ kind: 'not_found' });
  if (response.status === 409) return parseLinkedDeviceRevokeResultV1({ kind: 'conflict' });
  if (response.status === 401 || response.status === 403) {
    return parseLinkedDeviceRevokeResultV1({ kind: 'unauthorized' });
  }
  assertManagementSuccess(response, 'revoke linked device');
  return parseLinkedDeviceRevokeResultV1(stripOkField(response.body));
}

function assertManagementSuccess(
  response: { readonly status: number; readonly body: unknown },
  operation: string,
): void {
  if (response.status < 200 || response.status >= 300) {
    const detail = managementFailureDetail(response.body);
    throw new Error(
      detail
        ? `linked-device ${operation} failed with HTTP ${response.status}: ${detail}`
        : `linked-device ${operation} failed with HTTP ${response.status}`,
    );
  }
}

function managementFailureDetail(raw: unknown): string | null {
  if (!isRecord(raw)) return null;
  const message = raw.message;
  return typeof message === 'string' && message.trim() ? message : null;
}

function stripOkField(raw: unknown): unknown {
  if (!isRecord(raw)) return raw;
  const { ok: _ok, ...withoutOk } = raw;
  return withoutOk;
}

function isRecord(raw: unknown): raw is Record<string, unknown> {
  return raw !== null && typeof raw === 'object' && !Array.isArray(raw);
}
