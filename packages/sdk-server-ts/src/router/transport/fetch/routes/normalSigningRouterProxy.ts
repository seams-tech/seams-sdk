import { json } from '../../../framework/http';
import type { RouterAbNormalSigningRouterProxy } from '../../../framework/routerApi';
import type { RouterApiWalletRegistrationService } from '../../../framework/authServicePort';
import type { AuthorizedOperation } from '../../../../authorization/domain';
import {
  prepareLinkedDeviceWalletExecution,
  prepareOwnerWalletExecution,
  type ActiveLinkedDeviceExecutionProjectionV1,
  type LinkedDeviceExecutionAdmissionResolverV1,
  type LinkedDeviceLocalPresenceAuthorizationV1,
} from '../../../domains/signingOperations/walletExecutionAdmission';
import type { RouterAbNormalSigningMaterialSourceV1 } from '../../../domains/signingOperations/routerAbPrivateSigningWorker';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { RouterAbMpcMaterialActivationRefWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type {
  LaneShareEpoch,
  LinkedDeviceEnrollmentId,
  LinkedDeviceId,
  SigningLaneId,
  WalletKeyId,
} from '@shared/signing-lanes';
import {
  normalizeRouterAbInternalServiceAuthSecret,
  ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
} from '../../../../core/ThresholdService/routerAb/internalServiceHttp';

export const ROUTER_AB_ECDSA_DERIVATION_LINKED_DEVICE_SIGN_PATH =
  '/router-ab/ecdsa-derivation/linked-device/sign' as const;

export async function proxyNormalSigningRequestToMpcRouter(input: {
  readonly request: Request;
  readonly proxy: RouterAbNormalSigningRouterProxy | null | undefined;
  readonly body?: Record<string, unknown>;
  readonly targetPath?: string;
}): Promise<Response> {
  const proxy = input.proxy;
  if (!proxy) {
    return json(
      {
        ok: false,
        code: 'not_configured',
        message: 'MPC Router normal-signing transport is not configured',
      },
      { status: 501 },
    );
  }

  try {
    const headers = new Headers(input.request.headers);
    // Owner Wallet Session bearer tokens are gateway-only credentials. The
    // Router receives the validated owner admission in the operation body.
    if (input.body && isGatewayOwnerWalletSessionAdmission(input.body)) {
      headers.delete('authorization');
    }
    headers.set(
      ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
      normalizeRouterAbInternalServiceAuthSecret(proxy.internalServiceAuthSecret),
    );
    const request = input.targetPath
      ? new Request(new URL(input.targetPath, input.request.url), input.request)
      : input.request;
    const upstreamRequest = input.body
      ? new Request(request, {
          body: JSON.stringify(input.body),
          headers,
        })
      : new Request(request, { headers });
    if (input.body) upstreamRequest.headers.set('content-type', 'application/json');
    const upstream = await proxy.fetch(upstreamRequest);
    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: new Headers(upstream.headers),
    });
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'router_unreachable',
        message: error instanceof Error ? error.message : 'MPC Router request failed',
      },
      { status: 502 },
    );
  }
}

function isGatewayOwnerWalletSessionAdmission(body: Record<string, unknown>): boolean {
  const authorizedOperation = body.authorized_operation;
  if (!isRecord(authorizedOperation)) return false;
  return hasKind(authorizedOperation.binding, 'gateway_owner_wallet_session');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function hasKind(value: unknown, expected: string): boolean {
  return isRecord(value) && value.kind === expected;
}

export async function proxyOwnerLaneAdmittedNormalSigningRequest(input: {
  readonly request: Request;
  readonly proxy: RouterAbNormalSigningRouterProxy | null | undefined;
  readonly body: Record<string, unknown>;
  readonly authorizedOperation: AuthorizedOperation;
  readonly walletId: Parameters<
    RouterApiWalletRegistrationService['resolveActiveOwnerWalletExecutionLane']
  >[0]['walletId'];
  readonly expectedMaterialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly authorization: Parameters<
    RouterApiWalletRegistrationService['resolveActiveOwnerWalletExecutionLane']
  >[0]['authorization'];
  readonly walletRegistration: Pick<
    RouterApiWalletRegistrationService,
    'resolveActiveOwnerWalletExecutionLane'
  >;
}): Promise<Response> {
  const expectedMaterialActivation = routerAbMpcMaterialActivationRefFromWire(
    input.expectedMaterialActivation,
  );
  const resolved = await input.walletRegistration.resolveActiveOwnerWalletExecutionLane({
    walletId: input.walletId,
    expectedMaterialActivation,
    authorization: input.authorization,
  });
  if (resolved.kind === 'refused') {
    return json(
      {
        ok: false,
        code: 'wallet_execution_lane_refused',
        message: `Wallet execution lane is unavailable: ${resolved.reason}`,
      },
      { status: 403 },
    );
  }
  const admission = await prepareOwnerWalletExecution({
    authorizedOperation: input.authorizedOperation,
    evidence: {
      walletId: input.walletId,
      walletKey: resolved.projection.walletKey,
      lane: resolved.projection.lane,
      materialActivation: resolved.projection.materialActivation,
      expectedMaterialActivation,
      verifiedLaneParticipantBindingDigestB64u:
        resolved.projection.lane.participantBindingDigestB64u,
      verifiedActivationReceiptDigestB64u: resolved.projection.verifiedActivationReceiptDigestB64u,
    },
  });
  if (admission.kind === 'refused') {
    return json(
      {
        ok: false,
        code: 'wallet_execution_lane_refused',
        message: `Wallet execution lane admission failed: ${admission.reason}`,
      },
      { status: 403 },
    );
  }
  return await proxyNormalSigningRequestToMpcRouter({
    request: input.request,
    proxy: input.proxy,
    body: input.body,
  });
}

/** Resolves and admits a linked-device lane before forwarding its rotatable source. */
export async function proxyLinkedDeviceLaneAdmittedNormalSigningRequest(input: {
  readonly request: Request;
  readonly proxy: RouterAbNormalSigningRouterProxy | null | undefined;
  readonly body: Record<string, unknown>;
  readonly authorizedOperation: AuthorizedOperation;
  readonly walletId: Parameters<
    LinkedDeviceExecutionAdmissionResolverV1['resolveActiveLinkedDeviceExecutionV1']
  >[0]['walletId'];
  readonly walletSessionId: Parameters<
    LinkedDeviceExecutionAdmissionResolverV1['resolveActiveLinkedDeviceExecutionV1']
  >[0]['walletSessionId'];
  readonly quotaId: Parameters<
    LinkedDeviceExecutionAdmissionResolverV1['resolveActiveLinkedDeviceExecutionV1']
  >[0]['quotaId'];
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly walletKeyId: WalletKeyId;
  readonly laneId: SigningLaneId;
  readonly laneShareEpoch: LaneShareEpoch;
  readonly expectedMaterialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly laneRevocationEpoch: number;
  readonly localPresence: LinkedDeviceLocalPresenceAuthorizationV1;
  readonly linkedDeviceExecution: LinkedDeviceExecutionAdmissionResolverV1;
  readonly targetPath?: string;
}): Promise<Response> {
  if (input.authorizedOperation.lifecycle !== 'claimed') {
    return linkedAdmissionRefused('operation_not_claimed');
  }
  let expectedMaterialActivation: ReturnType<typeof routerAbMpcMaterialActivationRefFromWire>;
  try {
    expectedMaterialActivation = routerAbMpcMaterialActivationRefFromWire(
      input.expectedMaterialActivation,
    );
  } catch {
    return linkedAdmissionRefused('material_activation_mismatch');
  }
  let authorizationId: Parameters<
    LinkedDeviceExecutionAdmissionResolverV1['resolveActiveLinkedDeviceExecutionV1']
  >[0]['authorizationId'];
  try {
    authorizationId = linkedAuthorizationId(input.authorizedOperation);
  } catch {
    return linkedAdmissionRefused('authorization_grant_mismatch');
  }
  let resolved: Awaited<
    ReturnType<LinkedDeviceExecutionAdmissionResolverV1['resolveActiveLinkedDeviceExecutionV1']>
  >;
  try {
    resolved = await input.linkedDeviceExecution.resolveActiveLinkedDeviceExecutionV1({
      tenantId: input.authorizedOperation.operation.tenantId,
      walletSessionId: input.walletSessionId,
      quotaId: input.quotaId,
      walletId: input.walletId,
      enrollmentId: input.enrollmentId,
      deviceId: input.deviceId,
      walletKeyId: input.walletKeyId,
      laneId: input.laneId,
      laneShareEpoch: input.laneShareEpoch,
      laneRevocationEpoch: input.laneRevocationEpoch,
      materialActivation: expectedMaterialActivation,
      authorizationId,
      authorizedOperationId: input.authorizedOperation.authorizedOperationId,
    });
  } catch {
    return linkedAdmissionRefused('linked_execution_unavailable');
  }
  if (resolved.kind === 'refused') {
    return linkedAdmissionRefused(resolved.reason);
  }
  if (!linkedProjectionMatchesRequest(resolved.projection, input)) {
    return linkedAdmissionRefused('linked_device_mismatch');
  }
  const admission = await prepareLinkedDeviceWalletExecution({
    authorizedOperation: input.authorizedOperation,
    evidence: {
      ...resolved.projection,
      expectedMaterialActivation,
    },
    localPresence: input.localPresence,
  });
  if (admission.kind === 'refused') {
    return linkedAdmissionRefused(admission.reason);
  }
  return await proxyRotatableLaneAdmittedNormalSigningRequest({
    request: input.request,
    proxy: input.proxy,
    body: input.body,
    materialSource: resolved.projection.materialSource,
    targetPath: input.targetPath,
  });
}

function linkedProjectionMatchesRequest(
  projection: ActiveLinkedDeviceExecutionProjectionV1,
  input: {
    readonly walletId: Parameters<
      LinkedDeviceExecutionAdmissionResolverV1['resolveActiveLinkedDeviceExecutionV1']
    >[0]['walletId'];
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly deviceId: LinkedDeviceId;
    readonly walletKeyId: WalletKeyId;
    readonly laneId: SigningLaneId;
    readonly laneShareEpoch: LaneShareEpoch;
  },
): boolean {
  return (
    projection.walletKey.walletId === input.walletId &&
    projection.walletKey.walletKeyId === input.walletKeyId &&
    projection.enrollment.walletId === input.walletId &&
    String(projection.enrollment.enrollmentId) === String(input.enrollmentId) &&
    projection.enrollment.deviceId === input.deviceId &&
    projection.authorization.walletId === input.walletId &&
    String(projection.authorization.enrollmentId) === String(input.enrollmentId) &&
    projection.authorization.deviceId === input.deviceId &&
    projection.lane.walletId === input.walletId &&
    projection.lane.walletKeyId === input.walletKeyId &&
    projection.lane.laneId === input.laneId &&
    projection.lane.laneShareEpoch === input.laneShareEpoch &&
    projection.lane.linkedDeviceId === input.deviceId &&
    projection.product.walletId === input.walletId &&
    projection.product.walletKeyId === input.walletKeyId &&
    projection.product.laneId === input.laneId &&
    projection.product.laneShareEpoch === input.laneShareEpoch
  );
}

function linkedAuthorizationId(
  operation: AuthorizedOperation,
): Parameters<
  LinkedDeviceExecutionAdmissionResolverV1['resolveActiveLinkedDeviceExecutionV1']
>[0]['authorizationId'] {
  if (
    operation.authorization.kind !== 'authorization_grant' ||
    operation.authorization.authorizationGrantRef.kind !==
      'linked_device_wallet_session_authorization_v1'
  ) {
    throw new Error('linked-device authorization grant is required');
  }
  return operation.authorization.authorizationGrantRef.authorizationId;
}

function linkedAdmissionRefused(reason: string): Response {
  return json(
    {
      ok: false,
      code: 'wallet_execution_lane_refused',
      message: `Linked-device wallet execution lane admission failed: ${reason}`,
    },
    { status: 403 },
  );
}

/** Forwards a Gateway-admitted rotatable lane source to the private Router. */
export async function proxyRotatableLaneAdmittedNormalSigningRequest(input: {
  readonly request: Request;
  readonly proxy: RouterAbNormalSigningRouterProxy | null | undefined;
  readonly body: Record<string, unknown>;
  readonly materialSource: Extract<
    RouterAbNormalSigningMaterialSourceV1,
    { readonly kind: 'rotatable_lane' }
  >;
  readonly targetPath?: string;
}): Promise<Response> {
  return await proxyNormalSigningRequestToMpcRouter({
    request: input.request,
    proxy: input.proxy,
    body: {
      ...input.body,
      material_source: input.materialSource,
    },
    targetPath: input.targetPath,
  });
}
