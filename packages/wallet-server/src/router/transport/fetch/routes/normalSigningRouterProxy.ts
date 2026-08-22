import { json } from '../../../framework/http';
import type { RouterAbNormalSigningRouterProxy } from '../../../framework/routerApi';
import type { RouterApiWalletRegistrationService } from '../../../framework/authServicePort';
import type { AuthorizedOperation } from '../../../../authorization/domain';
import {
  prepareOwnerWalletExecution,
} from '../../../domains/signingOperations/walletExecutionAdmission';
import type { RouterAbNormalSigningMaterialSourceV1 } from '../../../domains/signingOperations/routerAbPrivateSigningWorker';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { RouterAbMpcMaterialActivationRefWire } from '@shared/utils/routerAbNormalSigningIdentity';
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
    // Wallet Session bearer tokens are gateway-only credentials. The Router
    // receives the validated owner or linked-device admission in the body.
    if (input.body && isGatewayWalletSessionAdmission(input.body)) {
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

function isGatewayWalletSessionAdmission(body: Record<string, unknown>): boolean {
  const authorizedOperation = body.authorized_operation;
  if (!isRecord(authorizedOperation)) return false;
  return (
    hasKind(authorizedOperation.binding, 'gateway_owner_wallet_session') ||
    hasKind(authorizedOperation.binding, 'reusable_wallet_session')
  );
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
