import type {
  LinkedDeviceListRequestV1,
  LinkedDeviceRevokeRequestV1,
} from '@shared/device-linking/contracts';
import {
  parseLinkedDeviceListRequestV1,
  parseLinkedDeviceRevokeRequestV1,
} from '@shared/device-linking/parsers';
import { parseLinkedDeviceId } from '@shared/signing-lanes/ids';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256Bytes } from '@shared/utils/digests';
import type {
  DeviceLinkingAuthDeniedV1,
  DeviceLinkingAuthenticatedRequestV1,
  DeviceLinkingOwnerRequestInputV1,
  DeviceLinkingRequestBindingV1,
} from './deviceLinking';
import type { LinkedDeviceManagementServiceV1 } from '../../../../core/deviceLinking/linkedDeviceManagement';
import type { FetchRouterApiContext } from '../createFetchRouter';
import { json } from '../../../framework/http';

export const LINKED_DEVICE_MANAGEMENT_BASE_V1 = '/wallet/device-linking/v1/devices';

export type DeviceManagementRouteServiceV1 = {
  readonly management: Pick<
    LinkedDeviceManagementServiceV1,
    'listLinkedDevicesV1' | 'revokeLinkedDeviceV1'
  >;
  readonly nowV1: () => number;
  authenticateOwnerRequestV1(
    input: DeviceLinkingOwnerRequestInputV1,
  ): Promise<DeviceLinkingAuthenticatedRequestV1 | DeviceLinkingAuthDeniedV1>;
};

export async function handleDeviceManagement(
  ctx: FetchRouterApiContext,
  service: DeviceManagementRouteServiceV1,
): Promise<Response | null> {
  const action = parseManagementPath(ctx.pathname);
  if (!action) return null;
  const nowMs = service.nowV1();
  try {
    if (action.kind === 'list') return await handleList(ctx, service, nowMs);
    return await handleRevoke(ctx, service, nowMs);
  } catch (error: unknown) {
    if (error instanceof DeviceManagementInputError) {
      return json({ ok: false, kind: 'invalid_input', message: error.message }, { status: 400 });
    }
    return json(
      { ok: false, kind: 'internal', message: error instanceof Error ? error.message : String(error) },
      { status: 500 },
    );
  }
}

async function handleList(
  ctx: FetchRouterApiContext,
  service: DeviceManagementRouteServiceV1,
  nowMs: number,
): Promise<Response | null> {
  if (ctx.method !== 'GET') return methodNotAllowedResponse();
  const request = parseBoundary(() => parseListQuery(ctx.url.searchParams));
  const canonicalPathname = canonicalListPath(ctx.pathname, request);
  const body = await readRequestBodyDigest(ctx.request);
  const authentication = await authenticateOwner(
    service,
    ctx,
    canonicalPathname,
    body.digestB64u,
    nowMs,
  );
  if (authentication.kind === 'denied') return authDeniedResponse(authentication);
  validateOwnerBinding(authentication.binding, ctx.method, canonicalPathname, body.digestB64u, nowMs);
  if (authentication.owner.walletId !== request.walletId) return unauthorizedResponse();
  if (body.bytes.byteLength !== 0) {
    throw new DeviceManagementInputError('linked-device list request must have an empty body');
  }
  const result = await service.management.listLinkedDevicesV1(
    request,
    authentication.owner,
    nowMs,
  );
  if ('kind' in result) return unauthorizedResponse();
  return json({ ok: true, devices: result.devices }, { status: 200 });
}

async function handleRevoke(
  ctx: FetchRouterApiContext,
  service: DeviceManagementRouteServiceV1,
  nowMs: number,
): Promise<Response | null> {
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const body = await readRequestBodyDigest(ctx.request);
  const authentication = await authenticateOwner(service, ctx, ctx.pathname, body.digestB64u, nowMs);
  if (authentication.kind === 'denied') return authDeniedResponse(authentication);
  validateOwnerBinding(authentication.binding, ctx.method, ctx.pathname, body.digestB64u, nowMs);
  const request = parseBoundary(() => parseLinkedDeviceRevokeRequestV1(authentication.body));
  if (authentication.owner.walletId !== request.walletId) return unauthorizedResponse();
  const pathDeviceId = parseBoundary(() => parsePathDeviceId(ctx.pathname));
  if (request.deviceId !== pathDeviceId) {
    throw new DeviceManagementInputError('device id does not match the route');
  }
  if (request.requestedAtMs > nowMs) {
    throw new DeviceManagementInputError('revoke request is from the future');
  }
  const result = await service.management.revokeLinkedDeviceV1(request, authentication.owner);
  switch (result.kind) {
    case 'revoked':
    case 'replayed':
      return json({ ok: true, ...result }, { status: 200 });
    case 'not_found':
      return json({ ok: false, kind: result.kind }, { status: 404 });
    case 'conflict':
      return json({ ok: false, kind: result.kind }, { status: 409 });
    case 'unauthorized':
      return unauthorizedResponse();
  }
}

async function authenticateOwner(
  service: DeviceManagementRouteServiceV1,
  ctx: FetchRouterApiContext,
  pathname: string,
  bodyDigestB64u: DigestB64u,
  nowMs: number,
): Promise<DeviceLinkingAuthenticatedRequestV1 | DeviceLinkingAuthDeniedV1> {
  return await service.authenticateOwnerRequestV1({
    request: ctx.request,
    method: ctx.method,
    pathname,
    bodyDigestB64u,
    requestedAtMs: nowMs,
  });
}

function parseListQuery(search: URLSearchParams): LinkedDeviceListRequestV1 {
  const keys = [...search.keys()].sort();
  if (keys.length !== 1 || keys[0] !== 'walletId') {
    throw new Error('linked-device list query must contain only walletId');
  }
  const walletId = search.get('walletId');
  if (!walletId) throw new Error('walletId is required');
  return parseLinkedDeviceListRequestV1({
    kind: 'linked_device_list_request_v1',
    walletId,
  });
}

function canonicalListPath(
  pathname: string,
  request: LinkedDeviceListRequestV1,
): string {
  const search = new URLSearchParams([['walletId', String(request.walletId)]]);
  return `${pathname}?${search.toString()}`;
}

function parsePathDeviceId(pathname: string) {
  const prefix = `${LINKED_DEVICE_MANAGEMENT_BASE_V1}/`;
  const suffix = pathname.slice(prefix.length);
  const parts = suffix.split('/');
  if (parts.length !== 2 || parts[1] !== 'revoke' || !parts[0]) {
    throw new Error('linked-device revoke path is invalid');
  }
  const parsed = parseLinkedDeviceId(decodePathComponent(parts[0]));
  if (!parsed.ok) throw new Error('linked-device revoke device id is invalid');
  return parsed.value;
}

function parseManagementPath(pathname: string): { readonly kind: 'list' | 'revoke' } | null {
  if (pathname === LINKED_DEVICE_MANAGEMENT_BASE_V1) return { kind: 'list' };
  if (pathname.startsWith(`${LINKED_DEVICE_MANAGEMENT_BASE_V1}/`)) return { kind: 'revoke' };
  return null;
}

function validateOwnerBinding(
  binding: DeviceLinkingRequestBindingV1,
  method: string,
  pathname: string,
  bodyDigestB64u: DigestB64u,
  nowMs: number,
): void {
  if (
    binding.kind !== 'linked_device_owner_request_binding_v1' ||
    binding.method !== method ||
    binding.pathname !== pathname ||
    binding.bodyDigestB64u !== bodyDigestB64u ||
    binding.expiresAtMs <= nowMs
  ) {
    throw new DeviceManagementInputError('owner request binding is invalid or expired');
  }
}

async function readRequestBodyDigest(request: Request): Promise<{
  readonly bytes: Uint8Array;
  readonly digestB64u: DigestB64u;
}> {
  const bytes = new Uint8Array(await request.clone().arrayBuffer());
  const digestB64u = parseDigestB64u(base64UrlEncode(await sha256Bytes(bytes)));
  return { bytes, digestB64u };
}

function decodePathComponent(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    throw new Error('linked-device revoke path is invalid');
  }
}

function parseBoundary<T>(parse: () => T): T {
  try {
    return parse();
  } catch (error: unknown) {
    throw new DeviceManagementInputError(error instanceof Error ? error.message : String(error));
  }
}

function authDeniedResponse(result: DeviceLinkingAuthDeniedV1): Response {
  return json(
    { ok: false, kind: 'unauthorized', code: result.code, message: result.message },
    { status: result.code === 'expired' ? 410 : 401 },
  );
}

function unauthorizedResponse(): Response {
  return json({ ok: false, kind: 'unauthorized' }, { status: 401 });
}

function methodNotAllowedResponse(): Response {
  return json({ ok: false, kind: 'method_not_allowed' }, { status: 405 });
}

class DeviceManagementInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DeviceManagementInputError';
  }
}
