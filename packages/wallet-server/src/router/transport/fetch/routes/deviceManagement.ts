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
import {
  LinkedDeviceListCursorError,
  MAX_LINKED_DEVICE_LIST_LIMIT_V1,
  type LinkedDeviceManagementOwnerV1,
  type LinkedDeviceManagementListPrincipalV1,
  type LinkedDeviceManagementServiceV1,
} from '../../../../core/deviceLinking/linkedDeviceManagement';
import { parseLinkedDeviceWalletSession } from '../../../domains/signingOperations/linkedDeviceNormalSigning';
import {
  buildFullOwnerDelegatedWalletAuthorityV1,
  sameDelegatedWalletAuthorityV1,
} from '@shared/authorization/delegatedAuthority';
import type { FetchRouterApiContext } from '../createFetchRouter';
import { json } from '../../../framework/http';

export const LINKED_DEVICE_MANAGEMENT_BASE_V1 = '/wallet/device-linking/v1/devices';
export const LINKED_DEVICE_MANAGEMENT_MAX_PAGE_SIZE_V1 = MAX_LINKED_DEVICE_LIST_LIMIT_V1;

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
    if (error instanceof DeviceManagementInputError || error instanceof LinkedDeviceListCursorError) {
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
  const linked = await authenticateLinkedDeviceManagementOwner(ctx, nowMs);
  let principal: LinkedDeviceManagementListPrincipalV1;
  if (linked.kind === 'authorized') {
    if (linked.owner.walletId !== request.walletId) return unauthorizedResponse();
    principal = linked.owner;
  } else {
    if (linked.kind === 'denied') return unauthorizedResponse();
    const authentication = await authenticateOwner(
      service,
      ctx,
      canonicalPathname,
      body.digestB64u,
      nowMs,
    );
    if (authentication.kind === 'denied') return authDeniedResponse(authentication);
    validateOwnerBinding(
      authentication.binding,
      ctx.method,
      canonicalPathname,
      body.digestB64u,
      nowMs,
    );
    if (authentication.owner.walletId !== request.walletId) return unauthorizedResponse();
    principal = {
      walletId: authentication.owner.walletId,
      expiresAtMs: authentication.owner.expiresAtMs,
      permission: buildFullOwnerDelegatedWalletAuthorityV1(),
    };
  }
  if (body.bytes.byteLength !== 0) {
    throw new DeviceManagementInputError('linked-device list request must have an empty body');
  }
  const result = await service.management.listLinkedDevicesV1(
    request,
    principal,
    nowMs,
  );
  if ('kind' in result) return unauthorizedResponse();
  return json(
    {
      ok: true,
      devices: result.devices,
      ownerDevices: result.ownerDevices,
      nextCursor: result.nextCursor,
    },
    { status: 200 },
  );
}

type LinkedDeviceManagementAuthenticationV1 =
  | { readonly kind: 'not_linked' }
  | { readonly kind: 'denied' }
  | {
      readonly kind: 'authorized';
      readonly owner: LinkedDeviceManagementOwnerV1;
    };

async function authenticateLinkedDeviceManagementOwner(
  ctx: FetchRouterApiContext,
  nowMs: number,
): Promise<LinkedDeviceManagementAuthenticationV1> {
  const linked = await parseLinkedDeviceWalletSession({
    session: ctx.opts.session,
    headers: Object.fromEntries(ctx.request.headers.entries()),
    nowMs: () => nowMs,
  });
  if (linked.kind !== 'linked_device') return { kind: 'not_linked' };
  const persisted = await ctx.service.authorizationSessions.readLinkedDeviceWalletSessionAuthorization({
    tenantId: linked.claims.tenantId,
    deviceId: linked.claims.deviceId,
    authorizationId: linked.claims.authorizationId,
    walletSessionId: linked.claims.walletSessionId,
    quotaId: linked.claims.quotaId,
    nowMs,
  });
  const authorization = persisted?.authorization;
  if (
    !persisted ||
    !authorization ||
    authorization.walletId !== linked.claims.walletId ||
    authorization.enrollmentId !== linked.claims.enrollmentId ||
    authorization.deviceId !== linked.claims.deviceId ||
    authorization.keyManifestDigestB64u !== linked.claims.keyManifestDigestB64u ||
    authorization.revocationEpoch !== linked.claims.revocationEpoch ||
    !sameDelegatedWalletAuthorityV1(authorization.permission, linked.claims.permission)
  ) {
    return { kind: 'denied' };
  }
  const expiresAtMs = Math.min(
    linked.claims.expiresAtMs,
    authorization.expiresAtMs,
    persisted.quota.expiresAtMs,
  );
  if (expiresAtMs <= nowMs) return { kind: 'denied' };
  return {
    kind: 'authorized',
    owner: {
      walletId: authorization.walletId,
      expiresAtMs,
      permission: authorization.permission,
    },
  };
}

async function handleRevoke(
  ctx: FetchRouterApiContext,
  service: DeviceManagementRouteServiceV1,
  nowMs: number,
): Promise<Response | null> {
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const body = await readRequestBodyDigest(ctx.request);
  const linked = await authenticateLinkedDeviceManagementOwner(ctx, nowMs);
  let request: LinkedDeviceRevokeRequestV1;
  let owner: LinkedDeviceManagementOwnerV1;
  if (linked.kind === 'authorized') {
    request = parseBoundary(() =>
      parseLinkedDeviceRevokeRequestV1(parseJsonBodyBytes(body.bytes)),
    );
    if (linked.owner.walletId !== request.walletId) return unauthorizedResponse();
    owner = linked.owner;
  } else {
    if (linked.kind === 'denied') return unauthorizedResponse();
    const authentication = await authenticateOwner(
      service,
      ctx,
      ctx.pathname,
      body.digestB64u,
      nowMs,
    );
    if (authentication.kind === 'denied') return authDeniedResponse(authentication);
    validateOwnerBinding(authentication.binding, ctx.method, ctx.pathname, body.digestB64u, nowMs);
    request = parseBoundary(() => parseLinkedDeviceRevokeRequestV1(authentication.body));
    if (authentication.owner.walletId !== request.walletId) return unauthorizedResponse();
    owner = {
      walletId: authentication.owner.walletId,
      expiresAtMs: authentication.owner.expiresAtMs,
      permission: buildFullOwnerDelegatedWalletAuthorityV1(),
    };
  }
  const pathDeviceId = parseBoundary(() => parsePathDeviceId(ctx.pathname));
  if (request.deviceId !== pathDeviceId) {
    throw new DeviceManagementInputError('device id does not match the route');
  }
  if (request.requestedAtMs > nowMs) {
    throw new DeviceManagementInputError('revoke request is from the future');
  }
  const result = await service.management.revokeLinkedDeviceV1(request, owner);
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
  if (keys.length !== 3 || keys[0] !== 'cursor' || keys[1] !== 'limit' || keys[2] !== 'walletId') {
    throw new Error('linked-device list query must contain walletId, limit, and cursor');
  }
  const walletId = search.get('walletId');
  const rawLimit = search.get('limit');
  const rawCursor = search.get('cursor');
  if (walletId === null || rawLimit === null || rawCursor === null) {
    throw new Error('walletId, limit, and cursor are required');
  }
  const request = parseLinkedDeviceListRequestV1({
    kind: 'linked_device_list_request_v1',
    walletId,
    limit: Number(rawLimit),
    cursor: rawCursor === '' ? null : rawCursor,
  });
  if (request.limit > LINKED_DEVICE_MANAGEMENT_MAX_PAGE_SIZE_V1) {
    throw new Error(
      `linked-device list limit must be at most ${LINKED_DEVICE_MANAGEMENT_MAX_PAGE_SIZE_V1}`,
    );
  }
  return request;
}

function canonicalListPath(
  pathname: string,
  request: LinkedDeviceListRequestV1,
): string {
  const search = new URLSearchParams([
    ['walletId', String(request.walletId)],
    ['limit', String(request.limit)],
    ['cursor', request.cursor ?? ''],
  ]);
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

function parseJsonBodyBytes(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new DeviceManagementInputError('request body must be valid JSON');
  }
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
