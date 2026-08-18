import { expect, test } from '@playwright/test';
import { parseWalletId } from '@shared/utils/domainIds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { handleDeviceManagement, LINKED_DEVICE_MANAGEMENT_BASE_V1 } from '../../packages/wallet-server/src/router/transport/fetch/routes/deviceManagement';
import type { DeviceManagementRouteServiceV1 } from '../../packages/wallet-server/src/router/transport/fetch/routes/deviceManagement';
import type { FetchRouterApiContext } from '../../packages/wallet-server/src/router/transport/fetch/fetchRouter.types';

const walletId = parseWalletId('wallet:r103').value;
const otherWalletId = parseWalletId('wallet:other').value;

test('binds a linked-device list authorization to its canonical wallet query', async () => {
  const signedPath = `${LINKED_DEVICE_MANAGEMENT_BASE_V1}?walletId=${encodeURIComponent(String(walletId))}&limit=10&cursor=`;
  let authenticatedPath: string | undefined;
  const service = managementRouteService({
    authenticateOwnerRequestV1: async ({ pathname, bodyDigestB64u }) => {
      authenticatedPath = pathname;
      return {
        kind: 'authorized' as const,
        body: null,
        binding: requestBinding('GET', signedPath, bodyDigestB64u),
        owner: { walletId, expiresAtMs: 11_000 },
      };
    },
  });

  const response = await invoke(
    service,
    `?walletId=${encodeURIComponent(String(otherWalletId))}&limit=10&cursor=`,
  );

  expect(response.status).toBe(400);
  expect(authenticatedPath).toBe(
    `${LINKED_DEVICE_MANAGEMENT_BASE_V1}?walletId=${encodeURIComponent(String(otherWalletId))}&limit=10&cursor=`,
  );
});

test('passes the canonical wallet query to owner authentication', async () => {
  let authenticatedPath: string | undefined;
  const service = managementRouteService({
    authenticateOwnerRequestV1: async ({ pathname, bodyDigestB64u }) => {
      authenticatedPath = pathname;
      return {
        kind: 'authorized' as const,
        body: null,
        binding: requestBinding('GET', pathname, bodyDigestB64u),
        owner: { walletId, expiresAtMs: 11_000 },
      };
    },
  });

  const response = await invoke(
    service,
    `?walletId=${encodeURIComponent(String(walletId))}&limit=10&cursor=`,
  );

  expect(response.status).toBe(200);
  expect(authenticatedPath).toBe(
    `${LINKED_DEVICE_MANAGEMENT_BASE_V1}?walletId=${encodeURIComponent(String(walletId))}&limit=10&cursor=`,
  );
  expect(await response.json()).toEqual({ ok: true, devices: [], nextCursor: null });
});

test('rejects a list page larger than the server-owned maximum', async () => {
  let authenticated = false;
  const service = managementRouteService({
    authenticateOwnerRequestV1: async () => {
      authenticated = true;
      throw new Error('authentication should not run');
    },
  });

  const response = await invoke(
    service,
    `?walletId=${encodeURIComponent(String(walletId))}&limit=51&cursor=`,
  );

  expect(response.status).toBe(400);
  expect(authenticated).toBe(false);
});

function managementRouteService(
  overrides: Pick<DeviceManagementRouteServiceV1, 'authenticateOwnerRequestV1'>,
): DeviceManagementRouteServiceV1 {
  return {
    ...overrides,
    nowV1: () => 10_000,
    management: {
      listLinkedDevicesV1: async () => ({ devices: [], nextCursor: null }),
      revokeLinkedDeviceV1: async () => ({ kind: 'not_found' as const }),
    },
  };
}

function requestBinding(
  method: 'GET' | 'POST',
  pathname: string,
  bodyDigestB64u: DigestB64u,
): {
  readonly kind: 'linked_device_owner_request_binding_v1';
  readonly method: 'GET' | 'POST';
  readonly pathname: string;
  readonly bodyDigestB64u: typeof bodyDigestB64u;
  readonly expiresAtMs: number;
} {
  return {
    kind: 'linked_device_owner_request_binding_v1',
    method,
    pathname,
    bodyDigestB64u,
    expiresAtMs: 11_000,
  };
}

async function invoke(
  service: DeviceManagementRouteServiceV1,
  search: string,
): Promise<Response> {
  const request = new Request(`https://example.test${LINKED_DEVICE_MANAGEMENT_BASE_V1}${search}`, {
    method: 'GET',
  });
  const context = {
    request,
    url: new URL(request.url),
    pathname: LINKED_DEVICE_MANAGEMENT_BASE_V1,
    method: 'GET',
    runtime: { kind: 'inline' as const },
    service: {},
    opts: {},
    logger: {},
    mePath: '/me',
    routeDefinitions: [],
  } as unknown as FetchRouterApiContext;
  const response = await handleDeviceManagement(context, service);
  if (!response) throw new Error('device-management route did not match');
  return response;
}
