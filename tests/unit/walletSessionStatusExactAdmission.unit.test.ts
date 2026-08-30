import { expect, test } from '@playwright/test';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import type { ExactWalletSessionStatusV2 } from '@server/authorization/domain';
import {
  buildExactWalletSessionQuotaProjectionV1,
  projectExactWalletSessionAuthorizationV1,
} from '@server/authorization/domain';
import { parseReusableWalletSessionStatusResponse } from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
import type { FetchRouterApiContext } from '@server/router/transport/fetch/fetchRouter.types';
import { handleReusableWalletSessionStatus } from '@server/router/transport/fetch/routes/sessions';
import type { IssuedWalletSessionAuthorizationV2 } from '@server/authorization/domain';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';

const STATUS_TENANT_ID = 'tenant:management';

async function exactStatusAuthorization(): Promise<IssuedWalletSessionAuthorizationV2> {
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'wallet-session-status-exact',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    expiresAtMs: Date.now() + 60_000,
    tenantId: STATUS_TENANT_ID,
    identity: {
      walletId: 'wallet:status-exact',
      authorityId: 'authority:status-exact',
      walletAuthMethodId: 'wallet-auth-method:status-exact',
      rpId: 'wallet.example.test',
    },
  });
  return fixture.issuedSession;
}

function quotaProjection(
  authorization: IssuedWalletSessionAuthorizationV2,
  overrides: { readonly remainingUses?: number } = {},
) {
  const remainingUses = overrides.remainingUses ?? authorization.quota.remainingUses;
  return buildExactWalletSessionQuotaProjectionV1({
    lifecycle: remainingUses === 0 ? 'exhausted' : 'active',
    tenantId: authorization.quota.tenantId,
    principalId: authorization.quota.principalId,
    walletSessionId: authorization.quota.walletSessionId,
    quotaId: authorization.quota.quotaId,
    remainingUses,
    expiresAtMs: authorization.quota.expiresAtMs,
  });
}

class WalletSessionStatusHarness {
  exactStatusReads = 0;
  legacyCredentialReads = 0;

  constructor(readonly status: ExactWalletSessionStatusV2) {}

  async readExactStatus(): Promise<ExactWalletSessionStatusV2> {
    this.exactStatusReads += 1;
    return this.status;
  }

  async readLegacyCredential(): Promise<null> {
    this.legacyCredentialReads += 1;
    return null;
  }
}

async function invokeStatus(input: {
  readonly harness: WalletSessionStatusHarness;
  readonly walletSessionId: string;
  readonly quotaId: string;
  readonly tenantId?: string;
}): Promise<Response> {
  const url = new URL('https://router.example.test/wallet/session/status');
  const request = new Request(url, {
    method: 'POST',
    headers: {
      authorization: 'Bearer wallet-session-operation-credential',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      walletSessionId: input.walletSessionId,
      quotaId: input.quotaId,
    }),
  });
  const response = await handleReusableWalletSessionStatus({
    request,
    url,
    pathname: url.pathname,
    method: request.method,
    service: {
      authorizationSessions: {
        tenantId: input.tenantId ?? STATUS_TENANT_ID,
        readExactWalletSessionStatusByOperationCredential: input.harness.readExactStatus.bind(
          input.harness,
        ),
        readWalletSessionAuthorizationV2ByOperationCredential:
          input.harness.readLegacyCredential.bind(input.harness),
        resolveOpaqueWalletSessionToken: input.harness.readLegacyCredential.bind(input.harness),
      },
    },
  } as unknown as FetchRouterApiContext);
  if (!response) throw new Error('Wallet Session status route did not match');
  return response;
}

async function invokeForStatus(
  status: ExactWalletSessionStatusV2,
  requested: IssuedWalletSessionAuthorizationV2,
): Promise<{
  readonly response: Response;
  readonly harness: WalletSessionStatusHarness;
}> {
  const harness = new WalletSessionStatusHarness(status);
  const response = await invokeStatus({
    harness,
    walletSessionId: String(requested.session.walletSessionId),
    quotaId: String(requested.session.quotaId),
  });
  return { response, harness };
}

function expectedObservedBody(
  authorization: IssuedWalletSessionAuthorizationV2,
  overrides: { readonly status: string; readonly remainingUses?: number },
): Record<string, unknown> {
  return {
    ok: true,
    status: overrides.status,
    walletSessionId: authorization.session.walletSessionId,
    quotaId: authorization.session.quotaId,
    remainingUses: overrides.remainingUses ?? authorization.quota.remainingUses,
    expiresAtMs: authorization.quota.expiresAtMs,
    quotaLifecycle: overrides.remainingUses === 0 ? 'exhausted' : 'active',
    authorization: projectExactWalletSessionAuthorizationV1(authorization.session),
  };
}

test('Wallet Session status returns the exact authorization quota projection', async () => {
  const authorization = await exactStatusAuthorization();
  const { response, harness } = await invokeForStatus(
    { kind: 'active', session: authorization.session, quota: quotaProjection(authorization) },
    authorization,
  );

  expect(response.status).toBe(200);
  const body = (await response.json()) as unknown;
  expect(body).toEqual(expectedObservedBody(authorization, { status: 'active' }));
  // The shared client parser is the only consumer of this shape; it must accept
  // the published projection.
  expect(
    parseReusableWalletSessionStatusResponse(body, {
      walletSessionId: authorization.session.walletSessionId,
      quotaId: authorization.session.quotaId,
    }),
  ).toMatchObject({
    status: 'active',
    quotaLifecycle: 'active',
    authorization: { authorityId: authorization.session.authorityId },
  });
  // The authority digest belongs in the projection; the credential that
  // resolved the read, and its digest, must never appear on the wire.
  expect(JSON.stringify(body)).not.toContain('operationCredential');
  expect(JSON.stringify(body)).not.toContain('primaryOperationCredentialDigestB64u');
  expect(harness.exactStatusReads).toBe(1);
  expect(harness.legacyCredentialReads).toBe(0);
});

const OBSERVED_WIRE_CASES: readonly {
  readonly kind: Exclude<ExactWalletSessionStatusV2['kind'], 'missing' | 'active'>;
  readonly status: string;
  readonly remainingUses?: number;
}[] = [
  { kind: 'exhausted', status: 'exhausted', remainingUses: 0 },
  { kind: 'expired', status: 'expired' },
  { kind: 'retired', status: 'superseded' },
  { kind: 'authority_unavailable', status: 'authority_unavailable' },
  { kind: 'method_unavailable', status: 'method_unavailable' },
  { kind: 'capability_unavailable', status: 'capability_unavailable' },
];

for (const testCase of OBSERVED_WIRE_CASES) {
  test(`Wallet Session status publishes the authorization with ${testCase.status}`, async () => {
    const authorization = await exactStatusAuthorization();
    const quota = quotaProjection(
      authorization,
      testCase.remainingUses === undefined ? {} : { remainingUses: testCase.remainingUses },
    );
    const { response, harness } = await invokeForStatus(
      testCase.kind === 'retired'
        ? {
            kind: 'retired',
            session: authorization.session,
            quota,
            retiredAtMs: authorization.session.createdAtMs + 1,
          }
        : { kind: testCase.kind, session: authorization.session, quota },
      authorization,
    );

    expect(response.status).toBe(200);
    const body = (await response.json()) as unknown;
    const expected = expectedObservedBody(authorization, {
      status: testCase.status,
      ...(testCase.remainingUses === undefined ? {} : { remainingUses: testCase.remainingUses }),
    });
    expect(body).toEqual(expected);
    expect(
      parseReusableWalletSessionStatusResponse(body, {
        walletSessionId: authorization.session.walletSessionId,
        quotaId: authorization.session.quotaId,
      }),
    ).toMatchObject({ status: testCase.status });
  });
}

test('Wallet Session status rejects a different exact tuple', async () => {
  const authorization = await exactStatusAuthorization();
  const harness = new WalletSessionStatusHarness({
    kind: 'active',
    session: authorization.session,
    quota: quotaProjection(authorization),
  });

  const response = await invokeStatus({
    harness,
    walletSessionId: 'wallet-session:status-other',
    quotaId: 'quota:status-other',
  });

  expect(response.status).toBe(403);
  await expect(response.json()).resolves.toMatchObject({
    ok: false,
    code: 'wallet_session_scope_mismatch',
  });
  expect(harness.legacyCredentialReads).toBe(0);
});

test('Wallet Session status rejects a quota identity the authorization does not own', async () => {
  const authorization = await exactStatusAuthorization();
  const sibling = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'wallet-session-status-sibling',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    expiresAtMs: authorization.session.expiresAtMs,
    tenantId: STATUS_TENANT_ID,
    identity: {
      walletId: 'wallet:status-exact',
      authorityId: 'authority:status-sibling',
      walletAuthMethodId: 'wallet-auth-method:status-sibling',
      rpId: 'wallet.example.test',
    },
  });
  const harness = new WalletSessionStatusHarness({
    kind: 'active',
    session: authorization.session,
    quota: quotaProjection(sibling.issuedSession),
  });

  const response = await invokeStatus({
    harness,
    walletSessionId: String(authorization.session.walletSessionId),
    quotaId: String(authorization.session.quotaId),
  });

  expect(response.status).toBe(403);
});

test('Wallet Session status rejects an authorization minted for another tenant', async () => {
  const authorization = await exactStatusAuthorization();
  const harness = new WalletSessionStatusHarness({
    kind: 'active',
    session: authorization.session,
    quota: quotaProjection(authorization),
  });

  const response = await invokeStatus({
    harness,
    walletSessionId: String(authorization.session.walletSessionId),
    quotaId: String(authorization.session.quotaId),
    tenantId: 'tenant:other-management',
  });

  expect(response.status).toBe(403);
});

test('Wallet Session status returns invalid for missing exact state', async () => {
  const { response, harness } = await invokeForStatus(
    { kind: 'missing' },
    await exactStatusAuthorization(),
  );

  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({ ok: true, status: 'invalid' });
  expect(harness.exactStatusReads).toBe(1);
  expect(harness.legacyCredentialReads).toBe(0);
});

test('Wallet Session status requires a presented operation credential', async () => {
  const authorization = await exactStatusAuthorization();
  const harness = new WalletSessionStatusHarness({
    kind: 'active',
    session: authorization.session,
    quota: quotaProjection(authorization),
  });
  const url = new URL('https://router.example.test/wallet/session/status');
  const response = await handleReusableWalletSessionStatus({
    request: new Request(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        walletSessionId: String(authorization.session.walletSessionId),
        quotaId: String(authorization.session.quotaId),
      }),
    }),
    url,
    pathname: url.pathname,
    method: 'POST',
    service: {
      authorizationSessions: {
        tenantId: STATUS_TENANT_ID,
        readExactWalletSessionStatusByOperationCredential: harness.readExactStatus.bind(harness),
      },
    },
  } as unknown as FetchRouterApiContext);

  expect(response?.status).toBe(401);
  expect(harness.exactStatusReads).toBe(0);
});
