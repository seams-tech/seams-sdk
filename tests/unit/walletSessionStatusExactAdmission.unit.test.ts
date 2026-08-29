import { expect, test } from '@playwright/test';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import type { RouterApiWalletSessionAuthorizationV2AdmissionContext } from '@server/router/framework/authServicePort';
import type { FetchRouterApiContext } from '@server/router/transport/fetch/fetchRouter.types';
import { handleReusableWalletSessionStatus } from '@server/router/transport/fetch/routes/sessions';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';

async function exactStatusContext(): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext> {
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'wallet-session-status-exact',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    expiresAtMs: Date.now() + 60_000,
    identity: {
      walletId: 'wallet:status-exact',
      authorityId: 'authority:status-exact',
      walletAuthMethodId: 'wallet-auth-method:status-exact',
      rpId: 'wallet.example.test',
    },
  });
  return {
    authorization: fixture.issuedSession,
    authority: fixture.authority,
    authMethod: fixture.authMethod,
    retiredAtMs: null,
  };
}

class WalletSessionStatusHarness {
  exactReads = 0;
  legacyReads = 0;
  reusableStatusReads = 0;

  constructor(
    readonly exactContext: RouterApiWalletSessionAuthorizationV2AdmissionContext | null,
  ) {}

  async readExact(): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext | null> {
    this.exactReads += 1;
    return this.exactContext;
  }

  async readLegacy(): Promise<null> {
    this.legacyReads += 1;
    return null;
  }

  async readReusableStatus(): Promise<never> {
    this.reusableStatusReads += 1;
    throw new Error('Exact status must not read the V1 reusable-session store');
  }
}

async function invokeStatus(input: {
  readonly harness: WalletSessionStatusHarness;
  readonly walletSessionId: string;
  readonly quotaId: string;
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
        tenantId: 'tenant:management',
        readWalletSessionAuthorizationV2ByOperationCredential:
          input.harness.readExact.bind(input.harness),
        resolveOpaqueWalletSessionToken: input.harness.readLegacy.bind(input.harness),
        readReusableWalletSessionStatus: input.harness.readReusableStatus.bind(input.harness),
      },
    },
  } as unknown as FetchRouterApiContext);
  if (!response) throw new Error('Wallet Session status route did not match');
  return response;
}

test('Wallet Session status returns the exact authorization quota projection', async () => {
  const context = await exactStatusContext();
  const harness = new WalletSessionStatusHarness(context);

  const response = await invokeStatus({
    harness,
    walletSessionId: String(context.authorization.session.walletSessionId),
    quotaId: String(context.authorization.session.quotaId),
  });

  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({
    ok: true,
    status: 'active',
    walletSessionId: context.authorization.session.walletSessionId,
    quotaId: context.authorization.session.quotaId,
    remainingUses: context.authorization.quota.remainingUses,
    expiresAtMs: context.authorization.quota.expiresAtMs,
  });
  expect(harness.exactReads).toBe(1);
  expect(harness.legacyReads).toBe(0);
  expect(harness.reusableStatusReads).toBe(0);
});

test('Wallet Session status rejects a different exact tuple', async () => {
  const context = await exactStatusContext();
  const harness = new WalletSessionStatusHarness(context);

  const response = await invokeStatus({
    harness,
    walletSessionId: 'wallet-session:status-other',
    quotaId: 'quota:status-other',
  });

  expect(response.status).toBe(403);
  expect(harness.legacyReads).toBe(0);
  expect(harness.reusableStatusReads).toBe(0);
});

test('Wallet Session status returns invalid for missing exact state without V1 reads', async () => {
  const context = await exactStatusContext();
  const harness = new WalletSessionStatusHarness(null);

  const response = await invokeStatus({
    harness,
    walletSessionId: String(context.authorization.session.walletSessionId),
    quotaId: String(context.authorization.session.quotaId),
  });

  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({ ok: true, status: 'invalid' });
  expect(harness.exactReads).toBe(1);
  expect(harness.legacyReads).toBe(0);
  expect(harness.reusableStatusReads).toBe(0);
});
