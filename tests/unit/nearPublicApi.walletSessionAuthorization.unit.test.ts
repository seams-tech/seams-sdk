import { expect, test } from '@playwright/test';
import { fundImplicitNearAccountFromCurrentSession } from '@/SeamsWeb/publicApi/near';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { IndexedDBManager } from '@/core/indexedDB';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toAccountId } from '@/core/types/accountIds';
import type { RouterApiWalletSessionAuthorizationV2AdmissionContext } from '../../packages/wallet-server/src/router/framework/authServicePort';
import type { FetchRouterApiContext } from '../../packages/wallet-server/src/router/transport/fetch/fetchRouter.types';
import { handleNearPublicKeys } from '../../packages/wallet-server/src/router/transport/fetch/routes/nearPublicKeys';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';

const WALLET_ID = toWalletId('wallet-near-public-funding');
const NEAR_ACCOUNT_ID = toAccountId('a'.repeat(64));
type ExactFundingFixture = Awaited<ReturnType<typeof buildLinkedDeviceManagementAuthorityFixture>>;

function resolvedFundingSelection(fixture: ExactFundingFixture) {
  return {
    kind: 'resolved' as const,
    selection: {
      kind: 'wallet_selection_v1' as const,
      walletId: fixture.authority.walletId,
      walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
      lockGeneration: 0,
      lockState: 'unlocked' as const,
      updatedAtMs: 1,
    },
    authMethod: fixture.authMethod,
    authority: fixture.authority,
    signerMaterials: [],
    exportRoot: null,
  };
}

async function exactFundingFixture(): Promise<ExactFundingFixture> {
  return await buildLinkedDeviceManagementAuthorityFixture({
    label: 'near-public-funding',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: 'ed25519',
    expiresAtMs: Date.now() + 60_000,
    identity: {
      walletId: String(WALLET_ID),
      authorityId: 'authority:near-public-funding',
      walletAuthMethodId: 'auth-method:near-public-funding',
      rpId: 'near-public-funding.example.test',
    },
  });
}

function fundingConfigs() {
  return {
    ...PASSKEY_MANAGER_DEFAULT_CONFIGS,
    network: {
      ...PASSKEY_MANAGER_DEFAULT_CONFIGS.network,
      relayer: {
        ...PASSKEY_MANAGER_DEFAULT_CONFIGS.network.relayer,
        url: 'https://relay.example.test',
      },
    },
  };
}

class NearPublicKeysRouteHarness {
  readonly listedUserIds: string[] = [];

  constructor(
    readonly exactAdmission: RouterApiWalletSessionAuthorizationV2AdmissionContext | null,
  ) {}

  async readExactAdmission(): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext | null> {
    return this.exactAdmission;
  }

  async listNearPublicKeys(input: { readonly userId: string }) {
    this.listedUserIds.push(input.userId);
    return { ok: true as const, keys: [] };
  }

  service() {
    return {
      authorizationSessions: {
        tenantId: 'tenant:near-public-keys',
        readWalletSessionAuthorizationV2ByOperationCredential: this.readExactAdmission.bind(this),
      },
      nearFunding: {
        listNearPublicKeysForUser: this.listNearPublicKeys.bind(this),
      },
    };
  }
}

function nearPublicKeysRouteContext(
  request: Request,
  harness: NearPublicKeysRouteHarness,
): FetchRouterApiContext {
  const url = new URL(request.url);
  return {
    request,
    url,
    pathname: url.pathname,
    method: request.method,
    runtime: { kind: 'inline' },
    service: harness.service(),
    opts: {},
    logger: {},
    routeDefinitions: [],
  } as unknown as FetchRouterApiContext;
}

async function exactNearPublicKeysAdmission(): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext> {
  const exact = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'near-public-keys-route',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: 'ed25519',
    expiresAtMs: Date.now() + 60_000,
  });
  return {
    authorization: exact.issuedSession,
    authority: exact.authority,
    authMethod: exact.authMethod,
    retiredAtMs: null,
  };
}

async function invokeNearPublicKeysRoute(harness: NearPublicKeysRouteHarness): Promise<Response> {
  const request = new Request('https://relay.example.test/near/public-keys', {
    headers: { authorization: 'Bearer wallet-session-operation-credential' },
  });
  const response = await handleNearPublicKeys(nearPublicKeysRouteContext(request, harness));
  if (!response) throw new Error('NEAR public-keys route did not match');
  return response;
}

test('NEAR public-key listing admits the exact operation credential without probing legacy sessions', async () => {
  const admission = await exactNearPublicKeysAdmission();
  const harness = new NearPublicKeysRouteHarness(admission);

  const response = await invokeNearPublicKeysRoute(harness);

  expect(response.status).toBe(200);
  expect(harness.listedUserIds).toEqual([String(admission.authorization.session.walletId)]);
});

test('NEAR public-key listing rejects a missing exact session without probing legacy sessions', async () => {
  const harness = new NearPublicKeysRouteHarness(null);

  const response = await invokeNearPublicKeysRoute(harness);

  expect(response.status).toBe(401);
  expect(harness.listedUserIds).toEqual([]);
});

test('implicit NEAR funding reads the selected exact Wallet Session tuple', async () => {
  const fixture = await exactFundingFixture();
  const originalResolve = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalRead = walletSessionAuthorizations.readExactWithOperationCredential;
  const originalFetch = globalThis.fetch;
  const authorizationHeaders: string[] = [];
  const exactReads: unknown[] = [];
  IndexedDBManager.resolveSelectedWalletAuthority = async () => resolvedFundingSelection(fixture);
  walletSessionAuthorizations.readExactWithOperationCredential = async (input) => {
    exactReads.push(input);
    return {
      kind: 'found',
      record: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
    };
  };
  globalThis.fetch = async (_input, init) => {
    authorizationHeaders.push(String(new Headers(init?.headers).get('authorization') || ''));
    return new Response(
      JSON.stringify({
        ok: true,
        walletId: WALLET_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        fundedAmountYocto: '1',
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  };

  try {
    const result = await fundImplicitNearAccountFromCurrentSession({
      configs: fundingConfigs(),
      walletSession: { walletId: WALLET_ID, walletSessionUserId: 'near-public-funding' },
      nearAccount: { kind: 'implicit', accountId: NEAR_ACCOUNT_ID },
      nearPublicKey: 'ed25519:near-public-funding-key',
    });

    expect(result.ok).toBe(true);
    expect(authorizationHeaders).toEqual([`Bearer ${fixture.operationCredential.token}`]);
    expect(exactReads).toEqual([
      {
        walletId: fixture.authority.walletId,
        authorityId: fixture.authority.authorityId,
        authMethodId: fixture.authMethod.walletAuthMethodId,
      },
    ]);
  } finally {
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolve;
    walletSessionAuthorizations.readExactWithOperationCredential = originalRead;
    globalThis.fetch = originalFetch;
  }
});

test('implicit NEAR funding rejects an absent or expired exact session before fetch', async () => {
  const fixture = await exactFundingFixture();
  const originalResolve = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalRead = walletSessionAuthorizations.readExactWithOperationCredential;
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  IndexedDBManager.resolveSelectedWalletAuthority = async () => resolvedFundingSelection(fixture);
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error('fetch must not run');
  };

  try {
    walletSessionAuthorizations.readExactWithOperationCredential = async () => ({
      kind: 'missing',
    });
    await expect(
      fundImplicitNearAccountFromCurrentSession({
        configs: fundingConfigs(),
        walletSession: { walletId: WALLET_ID, walletSessionUserId: 'near-public-funding' },
        nearAccount: { kind: 'implicit', accountId: NEAR_ACCOUNT_ID },
        nearPublicKey: 'ed25519:near-public-funding-key',
      }),
    ).rejects.toThrow('Current Ed25519 wallet session is required');

    walletSessionAuthorizations.readExactWithOperationCredential = async () => ({
      kind: 'found',
      record: { ...fixture.activeWalletSession, expiresAtMs: Date.now() - 1 },
      operationCredential: fixture.operationCredential,
    });
    await expect(
      fundImplicitNearAccountFromCurrentSession({
        configs: fundingConfigs(),
        walletSession: { walletId: WALLET_ID, walletSessionUserId: 'near-public-funding' },
        nearAccount: { kind: 'implicit', accountId: NEAR_ACCOUNT_ID },
        nearPublicKey: 'ed25519:near-public-funding-key',
      }),
    ).rejects.toThrow('Current Ed25519 wallet session is required');
    expect(fetchCalls).toBe(0);
  } finally {
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolve;
    walletSessionAuthorizations.readExactWithOperationCredential = originalRead;
    globalThis.fetch = originalFetch;
  }
});
