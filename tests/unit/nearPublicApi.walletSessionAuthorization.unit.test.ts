import { expect, test } from '@playwright/test';
import { fundImplicitNearAccountFromCurrentSession } from '@/SeamsWeb/publicApi/near';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import {
  buildActiveWalletSessionAuthorizationProjection,
  walletSessionAuthorizations,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseThresholdEd25519SessionId } from '@shared/utils/domainIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toAccountId } from '@/core/types/accountIds';
import type { RouterApiWalletSessionAuthorizationV2AdmissionContext } from '../../packages/wallet-server/src/router/framework/authServicePort';
import type { FetchRouterApiContext } from '../../packages/wallet-server/src/router/transport/fetch/fetchRouter.types';
import { handleNearPublicKeys } from '../../packages/wallet-server/src/router/transport/fetch/routes/nearPublicKeys';
import { buildWalletAuthAuthorityRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';

const WALLET_ID = toWalletId('wallet-near-public-funding');
const NEAR_ACCOUNT_ID = toAccountId('a'.repeat(64));
const WALLET_SESSION_TOKEN = 'opaque-wallet-session-token:near-public-funding';

function buildActiveAuthorization(expiresAtMs: number) {
  const walletSessionId = parseWalletSessionId('wallet-session-near-public-funding');
  const authorizationId = parseWalletSessionAuthorizationId(
    'wallet-session-authorization:near-public-funding',
  );
  const quotaId = parseMpcWalletSigningQuotaId('quota-near-public-funding');
  const thresholdSessionId = parseThresholdEd25519SessionId('threshold-near-public-funding');
  if (!walletSessionId.ok || !authorizationId.ok || !quotaId.ok || !thresholdSessionId.ok) {
    throw new Error('Failed to build Wallet Session authorization fixture');
  }
  return buildActiveWalletSessionAuthorizationProjection({
    walletId: WALLET_ID,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    walletSessionTokens: {
      kind: 'near_ed25519',
      ed25519: {
        authorizationId: authorizationId.value,
        walletSessionToken: WALLET_SESSION_TOKEN,
        thresholdSessionId: thresholdSessionId.value,
      },
    },
    authMethod: 'passkey',
    authority: buildWalletAuthAuthorityRefFixture({
      walletId: String(WALLET_ID),
      label: 'near-public-funding',
    }),
    expiresAtMs,
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
  legacyReads = 0;

  constructor(
    readonly exactAdmission: RouterApiWalletSessionAuthorizationV2AdmissionContext | null,
  ) {}

  async readExactAdmission(): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext | null> {
    return this.exactAdmission;
  }

  async resolveLegacySession(): Promise<null> {
    this.legacyReads += 1;
    return null;
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
        resolveOpaqueWalletSessionToken: this.resolveLegacySession.bind(this),
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
  expect(harness.legacyReads).toBe(0);
});

test('NEAR public-key listing rejects a missing exact session without probing legacy sessions', async () => {
  const harness = new NearPublicKeysRouteHarness(null);

  const response = await invokeNearPublicKeysRoute(harness);

  expect(response.status).toBe(401);
  expect(harness.listedUserIds).toEqual([]);
  expect(harness.legacyReads).toBe(0);
});

test('implicit NEAR funding reads the canonical Wallet Session authorization projection', async () => {
  const originalRead = walletSessionAuthorizations.readActiveForWallet;
  const originalFetch = globalThis.fetch;
  const authorizationHeaders: string[] = [];
  walletSessionAuthorizations.readActiveForWallet = async () => ({
    kind: 'found',
    projection: buildActiveAuthorization(Date.now() + 60_000),
  });
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
    expect(authorizationHeaders).toEqual([`Bearer ${WALLET_SESSION_TOKEN}`]);
  } finally {
    walletSessionAuthorizations.readActiveForWallet = originalRead;
    globalThis.fetch = originalFetch;
  }
});

test('implicit NEAR funding rejects absent or expired authorization before fetch', async () => {
  const originalRead = walletSessionAuthorizations.readActiveForWallet;
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error('fetch must not run');
  };

  try {
    walletSessionAuthorizations.readActiveForWallet = async () => ({ kind: 'missing' });
    await expect(
      fundImplicitNearAccountFromCurrentSession({
        configs: fundingConfigs(),
        walletSession: { walletId: WALLET_ID, walletSessionUserId: 'near-public-funding' },
        nearAccount: { kind: 'implicit', accountId: NEAR_ACCOUNT_ID },
        nearPublicKey: 'ed25519:near-public-funding-key',
      }),
    ).rejects.toThrow('Current Ed25519 wallet session is required');

    walletSessionAuthorizations.readActiveForWallet = async () => ({
      kind: 'found',
      projection: buildActiveAuthorization(Date.now() - 1),
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
    walletSessionAuthorizations.readActiveForWallet = originalRead;
    globalThis.fetch = originalFetch;
  }
});
