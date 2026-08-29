import { expect, test } from '@playwright/test';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import type { RouterApiWalletSessionAuthorizationV2AdmissionContext } from '../../packages/wallet-server/src/router/framework/authServicePort';
import { createRouterApiRouteDefinitions } from '../../packages/wallet-server/src/router/framework/routeDefinitions';
import type { FetchRouterApiContext } from '../../packages/wallet-server/src/router/transport/fetch/fetchRouter.types';
import { handleWalletCustodyEnvelopeOwnershipUpgrade } from '../../packages/wallet-server/src/router/transport/fetch/routes/passkeyCustody';
import {
  OWNING_WALLET_AUTH_METHOD_ID,
  RP_ID,
  WALLET_ID,
  passkeyCustodyEnvelope,
} from './helpers/passkeyCustodyEnvelope.fixtures';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';

type UpgradeInput = {
  readonly walletId: string;
  readonly walletAuthMethodId: string;
  readonly envelope: ReturnType<typeof passkeyCustodyEnvelope>;
};

class CustodyOwnershipRouteHarness {
  readonly upgrades: UpgradeInput[] = [];

  constructor(
    readonly exactAdmission: RouterApiWalletSessionAuthorizationV2AdmissionContext | null,
  ) {}

  async readExactAdmission(): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext | null> {
    return this.exactAdmission;
  }

  async upgradeEnvelopeOwnership(input: UpgradeInput) {
    this.upgrades.push(input);
    return { kind: 'already_owned' as const };
  }

  service() {
    return {
      authorizationSessions: {
        tenantId: 'tenant:custody-ownership',
        readWalletSessionAuthorizationV2ByOperationCredential: this.readExactAdmission.bind(this),
      },
      passkeyCustody: {
        upgradeEnvelopeOwnership: this.upgradeEnvelopeOwnership.bind(this),
      },
    };
  }
}

async function exactAdmission(): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext> {
  const exact = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'custody-envelope-ownership',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: 'ed25519',
    expiresAtMs: Date.now() + 60_000,
    identity: {
      walletId: WALLET_ID,
      authorityId: 'authority:custody-envelope-ownership',
      walletAuthMethodId: OWNING_WALLET_AUTH_METHOD_ID,
      rpId: RP_ID,
    },
  });
  return {
    authorization: exact.issuedSession,
    authority: exact.authority,
    authMethod: exact.authMethod,
    retiredAtMs: null,
  };
}

function routeContext(
  request: Request,
  harness: CustodyOwnershipRouteHarness,
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
    routeDefinitions: createRouterApiRouteDefinitions(),
  } as unknown as FetchRouterApiContext;
}

function ownershipUpgradeRequest(): Request {
  const envelope = passkeyCustodyEnvelope({
    envelopeRevision: 2,
    ownership: {
      kind: 'method_bound',
      walletAuthMethodId: OWNING_WALLET_AUTH_METHOD_ID,
    },
  });
  return new Request(`https://relay.example.test/wallets/${WALLET_ID}/custody/envelope/ownership`, {
    method: 'POST',
    headers: {
      authorization: 'Bearer wallet-session-operation-credential',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ envelope }),
  });
}

async function invokeRoute(harness: CustodyOwnershipRouteHarness): Promise<Response> {
  const request = ownershipUpgradeRequest();
  const response = await handleWalletCustodyEnvelopeOwnershipUpgrade(
    routeContext(request, harness),
  );
  if (!response) throw new Error('Custody envelope ownership route did not match');
  return response;
}

test('custody ownership upgrade forwards the exact session method without legacy reads', async () => {
  const admission = await exactAdmission();
  const harness = new CustodyOwnershipRouteHarness(admission);

  const response = await invokeRoute(harness);

  expect(response.status).toBe(200);
  expect(harness.upgrades).toHaveLength(1);
  expect(String(harness.upgrades[0]?.walletId)).toBe(WALLET_ID);
  expect(String(harness.upgrades[0]?.walletAuthMethodId)).toBe(OWNING_WALLET_AUTH_METHOD_ID);
});

test('custody ownership upgrade rejects a missing exact session without legacy reads', async () => {
  const harness = new CustodyOwnershipRouteHarness(null);

  const response = await invokeRoute(harness);

  expect(response.status).toBe(401);
  expect(harness.upgrades).toEqual([]);
});
