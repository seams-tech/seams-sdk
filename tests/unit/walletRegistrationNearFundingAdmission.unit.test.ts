import { expect, test } from '@playwright/test';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { base58Encode, base64UrlDecode } from '@shared/utils/encoders';
import { deriveImplicitNearAccountIdFromEd25519PublicKey } from '@shared/utils/near';
import type { RouterApiWalletSessionAuthorizationV2AdmissionContext } from '@server/router/framework/authServicePort';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
  type RouteDefinition,
} from '@server/router/framework/routeDefinitions';
import { handleRouterApiWalletNearImplicitAccountFund } from '@server/router/domains/walletRegistration/walletRegistrationRoutes';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';

const WALLET_ID = 'wallet:near-funding-exact';
const TOKEN = 'wallet-session-operation-credential';

const ROUTES = createRouterApiRouteDefinitions({
  enableHealthz: true,
  enableSigningSessionSeal: true,
  enableReadyz: true,
});

const NOOP_LOGGER = {
  debug(): void {},
  info(): void {},
  warn(): void {},
  error(): void {},
};

function requiredRoute(id: string): RouteDefinition {
  const route = findRouteDefinitionById(ROUTES, id);
  if (!route) throw new Error(`Missing route ${id}`);
  return route;
}

function nearPublicKeyFromRaw(raw: Uint8Array): string {
  return `ed25519:${base58Encode(raw)}`;
}

async function exactFundingAdmission(): Promise<{
  readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext;
  readonly nearPublicKeyStr: string;
  readonly nearAccountId: string;
}> {
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'near-funding-exact',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: 'ed25519',
    materialActivation: buildMpcMaterialActivationRefFixture(
      'near-funding-exact',
      WALLET_ID,
    ),
    expiresAtMs: Date.now() + 60_000,
    identity: {
      walletId: WALLET_ID,
      authorityId: 'authority:near-funding-exact',
      walletAuthMethodId: 'wallet-auth-method:near-funding-exact',
      rpId: 'wallet.example.test',
    },
  });
  const signer = fixture.authority.signerActivations.ed25519?.signer;
  if (!signer) throw new Error('Funding fixture must contain an Ed25519 signer');
  const nearPublicKeyStr = nearPublicKeyFromRaw(
    base64UrlDecode(signer.registeredPublicKeyB64u),
  );
  return {
    context: {
      authorization: fixture.issuedSession,
      authority: fixture.authority,
      authMethod: fixture.authMethod,
      retiredAtMs: null,
    },
    nearPublicKeyStr,
    nearAccountId: deriveImplicitNearAccountIdFromEd25519PublicKey(nearPublicKeyStr),
  };
}

class NearFundingAdmissionHarness {
  exactReads = 0;
  legacyReads = 0;
  fundCalls = 0;

  constructor(
    readonly exactContext: RouterApiWalletSessionAuthorizationV2AdmissionContext | null,
  ) {}

  async readExact(): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext | null> {
    this.exactReads += 1;
    return this.exactContext;
  }

  async resolveLegacy(): Promise<null> {
    this.legacyReads += 1;
    return null;
  }

  async fund(input: { readonly walletId: string; readonly nearAccountId: string }): Promise<{
    readonly ok: true;
    readonly walletId: string;
    readonly nearAccountId: string;
    readonly fundedAmountYocto: string;
  }> {
    this.fundCalls += 1;
    return {
      ok: true,
      walletId: input.walletId,
      nearAccountId: input.nearAccountId,
      fundedAmountYocto: '1',
    };
  }
}

function routeInput(input: {
  readonly harness: NearFundingAdmissionHarness;
  readonly nearPublicKeyStr: string;
  readonly nearAccountId: string;
}): Parameters<typeof handleRouterApiWalletNearImplicitAccountFund>[0] {
  return {
    body: {
      nearPublicKeyStr: input.nearPublicKeyStr,
      nearAccountId: input.nearAccountId,
    },
    headers: { authorization: `Bearer ${TOKEN}` },
    logger: NOOP_LOGGER,
    pathParams: { walletId: WALLET_ID },
    route: requiredRoute('wallet_near_implicit_account_fund'),
    services: {
      authorizationSessions: {
        tenantId: 'tenant:management',
        readWalletSessionAuthorizationV2ByOperationCredential:
          input.harness.readExact.bind(input.harness),
        resolveOpaqueWalletSessionToken: input.harness.resolveLegacy.bind(input.harness),
      },
      walletRegistration: {
        fundImplicitNearAccount: input.harness.fund.bind(input.harness),
      },
    },
  } as unknown as Parameters<typeof handleRouterApiWalletNearImplicitAccountFund>[0];
}

test('implicit NEAR funding derives wallet and account from one exact operation credential', async () => {
  const admission = await exactFundingAdmission();
  const harness = new NearFundingAdmissionHarness(admission.context);

  const response = await handleRouterApiWalletNearImplicitAccountFund(
    routeInput({
      harness,
      nearPublicKeyStr: admission.nearPublicKeyStr,
      nearAccountId: admission.nearAccountId,
    }),
  );

  expect(response.status).toBe(200);
  expect(harness.exactReads).toBe(1);
  expect(harness.legacyReads).toBe(0);
  expect(harness.fundCalls).toBe(1);
});

test('implicit NEAR funding rejects a different signer before funding', async () => {
  const admission = await exactFundingAdmission();
  const harness = new NearFundingAdmissionHarness(admission.context);
  const otherNearPublicKeyStr = nearPublicKeyFromRaw(new Uint8Array(32).fill(51));

  const response = await handleRouterApiWalletNearImplicitAccountFund(
    routeInput({
      harness,
      nearPublicKeyStr: otherNearPublicKeyStr,
      nearAccountId: deriveImplicitNearAccountIdFromEd25519PublicKey(otherNearPublicKeyStr),
    }),
  );

  expect(response.status).toBe(403);
  expect(harness.exactReads).toBe(1);
  expect(harness.legacyReads).toBe(0);
  expect(harness.fundCalls).toBe(0);
});

test('implicit NEAR funding rejects missing exact state without legacy lookup', async () => {
  const admission = await exactFundingAdmission();
  const harness = new NearFundingAdmissionHarness(null);

  const response = await handleRouterApiWalletNearImplicitAccountFund(
    routeInput({
      harness,
      nearPublicKeyStr: admission.nearPublicKeyStr,
      nearAccountId: admission.nearAccountId,
    }),
  );

  expect(response.status).toBe(401);
  expect(harness.exactReads).toBe(1);
  expect(harness.legacyReads).toBe(0);
  expect(harness.fundCalls).toBe(0);
});
