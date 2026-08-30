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

async function exactFundingAdmission(
  input: {
    readonly label?: string;
    readonly authorityId?: string;
    readonly walletAuthMethodId?: string;
  } = {},
): Promise<{
  readonly fixture: Awaited<ReturnType<typeof buildLinkedDeviceManagementAuthorityFixture>>;
  readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext;
  readonly nearPublicKeyStr: string;
  readonly nearAccountId: string;
}> {
  const label = input.label ?? 'near-funding-exact';
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label,
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: 'ed25519',
    materialActivation: buildMpcMaterialActivationRefFixture(label, WALLET_ID),
    expiresAtMs: Date.now() + 60_000,
    identity: {
      walletId: WALLET_ID,
      authorityId: input.authorityId ?? `authority:${label}`,
      walletAuthMethodId: input.walletAuthMethodId ?? `wallet-auth-method:${label}`,
      rpId: 'wallet.example.test',
    },
  });
  const signer = fixture.authority.signerActivations.ed25519?.signer;
  if (!signer) throw new Error('Funding fixture must contain an Ed25519 signer');
  const nearPublicKeyStr = nearPublicKeyFromRaw(base64UrlDecode(signer.registeredPublicKeyB64u));
  return {
    fixture,
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
  readonly exactReadTokens: string[] = [];
  readonly exactReadAuthMethodIds: string[] = [];
  fundCalls = 0;

  constructor(
    readonly exactContext: RouterApiWalletSessionAuthorizationV2AdmissionContext | null,
    private readonly exactContextsByToken: ReadonlyMap<
      string,
      RouterApiWalletSessionAuthorizationV2AdmissionContext
    > = new Map(),
  ) {}

  async readExact(input: {
    readonly token?: string;
  }): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext | null> {
    this.exactReads += 1;
    const token = String(input.token || '');
    this.exactReadTokens.push(token);
    const context =
      this.exactContextsByToken.size > 0
        ? this.exactContextsByToken.get(token) || null
        : this.exactContext;
    if (context) {
      this.exactReadAuthMethodIds.push(String(context.authorization.session.walletAuthMethodId));
    }
    return context;
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
  readonly token?: string;
}): Parameters<typeof handleRouterApiWalletNearImplicitAccountFund>[0] {
  return {
    body: {
      nearPublicKeyStr: input.nearPublicKeyStr,
      nearAccountId: input.nearAccountId,
    },
    headers: { authorization: `Bearer ${input.token ?? TOKEN}` },
    logger: NOOP_LOGGER,
    pathParams: { walletId: WALLET_ID },
    route: requiredRoute('wallet_near_implicit_account_fund'),
    services: {
      authorizationSessions: {
        tenantId: 'tenant:management',
        readWalletSessionAuthorizationV2ByOperationCredential: input.harness.readExact.bind(
          input.harness,
        ),
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
  expect(harness.fundCalls).toBe(0);
});

test('implicit NEAR funding keeps same-wallet sibling method credentials isolated', async () => {
  const primary = await exactFundingAdmission();
  const sibling = await exactFundingAdmission({
    label: 'near-funding-sibling',
    authorityId: 'authority:near-funding-sibling',
    walletAuthMethodId: 'wallet-auth-method:near-funding-sibling',
  });
  const harness = new NearFundingAdmissionHarness(
    null,
    new Map([
      [primary.fixture.operationCredential.token, primary.context],
      [sibling.fixture.operationCredential.token, sibling.context],
    ]),
  );

  const primaryResponse = await handleRouterApiWalletNearImplicitAccountFund(
    routeInput({
      harness,
      nearPublicKeyStr: primary.nearPublicKeyStr,
      nearAccountId: primary.nearAccountId,
      token: primary.fixture.operationCredential.token,
    }),
  );
  const siblingResponse = await handleRouterApiWalletNearImplicitAccountFund(
    routeInput({
      harness,
      nearPublicKeyStr: sibling.nearPublicKeyStr,
      nearAccountId: sibling.nearAccountId,
      token: sibling.fixture.operationCredential.token,
    }),
  );

  expect(primaryResponse.status).toBe(200);
  expect(siblingResponse.status).toBe(200);
  expect(harness.exactReadTokens).toEqual([
    primary.fixture.operationCredential.token,
    sibling.fixture.operationCredential.token,
  ]);
  expect(harness.exactReadAuthMethodIds).toEqual([
    primary.fixture.authMethod.walletAuthMethodId,
    sibling.fixture.authMethod.walletAuthMethodId,
  ]);
  expect(harness.fundCalls).toBe(2);
});
