import { expect, test } from '@playwright/test';
import {
  buildSigningOnlyPermissionsV1,
  parseDelegatedWalletPermissionSetV1,
} from '@shared/authorization/delegatedAuthority';
import {
  parseHostedWalletSessionCredentialId,
  parseSessionOrigin,
} from '../../packages/wallet-server/src/authorization/domain';
import type {
  RouterApiHostedWalletSessionAuthorizationV2AdmissionContext,
  RouterApiWalletSessionAuthorizationV2AdmissionContext,
} from '../../packages/wallet-server/src/router/framework/authServicePort';
import { handleRouterApiWalletEcdsaKeyFactsInventory } from '../../packages/wallet-server/src/router/domains/walletRegistration/walletRegistrationRoutes';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
} from '../../packages/wallet-server/src/router/framework/routeDefinitions';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

const PRIMARY_TOKEN = `wst_${'p'.repeat(43)}`;
const HOSTED_TOKEN = `wsh_${'h'.repeat(43)}`;
const WALLET_ID = 'wallet:hosted-inventory';
const WALLET_ORIGIN = 'https://wallet.hosted-inventory.example.test';
const APP_ORIGIN = 'https://app.hosted-inventory.example.test';
const routeDefinitions = createRouterApiRouteDefinitions({
  enableHealthz: true,
  enableReadyz: true,
  enableSigningSessionSeal: true,
});

function requiredPermissionSet(raw: readonly string[]) {
  const parsed = parseDelegatedWalletPermissionSetV1(raw);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

async function exactInventoryContext(input: {
  readonly label: string;
  readonly permissions: ReturnType<typeof buildSigningOnlyPermissionsV1>;
}): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext> {
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: input.label,
    permissions: input.permissions,
    provenance: 'wallet_registration',
    keyFamily: 'ecdsa_secp256k1',
    materialActivation: buildMpcMaterialActivationRefFixture(input.label, WALLET_ID),
    expiresAtMs: Date.now() + 60_000,
    identity: {
      walletId: WALLET_ID,
      authorityId: `authority:${input.label}`,
      walletAuthMethodId: `wallet-auth-method:${input.label}`,
      rpId: 'wallet.hosted-inventory.example.test',
    },
  });
  return {
    authorization: fixture.issuedSession,
    authority: fixture.authority,
    authMethod: fixture.authMethod,
    retiredAtMs: null,
  };
}

function hostedInventoryContext(
  exact: RouterApiWalletSessionAuthorizationV2AdmissionContext,
): RouterApiHostedWalletSessionAuthorizationV2AdmissionContext {
  return {
    ...exact,
    hostedCredentialId: parseHostedWalletSessionCredentialId('hosted-credential:inventory'),
    appOrigin: parseSessionOrigin(APP_ORIGIN),
    walletOrigin: parseSessionOrigin(WALLET_ORIGIN),
    expiresAtMs: exact.authorization.session.expiresAtMs,
  };
}

class InventoryRouteHarness {
  primaryReads = 0;
  hostedReads = 0;
  inventoryReads = 0;
  hostedReadInput: unknown = null;

  constructor(
    readonly primaryContext: RouterApiWalletSessionAuthorizationV2AdmissionContext | null,
    readonly hostedContext: RouterApiHostedWalletSessionAuthorizationV2AdmissionContext | null,
  ) {}

  async readPrimary(): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext | null> {
    this.primaryReads += 1;
    return this.primaryContext;
  }

  async readHosted(
    input: unknown,
  ): Promise<RouterApiHostedWalletSessionAuthorizationV2AdmissionContext | null> {
    this.hostedReads += 1;
    this.hostedReadInput = input;
    return this.hostedContext;
  }

  async listInventory() {
    this.inventoryReads += 1;
    return {
      records: [],
      diagnostics: {
        userId: WALLET_ID,
        inputCount: 1,
        returnedCount: 0,
        ecdsaBootstrapExportRuntimePresent: true,
        rejected: {},
      },
    };
  }

  authorizationSessions() {
    return {
      tenantId:
        this.primaryContext?.authorization.session.tenantId ??
        this.hostedContext?.authorization.session.tenantId ??
        'tenant:hosted-inventory',
      readWalletSessionAuthorizationV2ByOperationCredential: this.readPrimary.bind(this),
      readHostedWalletSessionOperationCredentialV2: this.readHosted.bind(this),
    };
  }

  walletRegistration() {
    return {
      listWalletEcdsaKeyFactsInventory: this.listInventory.bind(this),
    };
  }
}

function inventoryRouteInput(input: {
  readonly harness: InventoryRouteHarness;
  readonly token: string;
  readonly walletSessionId: string;
  readonly origin?: string;
  readonly hostedWalletOrigins?: readonly string[];
  readonly walletId?: string;
}): Parameters<typeof handleRouterApiWalletEcdsaKeyFactsInventory>[0] {
  const route = findRouteDefinitionById(routeDefinitions, 'wallet_ecdsa_key_facts_inventory');
  if (!route) throw new Error('ECDSA inventory route is missing');
  return {
    body: {
      rpId: 'wallet.hosted-inventory.example.test',
      keyTargets: [
        {
          keyHandle: 'ederivation-key-hosted-inventory',
          chainTarget: { kind: 'tempo', chainId: 42431 },
        },
      ],
      auth: {
        kind: input.token.startsWith('wsh_')
          ? 'opaque_hosted_wallet_session_operation_credential_v1'
          : 'opaque_wallet_session_operation_credential_v1',
        walletSessionId: input.walletSessionId,
      },
    },
    headers: { authorization: `Bearer ${input.token}` },
    hostedWalletOrigins: input.hostedWalletOrigins ?? [],
    logger: { debug() {}, info() {}, warn() {}, error() {} },
    origin: input.origin,
    pathParams: { walletId: input.walletId ?? WALLET_ID },
    route,
    services: {
      authorizationSessions: input.harness.authorizationSessions(),
      walletRegistration: input.harness.walletRegistration(),
    },
  } as unknown as Parameters<typeof handleRouterApiWalletEcdsaKeyFactsInventory>[0];
}

test('ECDSA inventory preserves primary exact credential admission without hosted or legacy reads', async () => {
  const exact = await exactInventoryContext({
    label: 'primary-inventory',
    permissions: buildSigningOnlyPermissionsV1(),
  });
  const harness = new InventoryRouteHarness(exact, null);

  const response = await handleRouterApiWalletEcdsaKeyFactsInventory(
    inventoryRouteInput({
      harness,
      token: PRIMARY_TOKEN,
      walletSessionId: exact.authorization.session.walletSessionId,
    }),
  );

  expect(response.status).toBe(200);
  expect(harness.primaryReads).toBe(1);
  expect(harness.hostedReads).toBe(0);
  expect(harness.inventoryReads).toBe(1);
});

test('ECDSA inventory admits an allowed-origin hosted child through its exact parent', async () => {
  const exact = await exactInventoryContext({
    label: 'hosted-inventory',
    permissions: buildSigningOnlyPermissionsV1(),
  });
  const harness = new InventoryRouteHarness(null, hostedInventoryContext(exact));

  const response = await handleRouterApiWalletEcdsaKeyFactsInventory(
    inventoryRouteInput({
      harness,
      token: HOSTED_TOKEN,
      walletSessionId: exact.authorization.session.walletSessionId,
      origin: WALLET_ORIGIN,
      hostedWalletOrigins: [WALLET_ORIGIN],
    }),
  );

  expect(response.status).toBe(200);
  expect(harness.primaryReads).toBe(0);
  expect(harness.hostedReads).toBe(1);
  expect(harness.hostedReadInput).toMatchObject({
    token: HOSTED_TOKEN,
    requestOrigin: WALLET_ORIGIN,
  });
  expect(harness.inventoryReads).toBe(1);
});

test('ECDSA inventory rejects a hosted child when only an unrelated origin is allowed', async () => {
  const harness = new InventoryRouteHarness(null, null);

  const response = await handleRouterApiWalletEcdsaKeyFactsInventory(
    inventoryRouteInput({
      harness,
      token: HOSTED_TOKEN,
      walletSessionId: 'wallet-session:unavailable-origin',
      origin: WALLET_ORIGIN,
      hostedWalletOrigins: [APP_ORIGIN],
    }),
  );

  expect(response.status).toBe(403);
  expect(harness.primaryReads).toBe(0);
  expect(harness.hostedReads).toBe(0);
  expect(harness.inventoryReads).toBe(0);
});

test('ECDSA inventory rejects a hosted child whose parent wallet or ECDSA sign subject is wrong', async () => {
  const signingExact = await exactInventoryContext({
    label: 'hosted-wallet-mismatch',
    permissions: buildSigningOnlyPermissionsV1(),
  });
  const walletMismatchHarness = new InventoryRouteHarness(
    null,
    hostedInventoryContext(signingExact),
  );
  const walletMismatch = await handleRouterApiWalletEcdsaKeyFactsInventory(
    inventoryRouteInput({
      harness: walletMismatchHarness,
      token: HOSTED_TOKEN,
      walletSessionId: signingExact.authorization.session.walletSessionId,
      origin: WALLET_ORIGIN,
      hostedWalletOrigins: [WALLET_ORIGIN],
      walletId: 'wallet:other',
    }),
  );

  const exportExact = await exactInventoryContext({
    label: 'hosted-export-only',
    permissions: requiredPermissionSet(['export_keys']),
  });
  const exportHarness = new InventoryRouteHarness(null, hostedInventoryContext(exportExact));
  const exportOnly = await handleRouterApiWalletEcdsaKeyFactsInventory(
    inventoryRouteInput({
      harness: exportHarness,
      token: HOSTED_TOKEN,
      walletSessionId: exportExact.authorization.session.walletSessionId,
      origin: WALLET_ORIGIN,
      hostedWalletOrigins: [WALLET_ORIGIN],
    }),
  );

  expect(walletMismatch.status).toBe(403);
  expect(exportOnly.status).toBe(401);
  expect(walletMismatchHarness.inventoryReads).toBe(0);
  expect(exportHarness.inventoryReads).toBe(0);
});
