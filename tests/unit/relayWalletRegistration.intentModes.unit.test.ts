import { expect, test } from '@playwright/test';
import { createInMemoryConsoleOrgProjectEnvService } from '@server/console/orgProjectEnv';
import { handleRouterApiWalletRegistrationIntent } from '../../packages/sdk-server-ts/src/router/walletRegistrationRoutes';
import type { RouterApiWalletRegistrationRouteService } from '../../packages/sdk-server-ts/src/router/authServicePort';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
  type RouteDefinition,
} from '../../packages/sdk-server-ts/src/router/routeDefinitions';
import type { RouterApiKeyAuthAdapter } from '../../packages/sdk-server-ts/src/router/routerApi';
import {
  implicitNearAccountProvisioning,
  parseServerAllocatedWalletId,
  registrationIntentGrantFromString,
  requireServerAllocatedWalletId,
  sponsoredNamedNearAccountProvisioning,
  type RegistrationSignerSetSelection,
  type WalletId,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseNamedNearAccountId } from '../../packages/shared-ts/src/utils/near';

const ORG_ID = 'org_registration_intent_modes';
const PROJECT_ID = 'project_registration_intent_modes';
const ENV_ID = 'dev';
const ENVIRONMENT_ID = `${PROJECT_ID}:${ENV_ID}`;
const SIGNING_ROOT_VERSION = 'root_v1';
const TEST_SERVER_ALLOCATED_WALLET_ID = requireServerAllocatedWalletId('frost-fjord-rgcmpa');
const TEST_REGISTRATION_INTENT_GRANT = registrationIntentGrantFromString(
  'rig_registration_intent_modes',
);

type CreateRegistrationIntentForRoute =
  RouterApiWalletRegistrationRouteService['createRegistrationIntent'];
type CreateRegistrationIntentForRouteInput = Parameters<CreateRegistrationIntentForRoute>[0];
type CreateRegistrationIntentForRouteResult = Awaited<ReturnType<CreateRegistrationIntentForRoute>>;

function namedProvisioning(accountId: string) {
  const parsed = parseNamedNearAccountId(accountId);
  if (!parsed.ok) throw new Error(parsed.message);
  return sponsoredNamedNearAccountProvisioning(parsed.value);
}

const routeDefinitions = createRouterApiRouteDefinitions({
  enableHealthz: true,
  enableSigningSessionSeal: true,
  enableReadyz: true,
});

const signerSetCases = [
  {
    name: 'near_ed25519',
    wallet: { kind: 'provided', walletId: 'wallet_alice' },
    expectedKinds: ['near_ed25519'],
    signerSelection: {
      kind: 'signer_set',
      signers: [
        {
          kind: 'near_ed25519',
          accountProvisioning: namedProvisioning('alice.testnet'),
          signerSlot: 1,
          participantIds: [1, 2],
          derivationVersion: 1,
        },
      ],
    },
  },
  {
    name: 'evm_family_ecdsa',
    wallet: { kind: 'server_allocated' },
    expectedKinds: ['evm_family_ecdsa'],
    signerSelection: {
      kind: 'signer_set',
      signers: [
        {
          kind: 'evm_family_ecdsa',
          chainTargets: [{ kind: 'tempo', chainId: 978, networkSlug: 'tempo-testnet' }],
          participantIds: [1, 2],
        },
      ],
    },
  },
  {
    name: 'near_ed25519 and evm_family_ecdsa',
    wallet: { kind: 'provided', walletId: 'wallet_alice' },
    expectedKinds: ['near_ed25519', 'evm_family_ecdsa'],
    signerSelection: {
      kind: 'signer_set',
      signers: [
        {
          kind: 'near_ed25519',
          accountProvisioning: namedProvisioning('combined.testnet'),
          signerSlot: 1,
          participantIds: [1, 2],
          derivationVersion: 1,
        },
        {
          kind: 'evm_family_ecdsa',
          chainTargets: [{ kind: 'tempo', chainId: 978, networkSlug: 'tempo-testnet' }],
          participantIds: [1, 2],
        },
      ],
    },
  },
] satisfies ReadonlyArray<{
  name: string;
  wallet: Record<string, unknown>;
  expectedKinds: string[];
  signerSelection: RegistrationSignerSetSelection;
}>;

const signerSetSelection = {
  kind: 'signer_set',
  signers: [
    {
      kind: 'near_ed25519',
      accountProvisioning: namedProvisioning('set-combined.testnet'),
      signerSlot: 1,
      participantIds: [1, 2],
      derivationVersion: 1,
    },
    {
      kind: 'evm_family_ecdsa',
      chainTargets: [{ kind: 'tempo', chainId: 978, networkSlug: 'tempo-testnet' }],
      participantIds: [1, 2],
    },
  ],
} as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function signerKindsFromSelection(selection: unknown): string[] {
  if (!isRecord(selection) || !Array.isArray(selection.signers)) return [];
  const kinds: string[] = [];
  for (const signer of selection.signers) {
    if (isRecord(signer)) kinds.push(String(signer.kind || ''));
  }
  return kinds;
}

function route(id: string): RouteDefinition {
  const found = findRouteDefinitionById(routeDefinitions, id);
  if (!found) throw new Error(`missing route ${id}`);
  return found;
}

function getNoThresholdSigningService(): null {
  return null;
}

async function unsupportedWalletRegistrationRouteMethod(_input: unknown): Promise<never> {
  throw new Error('wallet registration route fake received an unsupported method call');
}

function signerSelectionUsesImplicitNearAccount(
  selection: RegistrationSignerSetSelection,
): boolean {
  for (const signer of selection.signers) {
    if (
      signer.kind === 'near_ed25519' &&
      signer.accountProvisioning.kind === 'implicit_account'
    ) {
      return true;
    }
  }
  return false;
}

function resolveWalletIdForRegistrationIntent(
  input: CreateRegistrationIntentForRouteInput,
):
  | { ok: true; walletId: WalletId }
  | { ok: false; code: 'invalid_body'; message: string } {
  if (input.request.wallet.kind === 'server_allocated') {
    return { ok: true, walletId: TEST_SERVER_ALLOCATED_WALLET_ID };
  }
  const walletId = input.request.wallet.walletId;
  if (signerSelectionUsesImplicitNearAccount(input.request.signerSelection)) {
    const parsed = parseServerAllocatedWalletId(walletId);
    if (!parsed.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'implicit account registration requires a generated readable walletId',
      };
    }
  }
  return { ok: true, walletId };
}

async function createRegistrationIntentForTest(
  input: CreateRegistrationIntentForRouteInput,
): Promise<CreateRegistrationIntentForRouteResult> {
  const wallet = resolveWalletIdForRegistrationIntent(input);
  if (!wallet.ok) {
    return {
      ok: false,
      code: wallet.code,
      message: wallet.message,
    };
  }
  const intent = input.runtimePolicyScope
    ? {
        version: 'registration_intent_v1' as const,
        walletId: wallet.walletId,
        authMethod: input.request.authMethod,
        signerSelection: input.request.signerSelection,
        runtimePolicyScope: input.runtimePolicyScope,
        nonceB64u: 'nonce',
      }
    : {
        version: 'registration_intent_v1' as const,
        walletId: wallet.walletId,
        authMethod: input.request.authMethod,
        signerSelection: input.request.signerSelection,
        nonceB64u: 'nonce',
      };
  return {
    ok: true,
    intent,
    registrationIntentDigestB64u: 'digest',
    registrationIntentGrant: TEST_REGISTRATION_INTENT_GRANT,
    expiresAtMs: 1,
  };
}

function makeWalletRegistrationService(input?: {
  readonly createRegistrationIntent?: CreateRegistrationIntentForRoute;
}): RouterApiWalletRegistrationRouteService {
  return {
    getThresholdSigningService: getNoThresholdSigningService,
    createRegistrationIntent:
      input?.createRegistrationIntent ?? createRegistrationIntentForTest,
    prepareWalletRegistration: unsupportedWalletRegistrationRouteMethod,
    startWalletRegistration: unsupportedWalletRegistrationRouteMethod,
    respondWalletRegistrationHss: unsupportedWalletRegistrationRouteMethod,
    finalizeWalletRegistration: unsupportedWalletRegistrationRouteMethod,
    createAddAuthMethodIntent: unsupportedWalletRegistrationRouteMethod,
    createAddSignerIntent: unsupportedWalletRegistrationRouteMethod,
    finalizeWalletAddAuthMethod: unsupportedWalletRegistrationRouteMethod,
    finalizeWalletAddSigner: unsupportedWalletRegistrationRouteMethod,
    respondWalletAddSignerHss: unsupportedWalletRegistrationRouteMethod,
    revokeWalletAuthMethod: unsupportedWalletRegistrationRouteMethod,
    startWalletAddAuthMethod: unsupportedWalletRegistrationRouteMethod,
    startWalletAddSigner: unsupportedWalletRegistrationRouteMethod,
    validateAppSessionVersion: unsupportedWalletRegistrationRouteMethod,
    verifyWebAuthnAuthenticationLite: unsupportedWalletRegistrationRouteMethod,
    fundImplicitNearAccount: unsupportedWalletRegistrationRouteMethod,
    listWalletEcdsaKeyFactsInventory: unsupportedWalletRegistrationRouteMethod,
  };
}

function makeApiKeyAuth(): RouterApiKeyAuthAdapter {
  return {
    authenticate: async (request) => {
      expect(request).toMatchObject({
        secret: 'sk_test',
        endpoint: 'POST /wallets/register/intent',
        requiredScopes: ['accounts.create'],
        environmentId: ENVIRONMENT_ID,
      });
      return {
        ok: true,
        principal: {
          apiKeyId: 'ak_registration_modes',
          orgId: ORG_ID,
          projectId: PROJECT_ID,
          envId: ENV_ID,
          environmentId: ENVIRONMENT_ID,
          scopes: ['accounts.create'],
        },
      };
    },
  };
}

async function makeOrgProjectEnv() {
  const service = createInMemoryConsoleOrgProjectEnvService();
  const ctx = { orgId: ORG_ID, actorUserId: 'registration-mode-test', roles: ['system'] };
  await service.upsertOrganization(ctx, {
    name: 'Registration Intent Modes',
    slug: 'registration-intent-modes',
  });
  await service.createProject(ctx, {
    id: PROJECT_ID,
    name: 'Registration Intent Modes',
  });
  await service.updateEnvironment(ctx, ENVIRONMENT_ID, {
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  return service;
}

test.describe('wallet registration intent relayer signer sets', () => {
  test('requires an exact origin before API credential auth', async () => {
    let authCalled = false;
    const response = await handleRouterApiWalletRegistrationIntent({
      body: {
        wallet: { kind: 'server_allocated' },
        authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
        signerSelection: signerSetCases[0].signerSelection,
      },
      headers: {
        authorization: 'Bearer sk_test',
        'x-seams-environment-id': ENVIRONMENT_ID,
      },
      logger: {
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: () => {},
      },
      origin: 'wallet.example.test',
      route: route('wallet_registration_intent'),
      services: {
        walletRegistration: makeWalletRegistrationService(),
        apiKeyAuth: {
          authenticate: async () => {
            authCalled = true;
            return {
              ok: false,
              status: 401,
              code: 'secret_key_invalid',
              message: 'must not authenticate without a valid origin',
            };
          },
        },
      },
    });

    expect(authCalled).toBe(false);
    expect(response.status).toBe(403);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'forbidden',
      message: 'Origin header is required and must be a valid exact origin',
    });
  });

  test('passes environment and normalized origin context to intent creation', async () => {
    let capturedRequest: unknown = null;
    const response = await handleRouterApiWalletRegistrationIntent({
      body: {
        wallet: { kind: 'server_allocated' },
        authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
        signerSelection: signerSetCases[0].signerSelection,
      },
      headers: {
        authorization: 'Bearer sk_test',
        'x-seams-environment-id': ENVIRONMENT_ID,
      },
      logger: {
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: () => {},
      },
      origin: 'https://wallet.example.test/',
      route: route('wallet_registration_intent'),
      services: {
        walletRegistration: makeWalletRegistrationService({
          createRegistrationIntent: async (request) => {
            capturedRequest = request;
            return createRegistrationIntentForTest(request);
          },
        }),
        apiKeyAuth: makeApiKeyAuth(),
        orgProjectEnv: await makeOrgProjectEnv(),
      },
    });

    expect(route('wallet_registration_intent').metering).toEqual({ kind: 'none' });
    expect(response.status).toBe(200);
    expect(capturedRequest).toMatchObject({
      orgId: ORG_ID,
      runtimePolicyScope: {
        orgId: ORG_ID,
        projectId: PROJECT_ID,
        envId: ENV_ID,
        signingRootVersion: SIGNING_ROOT_VERSION,
      },
      signingRootId: `${PROJECT_ID}:${ENV_ID}`,
      signingRootVersion: SIGNING_ROOT_VERSION,
      expectedOrigin: 'https://wallet.example.test',
    });
  });

  for (const entry of signerSetCases) {
    test(`creates ${entry.name} registration intents through the relayer route`, async () => {
      const response = await handleRouterApiWalletRegistrationIntent({
        body: {
          wallet: entry.wallet,
          authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
          signerSelection: entry.signerSelection,
        },
        headers: {
          authorization: 'Bearer sk_test',
          'x-seams-environment-id': ENVIRONMENT_ID,
        },
        logger: {
          debug: () => {},
          info: () => {},
          warn: () => {},
          error: () => {},
        },
        origin: 'https://wallet.example.test',
        route: route('wallet_registration_intent'),
        services: {
          walletRegistration: makeWalletRegistrationService(),
          apiKeyAuth: makeApiKeyAuth(),
          orgProjectEnv: await makeOrgProjectEnv(),
        },
      });

      expect(response.status).toBe(200);
      expect(response.body.ok).toBe(true);
      if (!response.body.ok) throw new Error(response.body.message);
      expect(response.body.intent.authMethod).toMatchObject({
        kind: 'passkey',
        rpId: 'wallet.example.test',
      });
      expect(response.body.intent.runtimePolicyScope).toEqual({
        orgId: ORG_ID,
        projectId: PROJECT_ID,
        envId: ENV_ID,
        signingRootVersion: SIGNING_ROOT_VERSION,
      });
      expect(response.body.intent.signerSelection.kind).toBe('signer_set');
      expect(Object.prototype.hasOwnProperty.call(response.body.intent.signerSelection, 'mode')).toBe(
        false,
      );
      expect(signerKindsFromSelection(response.body.intent.signerSelection)).toEqual(
        entry.expectedKinds,
      );
      expect(response.body.registrationIntentGrant).toMatch(/^rig_/);
    });
  }

  test('accepts signer-set registration intent input at the relayer route boundary', async () => {
    const response = await handleRouterApiWalletRegistrationIntent({
      body: {
        wallet: { kind: 'provided', walletId: 'wallet_signer_set' },
        authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
        signerSelection: signerSetSelection,
      },
      headers: {
        authorization: 'Bearer sk_test',
        'x-seams-environment-id': ENVIRONMENT_ID,
      },
      logger: {
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: () => {},
      },
      origin: 'https://wallet.example.test',
      route: route('wallet_registration_intent'),
      services: {
        walletRegistration: makeWalletRegistrationService(),
        apiKeyAuth: makeApiKeyAuth(),
        orgProjectEnv: await makeOrgProjectEnv(),
      },
    });

    expect(response.status).toBe(200);
    expect(response.body.ok).toBe(true);
    if (!response.body.ok) throw new Error(response.body.message);
    expect(response.body.intent.signerSelection.kind).toBe('signer_set');
    expect(Object.prototype.hasOwnProperty.call(response.body.intent.signerSelection, 'mode')).toBe(
      false,
    );
    expect(signerKindsFromSelection(response.body.intent.signerSelection)).toEqual([
      'near_ed25519',
      'evm_family_ecdsa',
    ]);
    expect(response.body.registrationIntentGrant).toMatch(/^rig_/);
  });

  test('creates an implicit Ed25519 registration intent with a server-allocated wallet ID', async () => {
    const response = await handleRouterApiWalletRegistrationIntent({
      body: {
        wallet: { kind: 'server_allocated' },
        authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: implicitNearAccountProvisioning(),
              signerSlot: 1,
              participantIds: [1, 2],
              derivationVersion: 1,
            },
          ],
        },
      },
      headers: {
        authorization: 'Bearer sk_test',
        'x-seams-environment-id': ENVIRONMENT_ID,
      },
      logger: {
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: () => {},
      },
      origin: 'https://wallet.example.test',
      route: route('wallet_registration_intent'),
      services: {
        walletRegistration: makeWalletRegistrationService(),
        apiKeyAuth: makeApiKeyAuth(),
        orgProjectEnv: await makeOrgProjectEnv(),
      },
    });

    expect(response.status).toBe(200);
    expect(response.body.ok).toBe(true);
    if (!response.body.ok) throw new Error(response.body.message);

    const serverAllocatedWalletId = parseServerAllocatedWalletId(response.body.intent.walletId);
    expect(serverAllocatedWalletId.ok).toBe(true);
    expect(response.body.intent.signerSelection).toMatchObject({
      kind: 'signer_set',
      signers: [
        {
          kind: 'near_ed25519',
          accountProvisioning: { kind: 'implicit_account' },
        },
      ],
    });
    expect(Object.prototype.hasOwnProperty.call(response.body.intent.signerSelection, 'mode')).toBe(
      false,
    );
    expect(response.body.registrationIntentGrant).toMatch(/^rig_/);
  });

  test('creates an implicit Ed25519 registration intent with a preselected readable wallet ID', async () => {
    const providedWalletId = 'frost-fjord-rgcmpa';
    const response = await handleRouterApiWalletRegistrationIntent({
      body: {
        wallet: { kind: 'provided', walletId: providedWalletId },
        authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: implicitNearAccountProvisioning(),
              signerSlot: 1,
              participantIds: [1, 2],
              derivationVersion: 1,
            },
          ],
        },
      },
      headers: {
        authorization: 'Bearer sk_test',
        'x-seams-environment-id': ENVIRONMENT_ID,
      },
      logger: {
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: () => {},
      },
      origin: 'https://wallet.example.test',
      route: route('wallet_registration_intent'),
      services: {
        walletRegistration: makeWalletRegistrationService(),
        apiKeyAuth: makeApiKeyAuth(),
        orgProjectEnv: await makeOrgProjectEnv(),
      },
    });

    expect(response.status).toBe(200);
    expect(response.body.ok).toBe(true);
    if (!response.body.ok) throw new Error(response.body.message);
    expect(response.body.intent.walletId).toBe(providedWalletId);
    const serverAllocatedWalletId = parseServerAllocatedWalletId(response.body.intent.walletId);
    expect(serverAllocatedWalletId.ok).toBe(true);
  });

  test('rejects arbitrary provided wallet IDs for implicit Ed25519 registration', async () => {
    const response = await handleRouterApiWalletRegistrationIntent({
      body: {
        wallet: { kind: 'provided', walletId: 'wallet_alice' },
        authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: implicitNearAccountProvisioning(),
              signerSlot: 1,
              participantIds: [1, 2],
              derivationVersion: 1,
            },
          ],
        },
      },
      headers: {
        authorization: 'Bearer sk_test',
        'x-seams-environment-id': ENVIRONMENT_ID,
      },
      logger: {
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: () => {},
      },
      origin: 'https://wallet.example.test',
      route: route('wallet_registration_intent'),
      services: {
        walletRegistration: makeWalletRegistrationService(),
        apiKeyAuth: makeApiKeyAuth(),
        orgProjectEnv: await makeOrgProjectEnv(),
      },
    });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'implicit account registration requires a generated readable walletId',
    });
  });
});
