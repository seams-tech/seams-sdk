import { expect, test } from '@playwright/test';
import { AuthService } from '@server/core/AuthService';
import { createInMemoryConsoleOrgProjectEnvService } from '@server/console/orgProjectEnv';
import { handleRelayWalletRegistrationIntent } from '../../server/src/router/relayWalletRegistration';
import {
  createRelayRouteDefinitions,
  findRouteDefinitionById,
  type RouteDefinition,
} from '../../server/src/router/routeDefinitions';
import type { RelayApiKeyAuthAdapter } from '../../server/src/router/relay';
import type { RegistrationSignerSelection } from '../../shared/src/utils/registrationIntent';
import { DEFAULT_TEST_CONFIG } from '../setup/config';

const ORG_ID = 'org_registration_intent_modes';
const PROJECT_ID = 'project_registration_intent_modes';
const ENV_ID = 'dev';
const ENVIRONMENT_ID = `${PROJECT_ID}:${ENV_ID}`;
const SIGNING_ROOT_VERSION = 'root_v1';

const routeDefinitions = createRelayRouteDefinitions({
  enableHealthz: true,
  enableSigningSessionSeal: true,
  enableReadyz: true,
});

const modeCases = [
  {
    mode: 'ed25519_only',
    signerSelection: {
      mode: 'ed25519_only',
      ed25519: {
        nearAccountId: 'alice.testnet',
        signerSlot: 1,
        participantIds: [1, 2],
        keyPurpose: 'near_tx',
        keyVersion: 'threshold-ed25519-hss-v1',
        derivationVersion: 1,
        createNearAccount: true,
      },
    },
  },
  {
    mode: 'ecdsa_only',
    signerSelection: {
      mode: 'ecdsa_only',
      ecdsa: {
        chainTargets: [{ chain: 'tempo', chainId: 978 }],
        participantIds: [1, 2],
      },
    },
  },
  {
    mode: 'ed25519_and_ecdsa',
    signerSelection: {
      mode: 'ed25519_and_ecdsa',
      ed25519: {
        nearAccountId: 'combined.testnet',
        signerSlot: 1,
        participantIds: [1, 2],
        keyPurpose: 'near_tx',
        keyVersion: 'threshold-ed25519-hss-v1',
        derivationVersion: 1,
        createNearAccount: true,
      },
      ecdsa: {
        chainTargets: [{ chain: 'tempo', chainId: 978 }],
        participantIds: [1, 2],
      },
    },
  },
] satisfies ReadonlyArray<{
  mode: RegistrationSignerSelection['mode'];
  signerSelection: RegistrationSignerSelection;
}>;

function route(id: string): RouteDefinition {
  const found = findRouteDefinitionById(routeDefinitions, id);
  if (!found) throw new Error(`missing route ${id}`);
  return found;
}

function makeService(): AuthService {
  return new AuthService({
    relayerAccount: 'relayer.testnet',
    relayerPrivateKey: 'ed25519:dummy',
    nearRpcUrl: DEFAULT_TEST_CONFIG.nearRpcUrl,
    networkId: DEFAULT_TEST_CONFIG.nearNetwork,
    accountInitialBalance: '1',
    createAccountAndRegisterGas: '1',
    logger: null,
  });
}

function makeApiKeyAuth(): RelayApiKeyAuthAdapter {
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

test.describe('wallet registration intent relayer modes', () => {
  test('requires an exact origin before API credential auth', async () => {
    let authCalled = false;
    const response = await handleRelayWalletRegistrationIntent({
      body: {
        walletSubject: { kind: 'server_generated' },
        rpId: 'wallet.example.test',
        authMethod: { kind: 'passkey' },
        signerSelection: modeCases[0].signerSelection,
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
        authService: makeService(),
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
    const response = await handleRelayWalletRegistrationIntent({
      body: {
        walletSubject: { kind: 'server_generated' },
        rpId: 'wallet.example.test',
        authMethod: { kind: 'passkey' },
        signerSelection: modeCases[0].signerSelection,
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
        authService: {
          createRegistrationIntent: async (request: unknown) => {
            capturedRequest = request;
            return {
              ok: true,
              intent: {
                version: 'registration_intent_v1',
                walletSubjectId: 'wallet_subject_route_context',
                rpId: 'wallet.example.test',
                authMethod: { kind: 'passkey' },
                signerSelection: modeCases[0].signerSelection,
                runtimePolicyScope: {
                  orgId: ORG_ID,
                  projectId: PROJECT_ID,
                  envId: ENV_ID,
                  signingRootVersion: SIGNING_ROOT_VERSION,
                },
                nonceB64u: 'nonce',
              },
              registrationIntentDigestB64u: 'digest',
              registrationIntentGrant: 'rig_context',
              expiresAtMs: 1,
            };
          },
        },
        apiKeyAuth: makeApiKeyAuth(),
        orgProjectEnv: await makeOrgProjectEnv(),
      },
    } as unknown as Parameters<typeof handleRelayWalletRegistrationIntent>[0]);

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

  for (const entry of modeCases) {
    test(`creates ${entry.mode} registration intents through the relayer route`, async () => {
      const response = await handleRelayWalletRegistrationIntent({
        body: {
          walletSubject: { kind: 'server_generated' },
          rpId: 'wallet.example.test',
          authMethod: { kind: 'passkey' },
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
          authService: makeService(),
          apiKeyAuth: makeApiKeyAuth(),
          orgProjectEnv: await makeOrgProjectEnv(),
        },
      });

      expect(response.status).toBe(200);
      expect(response.body.ok).toBe(true);
      if (!response.body.ok) throw new Error(response.body.message);
      expect(response.body.intent.rpId).toBe('wallet.example.test');
      expect(response.body.intent.runtimePolicyScope).toEqual({
        orgId: ORG_ID,
        projectId: PROJECT_ID,
        envId: ENV_ID,
        signingRootVersion: SIGNING_ROOT_VERSION,
      });
      expect(response.body.intent.signerSelection.mode).toBe(entry.mode);
      expect(response.body.registrationIntentGrant).toMatch(/^rig_/);
    });
  }
});
