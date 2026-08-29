import { expect, test } from '@playwright/test';
import {
  handleRouterApiWalletAddAuthMethodFinalize,
  handleRouterApiWalletAddAuthMethodIntent,
  handleRouterApiWalletRevokeAuthMethod,
  handleRouterApiWalletAddAuthMethodStart,
  handleRouterApiWalletAddSignerFinalize,
  handleRouterApiWalletAddSignerIntent,
  handleRouterApiWalletAddSignerStart,
  handleRouterApiWalletEcdsaKeyFactsInventory,
  handleRouterApiWalletRegistrationNearProvisioning,
} from '../../packages/wallet-server/src/router/domains/walletRegistration/walletRegistrationRoutes';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
  type RouteDefinition,
} from '../../packages/wallet-server/src/router/framework/routeDefinitions';
import { computeWalletEcdsaKeyFactsInventoryChallengeDigestB64u } from '../../packages/shared-ts/src/utils/ecdsaKeyFactsInventory';
import { ROUTER_AB_PUBLIC_KEYSET_VERSION_V2 } from '../../packages/shared-ts/src/utils/routerAbPublicKeyset';
import {
  computeAddAuthMethodIntentDigestB64u,
  computeAddSignerIntentDigestB64u,
  type AddAuthMethodIntentV1,
  walletIdFromString,
  type AddSignerIntentV1,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWebAuthnRpId,
  type WebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { deriveEvmFamilySigningKeySlotId } from '../../packages/shared-ts/src/signing-lanes';
import { WALLET_SESSION_CLIENT_CAPABILITY_V1 } from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { thresholdEcdsaChainTargetKey } from '../../packages/wallet-server/src/core/thresholdEcdsaChainTarget';
import { buildEmailOtpWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import {
  parseDelegatedWalletPermissionSetV1,
  buildSigningOnlyPermissionsV1,
} from '../../packages/shared-ts/src/authorization/delegatedAuthority';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';

const routeDefinitions = createRouterApiRouteDefinitions({
  enableHealthz: true,
  enableSigningSessionSeal: true,
  enableReadyz: true,
});

const ROUTER_AB_PUBLIC_KEYSET = {
  keyset_version: ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  signer_envelope_hpke: {
    current: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-a',
        public_key: 'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-b',
        public_key: 'x25519:2222222222222222222222222222222222222222222222222222222222222222',
      },
    },
  },
  signer_peer_verifying_keys: {
    deriver_a: {
      role: 'signer_a',
      verifying_key_hex: '5afa80b305e72e02615ed1f580144a40a42a71dfcac175809ceb5d79e740d015',
    },
    deriver_b: {
      role: 'signer_b',
      verifying_key_hex: '0c700dd63695221e508f3164b528f190bed63a4437d38e882308f9a57acc1bc3',
    },
  },
  signing_worker_server_output_hpke: {
    key_epoch: 'epoch-server',
    public_key: 'x25519:3333333333333333333333333333333333333333333333333333333333333333',
  },
} as const;

function route(id: string): RouteDefinition {
  const found = findRouteDefinitionById(routeDefinitions, id);
  if (!found) throw new Error(`missing route ${id}`);
  return found;
}

function ecdsaInventoryInputFor(args: {
  body: unknown;
  authService: Record<string, unknown>;
  session: Record<string, unknown>;
  headers?: Record<string, string>;
  authorizationSessions?: Record<string, unknown>;
  walletId?: string;
  origin?: string;
}) {
  return {
    body: args.body,
    headers: args.headers ?? { authorization: 'Bearer test-session' },
    logger: {
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {},
    },
    origin: args.origin || 'https://wallet.example.test',
    pathParams: { walletId: args.walletId || 'wallet_alice' },
    route: route('wallet_ecdsa_key_facts_inventory'),
    services: {
      walletRegistration: args.authService,
      authService: args.authService,
      session: args.session,
      ...(args.authorizationSessions
        ? { authorizationSessions: args.authorizationSessions }
        : {}),
    },
  } as unknown as Parameters<typeof handleRouterApiWalletEcdsaKeyFactsInventory>[0];
}

function addSignerInputFor(args: {
  routeId: 'wallet_add_signer_intent' | 'wallet_add_signer_start' | 'wallet_add_signer_finalize';
  body: unknown;
  authService: Record<string, unknown>;
  session?: Record<string, unknown>;
  walletId?: string;
  headers?: Record<string, string>;
  origin?: string;
  apiKeyAuth?: Record<string, unknown>;
  publishableKeyAuth?: Record<string, unknown>;
  orgProjectEnv?: Record<string, unknown>;
}) {
  return {
    body: args.body,
    headers: args.headers || { authorization: 'Bearer test-session' },
    logger: {
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {},
    },
    origin: args.origin || 'https://wallet.example.test',
    pathParams: { walletId: args.walletId || 'wallet_alice' },
    route: route(args.routeId),
    services: {
      walletRegistration: args.authService,
      authService: args.authService,
      session: args.session || {},
      apiKeyAuth: args.apiKeyAuth,
      publishableKeyAuth: args.publishableKeyAuth,
      orgProjectEnv: args.orgProjectEnv,
      routerAbPublicKeyset: ROUTER_AB_PUBLIC_KEYSET,
    },
  } as unknown as Parameters<typeof handleRouterApiWalletAddSignerStart>[0];
}

function addAuthMethodInputFor(args: {
  routeId:
    | 'wallet_add_auth_method_intent'
    | 'wallet_add_auth_method_start'
    | 'wallet_add_auth_method_finalize'
    | 'wallet_revoke_auth_method';
  body: unknown;
  authService: Record<string, unknown>;
  session?: Record<string, unknown>;
  apiKeyAuth?: Record<string, unknown>;
  orgProjectEnv?: Record<string, unknown>;
  authorizationSessions?: Record<string, unknown>;
  walletId?: string;
  walletAuthMethodId?: string;
  headers?: Record<string, string>;
  origin?: string;
}) {
  return {
    body: args.body,
    headers: args.headers || { authorization: 'Bearer test-session' },
    logger: {
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {},
    },
    origin: args.origin || 'https://wallet.example.test',
    pathParams: {
      walletId: args.walletId || 'wallet_alice',
      ...(args.walletAuthMethodId ? { walletAuthMethodId: args.walletAuthMethodId } : {}),
    },
    route: route(args.routeId),
    services: {
      walletRegistration: args.authService,
      authService: args.authService,
      session: args.session || {},
      publishableKeyAuth: args.apiKeyAuth,
      orgProjectEnv: args.orgProjectEnv,
      ...(args.authorizationSessions ? { authorizationSessions: args.authorizationSessions } : {}),
    },
  } as unknown as Parameters<typeof handleRouterApiWalletAddAuthMethodStart>[0];
}

function fakeWebAuthnAuthentication() {
  return {
    id: 'credential-id',
    rawId: 'credential-id',
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: 'client-data-json',
      authenticatorData: 'authenticator-data',
      signature: 'signature',
      userHandle: null,
    },
    clientExtensionResults: null,
  };
}

function b64u(bytes: number[]): string {
  return Buffer.from(bytes).toString('base64url');
}

const ECDSA_CHAIN_TARGET = { kind: 'tempo' as const, chainId: 42431, networkSlug: 'tempo-testnet' };
const ECDSA_CHAIN_TARGET_KEY = thresholdEcdsaChainTargetKey(ECDSA_CHAIN_TARGET);

const ECDSA_SIGNING_KEY_SLOT_ID = deriveEvmFamilySigningKeySlotId({
  walletId: 'wallet_alice',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  chainTargetKey: ECDSA_CHAIN_TARGET_KEY,
});

function validEcdsaClientBootstrap() {
  return {
    formatVersion: 'ecdsa-derivation-role-local',
    walletId: 'wallet_alice',
    evmFamilySigningKeySlotId: ECDSA_SIGNING_KEY_SLOT_ID,
    ecdsaThresholdKeyId: 'ederivation-alice',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
    keyScope: 'evm-family',
    relayerKeyId: 'ederivation-relayer-alice',
    derivationClientSharePublicKey33B64u: b64u([2, ...Array(32).fill(1)]),
    clientShareRetryCounter: 0,
    contextBinding32B64u: b64u(Array(32).fill(2)),
    requestId: 'request-1',
    registrationPreparationId: 'wrp_123',
    thresholdSessionId: 'session-1',
    ttlMs: 300_000,
    remainingUses: 1,
    participantIds: [1, 2],
    runtimePolicyScope: {
      orgId: 'org',
      projectId: 'project',
      envId: 'dev',
      signingRootVersion: 'default',
    },
  };
}

function validNearAddSignerCustodyKeySet() {
  return {
    kind: 'near_ed25519_v1',
    keyManifestDigestB64u: b64u(Array(32).fill(3)),
    registeredPublicKeyB64u: b64u(Array(32).fill(4)),
  };
}

function validEcdsaAddSignerCustodyKeySet() {
  return {
    kind: 'evm_family_ecdsa_v1',
    keyManifestDigestB64u: b64u(Array(32).fill(3)),
    clientRootPublicKey33B64u: b64u([2, ...Array(32).fill(1)]),
  };
}

function webAuthnRpId(value: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function walletAuthMethodId(value: string) {
  const parsed = parseWalletAuthMethodId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function walletAuthorityId(value: string) {
  const parsed = parseWalletAuthorityId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function addAuthMethodIntentSource() {
  return {
    walletAuthorityId: walletAuthorityId('wallet-authority:source'),
    walletAuthMethodId: walletAuthMethodId('wallet-auth-method:source'),
    walletSessionId: 'wallet-session:source',
    authorityDigestB64u: 'authority-digest:source',
    revocationEpoch: 0,
  };
}

function addAuthMethodIntentCaller() {
  return {
    caller: 'same_device_addition' as const,
    source: addAuthMethodIntentSource(),
  };
}

const RP_ID = webAuthnRpId('wallet.example.test');

function ecdsaAddSignerIntent(): AddSignerIntentV1 {
  return {
    version: 'add_signer_intent_v1',
    walletId: walletIdFromString('wallet_alice'),
    signerSelection: {
      mode: 'ecdsa',
      ecdsa: {
        chainTargets: [{ kind: 'tempo', chainId: 42431 }],
        participantIds: [1, 2],
      },
    },
    nonceB64u: 'add-signer-nonce',
  };
}

function ed25519AddSignerIntent(): AddSignerIntentV1 {
  return {
    version: 'add_signer_intent_v1',
    walletId: walletIdFromString('wallet_alice'),
    signerSelection: {
      mode: 'ed25519',
      ed25519: {
        mode: 'create_implicit_near_account',
        signerSlot: 2,
        participantIds: [1, 2],
        keyPurpose: 'near_tx',
        keyVersion: 'router-ab-ed25519-yao-v1',
        derivationVersion: 1,
      },
    },
    nonceB64u: 'add-signer-nonce',
  };
}

function ed25519AddSignerAdmissionRequest() {
  return {
    scope: {
      lifecycle_id: 'wasc_1',
      root_share_epoch: 'root-share-epoch-1',
      account_id: 'wallet_alice',
      threshold_session_id: 'threshold-session-add-signer-1',
      signer_set_id: 'signer-set-add-signer-1',
      signing_worker_id: 'signing-worker-test',
    },
    application_binding: {
      wallet_id: 'wallet_alice',
      near_ed25519_signing_key_id: 'wallet_alice',
      signing_root_id: 'project:dev',
      key_creation_signer_slot: 2,
    },
    participant_ids: [1, 2] as const,
  };
}

function addAuthMethodIntent(
  kind: 'passkey' | 'email_otp' = 'passkey',
  caller: 'same_device_addition' | 'linked_device_ceremony' = 'same_device_addition',
): AddAuthMethodIntentV1 {
  const common = {
    version: 'add_auth_method_intent_v1' as const,
    walletId: walletIdFromString('wallet_alice'),
    authMethod:
      kind === 'passkey'
        ? { kind: 'passkey' as const, rpId: RP_ID }
        : {
            kind: 'email_otp' as const,
            email: 'alice@example.test',
          },
    targetWalletAuthMethodId: walletAuthMethodId('wallet-auth-method:target'),
    nonceB64u: 'add-auth-method-nonce',
  };
  if (caller === 'linked_device_ceremony') {
    return { ...common, caller };
  }
  return {
    ...common,
    ...addAuthMethodIntentCaller(),
  };
}

function linkDevicesOnlyPermissions() {
  const parsed = parseDelegatedWalletPermissionSetV1(['link_devices']);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

test.describe('wallet registration route boundaries', () => {
  test('add-signer start rejects threshold-session auth before service dispatch', async () => {
    const intent = ecdsaAddSignerIntent();
    const digest = await computeAddSignerIntentDigestB64u(intent);
    let called = false;
    const response = await handleRouterApiWalletAddSignerStart(
      addSignerInputFor({
        routeId: 'wallet_add_signer_start',
        body: {
          intent,
          addSignerIntentGrant: 'wasig_test',
          addSignerIntentDigestB64u: digest,
          auth: {
            kind: 'wallet_session',
            jwt: 'ed25519-threshold-session',
          },
        },
        authService: {
          startWalletAddSigner: async () => {
            called = true;
            return { ok: true };
          },
        },
      }),
    );

    expect(called).toBe(false);
    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'add-signer auth.kind is unsupported',
    });
  });

  test('add-signer start verifies WebAuthn challenge digest', async () => {
    const intent = ecdsaAddSignerIntent();
    const digest = await computeAddSignerIntentDigestB64u(intent);
    const credential = fakeWebAuthnAuthentication();
    let verifyRequest: unknown = null;
    let serviceRequest: unknown = null;
    const response = await handleRouterApiWalletAddSignerStart(
      addSignerInputFor({
        routeId: 'wallet_add_signer_start',
        body: {
          intent,
          addSignerIntentGrant: 'wasig_test',
          addSignerIntentDigestB64u: digest,
          auth: {
            kind: 'webauthn_assertion',
            rpId: 'wallet.example.test',
            credential,
            expectedChallengeDigestB64u: digest,
          },
        },
        authService: {
          verifyWebAuthnAuthenticationLite: async (request: unknown) => {
            verifyRequest = request;
            return { success: true, verified: true };
          },
          startWalletAddSigner: async (request: unknown) => {
            serviceRequest = request;
            return {
              ok: true,
              addSignerCeremonyId: 'wasc_1',
              intent,
              ecdsa: {
                kind: 'evm_family_ecdsa_keygen',
                chainTargets: [{ kind: 'tempo', chainId: 42431 }],
                prepare: validEcdsaClientBootstrap(),
              },
            };
          },
        },
      }),
    );

    expect(response.status).toBe(200);
    expect(verifyRequest).toEqual({
      userId: 'wallet_alice',
      rpId: 'wallet.example.test',
      expectedChallenge: digest,
      expected_origin: 'https://wallet.example.test',
      webauthn_authentication: credential,
    });
    expect(serviceRequest).toMatchObject({
      addSignerIntentDigestB64u: digest,
      auth: {
        kind: 'webauthn_assertion',
        expectedChallengeDigestB64u: digest,
      },
    });
  });

  test('add-signer start normalizes Ed25519 key derivation fields', async () => {
    const intent = ed25519AddSignerIntent();
    const digest = await computeAddSignerIntentDigestB64u(intent);
    const credential = fakeWebAuthnAuthentication();
    let serviceRequest: unknown = null;
    const response = await handleRouterApiWalletAddSignerStart(
      addSignerInputFor({
        routeId: 'wallet_add_signer_start',
        body: {
          intent,
          addSignerIntentGrant: 'wasig_test',
          addSignerIntentDigestB64u: digest,
          auth: {
            kind: 'webauthn_assertion',
            rpId: 'wallet.example.test',
            credential,
            expectedChallengeDigestB64u: digest,
          },
        },
        authService: {
          verifyWebAuthnAuthenticationLite: async () => ({ success: true, verified: true }),
          startWalletAddSigner: async (request: unknown) => {
            serviceRequest = request;
            return {
              ok: true,
              addSignerCeremonyId: 'wasc_1',
              intent,
              kind: 'near_ed25519',
              ed25519: {
                admissionRequest: ed25519AddSignerAdmissionRequest(),
              },
            };
          },
        },
      }),
    );

    expect(response.status, JSON.stringify(response.body)).toBe(200);
    expect(response.body).toMatchObject({
      ok: true,
      kind: 'near_ed25519',
      ed25519: {
        admissionRequest: {
          scope: { lifecycle_id: 'wasc_1' },
          application_binding: {
            wallet_id: 'wallet_alice',
            key_creation_signer_slot: 2,
          },
          participant_ids: [1, 2],
        },
      },
    });
    expect(serviceRequest).toMatchObject({
      intent: {
        signerSelection: {
          mode: 'ed25519',
          ed25519: {
            mode: 'create_implicit_near_account',
            signerSlot: 2,
            participantIds: [1, 2],
            keyPurpose: 'near_tx',
            keyVersion: 'router-ab-ed25519-yao-v1',
            derivationVersion: 1,
          },
        },
      },
    });
  });

  test('add-signer start rejects incomplete Ed25519 derivation fields', async () => {
    const intent = ed25519AddSignerIntent();
    const incompleteIntent = {
      ...intent,
      signerSelection: {
        mode: 'ed25519',
        ed25519: {
          mode: 'create_implicit_near_account',
          signerSlot: 2,
          participantIds: [1, 2],
        },
      },
    };
    let called = false;
    const response = await handleRouterApiWalletAddSignerStart(
      addSignerInputFor({
        routeId: 'wallet_add_signer_start',
        body: {
          intent: incompleteIntent,
          addSignerIntentGrant: 'wasig_test',
          addSignerIntentDigestB64u: 'invalid-intent-digest',
          auth: {
            kind: 'webauthn_assertion',
            credential: fakeWebAuthnAuthentication(),
            expectedChallengeDigestB64u: 'invalid-intent-digest',
          },
        },
        authService: {
          startWalletAddSigner: async () => {
            called = true;
            return { ok: true };
          },
        },
      }),
    );

    expect(called).toBe(false);
    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'add-signer Ed25519 spec is invalid',
    });
  });

  test('add-signer finalize normalizes ECDSA payloads', async () => {
    const custodyKeySet = validEcdsaAddSignerCustodyKeySet();
    let finalizeRequest: unknown = null;
    const finalize = await handleRouterApiWalletAddSignerFinalize(
      addSignerInputFor({
        routeId: 'wallet_add_signer_finalize',
        body: {
          addSignerCeremonyId: ' wasc_1 ',
          idempotencyKey: ' add-signer-finalize-1 ',
          kind: 'evm_family_ecdsa',
          ecdsa: {
            expectedKeyHandles: [' key-handle-1 '],
          },
          custodyKeySet,
        },
        authService: {
          finalizeWalletAddSigner: async (request: unknown) => {
            finalizeRequest = request;
            return {
              ok: true,
              walletId: 'wallet_alice',
              kind: 'evm_family_ecdsa',
              rpId: 'wallet.example.test',
              ecdsa: { walletKeys: [] },
            };
          },
        },
      }),
    );

    expect(finalize.status).toBe(200);
    expect(finalizeRequest).toEqual({
      addSignerCeremonyId: 'wasc_1',
      idempotencyKey: 'add-signer-finalize-1',
      kind: 'evm_family_ecdsa',
      ecdsa: {
        expectedKeyHandles: ['key-handle-1'],
      },
      custodyKeySet,
    });
  });

  test('add-signer finalize forwards the exact Ed25519 Yao activation reference', async () => {
    const sessionId = new Array<number>(32).fill(7);
    const custodyKeySet = validNearAddSignerCustodyKeySet();
    let finalizeRequest: unknown = null;
    const response = await handleRouterApiWalletAddSignerFinalize(
      addSignerInputFor({
        routeId: 'wallet_add_signer_finalize',
        body: {
          addSignerCeremonyId: ' wasc_1 ',
          idempotencyKey: ' add-signer-finalize-yao-1 ',
          kind: 'near_ed25519',
          ed25519: {
            activationReference: {
              kind: 'router_ab_ed25519_yao_activation_reference_v1',
              lifecycle_id: 'wasc_1',
              session_id: sessionId,
            },
          },
          custodyKeySet,
        },
        authService: {
          finalizeWalletAddSigner: async (request: unknown) => {
            finalizeRequest = request;
            return { ok: false, code: 'captured', message: 'captured request' };
          },
        },
      }),
    );

    expect(response.status).toBe(400);
    expect(finalizeRequest).toEqual({
      addSignerCeremonyId: 'wasc_1',
      idempotencyKey: 'add-signer-finalize-yao-1',
      kind: 'near_ed25519',
      ed25519: {
        activationReference: {
          kind: 'router_ab_ed25519_yao_activation_reference_v1',
          lifecycle_id: 'wasc_1',
          session_id: sessionId,
        },
      },
      custodyKeySet,
    });
  });

  test('add-auth-method intent uses a dedicated scope and route family', async () => {
    let capturedRequest: unknown = null;
    const response = await handleRouterApiWalletAddAuthMethodIntent(
      addAuthMethodInputFor({
        routeId: 'wallet_add_auth_method_intent',
        body: {
          walletId: 'wallet_alice',
          authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
          ...addAuthMethodIntentCaller(),
        },
        headers: {
          authorization: 'Bearer sk_test',
          'x-seams-environment-id': 'project:dev',
        },
        origin: 'https://wallet.example.test',
        authService: {
          createAddAuthMethodIntent: async (request: unknown) => {
            capturedRequest = request;
            return {
              ok: true,
              intent: addAuthMethodIntent(),
              addAuthMethodIntentDigestB64u: 'digest',
              addAuthMethodIntentGrant: 'waig_1',
              expiresAtMs: Date.now() + 60_000,
            };
          },
        },
        apiKeyAuth: {
          authenticate: async (request: unknown) => {
            expect(request).toMatchObject({
              secret: 'sk_test',
              environmentId: 'project:dev',
            });
            return {
              ok: true,
              principal: {
                apiKeyId: 'ak_add_auth_method',
                orgId: 'org_add_auth_method',
                projectId: 'project',
                envId: 'dev',
                environmentId: 'project:dev',
                scopes: ['wallets.auth_methods.create'],
              },
            };
          },
        },
      }),
    );

    expect(response.status).toBe(200);
    expect(capturedRequest).toMatchObject({
      command: {
        subject: {
          kind: 'wallet_auth_method_management',
          walletId: 'wallet_alice',
        },
        authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
      },
      expectedOrigin: 'https://wallet.example.test',
    });
  });

  test('add-signer intent rejects invalid signerSelection before service dispatch', async () => {
    let called = false;
    const response = await handleRouterApiWalletAddSignerIntent(
      addSignerInputFor({
        routeId: 'wallet_add_signer_intent',
        body: {
          rpId: 'wallet.example.test',
          signerSelection: {
            mode: 'ed25519',
            ed25519: {
              mode: 'create_implicit_near_account',
              signerSlot: 1,
              participantIds: [],
              keyPurpose: 'near_tx',
              keyVersion: 'router-ab-ed25519-yao-v1',
              derivationVersion: 1,
            },
          },
        },
        headers: {
          authorization: 'Bearer sk_test',
          'x-seams-environment-id': 'project:dev',
        },
        origin: 'https://wallet.example.test',
        authService: {
          createAddSignerIntent: async () => {
            called = true;
            return { ok: true };
          },
        },
        apiKeyAuth: {
          authenticate: async () => ({
            ok: true,
            principal: {
              apiKeyId: 'ak_add_signer',
              orgId: 'org_add_signer',
              projectId: 'project',
              envId: 'dev',
              environmentId: 'project:dev',
              scopes: ['wallets.signers.create'],
            },
          }),
        },
      }) as unknown as Parameters<typeof handleRouterApiWalletAddSignerIntent>[0],
    );

    expect(called).toBe(false);
    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'add-signer Ed25519 participantIds must contain participant ids',
    });
  });

  test('add-signer intent dispatches an exact wallet signer subject', async () => {
    let capturedCommand: unknown = null;
    const response = await handleRouterApiWalletAddSignerIntent(
      addSignerInputFor({
        routeId: 'wallet_add_signer_intent',
        body: {
          signerSelection: {
            mode: 'ed25519',
            ed25519: {
              mode: 'create_implicit_near_account',
              signerSlot: 1,
              participantIds: [1, 2],
              keyPurpose: 'near_tx',
              keyVersion: 'router-ab-ed25519-yao-v1',
              derivationVersion: 1,
            },
          },
        },
        headers: {
          authorization: 'Bearer pk_test',
          'x-seams-environment-id': 'project:dev',
        },
        authService: {
          createAddSignerIntent: async (input: unknown) => {
            capturedCommand = input;
            return {
              ok: true,
              intent: { version: 'add_signer_intent_v1' },
              addSignerIntentDigestB64u: 'digest',
              addSignerIntentGrant: 'wasig_1',
              expiresAtMs: Date.now() + 60_000,
            };
          },
        },
        publishableKeyAuth: {
          authenticate: async () => ({
            ok: true,
            principal: {
              apiKeyId: 'pk_add_signer',
              orgId: 'org_add_signer',
              projectId: 'project',
              envId: 'dev',
              environmentId: 'project:dev',
              scopes: ['wallets.signers.create'],
            },
          }),
        },
      }) as unknown as Parameters<typeof handleRouterApiWalletAddSignerIntent>[0],
    );

    expect(response.status).toBe(200);
    expect(capturedCommand).toMatchObject({
      command: {
        subject: {
          kind: 'wallet_signer_management',
          walletId: 'wallet_alice',
        },
        signerSelection: { mode: 'ed25519' },
      },
      expectedOrigin: 'https://wallet.example.test',
    });
  });

  test('add-auth-method start rejects wallet-session body facts before service dispatch', async () => {
    const intent = addAuthMethodIntent();
    const digest = await computeAddAuthMethodIntentDigestB64u(intent);
    let called = false;
    const response = await handleRouterApiWalletAddAuthMethodStart(
      addAuthMethodInputFor({
        routeId: 'wallet_add_auth_method_start',
        body: {
          intent,
          addAuthMethodIntentGrant: 'waig_1',
          addAuthMethodIntentDigestB64u: digest,
          auth: {
            kind: 'wallet_session',
            jwt: 'threshold-session-jwt',
          },
        },
        authService: {
          startWalletAddAuthMethod: async () => {
            called = true;
            return { ok: true };
          },
        },
      }),
    );

    expect(called).toBe(false);
    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'wallet_session auth carries no body facts',
    });
  });

  test('add-auth-method linked-device start admits an exact link_devices credential', async () => {
    const fixture = await buildLinkedDeviceManagementAuthorityFixture({
      label: 'route-exact',
      permissions: linkDevicesOnlyPermissions(),
      provenance: 'wallet_registration',
      expiresAtMs: Date.now() + 60_000,
      identity: {
        walletId: 'wallet_alice',
        authorityId: 'authority:route-exact',
        walletAuthMethodId: 'auth-method:route-exact',
        rpId: 'wallet.example.test',
      },
    });
    const intent = addAuthMethodIntent('passkey', 'linked_device_ceremony');
    const digest = await computeAddAuthMethodIntentDigestB64u(intent);
    const token = String(fixture.operationCredential.token);
    let exactReadInput: unknown = null;
    let serviceRequest: unknown = null;
    const response = await handleRouterApiWalletAddAuthMethodStart(
      addAuthMethodInputFor({
        routeId: 'wallet_add_auth_method_start',
        body: {
          intent,
          addAuthMethodIntentGrant: 'waig_1',
          addAuthMethodIntentDigestB64u: digest,
          auth: { kind: 'wallet_session' },
          authority: { kind: 'passkey' },
        },
        headers: { authorization: `Bearer ${token}` },
        authorizationSessions: {
          tenantId: fixture.issuedSession.session.tenantId,
          readWalletSessionAuthorizationV2ByOperationCredential: async (input: unknown) => {
            exactReadInput = input;
            return {
              authorization: fixture.issuedSession,
              authority: fixture.authority,
              authMethod: fixture.authMethod,
              retiredAtMs: null,
            };
          },
        },
        authService: {
          startWalletAddAuthMethod: async (request: unknown) => {
            serviceRequest = request;
            return { ok: true };
          },
        },
      }),
    );

    expect(response.status).toBe(200);
    expect(exactReadInput).toMatchObject({
      tenantId: fixture.issuedSession.session.tenantId,
      token,
      nowMs: expect.any(Number),
    });
    expect(serviceRequest).toMatchObject({
      walletId: 'wallet_alice',
      subject: {
        kind: 'wallet_auth_method_management',
        walletId: 'wallet_alice',
      },
      intent: {
        caller: 'linked_device_ceremony',
      },
      auth: {
        kind: 'wallet_session',
        walletSessionId: fixture.issuedSession.session.walletSessionId,
        authorizationId: fixture.issuedSession.session.authorizationId,
        rpId: fixture.authMethod.rpId,
        credentialIdB64u: fixture.authMethod.credentialIdB64u,
      },
    });
  });

  test('add-auth-method linked-device start rejects an exact session without link_devices', async () => {
    const fixture = await buildLinkedDeviceManagementAuthorityFixture({
      label: 'route-no-link',
      permissions: buildSigningOnlyPermissionsV1(),
      provenance: 'wallet_registration',
      expiresAtMs: Date.now() + 60_000,
      identity: {
        walletId: 'wallet_alice',
        authorityId: 'authority:route-no-link',
        walletAuthMethodId: 'auth-method:route-no-link',
        rpId: 'wallet.example.test',
      },
    });
    const intent = addAuthMethodIntent('passkey', 'linked_device_ceremony');
    const digest = await computeAddAuthMethodIntentDigestB64u(intent);
    let serviceCalled = false;
    const response = await handleRouterApiWalletAddAuthMethodStart(
      addAuthMethodInputFor({
        routeId: 'wallet_add_auth_method_start',
        body: {
          intent,
          addAuthMethodIntentGrant: 'waig_1',
          addAuthMethodIntentDigestB64u: digest,
          auth: { kind: 'wallet_session' },
          authority: { kind: 'passkey' },
        },
        headers: { authorization: `Bearer ${String(fixture.operationCredential.token)}` },
        authorizationSessions: {
          tenantId: fixture.issuedSession.session.tenantId,
          readWalletSessionAuthorizationV2ByOperationCredential: async () => ({
            authorization: fixture.issuedSession,
            authority: fixture.authority,
            authMethod: fixture.authMethod,
            retiredAtMs: null,
          }),
        },
        authService: {
          startWalletAddAuthMethod: async () => {
            serviceCalled = true;
            return { ok: true };
          },
        },
      }),
    );

    expect(response.status).toBe(401);
    expect(serviceCalled).toBe(false);
  });

  test('add-auth-method start validates digest and forwards normalized passkey authority', async () => {
    const intent = addAuthMethodIntent();
    const digest = await computeAddAuthMethodIntentDigestB64u(intent);
    const credential = fakeWebAuthnAuthentication();
    let verifyRequest: unknown = null;
    let serviceRequest: unknown = null;
    const response = await handleRouterApiWalletAddAuthMethodStart(
      addAuthMethodInputFor({
        routeId: 'wallet_add_auth_method_start',
        body: {
          intent,
          addAuthMethodIntentGrant: 'waig_1',
          addAuthMethodIntentDigestB64u: digest,
          auth: {
            kind: 'webauthn_assertion',
            rpId: 'wallet.example.test',
            credential,
            expectedChallengeDigestB64u: digest,
          },
        },
        authService: {
          verifyWebAuthnAuthenticationLite: async (request: unknown) => {
            verifyRequest = request;
            return { success: true, verified: true };
          },
          startWalletAddAuthMethod: async (request: unknown) => {
            serviceRequest = request;
            return {
              ok: true,
              addAuthMethodCeremonyId: 'waac_1',
              intent,
            };
          },
        },
      }),
    );

    expect(response.status).toBe(200);
    expect(verifyRequest).toEqual({
      userId: 'wallet_alice',
      rpId: 'wallet.example.test',
      expectedChallenge: digest,
      expected_origin: 'https://wallet.example.test',
      webauthn_authentication: credential,
    });
    expect(serviceRequest).toMatchObject({
      subject: {
        kind: 'wallet_auth_method_management',
        walletId: 'wallet_alice',
      },
      addAuthMethodIntentDigestB64u: digest,
      intent: {
        authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
      },
      authority: {
        kind: 'passkey',
      },
    });
  });

  test('add-auth-method start forwards normalized Email OTP authority', async () => {
    const intent = addAuthMethodIntent('email_otp');
    const digest = await computeAddAuthMethodIntentDigestB64u(intent);
    let serviceRequest: unknown = null;
    const response = await handleRouterApiWalletAddAuthMethodStart(
      addAuthMethodInputFor({
        routeId: 'wallet_add_auth_method_start',
        body: {
          intent,
          addAuthMethodIntentGrant: 'waig_1',
          addAuthMethodIntentDigestB64u: digest,
          auth: {
            kind: 'webauthn_assertion',
            rpId: 'wallet.example.test',
            credential: fakeWebAuthnAuthentication(),
            expectedChallengeDigestB64u: digest,
          },
          emailOtpRegistrationProof: {
            version: 'email_otp_registration_proof_v1',
            proofKind: 'otp_challenge',
            providerSubject: 'google:alice',
            email: 'Alice@Example.test',
            challengeId: 'challenge-1',
            otpCode: '123456',
            otpChannel: 'email_otp',
            registrationIntentDigestB64u: digest,
          },
        },
        authService: {
          verifyWebAuthnAuthenticationLite: async () => ({ success: true, verified: true }),
          startWalletAddAuthMethod: async (request: unknown) => {
            serviceRequest = request;
            return {
              ok: true,
              addAuthMethodCeremonyId: 'waac_1',
              intent,
            };
          },
        },
      }),
    );

    expect(response.status).toBe(200);
    expect(serviceRequest).toMatchObject({
      subject: {
        kind: 'wallet_auth_method_management',
        walletId: 'wallet_alice',
      },
      intent: {
        authMethod: { kind: 'email_otp', email: 'alice@example.test' },
      },
      authority: {
        kind: 'email_otp',
        emailOtpRegistrationProof: {
          email: 'alice@example.test',
          challengeId: 'challenge-1',
        },
      },
    });
  });

  test('add-auth-method finalize normalizes ceremony id and forwards request', async () => {
    let finalizeRequest: unknown = null;
    const response = await handleRouterApiWalletAddAuthMethodFinalize(
      addAuthMethodInputFor({
        routeId: 'wallet_add_auth_method_finalize',
        body: {
          addAuthMethodCeremonyId: ' waac_1 ',
        },
        authService: {
          finalizeWalletAddAuthMethod: async (request: unknown) => {
            finalizeRequest = request;
            return {
              ok: true,
              walletId: 'wallet_alice',
              rpId: 'wallet.example.test',
              authMethod: { kind: 'passkey', status: 'active' },
            };
          },
        },
      }),
    );

    expect(response.status).toBe(200);
    expect(finalizeRequest).toEqual({
      subject: {
        kind: 'wallet_auth_method_management',
        walletId: 'wallet_alice',
      },
      authorization: { kind: 'owner' },
      addAuthMethodCeremonyId: 'waac_1',
    });
  });

  test('auth-method revoke verifies and forwards one exact auth-method id', async () => {
    let revokeRequest: unknown = null;
    let proofRequest: unknown = null;
    const response = await handleRouterApiWalletRevokeAuthMethod(
      addAuthMethodInputFor({
        routeId: 'wallet_revoke_auth_method',
        walletAuthMethodId: 'wallet-auth-method:target',
        body: {
          walletId: 'wallet_alice',
          walletAuthMethodId: 'wallet-auth-method:target',
          requestedAtMs: 1_000,
          sourceProof: {
            kind: 'email_otp',
            challengeId: 'email-otp-challenge:revoke',
            otpCode: '123456',
            ownerProofBindingDigest: 'digest:revoke',
          },
        },
        authService: {
          verifyWalletAuthMethodRevokeProof: async (request: unknown) => {
            proofRequest = request;
            return {
              kind: 'authorized',
              walletAuthMethodId: 'wallet-auth-method:source',
              verifiedAtMs: 1_001,
            };
          },
          revokeWalletAuthMethod: async (request: unknown) => {
            revokeRequest = request;
            return {
              ok: true,
              walletId: 'wallet_alice',
              authMethod: { kind: 'email_otp', status: 'revoked' },
            };
          },
        },
      }),
    );

    expect(response.status).toBe(200);
    expect(proofRequest).toEqual({
      walletId: 'wallet_alice',
      targetWalletAuthMethodId: 'wallet-auth-method:target',
      requestedAtMs: 1_000,
      sourceProof: {
        kind: 'email_otp',
        challengeId: 'email-otp-challenge:revoke',
        otpCode: '123456',
        ownerProofBindingDigest: 'digest:revoke',
      },
      expectedOrigin: 'https://wallet.example.test',
    });
    expect(revokeRequest).toEqual({
      subject: {
        kind: 'wallet_auth_method_management',
        walletId: 'wallet_alice',
      },
      walletId: 'wallet_alice',
      walletAuthMethodId: 'wallet-auth-method:target',
      requestedAtMs: 1_000,
      sourceProof: {
        kind: 'email_otp',
        challengeId: 'email-otp-challenge:revoke',
        otpCode: '123456',
        ownerProofBindingDigest: 'digest:revoke',
      },
      verifiedSource: {
        walletAuthMethodId: 'wallet-auth-method:source',
        verifiedAtMs: 1_001,
      },
    });
  });

  test('ECDSA key-facts inventory rejects opaque authorization without a bearer token', async () => {
    let inventoryCalled = false;
    const response = await handleRouterApiWalletEcdsaKeyFactsInventory(
      ecdsaInventoryInputFor({
        body: {
          rpId: 'wallet.example.test',
          keyTargets: [
            {
              keyHandle: 'ederivation-key-alice',
              chainTarget: { kind: 'tempo', chainId: 42431 },
            },
          ],
          auth: {
            kind: 'opaque_wallet_session',
            curve: 'ecdsa_secp256k1',
          },
        },
        authService: {
          listWalletEcdsaKeyFactsInventory: async () => {
            inventoryCalled = true;
            return { records: [], diagnostics: {} };
          },
        },
        session: {},
        headers: {},
      }),
    );

    expect(response.status).toBe(401);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'unauthorized',
    });
    expect(inventoryCalled).toBe(false);
  });

  test('ECDSA key-facts inventory rejects mismatched WebAuthn challenge digest', async () => {
    let verifyCalled = false;
    let inventoryCalled = false;
    const response = await handleRouterApiWalletEcdsaKeyFactsInventory(
      ecdsaInventoryInputFor({
        body: {
          rpId: 'wallet.example.test',
          keyTargets: [
            {
              keyHandle: 'ederivation-key-alice',
              chainTarget: { kind: 'tempo', chainId: 42431 },
            },
          ],
          auth: {
            kind: 'webauthn_assertion',
            credential: fakeWebAuthnAuthentication(),
            serverNonceB64u: 'nonce-1',
            expectedChallengeDigestB64u: 'wrong-digest',
          },
        },
        authService: {
          verifyWebAuthnAuthenticationLite: async () => {
            verifyCalled = true;
            return { success: true, verified: true };
          },
          listWalletEcdsaKeyFactsInventory: async () => {
            inventoryCalled = true;
            return { records: [], diagnostics: {} };
          },
        },
        session: {},
      }),
    );

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'auth.expectedChallengeDigestB64u mismatch',
    });
    expect(verifyCalled).toBe(false);
    expect(inventoryCalled).toBe(false);
  });

  test('ECDSA key-facts inventory accepts verified WebAuthn inventory authorization', async () => {
    const keyTargets = [
      {
        keyHandle: 'ederivation-key-alice',
        chainTarget: { kind: 'tempo' as const, chainId: 42431 },
      },
    ];
    const expectedChallenge = await computeWalletEcdsaKeyFactsInventoryChallengeDigestB64u({
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
      keyTargets,
      serverNonceB64u: 'nonce-1',
    });
    const credential = fakeWebAuthnAuthentication();
    let verifyRequest: unknown = null;
    let inventoryRequest: unknown = null;

    const response = await handleRouterApiWalletEcdsaKeyFactsInventory(
      ecdsaInventoryInputFor({
        body: {
          rpId: 'wallet.example.test',
          keyTargets,
          auth: {
            kind: 'webauthn_assertion',
            credential,
            serverNonceB64u: 'nonce-1',
            expectedChallengeDigestB64u: expectedChallenge,
          },
        },
        authService: {
          verifyWebAuthnAuthenticationLite: async (request: unknown) => {
            verifyRequest = request;
            return { success: true, verified: true };
          },
          listWalletEcdsaKeyFactsInventory: async (request: unknown) => {
            inventoryRequest = request;
            return {
              records: [],
              diagnostics: {
                userId: 'wallet_alice',
                inputCount: 1,
                returnedCount: 0,
                ecdsaBootstrapExportRuntimePresent: true,
                rejected: {},
              },
            };
          },
        },
        session: {},
      }),
    );

    expect(response.status).toBe(200);
    expect(verifyRequest).toEqual({
      userId: 'wallet_alice',
      rpId: 'wallet.example.test',
      expectedChallenge,
      expected_origin: 'https://wallet.example.test',
      webauthn_authentication: credential,
    });
    expect(inventoryRequest).toEqual({
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
      keyTargets,
    });
  });

  test('NEAR provisioning attaches the Email OTP app session to the terminal result', async () => {
    const sessionClaims: { subject?: string; [key: string]: unknown } = {};
    const session = {
      verifyJwt: async () => ({
        valid: true as const,
        payload: {
          kind: 'wallet_registration_setup_v1',
          registrationCeremonyId: 'registration-ceremony',
          walletId: 'wallet_alice',
          orgId: 'org',
          signingRootId: 'project:dev',
          signingRootVersion: 'root-v1',
          policy: {
            kind: 'runtime_policy_scope',
            scope: {
              orgId: 'org',
              projectId: 'project',
              envId: 'dev',
              signingRootVersion: 'root-v1',
            },
          },
          setupDigestB64u: 'setup-digest',
          expiresAtMs: Date.now() + 60_000,
        },
      }),
      signJwt: async (subject: string, claims: Record<string, unknown>) => {
        sessionClaims.subject = subject;
        Object.assign(sessionClaims, claims);
        return 'registration-email-otp-app-session';
      },
    };
    const authority = buildEmailOtpWalletAuthAuthority({
      walletId: 'wallet_alice',
      provider: 'google',
      providerUserId: 'google:alice',
      emailHashHex: 'a'.repeat(64),
    });
    const service = {
      completeWalletRegistrationNearProvisioning: async () =>
        ({
          ok: true,
          walletId: walletIdFromString('wallet_alice'),
          authority,
          authMethod: {
            kind: 'email_otp',
            registrationAuthorityId: 'registration-authority',
          },
          kind: 'near_ed25519',
          authorityScope: {
            kind: 'email_otp',
            provider: 'google',
            providerUserId: 'google:alice',
          },
          accountProvisioning: {
            kind: 'implicit_account',
            accountIdSource: 'ed25519_public_key',
          },
          resolvedAccount: {
            kind: 'implicit_account',
            nearAccountId: 'ab'.repeat(32),
            nearEd25519SigningKeyId: 'near-ed25519-key',
          },
          ed25519: {
            signerSlot: 1,
            nearAccountId: 'ab'.repeat(32),
            nearEd25519SigningKeyId: 'near-ed25519-key',
            publicKey: 'ed25519:registration-public-key',
            relayerKeyId: 'signing-worker',
            keyVersion: 'router-ab-ed25519-yao-v1',
            recoveryExportCapable: true,
            participantIds: [1, 2],
            thresholdSessionId: 'threshold-session',
            runtimePolicyScope: {
              orgId: 'org',
              projectId: 'project',
              envId: 'dev',
              signingRootVersion: 'root-v1',
            },
            routerAbNormalSigning: {
              kind: 'router_ab_ed25519_normal_signing_v1',
              signingWorkerId: 'signing-worker',
            },
          },
          nearProvisioning: { status: 'near_ready' },
          appSessionJwt: 'registration-email-otp-app-session',
          registrationEstablishedSession: {},
        }) as never,
      getOrCreateAppSessionVersion: async () => ({
        ok: true as const,
        appSessionVersion: 'app-session-v1',
      }),
    };
    const response = await handleRouterApiWalletRegistrationNearProvisioning({
      body: {
        registrationCeremonyId: 'registration-ceremony',
        signedSetup: 'signed-setup',
        idempotencyKey: 'near-provisioning-key',
        walletSessionClientCapability: WALLET_SESSION_CLIENT_CAPABILITY_V1,
        ed25519: { activationReference: {} },
      },
      headers: {},
      logger: {
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: () => {},
      },
      origin: 'https://wallet.example.test',
      route: route('wallet_registration_near_provisioning'),
      services: {
        walletRegistration: service,
        session,
      },
    } as never);

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({
      ok: true,
      appSessionJwt: 'registration-email-otp-app-session',
    });
    expect(sessionClaims).toEqual({});
  });
});
