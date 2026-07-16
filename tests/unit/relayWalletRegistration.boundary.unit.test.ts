import { expect, test } from '@playwright/test';
import {
  handleRouterApiWalletAddAuthMethodFinalize,
  handleRouterApiWalletAddAuthMethodIntent,
  handleRouterApiWalletRevokeAuthMethod,
  handleRouterApiWalletAddAuthMethodStart,
  handleRouterApiWalletAddSignerFinalize,
  handleRouterApiWalletAddSignerDerivationRespond,
  handleRouterApiWalletAddSignerIntent,
  handleRouterApiWalletAddSignerStart,
  handleRouterApiWalletRegistrationIntent,
  handleRouterApiWalletRegistrationStart,
  handleRouterApiWalletRegistrationFinalize,
  handleRouterApiWalletRegistrationDerivationRespond,
  handleRouterApiWalletEcdsaKeyFactsInventory,
} from '../../packages/sdk-server-ts/src/router/walletRegistrationRoutes';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
  type RouteDefinition,
} from '../../packages/sdk-server-ts/src/router/routeDefinitions';
import { computeWalletEcdsaKeyFactsInventoryChallengeDigestB64u } from '../../packages/shared-ts/src/utils/ecdsaKeyFactsInventory';
import { ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND } from '../../packages/shared-ts/src/utils/sessionTokens';
import { ROUTER_AB_PUBLIC_KEYSET_VERSION_V2 } from '../../packages/shared-ts/src/utils/routerAbPublicKeyset';
import {
  computeAddAuthMethodIntentDigestB64u,
  computeAddSignerIntentDigestB64u,
  computeRegistrationIntentDigestB64u,
  implicitNearAccountProvisioning,
  sponsoredNamedNearAccountProvisioning,
  type AddAuthMethodIntentV1,
  type RegistrationIntentV1,
  walletIdFromString,
  type AddSignerIntentV1,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseNamedNearAccountId } from '../../packages/shared-ts/src/utils/near';
import { parseWebAuthnRpId, type WebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import { deriveEvmFamilySigningKeySlotId } from '../../packages/shared-ts/src/signing-lanes';
import { thresholdEcdsaChainTargetKey } from '../../packages/sdk-server-ts/src/core/thresholdEcdsaChainTarget';

const routeDefinitions = createRouterApiRouteDefinitions({
  enableHealthz: true,
  enableSigningSessionSeal: true,
  enableReadyz: true,
});

function namedProvisioning(accountId: string) {
  const parsed = parseNamedNearAccountId(accountId);
  if (!parsed.ok) throw new Error(parsed.message);
  return sponsoredNamedNearAccountProvisioning(parsed.value);
}

const ECDSA_REGISTRATION_DERIVATION_RESPOND_FORBIDDEN_FIELDS = [
  'clientRootProof',
  'passkeyBootstrapAuthorization',
  'sessionKind',
] as const;

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

function inputFor(
  routeId:
    | 'wallet_registration_start'
    | 'wallet_registration_derivation_respond'
    | 'wallet_registration_finalize',
  body: unknown,
  authService: Record<string, unknown>,
  session?: Record<string, unknown>,
) {
  return {
    body,
    headers: {},
    logger: {
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {},
    },
    route: route(routeId),
    services: {
      walletRegistration: authService,
      authService,
      routerAbPublicKeyset: ROUTER_AB_PUBLIC_KEYSET,
      ...(session ? { session } : {}),
    },
    sourceIp: '203.0.113.10',
  } as unknown as Parameters<typeof handleRouterApiWalletRegistrationStart>[0];
}

function ecdsaInventoryInputFor(args: {
  body: unknown;
  authService: Record<string, unknown>;
  session: Record<string, unknown>;
  walletId?: string;
  origin?: string;
}) {
  return {
    body: args.body,
    headers: { authorization: 'Bearer test-session' },
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
    },
  } as unknown as Parameters<typeof handleRouterApiWalletEcdsaKeyFactsInventory>[0];
}

function addSignerInputFor(args: {
  routeId:
    | 'wallet_add_signer_intent'
    | 'wallet_add_signer_start'
    | 'wallet_add_signer_derivation_respond'
    | 'wallet_add_signer_finalize';
  body: unknown;
  authService: Record<string, unknown>;
  session?: Record<string, unknown>;
  walletId?: string;
  headers?: Record<string, string>;
  origin?: string;
  apiKeyAuth?: Record<string, unknown>;
  orgProjectEnv?: Record<string, unknown>;
  bootstrapTokenVerifier?: Record<string, unknown>;
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
      orgProjectEnv: args.orgProjectEnv,
      bootstrapTokenVerifier: args.bootstrapTokenVerifier,
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
  bootstrapTokenVerifier?: Record<string, unknown>;
  walletId?: string;
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
    pathParams: { walletId: args.walletId || 'wallet_alice' },
    route: route(args.routeId),
    services: {
      walletRegistration: args.authService,
      authService: args.authService,
      session: args.session || {},
      apiKeyAuth: args.apiKeyAuth,
      orgProjectEnv: args.orgProjectEnv,
      bootstrapTokenVerifier: args.bootstrapTokenVerifier,
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
    signingGrantId: 'signing-grant-1',
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

function validNormalizedEcdsaClientBootstrap() {
  return validEcdsaClientBootstrap();
}

function validEcdsaServerBootstrap() {
  return {
    formatVersion: 'ecdsa-derivation-role-local',
    walletId: 'wallet_alice',
    evmFamilySigningKeySlotId: ECDSA_SIGNING_KEY_SLOT_ID,
    ecdsaThresholdKeyId: 'ederivation-alice',
    relayerKeyId: 'ederivation-relayer-alice',
    applicationBindingDigestB64u: b64u(Array(32).fill(9)),
    contextBinding32B64u: b64u(Array(32).fill(2)),
    publicIdentity: {
      derivationClientSharePublicKey33B64u: b64u([2, ...Array(32).fill(1)]),
      relayerPublicKey33B64u: b64u([3, ...Array(32).fill(6)]),
      groupPublicKey33B64u: b64u([2, ...Array(32).fill(5)]),
      ethereumAddress: '0x1111111111111111111111111111111111111111',
    },
    clientShareRetryCounter: 0,
    relayerShareRetryCounter: 1,
    publicTranscriptDigest32B64u: b64u(Array(32).fill(4)),
    keyHandle: 'ederivation-key-alice',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
    thresholdEcdsaPublicKeyB64u: b64u([2, ...Array(32).fill(5)]),
    ethereumAddress: '0x1111111111111111111111111111111111111111',
    relayerVerifyingShareB64u: b64u([3, ...Array(32).fill(6)]),
    participantIds: [1, 2],
    thresholdSessionId: 'session-1',
    signingGrantId: 'signing-grant-1',
    expiresAtMs: Date.now() + 300_000,
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
    remainingUses: 1,
  };
}

function signingSessionWithCapturedClaims(out: { claims: Record<string, unknown> | null }) {
  return {
    signJwt: async (sub: string, claims: Record<string, unknown>) => {
      void sub;
      out.claims = claims;
      return `signed:${String(claims.kind || '')}:${String(claims.thresholdSessionId || '')}`;
    },
  };
}

function webAuthnRpId(value: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
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
      wallet_session_id: 'wallet-session-add-signer-1',
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

function addAuthMethodIntent(kind: 'passkey' | 'email_otp' = 'passkey'): AddAuthMethodIntentV1 {
  return {
    version: 'add_auth_method_intent_v1',
    walletId: walletIdFromString('wallet_alice'),
    authMethod:
      kind === 'passkey'
        ? { kind: 'passkey', rpId: RP_ID }
        : {
            kind: 'email_otp',
            email: 'alice@example.test',
          },
    nonceB64u: 'add-auth-method-nonce',
  };
}

function nearEd25519RegistrationSigner() {
  return {
    kind: 'near_ed25519' as const,
    accountProvisioning: namedProvisioning('alice.testnet'),
    signerSlot: 1,
    participantIds: [1, 2],
    derivationVersion: 1,
  };
}

function registrationIntent(kind: 'passkey' | 'email_otp' = 'passkey'): RegistrationIntentV1 {
  return {
    version: 'registration_intent_v1',
    walletId: walletIdFromString('wallet_alice'),
    authMethod:
      kind === 'passkey'
        ? { kind: 'passkey', rpId: RP_ID }
        : {
            kind: 'email_otp',
            proofKind: 'otp_challenge',
            email: 'alice@example.test',
            otpCode: '123456',
            appSessionJwt: 'app-session.jwt',
          },
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
    nonceB64u: 'registration-nonce',
  };
}

test.describe('wallet registration route boundaries', () => {
  test('registration intent rejects branch-mixed authMethod before service dispatch', async () => {
    let called = false;
    const response = await handleRouterApiWalletRegistrationIntent({
      body: {
        wallet: { kind: 'server_allocated' },
        rpId: 'wallet.example.test',
        authMethod: {
          kind: 'passkey',
          email: 'alice@example.test',
        },
        signerSelection: registrationIntent().signerSelection,
      },
      headers: {
        authorization: 'Bearer sk_test',
        'x-seams-environment-id': 'project:dev',
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
        authService: {
          createRegistrationIntent: async () => {
            called = true;
            return { ok: true };
          },
        } as Record<string, unknown>,
        apiKeyAuth: {
          authenticate: async () => ({
            ok: true,
            principal: {
              apiKeyId: 'ak_wallet_registration',
              orgId: 'org_wallet_registration',
              projectId: 'project',
              envId: 'dev',
              environmentId: 'project:dev',
              scopes: ['accounts.create'],
            },
          }),
        },
      },
    } as unknown as Parameters<typeof handleRouterApiWalletRegistrationIntent>[0]);

    expect(called).toBe(false);
    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'authMethod is invalid',
    });
  });

  test('registration intent rejects stale Ed25519 account fields before service dispatch', async () => {
    const signer = nearEd25519RegistrationSigner();
    let called = false;
    const response = await handleRouterApiWalletRegistrationIntent({
      body: {
        wallet: { kind: 'provided', walletId: 'alice.testnet' },
        authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
        signerSelection: {
          kind: 'signer_set',
          signers: [{ ...signer, createNearAccount: true }],
        },
      },
      headers: {
        authorization: 'Bearer sk_test',
        'x-seams-environment-id': 'project:dev',
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
        authService: {
          createRegistrationIntent: async () => {
            called = true;
            return { ok: true };
          },
        } as Record<string, unknown>,
        apiKeyAuth: {
          authenticate: async () => ({
            ok: true,
            principal: {
              apiKeyId: 'ak_wallet_registration',
              orgId: 'org_wallet_registration',
              projectId: 'project',
              envId: 'dev',
              environmentId: 'project:dev',
              scopes: ['accounts.create'],
            },
          }),
        },
      },
    } as unknown as Parameters<typeof handleRouterApiWalletRegistrationIntent>[0]);

    expect(called).toBe(false);
    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'near_ed25519 signer spec is invalid',
    });
  });

  test('registration intent rejects branch-mixed account provisioning before service dispatch', async () => {
    const signer = nearEd25519RegistrationSigner();
    let called = false;
    const response = await handleRouterApiWalletRegistrationIntent({
      body: {
        wallet: { kind: 'server_allocated' },
        authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              ...signer,
              accountProvisioning: {
                kind: 'implicit_account',
                requestedAccountId: 'alice.testnet',
              },
            },
          ],
        },
      },
      headers: {
        authorization: 'Bearer sk_test',
        'x-seams-environment-id': 'project:dev',
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
        authService: {
          createRegistrationIntent: async () => {
            called = true;
            return { ok: true };
          },
        } as Record<string, unknown>,
        apiKeyAuth: {
          authenticate: async () => ({
            ok: true,
            principal: {
              apiKeyId: 'ak_wallet_registration',
              orgId: 'org_wallet_registration',
              projectId: 'project',
              envId: 'dev',
              environmentId: 'project:dev',
              scopes: ['accounts.create'],
            },
          }),
        },
      },
    } as unknown as Parameters<typeof handleRouterApiWalletRegistrationIntent>[0]);

    expect(called).toBe(false);
    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'near_ed25519 signer spec is invalid',
    });
  });

  test('registration start rejects mismatched intent digest before service dispatch', async () => {
    const intent = registrationIntent();
    let called = false;
    const response = await handleRouterApiWalletRegistrationStart(
      inputFor(
        'wallet_registration_start',
        {
          registrationIntentGrant: 'rig_1',
          registrationIntentDigestB64u: 'wrong-registration-intent-digest',
          intent,
          webauthn_registration: {
            response: { clientDataJSON: 'client-data' },
          },
        },
        {
          startWalletRegistration: async () => {
            called = true;
            return { ok: true };
          },
        },
      ),
    );

    expect(called).toBe(false);
    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'registration intent digest mismatch',
    });
  });

  test('registration start forwards a normalized Email OTP authority request', async () => {
    const intent = registrationIntent('email_otp');
    const digest = await computeRegistrationIntentDigestB64u(intent);
    let request: unknown = null;
    const response = await handleRouterApiWalletRegistrationStart(
      inputFor(
        'wallet_registration_start',
        {
          registrationIntentGrant: 'rig_1',
          registrationIntentDigestB64u: digest,
          intent,
          emailOtpRegistrationProof: {
            version: 'email_otp_registration_proof_v1',
            proofKind: 'otp_challenge',
            providerSubject: 'google:alice',
            email: 'Alice@Example.test',
            challengeId: 'challenge-1',
            otpCode: '123456',
            otpChannel: 'email_otp',
            registrationIntentDigestB64u: digest,
            appSessionVersion: 'v1',
          },
        },
        {
          startWalletRegistration: async (value: unknown) => {
            request = value;
            return { ok: true, registrationCeremonyId: 'wrc_1' };
          },
        },
      ),
    );

    expect(response.status).toBe(200);
    expect(request).toMatchObject({
      registrationIntentGrant: 'rig_1',
      registrationIntentDigestB64u: digest,
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

  for (const forbiddenField of ECDSA_REGISTRATION_DERIVATION_RESPOND_FORBIDDEN_FIELDS) {
    test(`respond rejects ECDSA registration field ${forbiddenField}`, async () => {
      let called = false;
      const response = await handleRouterApiWalletRegistrationDerivationRespond(
        inputFor(
          'wallet_registration_derivation_respond',
          {
            registrationCeremonyId: 'wrc_123',
            ecdsa: {
              clientBootstraps: [
                {
                  chainTarget: ECDSA_CHAIN_TARGET,
                  clientBootstrap: {
                    ...validEcdsaClientBootstrap(),
                    [forbiddenField]: 'server-auth-owned',
                  },
                },
              ],
            },
          },
          {
            respondWalletRegistrationDerivation: async () => {
              called = true;
              return { ok: true };
            },
          },
        ),
      );

      expect(called).toBe(false);
      expect(response.status).toBe(400);
      expect(response.body).toMatchObject({
        ok: false,
        code: 'invalid_body',
        message: `ecdsa.clientBootstraps.clientBootstrap.${forbiddenField} must stay outside the registration ceremony request`,
      });
    });
  }

  test('respond forwards normalized ECDSA registration client bootstrap', async () => {
    let captured: unknown = null;
    const signedClaims: { claims: Record<string, unknown> | null } = { claims: null };
    const clientBootstrap = validEcdsaClientBootstrap();
    const response = await handleRouterApiWalletRegistrationDerivationRespond(
      inputFor(
        'wallet_registration_derivation_respond',
        {
          registrationCeremonyId: ' wrc_123 ',
          ecdsa: {
            clientBootstraps: [
              {
                chainTarget: ECDSA_CHAIN_TARGET,
                clientBootstrap,
              },
            ],
          },
        },
        {
          respondWalletRegistrationDerivation: async (request: unknown) => {
            captured = request;
            return {
              ok: true,
              registrationCeremonyId: 'wrc_123',
              ecdsa: {
                bootstraps: [
                  {
                    chainTarget: ECDSA_CHAIN_TARGET,
                    bootstrap: validEcdsaServerBootstrap(),
                  },
                ],
              },
            };
          },
          getRouterAbNormalSigningRuntime: () => ({
            getSigningWorkerId: () => 'router-ab-signing-worker-local',
          }),
        },
        signingSessionWithCapturedClaims(signedClaims),
      ),
    );

    expect(response.status).toBe(200);
    expect(captured).toEqual({
      registrationCeremonyId: 'wrc_123',
      ecdsa: {
        clientBootstraps: [
          {
            chainTarget: ECDSA_CHAIN_TARGET,
            clientBootstrap: validNormalizedEcdsaClientBootstrap(),
          },
        ],
      },
    });
    expect((response.body as any).ecdsa.bootstraps[0].bootstrap.jwt).toBe(
      `signed:${ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND}:session-1`,
    );
    expect(signedClaims.claims).toMatchObject({
      kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
      routerAbEcdsaDerivationNormalSigning: {
        kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
        scope: {
          wallet_key_id: ECDSA_SIGNING_KEY_SLOT_ID,
          wallet_id: 'wallet_alice',
          ecdsa_threshold_key_id: 'ederivation-alice',
          signing_root_id: 'project:dev',
          signing_root_version: 'default',
          context: {
            application_binding_digest_b64u: b64u(Array(32).fill(9)),
          },
          signing_worker: {
            server_id: 'router-ab-signing-worker-local',
            key_epoch: 'epoch-server',
          },
          activation_epoch: 'session-1',
        },
      },
    });
    expect(signedClaims.claims?.routerAbEcdsaDerivationIssuerBinding).toBeUndefined();
  });

  test('finalize forwards normalized ECDSA expected key handles', async () => {
    let captured: unknown = null;
    const response = await handleRouterApiWalletRegistrationFinalize(
      inputFor(
        'wallet_registration_finalize',
        {
          registrationCeremonyId: ' wrc_123 ',
          kind: 'evm_family_ecdsa',
          ecdsa: {
            expectedKeyHandles: [' ederivation-key-alice ', 'ederivation-key-bob'],
          },
        },
        {
          finalizeWalletRegistration: async (request: unknown) => {
            captured = request;
            return {
              ok: true,
              walletId: 'wallet_alice',
              rpId: 'wallet.example.test',
              kind: 'evm_family_ecdsa',
              ecdsa: { walletKeys: [] },
            };
          },
        },
      ),
    );

    expect(response.status).toBe(200);
    expect(captured).toEqual({
      registrationCeremonyId: 'wrc_123',
      kind: 'evm_family_ecdsa',
      ecdsa: {
        expectedKeyHandles: ['ederivation-key-alice', 'ederivation-key-bob'],
      },
    });
  });

  test('finalize forwards normalized Email OTP backup acknowledgement metadata', async () => {
    let captured: unknown = null;
    const response = await handleRouterApiWalletRegistrationFinalize(
      inputFor(
        'wallet_registration_finalize',
        {
          registrationCeremonyId: ' wrc_123 ',
          kind: 'evm_family_ecdsa',
          ecdsa: {
            expectedKeyHandles: ['ederivation-key-alice'],
          },
          emailOtpBackupAck: {
            kind: 'email_otp_recovery_code_backup_ack_v1',
            offerId: ' offer-1 ',
            candidateId: ' candidate-1 ',
            recoveryCodesIssuedAtMs: 1_700_000_000_000,
            backupActionKind: 'manual',
            acknowledgedAtMs: 1_700_000_000_001,
            idempotencyKey: ' backup-ack-idempotency-1 ',
          },
        },
        {
          finalizeWalletRegistration: async (request: unknown) => {
            captured = request;
            return {
              ok: true,
              walletId: 'wallet_alice',
              rpId: 'wallet.example.test',
              kind: 'evm_family_ecdsa',
              ecdsa: { walletKeys: [] },
            };
          },
        },
      ),
    );

    expect(response.status).toBe(200);
    expect(captured).toMatchObject({
      registrationCeremonyId: 'wrc_123',
      kind: 'evm_family_ecdsa',
      emailOtpBackupAck: {
        kind: 'email_otp_recovery_code_backup_ack_v1',
        offerId: 'offer-1',
        candidateId: 'candidate-1',
        recoveryCodesIssuedAtMs: 1_700_000_000_000,
        backupActionKind: 'manual',
        acknowledgedAtMs: 1_700_000_000_001,
        idempotencyKey: 'backup-ack-idempotency-1',
      },
    });
  });

  test('finalize rejects secret material in Email OTP backup acknowledgement', async () => {
    let called = false;
    const response = await handleRouterApiWalletRegistrationFinalize(
      inputFor(
        'wallet_registration_finalize',
        {
          registrationCeremonyId: 'wrc_123',
          kind: 'evm_family_ecdsa',
          ecdsa: {
            expectedKeyHandles: ['ederivation-key-alice'],
          },
          emailOtpBackupAck: {
            kind: 'email_otp_recovery_code_backup_ack_v1',
            recoveryCodesIssuedAtMs: 1_700_000_000_000,
            backupActionKind: 'manual',
            acknowledgedAtMs: 1_700_000_000_001,
            idempotencyKey: 'backup-ack-idempotency-1',
            recoveryKeys: ['secret-code'],
          },
        },
        {
          finalizeWalletRegistration: async () => {
            called = true;
            return { ok: true };
          },
        },
      ),
    );

    expect(called).toBe(false);
    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'emailOtpBackupAck.recoveryKeys must not be included',
    });
  });

  test('finalize rejects OTP challenge fields at the top level', async () => {
    let called = false;
    const response = await handleRouterApiWalletRegistrationFinalize(
      inputFor(
        'wallet_registration_finalize',
        {
          registrationCeremonyId: 'wrc_123',
          kind: 'evm_family_ecdsa',
          ecdsa: {
            expectedKeyHandles: ['ederivation-key-alice'],
          },
          challengeId: 'otp-challenge-1',
        },
        {
          finalizeWalletRegistration: async () => {
            called = true;
            return { ok: true };
          },
        },
      ),
    );

    expect(called).toBe(false);
    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'challengeId must not be included in wallet registration finalize',
    });
  });

  test('finalize rejects OTP challenge fields inside Email OTP enrollment', async () => {
    let called = false;
    const response = await handleRouterApiWalletRegistrationFinalize(
      inputFor(
        'wallet_registration_finalize',
        {
          registrationCeremonyId: 'wrc_123',
          kind: 'evm_family_ecdsa',
          ecdsa: {
            expectedKeyHandles: ['ederivation-key-alice'],
          },
          emailOtpEnrollment: {
            recoveryWrappedEnrollmentEscrows: [{ enrollmentId: 'enrollment-1' }],
            enrollmentSealKeyVersion: 'email-otp-v1',
            clientUnlockPublicKeyB64u: 'client-unlock-public-key',
            unlockKeyVersion: 'unlock-v1',
            thresholdEcdsaClientVerifyingShareB64u: 'threshold-ecdsa-share',
            challengeId: 'otp-challenge-1',
          },
        },
        {
          finalizeWalletRegistration: async () => {
            called = true;
            return { ok: true };
          },
        },
      ),
    );

    expect(called).toBe(false);
    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'emailOtpEnrollment.challengeId must not be included',
    });
  });

  test('finalize rejects invalid ECDSA expected key handles', async () => {
    let called = false;
    const response = await handleRouterApiWalletRegistrationFinalize(
      inputFor(
        'wallet_registration_finalize',
        {
          registrationCeremonyId: 'wrc_123',
          kind: 'evm_family_ecdsa',
          ecdsa: {
            expectedKeyHandles: ['ederivation-key-alice', ' '],
          },
        },
        {
          finalizeWalletRegistration: async () => {
            called = true;
            return { ok: true };
          },
        },
      ),
    );

    expect(called).toBe(false);
    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'ecdsa.expectedKeyHandles contains an invalid key handle',
    });
  });

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
      walletId: 'wallet_alice',
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

  test('add-signer start requires app-session signer-provisioning policy', async () => {
    const intent = ecdsaAddSignerIntent();
    const digest = await computeAddSignerIntentDigestB64u(intent);
    let serviceRequest: unknown = null;
    const response = await handleRouterApiWalletAddSignerStart(
      addSignerInputFor({
        routeId: 'wallet_add_signer_start',
        body: {
          intent,
          addSignerIntentGrant: 'wasig_test',
          addSignerIntentDigestB64u: digest,
          auth: {
            kind: 'app_session',
            policy: {
              permission: 'wallet_signer_provision',
              walletId: 'wallet_alice',
              signerSelection: intent.signerSelection,
              expiresAtMs: Date.now() + 60_000,
            },
          },
        },
        authService: {
          validateAppSessionVersion: async (request: unknown) => {
            expect(request).toEqual({
              userId: 'app-user-1',
              appSessionVersion: 'asv-1',
            });
            return { ok: true };
          },
          startWalletAddSigner: async (request: unknown) => {
            serviceRequest = request;
            return {
              ok: true,
              addSignerCeremonyId: 'wasc_1',
              intent,
              kind: 'evm_family_ecdsa',
              ecdsa: { kind: 'evm_family_ecdsa_keygen', targets: [] },
            };
          },
        },
        session: {
          parse: async () => ({
            ok: true,
            claims: {
              kind: 'app_session_v1',
              sub: 'app-user-1',
              appSessionVersion: 'asv-1',
              exp: Math.floor(Date.now() / 1000) + 60,
            },
          }),
        },
      }),
    );

    expect(response.status).toBe(200);
    expect(serviceRequest).toMatchObject({
      walletId: 'wallet_alice',
      auth: {
        kind: 'app_session',
        policy: {
          permission: 'wallet_signer_provision',
          walletId: 'wallet_alice',
          signerSelection: intent.signerSelection,
        },
      },
    });
  });

  test('add-signer DERIVATION respond and finalize normalize ECDSA payloads', async () => {
    let respondRequest: unknown = null;
    let finalizeRequest: unknown = null;
    const respond = await handleRouterApiWalletAddSignerDerivationRespond(
      addSignerInputFor({
        routeId: 'wallet_add_signer_derivation_respond',
        body: {
          addSignerCeremonyId: ' wasc_1 ',
          ecdsa: {
            clientBootstraps: [
              {
                chainTarget: ECDSA_CHAIN_TARGET,
                clientBootstrap: validEcdsaClientBootstrap(),
              },
            ],
          },
        },
        authService: {
          respondWalletAddSignerDerivation: async (request: unknown) => {
            respondRequest = request;
            return {
              ok: true,
              addSignerCeremonyId: 'wasc_1',
              ecdsa: { bootstraps: [] },
            };
          },
        },
      }),
    );
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

    expect(respond.status).toBe(200);
    expect(finalize.status).toBe(200);
    expect(respondRequest).toEqual({
      addSignerCeremonyId: 'wasc_1',
      ecdsa: {
        clientBootstraps: [
          {
            chainTarget: ECDSA_CHAIN_TARGET,
            clientBootstrap: validNormalizedEcdsaClientBootstrap(),
          },
        ],
      },
    });
    expect(finalizeRequest).toEqual({
      addSignerCeremonyId: 'wasc_1',
      idempotencyKey: 'add-signer-finalize-1',
      kind: 'evm_family_ecdsa',
      ecdsa: {
        expectedKeyHandles: ['key-handle-1'],
      },
    });
  });

  test('add-signer finalize forwards the exact Ed25519 Yao activation reference', async () => {
    const sessionId = new Array<number>(32).fill(7);
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
              endpoint: 'POST /wallets/:walletId/auth-methods/intent',
              requiredScopes: ['wallets.auth_methods.create'],
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
      request: {
        walletId: 'wallet_alice',
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

  test('add-auth-method start rejects threshold-session auth before service dispatch', async () => {
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
          webauthnRegistration: { id: 'credential' },
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
      message: 'add-auth-method auth.kind is unsupported',
    });
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
          webauthnRegistration: {
            id: 'new-passkey-registration',
            response: { clientDataJSON: 'client-data' },
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
      walletId: 'wallet_alice',
      addAuthMethodIntentDigestB64u: digest,
      intent: {
        authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
      },
      authority: {
        kind: 'passkey',
        webauthnRegistration: {
          id: 'new-passkey-registration',
          response: { clientDataJSON: 'client-data' },
        },
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
            kind: 'app_session',
            policy: {
              permission: 'wallet_auth_method_provision',
              walletId: 'wallet_alice',
              authMethod: intent.authMethod,
              expiresAtMs: Date.now() + 60_000,
            },
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
            appSessionVersion: 'v1',
          },
        },
        session: {
          parse: async () => ({
            ok: true,
            claims: {
              kind: 'app_session_v1',
              sub: 'user_1',
              appSessionVersion: 'v1',
              exp: Math.floor(Date.now() / 1000) + 60,
            },
          }),
        },
        authService: {
          validateAppSessionVersion: async () => ({ ok: true }),
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
      walletId: 'wallet_alice',
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

  test('add-auth-method start rejects mismatched authority branch', async () => {
    const intent = addAuthMethodIntent('email_otp');
    const digest = await computeAddAuthMethodIntentDigestB64u(intent);
    const response = await handleRouterApiWalletAddAuthMethodStart(
      addAuthMethodInputFor({
        routeId: 'wallet_add_auth_method_start',
        body: {
          intent,
          addAuthMethodIntentGrant: 'waig_1',
          addAuthMethodIntentDigestB64u: digest,
          auth: {
            kind: 'app_session',
            policy: {
              permission: 'wallet_auth_method_provision',
              walletId: 'wallet_alice',
              authMethod: intent.authMethod,
              expiresAtMs: Date.now() + 60_000,
            },
          },
          webauthnRegistration: { id: 'new-passkey-registration' },
        },
        session: {
          parse: async () => ({
            ok: true,
            claims: {
              kind: 'app_session_v1',
              sub: 'user_1',
              appSessionVersion: 'v1',
              exp: Math.floor(Date.now() / 1000) + 60,
            },
          }),
        },
        authService: {
          validateAppSessionVersion: async () => ({ ok: true }),
          startWalletAddAuthMethod: async () => {
            throw new Error('service should not be called');
          },
        },
      }),
    );

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'new auth-method authority kind must match the requested auth-method kind',
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
      addAuthMethodCeremonyId: 'waac_1',
    });
  });

  test('auth-method revoke validates app-session policy target and forwards request', async () => {
    let revokeRequest: unknown = null;
    const response = await handleRouterApiWalletRevokeAuthMethod(
      addAuthMethodInputFor({
        routeId: 'wallet_revoke_auth_method',
        body: {
          target: {
            kind: 'email_otp',
            email: 'Alice@Example.test',
          },
          auth: {
            kind: 'app_session',
            policy: {
              permission: 'wallet_auth_method_revoke',
              walletId: 'wallet_alice',
              target: {
                kind: 'email_otp',
                email: 'alice@example.test',
              },
              expiresAtMs: Date.now() + 60_000,
            },
          },
        },
        session: {
          parse: async () => ({
            ok: true,
            claims: {
              kind: 'app_session_v1',
              sub: 'user_1',
              appSessionVersion: 'v1',
              exp: Math.floor(Date.now() / 1000) + 60,
            },
          }),
        },
        authService: {
          validateAppSessionVersion: async () => ({ ok: true }),
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
    expect(revokeRequest).toEqual({
      walletId: 'wallet_alice',
      auth: {
        kind: 'app_session',
        policy: {
          permission: 'wallet_auth_method_revoke',
          walletId: 'wallet_alice',
          target: {
            kind: 'email_otp',
            email: 'alice@example.test',
          },
          expiresAtMs: expect.any(Number),
        },
      },
      target: {
        kind: 'email_otp',
        email: 'alice@example.test',
      },
    });
  });

  test('ECDSA key-facts inventory accepts app-session inventory policy', async () => {
    let captured: unknown = null;
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
            kind: 'app_session',
            policy: {
              permission: 'ecdsa_key_facts_inventory',
              walletId: 'wallet_alice',
              chainTargets: [{ kind: 'tempo', chainId: 42431 }],
              expiresAtMs: Date.now() + 60_000,
            },
          },
        },
        authService: {
          validateAppSessionVersion: async (request: unknown) => {
            expect(request).toEqual({
              userId: 'app-user-1',
              appSessionVersion: 'asv-1',
            });
            return { ok: true };
          },
          listWalletEcdsaKeyFactsInventory: async (request: unknown) => {
            captured = request;
            return {
              records: [
                {
                  keyHandle: 'ederivation-key-alice',
                  ecdsaThresholdKeyId: 'ederivation-alice',
                  chainTarget: { kind: 'tempo', chainId: 42431 },
                  targetKey: 'tempo:42431',
                  accountAddress: '0x1111111111111111111111111111111111111111',
                  ownerAddress: '0x1111111111111111111111111111111111111111',
                  relayerKeyId: 'rk-1',
                  thresholdEcdsaPublicKeyB64u: 'group-public-key',
                  key: {
                    walletId: 'wallet_alice',
                    subjectId: 'wallet_alice',
                    rpId: 'wallet.example.test',
                    keyScope: 'evm-family',
                    ecdsaThresholdKeyId: 'ederivation-alice',
                    signingRootId: 'project:dev',
                    signingRootVersion: 'default',
                    participantIds: [1, 2],
                    thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
                  },
                },
              ],
              diagnostics: {
                userId: 'wallet_alice',
                inputCount: 1,
                returnedCount: 1,
                ecdsaBootstrapExportRuntimePresent: true,
                rejected: {},
              },
            };
          },
        },
        session: {
          parse: async () => ({
            ok: true,
            claims: {
              kind: 'app_session_v1',
              sub: 'app-user-1',
              appSessionVersion: 'asv-1',
              exp: Math.floor(Date.now() / 1000) + 60,
            },
          }),
        },
      }),
    );

    expect(response.status).toBe(200);
    expect(captured).toEqual({
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
      keyTargets: [
        {
          keyHandle: 'ederivation-key-alice',
          chainTarget: { kind: 'tempo', chainId: 42431 },
        },
      ],
    });
    expect(response.body).toMatchObject({
      ok: true,
      ecdsaKeyIdentityTargets: [
        {
          keyHandle: 'ederivation-key-alice',
          targetKey: 'tempo:42431',
        },
      ],
    });
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
});
