import { expect, test } from '@playwright/test';
import {
  handleRelayWalletAddAuthMethodFinalize,
  handleRelayWalletAddAuthMethodIntent,
  handleRelayWalletRevokeAuthMethod,
  handleRelayWalletAddAuthMethodStart,
  handleRelayWalletAddSignerFinalize,
  handleRelayWalletAddSignerHssRespond,
  handleRelayWalletAddSignerIntent,
  handleRelayWalletAddSignerStart,
  handleRelayWalletRegistrationIntent,
  handleRelayWalletRegistrationStart,
  handleRelayWalletRegistrationFinalize,
  handleRelayWalletRegistrationHssRespond,
  handleRelayWalletEcdsaKeyFactsInventory,
} from '../../server/src/router/relayWalletRegistration';
import {
  createRelayRouteDefinitions,
  findRouteDefinitionById,
  type RouteDefinition,
} from '../../server/src/router/routeDefinitions';
import { computeWalletEcdsaKeyFactsInventoryChallengeDigestB64u } from '../../shared/src/utils/ecdsaKeyFactsInventory';
import {
  computeAddAuthMethodIntentDigestB64u,
  computeAddSignerIntentDigestB64u,
  computeRegistrationIntentDigestB64u,
  type AddAuthMethodIntentV1,
  type RegistrationIntentV1,
  walletIdFromString,
  type AddSignerIntentV1,
} from '../../shared/src/utils/registrationIntent';

const routeDefinitions = createRelayRouteDefinitions({
  enableHealthz: true,
  enableSigningSessionSeal: true,
  enableReadyz: true,
});

const ED25519_HSS_RESPOND_FORBIDDEN_FIELDS = [
  'evaluatorOtStateB64u',
  'yClientB64u',
  'tauClientB64u',
  'rClientB64u',
  'clientOutputMaskB64u',
  'prfFirstB64u',
  'prfOutputB64u',
  'clientSecretB64u',
  'clientSecret32B64u',
  'yRelayerB64u',
  'tauRelayerB64u',
] as const;

const ED25519_HSS_FINALIZE_FORBIDDEN_FIELDS = [
  'stagedEvaluatorArtifactHandle',
  'evaluatorOtStateB64u',
  'xClientBaseB64u',
  'xRelayerBaseB64u',
  'yClientB64u',
  'tauClientB64u',
  'yRelayerB64u',
  'tauRelayerB64u',
  'rClientB64u',
  'clientOutputMaskB64u',
  'prfFirstB64u',
  'prfOutputB64u',
  'clientSecretB64u',
  'clientSecret32B64u',
  'seedOutputMessageB64u',
] as const;

const ECDSA_REGISTRATION_HSS_RESPOND_FORBIDDEN_FIELDS = [
  'clientRootProof',
  'passkeyBootstrapAuthorization',
  'sessionKind',
] as const;

function route(id: string): RouteDefinition {
  const found = findRouteDefinitionById(routeDefinitions, id);
  if (!found) throw new Error(`missing route ${id}`);
  return found;
}

function inputFor(
  routeId:
    | 'wallet_registration_start'
    | 'wallet_registration_hss_respond'
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
    services: { authService, ...(session ? { session } : {}) },
  } as unknown as Parameters<typeof handleRelayWalletRegistrationStart>[0];
}

function ecdsaInventoryInputFor(args: {
  body: unknown;
  authService: Record<string, unknown>;
  session: Record<string, unknown>;
  walletId?: string;
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
    pathParams: { walletId: args.walletId || 'wallet_alice' },
    route: route('wallet_ecdsa_key_facts_inventory'),
    services: {
      authService: args.authService,
      session: args.session,
    },
  } as unknown as Parameters<typeof handleRelayWalletEcdsaKeyFactsInventory>[0];
}

function addSignerInputFor(args: {
  routeId:
    | 'wallet_add_signer_intent'
    | 'wallet_add_signer_start'
    | 'wallet_add_signer_hss_respond'
    | 'wallet_add_signer_finalize';
  body: unknown;
  authService: Record<string, unknown>;
  session?: Record<string, unknown>;
  walletId?: string;
  headers?: Record<string, string>;
  origin?: string;
  apiKeyAuth?: Record<string, unknown>;
  orgProjectEnv?: Record<string, unknown>;
  bootstrapTokenStore?: Record<string, unknown>;
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
    origin: args.origin,
    pathParams: { walletId: args.walletId || 'wallet_alice' },
    route: route(args.routeId),
    services: {
      authService: args.authService,
      session: args.session || {},
      apiKeyAuth: args.apiKeyAuth,
      orgProjectEnv: args.orgProjectEnv,
      bootstrapTokenStore: args.bootstrapTokenStore,
    },
  } as unknown as Parameters<typeof handleRelayWalletAddSignerStart>[0];
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
  bootstrapTokenStore?: Record<string, unknown>;
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
    origin: args.origin,
    pathParams: { walletId: args.walletId || 'wallet_alice' },
    route: route(args.routeId),
    services: {
      authService: args.authService,
      session: args.session || {},
      apiKeyAuth: args.apiKeyAuth,
      orgProjectEnv: args.orgProjectEnv,
      bootstrapTokenStore: args.bootstrapTokenStore,
    },
  } as unknown as Parameters<typeof handleRelayWalletAddAuthMethodStart>[0];
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

function validEcdsaClientBootstrap() {
  return {
    formatVersion: 'ecdsa-hss-role-local',
    walletId: 'wallet_alice',
    rpId: 'wallet.example.test',
    ecdsaThresholdKeyId: 'ehss-alice',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
    keyScope: 'evm-family',
    relayerKeyId: 'ehss-relayer-alice',
    hssClientSharePublicKey33B64u: b64u([2, ...Array(32).fill(1)]),
    clientShareRetryCounter: 0,
    contextBinding32B64u: b64u(Array(32).fill(2)),
    requestId: 'request-1',
    sessionId: 'session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
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

function validEcdsaServerBootstrap() {
  return {
    formatVersion: 'ecdsa-hss-role-local',
    walletId: 'wallet_alice',
    rpId: 'wallet.example.test',
    ecdsaThresholdKeyId: 'ehss-alice',
    relayerKeyId: 'ehss-relayer-alice',
    contextBinding32B64u: b64u(Array(32).fill(2)),
    publicIdentity: {
      hssClientSharePublicKey33B64u: b64u([2, ...Array(32).fill(1)]),
      relayerPublicKey33B64u: b64u([3, ...Array(32).fill(6)]),
      groupPublicKey33B64u: b64u([2, ...Array(32).fill(5)]),
      ethereumAddress: '0x1111111111111111111111111111111111111111',
    },
    publicTranscriptDigest32B64u: b64u(Array(32).fill(4)),
    keyHandle: 'ehss-key-alice',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
    thresholdEcdsaPublicKeyB64u: b64u([2, ...Array(32).fill(5)]),
    ethereumAddress: '0x1111111111111111111111111111111111111111',
    relayerVerifyingShareB64u: b64u([3, ...Array(32).fill(6)]),
    participantIds: [1, 2],
    sessionId: 'session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
    expiresAtMs: Date.now() + 300_000,
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
    remainingUses: 1,
  };
}

function signingSession() {
  return {
    signJwt: async (sub: string, claims: Record<string, unknown>) =>
      `signed:${sub}:${String(claims.kind || '')}:${String(claims.sessionId || '')}`,
  };
}

function ecdsaAddSignerIntent(): AddSignerIntentV1 {
  return {
    version: 'add_signer_intent_v1',
    walletId: walletIdFromString('wallet_alice'),
    rpId: 'wallet.example.test',
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
    rpId: 'wallet.example.test',
    signerSelection: {
      mode: 'ed25519',
      ed25519: {
        mode: 'create_near_account',
        nearAccountId: 'alice.testnet',
        signerSlot: 2,
        participantIds: [1, 2],
        keyPurpose: 'near_tx',
        keyVersion: 'threshold-ed25519-hss-v1',
        derivationVersion: 1,
      },
    },
    nonceB64u: 'add-signer-nonce',
  };
}

function addAuthMethodIntent(kind: 'passkey' | 'email_otp' = 'passkey'): AddAuthMethodIntentV1 {
  return {
    version: 'add_auth_method_intent_v1',
    walletId: walletIdFromString('wallet_alice'),
    rpId: 'wallet.example.test',
    authMethod:
      kind === 'passkey'
        ? { kind: 'passkey' }
        : {
            kind: 'email_otp',
            email: 'alice@example.test',
          },
    nonceB64u: 'add-auth-method-nonce',
  };
}

function registrationIntent(kind: 'passkey' | 'email_otp' = 'passkey'): RegistrationIntentV1 {
  return {
    version: 'registration_intent_v1',
    walletId: walletIdFromString('wallet_alice'),
    rpId: 'wallet.example.test',
    authMethod:
      kind === 'passkey'
        ? { kind: 'passkey' }
        : {
            kind: 'email_otp',
            proofKind: 'otp_challenge',
            email: 'alice@example.test',
            otpCode: '123456',
            appSessionJwt: 'app-session.jwt',
          },
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
    nonceB64u: 'registration-nonce',
  };
}

test.describe('wallet registration route boundaries', () => {
  test('registration intent rejects branch-mixed authMethod before service dispatch', async () => {
    let called = false;
    const response = await handleRelayWalletRegistrationIntent({
      body: {
        wallet: { kind: 'server_generated' },
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
    } as unknown as Parameters<typeof handleRelayWalletRegistrationIntent>[0]);

    expect(called).toBe(false);
    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'authMethod is invalid',
    });
  });

  test('registration start rejects fresh-registration threshold-session branches before service dispatch', async () => {
    const intent = registrationIntent();
    const digest = await computeRegistrationIntentDigestB64u(intent);
    let called = false;
    const response = await handleRelayWalletRegistrationStart(
      inputFor(
        'wallet_registration_start',
        {
          registrationIntentGrant: 'rig_1',
          registrationIntentDigestB64u: digest,
          intent,
          webauthn_registration: {
            response: { clientDataJSON: 'client-data' },
          },
          threshold_ed25519: {
            session_policy: { kind: 'legacy-threshold-session' },
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
      message: 'fresh wallet registration does not accept session or legacy auth branches',
    });
  });

  test('registration start forwards a normalized Email OTP authority request', async () => {
    const intent = registrationIntent('email_otp');
    const digest = await computeRegistrationIntentDigestB64u(intent);
    let request: unknown = null;
    const response = await handleRelayWalletRegistrationStart(
      inputFor(
        'wallet_registration_start',
        {
          registrationIntentGrant: 'rig_1',
          registrationIntentDigestB64u: digest,
          intent,
          emailOtpRegistrationProof: {
            version: 'email_otp_registration_proof_v1',
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

  for (const forbiddenField of ED25519_HSS_RESPOND_FORBIDDEN_FIELDS) {
    test(`respond rejects Ed25519 HSS client-retained field ${forbiddenField}`, async () => {
      let called = false;
      const response = await handleRelayWalletRegistrationHssRespond(
        inputFor(
          'wallet_registration_hss_respond',
          {
            registrationCeremonyId: ' wrc_123 ',
            ed25519: {
              clientRequest: {
                clientRequestMessageB64u: 'client-request',
                [forbiddenField]: 'client-owned',
              },
            },
          },
          {
            respondWalletRegistrationHss: async () => {
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
        message: `ed25519.clientRequest.${forbiddenField} must stay outside the server-visible request`,
      });
    });
  }

  for (const forbiddenField of ED25519_HSS_FINALIZE_FORBIDDEN_FIELDS) {
    test(`finalize rejects Ed25519 HSS client-owned field ${forbiddenField}`, async () => {
      let called = false;
      const response = await handleRelayWalletRegistrationFinalize(
        inputFor(
          'wallet_registration_finalize',
          {
            registrationCeremonyId: 'wrc_123',
            ed25519: {
              evaluationResult: {
                contextBindingB64u: 'context',
                stagedEvaluatorArtifactB64u: 'artifact',
                [forbiddenField]: 'client-owned',
              },
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
        message: `ed25519.evaluationResult.${forbiddenField} must stay outside the client-owned staged artifact`,
      });
    });
  }

  test('respond forwards only the normalized server-visible client request', async () => {
    let captured: unknown = null;
    const response = await handleRelayWalletRegistrationHssRespond(
      inputFor(
        'wallet_registration_hss_respond',
        {
          registrationCeremonyId: ' wrc_123 ',
          ed25519: {
            clientRequest: {
              clientRequestMessageB64u: ' client-request ',
            },
          },
        },
        {
          respondWalletRegistrationHss: async (request: unknown) => {
            captured = request;
            return {
              ok: true,
              registrationCeremonyId: 'wrc_123',
              ed25519: {
                contextBindingB64u: 'context',
                serverInputDeliveryB64u: 'delivery',
              },
            };
          },
        },
      ),
    );

    expect(response.status).toBe(200);
    expect(captured).toEqual({
      registrationCeremonyId: 'wrc_123',
      ed25519: {
        clientRequest: {
          clientRequestMessageB64u: 'client-request',
        },
      },
    });
  });

  for (const forbiddenField of ECDSA_REGISTRATION_HSS_RESPOND_FORBIDDEN_FIELDS) {
    test(`respond rejects ECDSA registration field ${forbiddenField}`, async () => {
      let called = false;
      const response = await handleRelayWalletRegistrationHssRespond(
        inputFor(
          'wallet_registration_hss_respond',
          {
            registrationCeremonyId: 'wrc_123',
            ecdsa: {
              clientBootstrap: {
                ...validEcdsaClientBootstrap(),
                [forbiddenField]: 'server-auth-owned',
              },
            },
          },
          {
            respondWalletRegistrationHss: async () => {
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
        message: `ecdsa.clientBootstrap.${forbiddenField} must stay outside the registration ceremony request`,
      });
    });
  }

  test('respond forwards normalized ECDSA registration client bootstrap', async () => {
    let captured: unknown = null;
    const clientBootstrap = validEcdsaClientBootstrap();
    const response = await handleRelayWalletRegistrationHssRespond(
      inputFor(
        'wallet_registration_hss_respond',
        {
          registrationCeremonyId: ' wrc_123 ',
          ecdsa: {
            clientBootstrap,
          },
        },
        {
          respondWalletRegistrationHss: async (request: unknown) => {
            captured = request;
            return {
              ok: true,
              registrationCeremonyId: 'wrc_123',
              ecdsa: {
                bootstrap: validEcdsaServerBootstrap(),
              },
            };
          },
        },
        signingSession(),
      ),
    );

    expect(response.status).toBe(200);
    expect(captured).toEqual({
      registrationCeremonyId: 'wrc_123',
      ecdsa: {
        clientBootstrap,
      },
    });
    expect((response.body as any).ecdsa.bootstrap.jwt).toBe(
      'signed:wallet_alice:threshold_ecdsa_session_v2:session-1',
    );
  });

  test('finalize signs returned Ed25519 threshold session JWT', async () => {
    const response = await handleRelayWalletRegistrationFinalize(
      inputFor(
        'wallet_registration_finalize',
        {
          registrationCeremonyId: ' wrc_123 ',
          ed25519: {
            evaluationResult: {
              contextBindingB64u: 'context',
              stagedEvaluatorArtifactB64u: 'artifact',
            },
            sessionPolicy: {
              version: 'threshold_session_v1',
              sessionId: 'ed-session-1',
            },
            sessionKind: 'jwt',
          },
        },
        {
          finalizeWalletRegistration: async () => ({
            ok: true,
            walletId: 'wallet_alice',
            rpId: 'wallet.example.test',
            ed25519: {
              nearAccountId: 'alice.testnet',
              publicKey: 'ed25519:public',
              relayerKeyId: 'ed-relayer-key',
              keyVersion: 'threshold-ed25519-hss-v1',
              recoveryExportCapable: true,
              participantIds: [1, 2],
              session: {
                sessionKind: 'jwt',
                sessionId: 'ed-session-1',
                walletSigningSessionId: 'ed-wallet-session-1',
                expiresAtMs: Date.now() + 300_000,
                participantIds: [1, 2],
                remainingUses: 1,
              },
            },
          }),
        },
        signingSession(),
      ),
    );

    expect(response.status).toBe(200);
    expect((response.body as any).ed25519.session.jwt).toBe(
      'signed:alice.testnet:threshold_ed25519_session_v1:ed-session-1',
    );
  });

  test('finalize forwards normalized ECDSA expected key handles', async () => {
    let captured: unknown = null;
    const response = await handleRelayWalletRegistrationFinalize(
      inputFor(
        'wallet_registration_finalize',
        {
          registrationCeremonyId: ' wrc_123 ',
          ecdsa: {
            expectedKeyHandles: [' ehss-key-alice ', 'ehss-key-bob'],
          },
        },
        {
          finalizeWalletRegistration: async (request: unknown) => {
            captured = request;
            return {
              ok: true,
              walletId: 'wallet_alice',
              rpId: 'wallet.example.test',
              ecdsa: { walletKeys: [] },
            };
          },
        },
      ),
    );

    expect(response.status).toBe(200);
    expect(captured).toEqual({
      registrationCeremonyId: 'wrc_123',
      ecdsa: {
        expectedKeyHandles: ['ehss-key-alice', 'ehss-key-bob'],
      },
    });
  });

  test('finalize forwards normalized Email OTP backup acknowledgement metadata', async () => {
    let captured: unknown = null;
    const response = await handleRelayWalletRegistrationFinalize(
      inputFor(
        'wallet_registration_finalize',
        {
          registrationCeremonyId: ' wrc_123 ',
          ecdsa: {
            expectedKeyHandles: ['ehss-key-alice'],
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
              ecdsa: { walletKeys: [] },
            };
          },
        },
      ),
    );

    expect(response.status).toBe(200);
    expect(captured).toMatchObject({
      registrationCeremonyId: 'wrc_123',
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
    const response = await handleRelayWalletRegistrationFinalize(
      inputFor(
        'wallet_registration_finalize',
        {
          registrationCeremonyId: 'wrc_123',
          ecdsa: {
            expectedKeyHandles: ['ehss-key-alice'],
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
    const response = await handleRelayWalletRegistrationFinalize(
      inputFor(
        'wallet_registration_finalize',
        {
          registrationCeremonyId: 'wrc_123',
          ecdsa: {
            expectedKeyHandles: ['ehss-key-alice'],
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
    const response = await handleRelayWalletRegistrationFinalize(
      inputFor(
        'wallet_registration_finalize',
        {
          registrationCeremonyId: 'wrc_123',
          ecdsa: {
            expectedKeyHandles: ['ehss-key-alice'],
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
    const response = await handleRelayWalletRegistrationFinalize(
      inputFor(
        'wallet_registration_finalize',
        {
          registrationCeremonyId: 'wrc_123',
          ecdsa: {
            expectedKeyHandles: ['ehss-key-alice', ' '],
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
    const response = await handleRelayWalletAddSignerStart(
      addSignerInputFor({
        routeId: 'wallet_add_signer_start',
        body: {
          intent,
          addSignerIntentGrant: 'wasig_test',
          addSignerIntentDigestB64u: digest,
          auth: {
            kind: 'threshold_session',
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
    const response = await handleRelayWalletAddSignerStart(
      addSignerInputFor({
        routeId: 'wallet_add_signer_start',
        body: {
          intent,
          addSignerIntentGrant: 'wasig_test',
          addSignerIntentDigestB64u: digest,
          auth: {
            kind: 'webauthn_assertion',
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
      nearAccountId: 'wallet_alice',
      rpId: 'wallet.example.test',
      expectedChallenge: digest,
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
    const response = await handleRelayWalletAddSignerStart(
      addSignerInputFor({
        routeId: 'wallet_add_signer_start',
        body: {
          intent,
          addSignerIntentGrant: 'wasig_test',
          addSignerIntentDigestB64u: digest,
          auth: {
            kind: 'webauthn_assertion',
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
              ed25519: {
                ceremonyHandle: 'handle',
                preparedSession: {},
                clientOtOfferMessageB64u: 'client-ot-offer',
              },
            };
          },
        },
      }),
    );

    expect(response.status).toBe(200);
    expect(serviceRequest).toMatchObject({
      intent: {
        signerSelection: {
          mode: 'ed25519',
          ed25519: {
            mode: 'create_near_account',
            nearAccountId: 'alice.testnet',
            signerSlot: 2,
            participantIds: [1, 2],
            keyPurpose: 'near_tx',
            keyVersion: 'threshold-ed25519-hss-v1',
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
          mode: 'create_near_account',
          nearAccountId: 'alice.testnet',
          signerSlot: 2,
          participantIds: [1, 2],
        },
      },
    };
    const digest = await computeAddSignerIntentDigestB64u(incompleteIntent as AddSignerIntentV1);
    let called = false;
    const response = await handleRelayWalletAddSignerStart(
      addSignerInputFor({
        routeId: 'wallet_add_signer_start',
        body: {
          intent: incompleteIntent,
          addSignerIntentGrant: 'wasig_test',
          addSignerIntentDigestB64u: digest,
          auth: {
            kind: 'webauthn_assertion',
            credential: fakeWebAuthnAuthentication(),
            expectedChallengeDigestB64u: digest,
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
    const response = await handleRelayWalletAddSignerStart(
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
            return { ok: true, addSignerCeremonyId: 'wasc_1', intent };
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

  test('add-signer HSS respond and finalize normalize ECDSA payloads', async () => {
    let respondRequest: unknown = null;
    let finalizeRequest: unknown = null;
    const respond = await handleRelayWalletAddSignerHssRespond(
      addSignerInputFor({
        routeId: 'wallet_add_signer_hss_respond',
        body: {
          addSignerCeremonyId: ' wasc_1 ',
          ecdsa: {
            clientBootstrap: validEcdsaClientBootstrap(),
          },
        },
        authService: {
          respondWalletAddSignerHss: async (request: unknown) => {
            respondRequest = request;
            return { ok: true, addSignerCeremonyId: 'wasc_1' };
          },
        },
      }),
    );
    const finalize = await handleRelayWalletAddSignerFinalize(
      addSignerInputFor({
        routeId: 'wallet_add_signer_finalize',
        body: {
          addSignerCeremonyId: ' wasc_1 ',
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
        clientBootstrap: validEcdsaClientBootstrap(),
      },
    });
    expect(finalizeRequest).toEqual({
      addSignerCeremonyId: 'wasc_1',
      ecdsa: {
        expectedKeyHandles: ['key-handle-1'],
      },
    });
  });

  test('add-auth-method intent uses a dedicated scope and route family', async () => {
    let capturedRequest: unknown = null;
    const response = await handleRelayWalletAddAuthMethodIntent(
      addAuthMethodInputFor({
        routeId: 'wallet_add_auth_method_intent',
        body: {
          walletId: 'wallet_alice',
          rpId: 'wallet.example.test',
          authMethod: { kind: 'passkey' },
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
        rpId: 'wallet.example.test',
        authMethod: { kind: 'passkey' },
      },
      expectedOrigin: 'https://wallet.example.test',
    });
  });

  test('add-signer intent rejects invalid signerSelection before service dispatch', async () => {
    let called = false;
    const response = await handleRelayWalletAddSignerIntent(
      addSignerInputFor({
        routeId: 'wallet_add_signer_intent',
        body: {
          rpId: 'wallet.example.test',
          signerSelection: {
            mode: 'ed25519',
            ed25519: {
              mode: 'create_near_account',
              nearAccountId: 'alice.testnet',
              signerSlot: 1,
              participantIds: [],
              keyPurpose: 'near_tx',
              keyVersion: 'threshold-ed25519-hss-v1',
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
      }) as unknown as Parameters<typeof handleRelayWalletAddSignerIntent>[0],
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
    const response = await handleRelayWalletAddAuthMethodStart(
      addAuthMethodInputFor({
        routeId: 'wallet_add_auth_method_start',
        body: {
          intent,
          addAuthMethodIntentGrant: 'waig_1',
          addAuthMethodIntentDigestB64u: digest,
          auth: {
            kind: 'threshold_session',
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
    const response = await handleRelayWalletAddAuthMethodStart(
      addAuthMethodInputFor({
        routeId: 'wallet_add_auth_method_start',
        body: {
          intent,
          addAuthMethodIntentGrant: 'waig_1',
          addAuthMethodIntentDigestB64u: digest,
          auth: {
            kind: 'webauthn_assertion',
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
      nearAccountId: 'wallet_alice',
      rpId: 'wallet.example.test',
      expectedChallenge: digest,
      webauthn_authentication: credential,
    });
    expect(serviceRequest).toMatchObject({
      walletId: 'wallet_alice',
      addAuthMethodIntentDigestB64u: digest,
      intent: {
        authMethod: { kind: 'passkey' },
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
    const response = await handleRelayWalletAddAuthMethodStart(
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
    const response = await handleRelayWalletAddAuthMethodStart(
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
    const response = await handleRelayWalletAddAuthMethodFinalize(
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
    const response = await handleRelayWalletRevokeAuthMethod(
      addAuthMethodInputFor({
        routeId: 'wallet_revoke_auth_method',
        body: {
          rpId: 'wallet.example.test',
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
              rpId: 'wallet.example.test',
              authMethod: { kind: 'email_otp', status: 'revoked' },
            };
          },
        },
      }),
    );

    expect(response.status).toBe(200);
    expect(revokeRequest).toEqual({
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
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

  test('ECDSA key-facts inventory rejects Ed25519 threshold-session auth', async () => {
    let inventoryCalled = false;
    const response = await handleRelayWalletEcdsaKeyFactsInventory(
      ecdsaInventoryInputFor({
        body: {
          rpId: 'wallet.example.test',
          keyTargets: [
            {
              keyHandle: 'ehss-key-alice',
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
          validateAppSessionVersion: async () => ({ ok: true }),
          listWalletEcdsaKeyFactsInventory: async () => {
            inventoryCalled = true;
            return { records: [], diagnostics: {} };
          },
        },
        session: {
          parse: async () => ({
            ok: true,
            claims: {
              kind: 'threshold_ed25519_session_v1',
              sub: 'wallet_alice',
              walletId: 'wallet_alice',
              sessionId: 'ed25519-session',
              walletSigningSessionId: 'wallet-signing-session',
              relayerKeyId: 'ed25519-relayer-key',
              rpId: 'wallet.example.test',
              thresholdExpiresAtMs: Date.now() + 60_000,
              participantIds: [1, 2],
            },
          }),
        },
      }),
    );

    expect(response.status).toBe(401);
    expect(response.body).toMatchObject({
      ok: false,
      code: 'unauthorized',
      message: 'ECDSA key-facts inventory requires app-session auth',
    });
    expect(inventoryCalled).toBe(false);
  });

  test('ECDSA key-facts inventory accepts app-session inventory policy', async () => {
    let captured: unknown = null;
    const response = await handleRelayWalletEcdsaKeyFactsInventory(
      ecdsaInventoryInputFor({
        body: {
          rpId: 'wallet.example.test',
          keyTargets: [
            {
              keyHandle: 'ehss-key-alice',
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
                  keyHandle: 'ehss-key-alice',
                  ecdsaThresholdKeyId: 'ehss-alice',
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
                    ecdsaThresholdKeyId: 'ehss-alice',
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
                thresholdServicePresent: true,
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
          keyHandle: 'ehss-key-alice',
          chainTarget: { kind: 'tempo', chainId: 42431 },
        },
      ],
    });
    expect(response.body).toMatchObject({
      ok: true,
      ecdsaKeyIdentityTargets: [
        {
          keyHandle: 'ehss-key-alice',
          targetKey: 'tempo:42431',
        },
      ],
    });
  });

  test('ECDSA key-facts inventory rejects mismatched WebAuthn challenge digest', async () => {
    let verifyCalled = false;
    let inventoryCalled = false;
    const response = await handleRelayWalletEcdsaKeyFactsInventory(
      ecdsaInventoryInputFor({
        body: {
          rpId: 'wallet.example.test',
          keyTargets: [
            {
              keyHandle: 'ehss-key-alice',
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
        keyHandle: 'ehss-key-alice',
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

    const response = await handleRelayWalletEcdsaKeyFactsInventory(
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
                thresholdServicePresent: true,
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
      nearAccountId: 'wallet_alice',
      rpId: 'wallet.example.test',
      expectedChallenge,
      webauthn_authentication: credential,
    });
    expect(inventoryRequest).toEqual({
      walletId: 'wallet_alice',
      rpId: 'wallet.example.test',
      keyTargets,
    });
  });
});
