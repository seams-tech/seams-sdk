import { expect, test } from '@playwright/test';
import {
  handleRelayWalletAddSignerFinalize,
  handleRelayWalletAddSignerHssRespond,
  handleRelayWalletAddSignerStart,
  handleRelayWalletRegistrationFinalize,
  handleRelayWalletRegistrationHssRespond,
  handleRelayWalletSubjectEcdsaKeyFactsInventory,
} from '../../server/src/router/relayWalletRegistration';
import {
  createRelayRouteDefinitions,
  findRouteDefinitionById,
  type RouteDefinition,
} from '../../server/src/router/routeDefinitions';
import { computeWalletSubjectEcdsaKeyFactsInventoryChallengeDigestB64u } from '../../shared/src/utils/ecdsaKeyFactsInventory';
import {
  computeAddSignerIntentDigestB64u,
  walletSubjectIdFromString,
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
  routeId: 'wallet_registration_hss_respond' | 'wallet_registration_finalize',
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
  } as unknown as Parameters<typeof handleRelayWalletRegistrationHssRespond>[0];
}

function ecdsaInventoryInputFor(args: {
  body: unknown;
  authService: Record<string, unknown>;
  session: Record<string, unknown>;
  walletSubjectId?: string;
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
    pathParams: { walletSubjectId: args.walletSubjectId || 'wallet_subject_alice' },
    route: route('wallet_subject_ecdsa_key_facts_inventory'),
    services: {
      authService: args.authService,
      session: args.session,
    },
  } as unknown as Parameters<typeof handleRelayWalletSubjectEcdsaKeyFactsInventory>[0];
}

function addSignerInputFor(args: {
  routeId:
    | 'wallet_add_signer_start'
    | 'wallet_add_signer_hss_respond'
    | 'wallet_add_signer_finalize';
  body: unknown;
  authService: Record<string, unknown>;
  session?: Record<string, unknown>;
  walletSubjectId?: string;
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
    pathParams: { walletSubjectId: args.walletSubjectId || 'wallet_subject_alice' },
    route: route(args.routeId),
    services: {
      authService: args.authService,
      session: args.session || {},
    },
  } as unknown as Parameters<typeof handleRelayWalletAddSignerStart>[0];
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
    walletId: 'wallet_subject_alice',
    rpId: 'wallet.example.test',
    ecdsaThresholdKeyId: 'ehss-alice',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
    keyScope: 'evm-family',
    relayerKeyId: 'ehss-relayer-alice',
    clientPublicKey33B64u: b64u([2, ...Array(32).fill(1)]),
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
    walletId: 'wallet_subject_alice',
    rpId: 'wallet.example.test',
    ecdsaThresholdKeyId: 'ehss-alice',
    relayerKeyId: 'ehss-relayer-alice',
    contextBinding32B64u: b64u(Array(32).fill(2)),
    publicIdentity: {
      keyScope: 'evm-family',
      publicKey33B64u: b64u([2, ...Array(32).fill(3)]),
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
    walletSubjectId: walletSubjectIdFromString('wallet_subject_alice'),
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
    walletSubjectId: walletSubjectIdFromString('wallet_subject_alice'),
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

test.describe('wallet registration route boundaries', () => {
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
      'signed:wallet_subject_alice:threshold_ecdsa_session_v2:session-1',
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
            walletSubjectId: 'wallet_subject_alice',
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
              walletSubjectId: 'wallet_subject_alice',
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
      nearAccountId: 'wallet_subject_alice',
      rpId: 'wallet.example.test',
      expectedChallenge: digest,
      webauthn_authentication: credential,
    });
    expect(serviceRequest).toMatchObject({
      walletSubjectId: 'wallet_subject_alice',
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
              walletSubjectId: 'wallet_subject_alice',
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
      walletSubjectId: 'wallet_subject_alice',
      auth: {
        kind: 'app_session',
        policy: {
          permission: 'wallet_signer_provision',
          walletSubjectId: 'wallet_subject_alice',
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
              walletSubjectId: 'wallet_subject_alice',
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

  test('ECDSA key-facts inventory rejects Ed25519 threshold-session auth', async () => {
    let inventoryCalled = false;
    const response = await handleRelayWalletSubjectEcdsaKeyFactsInventory(
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
              walletSubjectId: 'wallet_subject_alice',
              chainTargets: [{ kind: 'tempo', chainId: 42431 }],
              expiresAtMs: Date.now() + 60_000,
            },
          },
        },
        authService: {
          validateAppSessionVersion: async () => ({ ok: true }),
          listWalletSubjectEcdsaKeyFactsInventory: async () => {
            inventoryCalled = true;
            return { records: [], diagnostics: {} };
          },
        },
        session: {
          parse: async () => ({
            ok: true,
            claims: {
              kind: 'threshold_ed25519_session_v1',
              sub: 'wallet_subject_alice',
              walletId: 'wallet_subject_alice',
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
    const response = await handleRelayWalletSubjectEcdsaKeyFactsInventory(
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
              walletSubjectId: 'wallet_subject_alice',
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
          listWalletSubjectEcdsaKeyFactsInventory: async (request: unknown) => {
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
                    walletId: 'wallet_subject_alice',
                    subjectId: 'wallet_subject_alice',
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
                userId: 'wallet_subject_alice',
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
      walletSubjectId: 'wallet_subject_alice',
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
    const response = await handleRelayWalletSubjectEcdsaKeyFactsInventory(
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
          listWalletSubjectEcdsaKeyFactsInventory: async () => {
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
    const expectedChallenge = await computeWalletSubjectEcdsaKeyFactsInventoryChallengeDigestB64u({
      walletSubjectId: 'wallet_subject_alice',
      rpId: 'wallet.example.test',
      keyTargets,
      serverNonceB64u: 'nonce-1',
    });
    const credential = fakeWebAuthnAuthentication();
    let verifyRequest: unknown = null;
    let inventoryRequest: unknown = null;

    const response = await handleRelayWalletSubjectEcdsaKeyFactsInventory(
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
          listWalletSubjectEcdsaKeyFactsInventory: async (request: unknown) => {
            inventoryRequest = request;
            return {
              records: [],
              diagnostics: {
                userId: 'wallet_subject_alice',
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
      nearAccountId: 'wallet_subject_alice',
      rpId: 'wallet.example.test',
      expectedChallenge,
      webauthn_authentication: credential,
    });
    expect(inventoryRequest).toEqual({
      walletSubjectId: 'wallet_subject_alice',
      rpId: 'wallet.example.test',
      keyTargets,
    });
  });
});
