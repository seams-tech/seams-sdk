import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import {
  buildLinkedDeviceWalletSessionAuthorizationRef,
  buildNearEd25519MpcOperationRef,
  parseAuthorizationAuditEventId,
  parseAuthorizedOperationId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseLinkedDeviceWalletSessionAuthorizationId,
  parseMpcWalletSigningQuotaId,
  parseTenantId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  buildCapabilityOperationEnvelope,
  computeCapabilityOperationFingerprintDigest,
} from '../../packages/shared-ts/src/authorization/operationFingerprint';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
} from '../../packages/shared-ts/src/utils/sessionTokens';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseWebAuthnCredentialIdB64u,
} from '../../packages/shared-ts/src/utils/domainIds';
import { computeLinkedDeviceLocalPresenceChallengeDigestV1 } from '../../packages/shared-ts/src/device-linking/digests';
import {
  handleLinkedDeviceEcdsaNormalSigning,
  handleLinkedDeviceEd25519NormalSigning,
} from '../../packages/sdk-server-ts/src/router/transport/fetch/routes/linkedDeviceNormalSigning';
import type { FetchRouterApiContext } from '../../packages/sdk-server-ts/src/router/transport/fetch/fetchRouter.types';
import type { SessionAdapter } from '../../packages/sdk-server-ts/src/router/framework/routerApi';
import { buildRouterAbEd25519NearTransactionPrepareRequestV2 } from '../../packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning';
import {
  buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
  routerAbEcdsaDerivationContextBindingB64uV1,
} from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import {
  buildAuthorizedOperation,
  buildLinkedDevicePrincipalId,
  type AuthorizedOperation,
} from '../../packages/sdk-server-ts/src/authorization/domain';
import { buildRouterAbEd25519AcceptedAuthorizedOperationV1 } from '../../packages/sdk-server-ts/src/router/domains/signingOperations/routerAbPrivateSigningWorker';

function digest(fill: number): string {
  return base64UrlEncode(new Uint8Array(32).fill(fill));
}

function hexB64u(hex: string): string {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return base64UrlEncode(bytes);
}

function linkedClaims(expiresAtMs: number): Record<string, unknown> {
  return {
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    authorizationKind: 'linked_device_wallet_session',
    sub: 'linked-device:device:2',
    walletId: 'wallet:1',
    tenantId: 'tenant:1',
    deviceId: 'device:2',
    enrollmentId: 'enrollment:2',
    walletKeyId: 'wallet-key:1',
    keyManifestDigestB64u: digest(1),
    revocationEpoch: 0,
    permission: {
      kind: 'owner_equivalent_signing',
      administrationScope: 'signing_only',
      localUserPresence: 'required',
    },
    issuedAtMs: 100,
    expiresAtMs,
    authorizationId: 'linked-device-wallet-session-authorization:1',
    walletSessionId: 'wallet-session:linked',
    quotaId: 'wallet-quota:linked',
    iat: 0,
    exp: Math.floor(expiresAtMs / 1000),
  };
}

function linkedEcdsaClaims(expiresAtMs: number): Record<string, unknown> {
  return {
    ...linkedClaims(expiresAtMs),
    kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
  };
}

function sessionWithClaims(claims: Record<string, unknown>): SessionAdapter {
  return {
    signJwt: async () => 'unused',
    verifyJwt: async () => ({ valid: false as const }),
    parse: async () => ({ ok: true as const, claims }),
    buildSetCookie: (token) => `session=${token}`,
    buildClearCookie: () => 'session=',
    refresh: async () => ({ ok: false }),
  };
}

function context(
  session: SessionAdapter,
  service: Record<string, unknown> = {},
): FetchRouterApiContext {
  const request = new Request('https://example.test/router-ab/ed25519/signing/prepare', {
    method: 'POST',
    headers: { authorization: 'Bearer linked-session' },
  });
  return {
    request,
    url: new URL(request.url),
    pathname: '/router-ab/ed25519/signing/prepare',
    method: 'POST',
    runtime: { kind: 'inline' },
    service,
    opts: { session },
    logger: {},
    mePath: '/me',
    routeDefinitions: [],
  } as unknown as FetchRouterApiContext;
}

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

async function localPresenceAssertion(input: {
  readonly authorizedOperationId?: string;
  readonly intentDigestB64u: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}) {
  const credentialIdB64u = base64UrlEncode(new TextEncoder().encode('linked-credential'));
  const challengeDigestB64u = await computeLinkedDeviceLocalPresenceChallengeDigestV1({
    authorizedOperationId: required(
      parseAuthorizedOperationId(
        input.authorizedOperationId ?? 'linked-ed25519-authorized-operation:linked-request',
      ),
    ),
    deviceId: required(parseLinkedDeviceId('device:2')),
    enrollmentId: required(parseLinkedDeviceEnrollmentId('enrollment:2')),
    credentialIdB64u: required(parseWebAuthnCredentialIdB64u(credentialIdB64u)),
    intentDigestB64u: parseDigestB64u(input.intentDigestB64u),
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
  });
  return {
    kind: 'linked_device_local_presence_assertion_v1',
    authorizedOperationId:
      input.authorizedOperationId ?? 'linked-ed25519-authorized-operation:linked-request',
    deviceId: 'device:2',
    enrollmentId: 'enrollment:2',
    credentialIdB64u,
    intentDigestB64u: input.intentDigestB64u,
    challengeDigestB64u,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
    assertion: {
      id: credentialIdB64u,
      rawId: credentialIdB64u,
      type: 'public-key',
      authenticatorAttachment: null,
      response: {
        clientDataJSON: base64UrlEncode(
          new TextEncoder().encode(
            JSON.stringify({
              challenge: challengeDigestB64u,
              origin: 'https://example.test',
              type: 'webauthn.get',
            }),
          ),
        ),
        authenticatorData: base64UrlEncode(new Uint8Array([1, 2, 3])),
        signature: base64UrlEncode(new Uint8Array([4, 5, 6])),
        userHandle: null,
      },
      clientExtensionResults: null,
    },
  };
}

async function linkedEd25519FinalizeFixture(nowMs: number) {
  const expiresAtMs = nowMs + 30_000;
  const materialActivation = {
    kind: 'mpc_material_activation_ref' as const,
    activation_id: 'activation:linked-ed25519',
    capability: 'capability:linked-ed25519',
    material_owner: 'wallet:1',
    key_binding: 'key-binding:linked-ed25519',
    lifecycle_binding: 'lifecycle:linked-ed25519',
    signing_worker: 'worker:linked-ed25519',
  };
  const scope = {
    request_id: 'linked-request',
    account_id: 'wallet:1',
    authorization: {
      kind: 'reusable_wallet_session' as const,
      wallet_session_id: 'wallet-session:linked',
    },
    material_activation: materialActivation,
    signing_worker_id: 'worker:linked-ed25519',
  };
  const prepared = await buildRouterAbEd25519NearTransactionPrepareRequestV2({
    scope,
    expiresAtMs,
    operationId: 'operation:linked-ed25519',
    operationFingerprint: `sha256:${digest(7)}`,
    displayDigestB64u: digest(8),
    nearAccountId: 'alice.testnet',
    nearNetworkId: 'testnet',
    transactions: [{ receiverId: 'receiver.testnet', actionFingerprint: 'action' }],
    unsignedTransactionBorshB64u: 'AQID',
    expectedSigningDigestB64u: 'A5BYxvLAy0ksUzsKTRTvd8wPeKvMztUofYShogEc-4E',
  });
  const intentDigestB64u = base64UrlEncode(
    Uint8Array.from(prepared.admissionMaterial.intentDigest.bytes),
  );
  const tenantId = required(parseTenantId('tenant:1'));
  const deviceId = required(parseLinkedDeviceId('device:2'));
  const operation = buildNearEd25519MpcOperationRef('near.sign_transaction');
  const envelope = buildCapabilityOperationEnvelope({
    tenantId,
    principalId: buildLinkedDevicePrincipalId(deviceId),
    capabilityId: required(parseCapabilityId(materialActivation.capability)),
    operationId: required(parseCapabilityOperationId('operation:linked-ed25519')),
    operation,
    digests: {
      laneDigest: parseDigestB64u(digest(7)),
      intentDigest: parseDigestB64u(intentDigestB64u),
      displayDigest: parseDigestB64u(digest(8)),
    },
  });
  const operationFingerprintDigest = await computeCapabilityOperationFingerprintDigest(envelope);
  const body = {
    scope,
    expires_at_ms: expiresAtMs,
    prepare_binding: {
      server_round1_handle: 'round1:linked-ed25519',
      round1_binding_digest: { bytes: Array.from(new Uint8Array(32).fill(10)) },
      intent_digest: prepared.admissionMaterial.intentDigest,
      signing_payload_digest: prepared.admissionMaterial.signingPayloadDigest,
    },
    protocol: {},
    authorized_operation: {
      kind: 'reusable_wallet_session_authorized_operation_v1',
      authorized_operation_id: 'linked-ed25519-authorized-operation:linked-request',
      operation_id: 'operation:linked-ed25519',
      capability_kind: 'near_ed25519_mpc_signing',
      operation_kind: 'near.sign_transaction',
      lane_digest_b64u: digest(7),
      intent_digest_b64u: intentDigestB64u,
      display_digest_b64u: digest(8),
      operation_fingerprint_digest: operationFingerprintDigest,
    },
    linkedDeviceExecution: {
      kind: 'linked_device_execution_v1',
      enrollmentId: 'enrollment:2',
      deviceId: 'device:2',
      walletKeyId: 'wallet-key:1',
      laneId: 'lane:linked-ed25519',
      laneShareEpoch: 'lane-share-epoch:linked-ed25519',
      materialActivation,
    },
    localPresenceAssertion: await localPresenceAssertion({
      intentDigestB64u,
      issuedAtMs: nowMs - 1_000,
      expiresAtMs,
    }),
  };
  return { body, envelope, operationFingerprintDigest, expiresAtMs };
}

async function claimedOperation(
  fixture: Awaited<ReturnType<typeof linkedEd25519FinalizeFixture>>,
): Promise<AuthorizedOperation> {
  return await buildAuthorizedOperation({
    tenantId: required(parseTenantId('tenant:1')),
    authorizedOperationId: required(
      parseAuthorizedOperationId('linked-ed25519-authorized-operation:linked-request'),
    ),
    auditEventId: required(parseAuthorizationAuditEventId('linked-ed25519-audit:linked-request')),
    operation: fixture.envelope,
    authorization: {
      kind: 'authorization_grant',
      authorizationGrantRef: buildLinkedDeviceWalletSessionAuthorizationRef(
        required(
          parseLinkedDeviceWalletSessionAuthorizationId(
            'linked-device-wallet-session-authorization:1',
          ),
        ),
      ),
    },
    quota: {
      kind: 'consume_reusable_wallet_session',
      quotaId: required(parseMpcWalletSigningQuotaId('wallet-quota:linked')),
    },
    claimedAtMs: Date.now() - 1_000,
  });
}

function configuredService(input: {
  readonly readAuthorizedOperation: () => Promise<AuthorizedOperation | null>;
  readonly admitAuthorizedOperation: () => Promise<Record<string, unknown>>;
  readonly completeAuthorizedOperation?: (
    operation: AuthorizedOperation,
  ) => Promise<AuthorizedOperation>;
}) {
  return {
    authorizedOperations: {
      tenantId: 'tenant:1',
      readAuthorizedOperation: input.readAuthorizedOperation,
      admitAuthorizedOperation: input.admitAuthorizedOperation,
      completeAuthorizedOperation: async ({ operation }: { operation: AuthorizedOperation }) =>
        input.completeAuthorizedOperation
          ? await input.completeAuthorizedOperation(operation)
          : operation,
    },
    linkedDeviceExecution: {
      resolveActiveLinkedDeviceExecutionV1: async () => ({
        kind: 'refused',
        reason: 'linked_enrollment_mismatch',
      }),
    },
    linkedDeviceLocalPresence: {
      verify: async () => ({ kind: 'verified', verifiedAtMs: Date.now() }),
    },
  };
}

async function linkedEcdsaPrepareFixture(nowMs: number) {
  const expiresAtMs = nowMs + 30_000;
  const materialActivation = {
    kind: 'mpc_material_activation_ref' as const,
    activation_id: 'activation:linked-ecdsa',
    capability: 'capability:linked-ecdsa',
    material_owner: 'wallet:1',
    key_binding: 'key-binding:linked-ecdsa',
    lifecycle_binding: 'lifecycle:linked-ecdsa',
    signing_worker: 'worker:linked-ecdsa',
  };
  const context = { application_binding_digest_b64u: digest(20) };
  const requestId = 'linked-ecdsa-request';
  const intentDigestB64u = digest(22);
  const request = buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1({
    scope: {
      wallet_id: 'wallet:1',
      ecdsa_threshold_key_id: 'ecdsa-key:linked',
      signing_root_id: 'signing-root:linked',
      signing_root_version: 'signing-root-version:linked',
      context,
      public_identity: {
        context_binding_b64u: await routerAbEcdsaDerivationContextBindingB64uV1(context),
        derivation_client_share_public_key33_b64u: hexB64u(
          '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        ),
        server_public_key33_b64u: hexB64u(
          '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
        ),
        threshold_public_key33_b64u: hexB64u(
          '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',
        ),
        ethereum_address20_b64u: base64UrlEncode(new Uint8Array(20).fill(5)),
        client_share_retry_counter: 0,
        server_share_retry_counter: 1,
      },
      material_activation: materialActivation,
      signing_worker: {
        server_id: 'worker:linked-ecdsa',
        key_epoch: 'worker-epoch:linked-ecdsa',
        recipient_encryption_key:
          'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      activation_epoch: 'activation-epoch:linked-ecdsa',
    },
    requestId,
    operationId: 'operation:linked-ecdsa',
    operationDigests: {
      lane_digest_b64u: digest(21),
      intent_digest_b64u: intentDigestB64u,
      display_digest_b64u: digest(23),
    },
    authorization: {
      kind: 'reusable_wallet_session',
      wallet_session_id: 'wallet-session:linked',
    },
    materialActivation,
    clientPresignatureId: 'presignature:linked-ecdsa',
    expiresAtMs,
    signingDigest32: new Uint8Array(32).fill(22),
    clientRerandomizationCommitment32: new Uint8Array(32).fill(24),
  });
  return {
    expiresAtMs,
    body: {
      ...request,
      linkedDeviceExecution: {
        kind: 'linked_device_execution_v1',
        enrollmentId: 'enrollment:2',
        deviceId: 'device:2',
        walletKeyId: 'wallet-key:1',
        laneId: 'lane:linked-ecdsa',
        laneShareEpoch: 'lane-share-epoch:linked-ecdsa',
        materialActivation,
      },
      localPresenceAssertion: await localPresenceAssertion({
        authorizedOperationId: `linked-ecdsa-authorized-operation:${requestId}`,
        intentDigestB64u,
        issuedAtMs: nowMs - 1_000,
        expiresAtMs,
      }),
    },
  };
}

test('routes a linked session into the linked admission branch', async () => {
  const result = await handleLinkedDeviceEd25519NormalSigning({
    ctx: context(sessionWithClaims(linkedClaims(Date.now() + 60_000))),
    body: {},
    phase: 'prepare',
  });
  expect(result?.status).toBe(501);
  expect(await result?.json()).toMatchObject({
    ok: false,
    code: 'not_configured',
  });
});

test('does not treat an expired linked session as an owner signing request', async () => {
  const result = await handleLinkedDeviceEd25519NormalSigning({
    ctx: context(sessionWithClaims(linkedClaims(Date.now() - 1))),
    body: {},
    phase: 'prepare',
  });
  expect(result).toBeNull();
});

test('parses linked ECDSA boundary fields before atomic admission', async () => {
  const fixture = await linkedEcdsaPrepareFixture(Date.now());
  let admissionCalls = 0;
  const result = await handleLinkedDeviceEcdsaNormalSigning({
    ctx: context(
      sessionWithClaims(linkedEcdsaClaims(fixture.expiresAtMs + 1_000)),
      configuredService({
        readAuthorizedOperation: async () => null,
        admitAuthorizedOperation: async () => {
          admissionCalls += 1;
          return { kind: 'material_mismatch' };
        },
      }),
    ),
    body: fixture.body,
    phase: 'prepare',
  });

  const responseBody = await result?.clone().json();
  expect({ status: result?.status, responseBody, admissionCalls }).toEqual({
    status: 403,
    responseBody: {
      ok: false,
      code: 'linked_device_authorization_rejected',
      message: 'Linked-device authorization was rejected: material_mismatch',
    },
    admissionCalls: 1,
  });
});

test('does not claim quota when Ed25519 finalize has no prepared operation', async () => {
  const nowMs = Date.now();
  const fixture = await linkedEd25519FinalizeFixture(nowMs);
  let admissionCalls = 0;
  const result = await handleLinkedDeviceEd25519NormalSigning({
    ctx: context(
      sessionWithClaims(linkedClaims(fixture.expiresAtMs + 1_000)),
      configuredService({
        readAuthorizedOperation: async () => null,
        admitAuthorizedOperation: async () => {
          admissionCalls += 1;
          return { kind: 'claimed' };
        },
      }),
    ),
    body: fixture.body,
    phase: 'finalize',
  });

  expect(result?.status).toBe(409);
  expect(await result?.json()).toMatchObject({ code: 'authorized_operation_missing' });
  expect(admissionCalls).toBe(0);
});

test('finalizes the exact prepared Ed25519 operation and completes its durable claim', async () => {
  const nowMs = Date.now();
  const fixture = await linkedEd25519FinalizeFixture(nowMs);
  const operation = await claimedOperation(fixture);
  let completionCalls = 0;
  const result = await handleLinkedDeviceEd25519NormalSigning({
    ctx: context(
      sessionWithClaims(linkedClaims(fixture.expiresAtMs + 1_000)),
      configuredService({
        readAuthorizedOperation: async () => operation,
        admitAuthorizedOperation: async () => ({ kind: 'operation_in_progress', operation }),
        completeAuthorizedOperation: async (claimed) => {
          completionCalls += 1;
          return {
            ...claimed,
            lifecycle: 'completed',
            result: 'failed_before_side_effect',
            response: { status: 403, contentType: 'application/json', bodyText: '{}' },
            resultDigest: parseDigestB64u(digest(15)),
            completedAtMs: Date.now(),
          };
        },
      }),
    ),
    body: fixture.body,
    phase: 'finalize',
  });

  expect(result?.status).toBe(403);
  expect(completionCalls).toBe(1);
});

test('builds the exact private Router envelope and public Ed25519 receipt from one claim', async () => {
  const fixture = await linkedEd25519FinalizeFixture(Date.now());
  const operation = await claimedOperation(fixture);
  const accepted = buildRouterAbEd25519AcceptedAuthorizedOperationV1({
    operation,
    binding: {
      kind: 'reusable_wallet_session',
      walletSessionId: 'wallet-session:linked',
      quotaId: 'wallet-quota:linked',
    },
  });

  expect(accepted).toEqual({
    binding: {
      kind: 'reusable_wallet_session',
      authorization_id: 'linked-device-wallet-session-authorization:1',
      wallet_session_id: 'wallet-session:linked',
      quota_id: 'wallet-quota:linked',
    },
    authorized_operation: fixture.body.authorized_operation,
  });
});

test('rejects linked signing when the request names another Wallet Session', async () => {
  const nowMs = Date.now();
  const fixture = await linkedEd25519FinalizeFixture(nowMs);
  const result = await handleLinkedDeviceEd25519NormalSigning({
    ctx: context(
      sessionWithClaims(linkedClaims(fixture.expiresAtMs + 1_000)),
      configuredService({
        readAuthorizedOperation: async () => null,
        admitAuthorizedOperation: async () => ({ kind: 'material_mismatch' }),
      }),
    ),
    body: {
      ...fixture.body,
      scope: {
        ...fixture.body.scope,
        authorization: {
          kind: 'reusable_wallet_session',
          wallet_session_id: 'wallet-session:substituted',
        },
      },
    },
    phase: 'finalize',
  });

  expect(result?.status).toBe(400);
  expect(await result?.json()).toMatchObject({
    code: 'invalid_body',
    message: 'linked-device signing Wallet Session does not match authorization scope',
  });
});

test('rejects a local-presence assertion whose signed challenge does not bind the intent', async () => {
  const nowMs = Date.now();
  const fixture = await linkedEd25519FinalizeFixture(nowMs);
  let admissionCalls = 0;
  const result = await handleLinkedDeviceEd25519NormalSigning({
    ctx: context(
      sessionWithClaims(linkedClaims(fixture.expiresAtMs + 1_000)),
      configuredService({
        readAuthorizedOperation: async () => null,
        admitAuthorizedOperation: async () => {
          admissionCalls += 1;
          return { kind: 'claimed' };
        },
      }),
    ),
    body: {
      ...fixture.body,
      localPresenceAssertion: {
        ...fixture.body.localPresenceAssertion,
        challengeDigestB64u: digest(12),
      },
    },
    phase: 'finalize',
  });

  expect(result?.status).toBe(403);
  expect(await result?.json()).toMatchObject({ code: 'local_presence_required' });
  expect(admissionCalls).toBe(0);
});
