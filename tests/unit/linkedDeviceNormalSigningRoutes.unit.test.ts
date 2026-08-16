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
import { routerAbMpcMaterialActivationRefToWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import {
  buildAuthorizedOperation,
  buildLinkedDevicePrincipalId,
  type AuthorizedOperation,
} from '../../packages/sdk-server-ts/src/authorization/domain';
import { buildRouterAbEd25519AcceptedAuthorizedOperationV1 } from '../../packages/sdk-server-ts/src/router/domains/signingOperations/routerAbPrivateSigningWorker';
import { buildLinkedDeviceWalletExecutionFixture } from './helpers/linkedDeviceWalletExecution.fixtures';

function digest(fill: number): string {
  return base64UrlEncode(new Uint8Array(32).fill(fill));
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
  readonly deviceId?: string;
  readonly enrollmentId?: string;
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
    deviceId: required(parseLinkedDeviceId(input.deviceId ?? 'device:2')),
    enrollmentId: required(parseLinkedDeviceEnrollmentId(input.enrollmentId ?? 'enrollment:2')),
    credentialIdB64u: required(parseWebAuthnCredentialIdB64u(credentialIdB64u)),
    intentDigestB64u: parseDigestB64u(input.intentDigestB64u),
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
  });
  return {
    kind: 'linked_device_local_presence_assertion_v1',
    authorizedOperationId:
      input.authorizedOperationId ?? 'linked-ed25519-authorized-operation:linked-request',
    deviceId: input.deviceId ?? 'device:2',
    enrollmentId: input.enrollmentId ?? 'enrollment:2',
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
  readonly verifyLocalPresence?: () => Promise<{
    readonly kind: 'verified';
    readonly verifiedAtMs: number;
  }>;
  readonly renewLinkedDeviceWalletSession?: () => Promise<void>;
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
      verify:
        input.verifyLocalPresence ?? (async () => ({ kind: 'verified', verifiedAtMs: Date.now() })),
    },
    authorizationSessions: {
      tenantId: 'tenant:1',
      renewLinkedDeviceWalletSession: input.renewLinkedDeviceWalletSession ?? (async () => {}),
    },
  };
}

async function linkedEcdsaPrepareFixture(nowMs: number) {
  const expiresAtMs = nowMs + 30_000;
  const linked = await buildLinkedDeviceWalletExecutionFixture();
  const scope = linked.projection.ecdsaNormalSigningScope;
  if (!scope) throw new Error('linked fixture is missing its ECDSA scope');
  const materialActivation = routerAbMpcMaterialActivationRefToWire(
    linked.projection.materialActivation,
  );
  const requestId = 'linked-ecdsa-request';
  const intentDigestB64u = digest(22);
  const request = {
    scope,
    request_id: requestId,
    operation_id: 'operation:linked-ecdsa',
    operation_digests: {
      lane_digest_b64u: digest(21),
      intent_digest_b64u: intentDigestB64u,
      display_digest_b64u: digest(23),
    },
    authorization: {
      kind: 'reusable_wallet_session',
      wallet_session_id: 'wallet-session:linked',
    },
    material_activation: materialActivation,
    client_presignature_id: 'presignature:linked-ecdsa',
    expires_at_ms: expiresAtMs,
    signing_digest_b64u: intentDigestB64u,
    client_rerandomization_commitment32_b64u: digest(24),
  };
  const claims = {
    ...linkedEcdsaClaims(expiresAtMs + 1_000),
    walletId: String(scope.walletId),
    deviceId: String(linked.projection.enrollment.deviceId),
    sub: `linked-device:${String(linked.projection.enrollment.deviceId)}`,
    enrollmentId: String(linked.projection.enrollment.enrollmentId),
    walletKeyId: String(scope.walletKeyId),
  };
  return {
    expiresAtMs,
    claims,
    body: {
      ...request,
      linkedDeviceExecution: {
        kind: 'linked_device_execution_v1',
        enrollmentId: String(linked.projection.enrollment.enrollmentId),
        deviceId: String(linked.projection.enrollment.deviceId),
        walletKeyId: String(scope.walletKeyId),
        laneId: String(scope.laneId),
        laneShareEpoch: String(scope.laneShareEpoch),
        materialActivation,
      },
      localPresenceAssertion: await localPresenceAssertion({
        authorizedOperationId: `linked-ecdsa-authorized-operation:${requestId}`,
        deviceId: String(linked.projection.enrollment.deviceId),
        enrollmentId: String(linked.projection.enrollment.enrollmentId),
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
      sessionWithClaims(fixture.claims),
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

test('renews an exhausted linked Wallet Session from fresh local presence and retries admission', async () => {
  const fixture = await linkedEcdsaPrepareFixture(Date.now());
  let admissionCalls = 0;
  let renewalCalls = 0;
  const result = await handleLinkedDeviceEcdsaNormalSigning({
    ctx: context(
      sessionWithClaims(fixture.claims),
      configuredService({
        readAuthorizedOperation: async () => null,
        admitAuthorizedOperation: async () => {
          admissionCalls += 1;
          return admissionCalls === 1
            ? { kind: 'wallet_session_quota_exhausted' }
            : { kind: 'material_mismatch' };
        },
        renewLinkedDeviceWalletSession: async () => {
          renewalCalls += 1;
        },
      }),
    ),
    body: fixture.body,
    phase: 'prepare',
  });

  expect(result?.status).toBe(403);
  expect(await result?.json()).toMatchObject({
    code: 'linked_device_authorization_rejected',
    message: 'Linked-device authorization was rejected: material_mismatch',
  });
  expect({ admissionCalls, renewalCalls }).toEqual({ admissionCalls: 2, renewalCalls: 1 });
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

test('rejects linked signing when the inner scope substitutes material identity', async () => {
  const fixture = await linkedEcdsaPrepareFixture(Date.now());
  let admissionCalls = 0;
  const result = await handleLinkedDeviceEcdsaNormalSigning({
    ctx: context(
      sessionWithClaims(fixture.claims),
      configuredService({
        readAuthorizedOperation: async () => null,
        admitAuthorizedOperation: async () => {
          admissionCalls += 1;
          return { kind: 'material_mismatch' };
        },
      }),
    ),
    body: {
      ...fixture.body,
      scope: {
        ...fixture.body.scope,
        materialActivation: {
          ...fixture.body.scope.materialActivation,
          keyBinding: 'key-binding:substituted',
        },
      },
    },
    phase: 'prepare',
  });

  expect(result?.status).toBe(400);
  expect(await result?.json()).toMatchObject({
    code: 'invalid_body',
    message: 'linked ECDSA material activation does not match scope',
  });
  expect(admissionCalls).toBe(0);
});

test('does not reverify the local-presence assertion during Ed25519 finalize', async () => {
  const nowMs = Date.now();
  const fixture = await linkedEd25519FinalizeFixture(nowMs);
  let admissionCalls = 0;
  let verifierCalls = 0;
  const result = await handleLinkedDeviceEd25519NormalSigning({
    ctx: context(
      sessionWithClaims(linkedClaims(fixture.expiresAtMs + 1_000)),
      configuredService({
        readAuthorizedOperation: async () => null,
        admitAuthorizedOperation: async () => {
          admissionCalls += 1;
          return { kind: 'claimed' };
        },
        verifyLocalPresence: async () => {
          verifierCalls += 1;
          return { kind: 'verified', verifiedAtMs: Date.now() };
        },
      }),
    ),
    body: fixture.body,
    phase: 'finalize',
  });

  expect(result?.status).toBe(409);
  expect(await result?.json()).toMatchObject({ code: 'authorized_operation_missing' });
  expect(admissionCalls).toBe(0);
  expect(verifierCalls).toBe(0);
});
