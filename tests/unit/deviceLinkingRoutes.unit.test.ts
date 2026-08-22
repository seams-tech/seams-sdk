import { expect, test } from '@playwright/test';
import {
  DEVICE_LINKING_REQUEST_PROOF_HEADER_V1,
  handleDeviceLinking,
  targetCredentialResultResponse,
  type DeviceLinkingRouteServiceV1,
} from '../../packages/wallet-server/src/router/transport/fetch/routes/deviceLinking';
import type {
  LinkedDeviceOwnerAuthorizationPortV1,
  LinkedDeviceSessionServiceV1,
} from '../../packages/wallet-server/src/core/deviceLinking/linkedDeviceSession';
import {
  D1LinkedDeviceSessionStoreV1,
  type D1LinkedDeviceSessionScopeV1,
} from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceSessionStore';
import { LinkedDeviceSessionServiceV1 as CoreLinkedDeviceSessionServiceV1 } from '../../packages/wallet-server/src/core/deviceLinking/linkedDeviceSession';
import {
  buildR103DeviceLinkFixture,
  buildR103OwnerApprovalContextV1,
} from './helpers/deviceLinkContracts.fixtures';
import {
  buildR103AwaitingTargetPasskeySessionRecordV1,
  buildR103UnclaimedLinkedDeviceSessionRecordV1,
} from './helpers/deviceLinkingServer.fixtures';
import { buildPasskeyTargetPreparationFixtureV1 } from './helpers/linkedDeviceTargetPreparation.fixtures';
import {
  parseLinkedDeviceTargetCredentialRegistrationResultV1,
  parseLinkedDeviceTargetCredentialRegistrationV1,
} from '@shared/device-linking/parsers';
import {
  buildOrdinaryEcdsaReservationPreparationFixture,
  buildOrdinaryMaterialActivationFixture,
} from './helpers/ordinarySignerMaterialReservation.fixtures';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256Bytes } from '@shared/utils/digests';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { FetchRouterApiContext } from '../../packages/wallet-server/src/router/transport/fetch/createFetchRouter';

const scope: D1LinkedDeviceSessionScopeV1 = {
  namespace: 'signer',
  orgId: 'org_route_test',
  projectId: 'project_route_test',
  envId: 'env_route_test',
};

let temporary: TemporaryD1Database | undefined;

test.afterEach(() => {
  if (temporary) cleanupTemporaryD1Database(temporary.tempDir);
  temporary = undefined;
});

test('creates and polls a QR session without exposing transcripts', async () => {
  temporary = await openDatabase();
  const fixture = buildR103DeviceLinkFixture({
    linkSessionId: 'link-session:route-create',
    expiresAtMs: Date.now() + 60_000,
  });
  const sessionService = buildSessionService(fixture);
  const routeService = routeServiceFor(sessionService, fixture, 3_000);

  const created = await invoke(routeService, {
    method: 'POST',
    pathname: '/wallet/device-linking/v1/sessions',
    body: {
      kind: 'linked_device_session_create_request_v1',
      payload: fixture.payload,
    },
  });
  expect(created.status).toBe(200);
  const createdBody = await created.json();
  expect(createdBody.ok).toBe(true);
  expect(createdBody.session.state).toEqual({ state: 'displaying_qr' });
  expect(createdBody.session).not.toHaveProperty('claimTranscript');
  expect(createdBody.session).not.toHaveProperty('approvalTranscript');

  const polled = await invoke(routeService, {
    method: 'GET',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}`,
  });
  expect(polled.status).toBe(200);
  const polledBody = await polled.json();
  expect(polledBody.session.state).toEqual({ state: 'displaying_qr' });
  expect(polledBody.session).not.toHaveProperty('claimTranscript');
});

test('claims and records owner approval through the linear route surface', async () => {
  temporary = await openDatabase();
  const fixture = buildR103DeviceLinkFixture({
    linkSessionId: 'link-session:route-approval',
    expiresAtMs: Date.now() + 60_000,
  });
  const sessionService = buildSessionService(fixture);
  const ownerCalls: string[] = [];
  const routeService = routeServiceFor(sessionService, fixture, 3_000, {
    authenticateOwnerRequestV1: async ({ request, method, pathname, bodyDigestB64u }) => {
      ownerCalls.push(pathname);
      return {
        kind: 'authorized' as const,
        body: method === 'GET' ? null : await request.clone().json(),
        owner: buildR103OwnerApprovalContextV1(fixture.approval),
        binding: requestBinding(method, pathname, bodyDigestB64u, 3_000),
      };
    },
  });

  await expect(
    invoke(routeService, {
      method: 'POST',
      pathname: '/wallet/device-linking/v1/sessions',
      body: {
        kind: 'linked_device_session_create_request_v1',
        payload: fixture.payload,
      },
    }),
  ).resolves.toHaveProperty('status', 200);

  const claimed = await invoke(routeService, {
    method: 'POST',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/claim`,
    body: fixture.claimRequest,
  });
  expect(claimed.status).toBe(200);
  expect(await claimed.json()).toMatchObject({
    kind: 'linked_device_session_claim_v1',
    linkSessionId: String(fixture.payload.linkSessionId),
    deviceId: String(fixture.approval.deviceId),
  });

  const approved = await invoke(routeService, {
    method: 'POST',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/approval`,
    body: fixture.approval,
  });
  expect(approved.status).toBe(200);
  expect(await approved.json()).toMatchObject({
    outcome: 'pending',
    state: { state: 'awaiting_target_factor', deviceId: String(fixture.approval.deviceId) },
  });
  expect(ownerCalls).toEqual([
    `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/claim`,
    `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/approval`,
  ]);
});

test('authenticates the owner before parsing a malformed claim body', async () => {
  temporary = await openDatabase();
  const fixture = buildR103DeviceLinkFixture({
    linkSessionId: 'link-session:route-parse',
    expiresAtMs: Date.now() + 60_000,
  });
  const sessionService = buildSessionService(fixture);
  let ownerAuthCalls = 0;
  const routeService = routeServiceFor(sessionService, fixture, 3_000, {
    authenticateOwnerRequestV1: async ({ request, method, pathname, bodyDigestB64u }) => {
      ownerAuthCalls += 1;
      return {
        kind: 'authorized' as const,
        body: await request.clone().json(),
        owner: buildR103OwnerApprovalContextV1(fixture.approval),
        binding: requestBinding(method, pathname, bodyDigestB64u, 3_000),
      };
    },
  });
  const malformed = await invoke(routeService, {
    method: 'POST',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/claim`,
    body: { unexpected: true },
  });
  expect(malformed.status).toBe(400);
  expect(ownerAuthCalls).toBe(1);
});

test('serializes the browser ECDSA recipient in the target credential response', async () => {
  const fixture = buildR103DeviceLinkFixture({ linkSessionId: 'link-session:route-result' });
  const digest = parseDigestB64u('Lcwi4R-zFWWooZJB2zonKJtBMlynySPIjt55tietXWE');
  const activation = buildOrdinaryMaterialActivationFixture('route-result');
  const preparation = buildOrdinaryEcdsaReservationPreparationFixture('route-result', activation);
  const targetWalletAuthMethodId = 'email_otp:wallet:r103:' + 'ab'.repeat(32);
  const targetCredential = parseLinkedDeviceTargetCredentialRegistrationResultV1({
    kind: 'linked_device_target_credential_registration_result_v1',
    outcome: 'applied',
    linkSessionId: fixture.payload.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    walletAuthMethodId: targetWalletAuthMethodId,
    targetPreparationDigestB64u: digest,
    targetFactor: {
      kind: 'verified_email_otp_target_v1',
      authMethod: {
        walletAuthMethodId: targetWalletAuthMethodId,
        walletId: fixture.approval.walletId,
        createdAtMs: 1_000,
        kind: 'email_otp',
        emailHashHex: 'ab'.repeat(32),
        registrationAuthorityId: 'authority:r103',
      },
      verificationDigestB64u: digest,
      verifiedAtMs: 2_000,
    },
    ordinarySignerMaterialPreparations: [preparation],
    ordinarySignerMaterialRecipientRequests: [
      {
        kind: 'ordinary_ecdsa_signer_material_recipient_request_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletKeyId: 'wallet-key:route-result',
        clientEphemeralPublicKey: preparation.registrationRequest.client_ephemeral_public_key,
      },
    ],
    keyManifestDigestB64u: digest,
  });
  const response = targetCredentialResultResponse(
    buildR103UnclaimedLinkedDeviceSessionRecordV1(fixture),
    'applied',
    targetCredential,
  );
  const body = await response.json();
  expect(body).toMatchObject({
    ok: true,
    targetCredential: {
      walletAuthMethodId: targetWalletAuthMethodId,
      ordinarySignerMaterialRecipientRequests: [
        {
          clientEphemeralPublicKey: preparation.registrationRequest.client_ephemeral_public_key,
        },
      ],
    },
  });
});

test('forwards the exact request Origin to target credential verification', async () => {
  temporary = await openDatabase();
  const fixture = buildR103DeviceLinkFixture({ linkSessionId: 'link-session:route-origin' });
  const session = await buildR103AwaitingTargetPasskeySessionRecordV1(fixture);
  const sessionService = buildSessionService(fixture);
  const baseRouteService = routeServiceFor(sessionService, fixture, 3_000);
  const digest = parseDigestB64u('Lcwi4R-zFWWooZJB2zonKJtBMlynySPIjt55tietXWE');
  const walletKeyId = fixture.approval.orderedOwnerSourceLaneHints[0]?.walletKey.walletKeyId;
  if (!walletKeyId) throw new Error('fixture signer binding is missing');
  const registration = parseLinkedDeviceTargetCredentialRegistrationV1({
    kind: 'linked_device_target_credential_registration_v1',
    linkSessionId: fixture.payload.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    walletAuthMethodId: 'passkey:wallet.example.test:target-preparation-test',
    targetFactor: { kind: 'passkey_prf' },
    targetPreparationDigestB64u: digest,
    ordinarySignerMaterialRecipientRequests: [
      {
        kind: 'ordinary_ed25519_signer_material_recipient_request_v1',
        keyFamily: 'ed25519',
        walletKeyId,
        recipientPublicKeyB64u: base64UrlEncode(new Uint8Array(32)),
      },
    ],
    webauthnRegistration: {
      kind: 'linked_device_webauthn_registration_v1',
      credentialIdB64u: 'dGFyZ2V0LWNyZWRlbnRpYWw',
      authenticatorAttachment: 'platform',
      clientDataJsonB64u: 'AQ',
      attestationObjectB64u: 'Ag',
      transports: ['internal'],
    },
    registeredAtMs: 2_500,
  });
  let observedOrigin: string | undefined;
  const routeService: DeviceLinkingRouteServiceV1 = {
    ...baseRouteService,
    sessionService: {
      ...baseRouteService.sessionService,
      getSessionV1: async () => session,
    },
    targetCredential: {
      ...baseRouteService.targetCredential,
      getTargetPreparationV1: async () => buildPasskeyTargetPreparationFixtureV1(),
      registerTargetCredentialV1: async (input) => {
        observedOrigin = input.origin;
        return { outcome: 'invalid_input', message: 'verification probe' };
      },
      buildVerifiedLinkInputV1: async () => {
        throw new Error('verified-link input is not reached by this probe');
      },
    },
  };
  const response = await invoke(routeService, {
    method: 'POST',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/credential`,
    body: registration,
    origin: 'https://target.example.test',
  });
  expect(response.status).toBe(400);
  expect(observedOrigin).toBe('https://target.example.test');
});

async function openDatabase(): Promise<TemporaryD1Database> {
  const database = createTemporaryD1Database();
  await applyD1MigrationFiles(database.database, listD1MigrationFiles('d1-signer'));
  return database;
}

function buildSessionService(
  fixture: ReturnType<typeof buildR103DeviceLinkFixture>,
): LinkedDeviceSessionServiceV1 {
  return new CoreLinkedDeviceSessionServiceV1({
    store: new D1LinkedDeviceSessionStoreV1({ database: temporary!.database, scope }),
    authorization: ownerAuthorization(fixture),
  });
}

function routeServiceFor(
  sessionService: LinkedDeviceSessionServiceV1,
  fixture: ReturnType<typeof buildR103DeviceLinkFixture>,
  nowMs: number,
  overrides: Partial<DeviceLinkingRouteServiceV1> = {},
): DeviceLinkingRouteServiceV1 {
  const defaults: DeviceLinkingRouteServiceV1 = {
    sessionService: {
      createUnclaimedSessionV1: sessionService.createUnclaimedSessionV1.bind(sessionService),
      claimSessionV1: sessionService.claimSessionV1.bind(sessionService),
      recordOwnerApprovalV1: sessionService.recordOwnerApprovalV1.bind(sessionService),
      recordTargetCredentialV1: sessionService.recordTargetCredentialV1.bind(sessionService),
      recordEmailOtpChallengeStateV1:
        sessionService.recordEmailOtpChallengeStateV1.bind(sessionService),
      cancelSessionV1: sessionService.cancelSessionV1.bind(sessionService),
      getSessionV1: sessionService.getSessionV1.bind(sessionService),
      listSessionsForWalletV1: sessionService.listSessionsForWalletV1.bind(sessionService),
    },
    nowV1: () => nowMs,
    verifyPublicSessionProofV1: async () => ({ kind: 'authorized' as const }),
    authenticateOwnerRequestV1: async ({ request, method, pathname, bodyDigestB64u }) => ({
      kind: 'authorized' as const,
      body: method === 'GET' ? null : await request.clone().json(),
      owner: buildR103OwnerApprovalContextV1(fixture.approval),
      binding: requestBinding(method, pathname, bodyDigestB64u, nowMs),
    }),
    authenticateDeviceRequestV1: async ({ request, method, proof }) => ({
      kind: 'authorized' as const,
      body: method === 'GET' ? null : await request.clone().json(),
      proof,
    }),
    targetCredential: {
      getTargetPreparationV1: async () => {
        throw new Error('target preparation adapter not configured for this test');
      },
      registerTargetCredentialV1: async () => {
        throw new Error('credential adapter not configured for this test');
      },
    },
  };
  return { ...defaults, ...overrides };
}

function ownerAuthorization(
  fixture: ReturnType<typeof buildR103DeviceLinkFixture>,
): LinkedDeviceOwnerAuthorizationPortV1 {
  return {
    authorizeOwnerClaimV1: async () => ({
      kind: 'authorized' as const,
      identity: {
        walletId: fixture.approval.walletId,
        enrollmentId: fixture.approval.enrollmentId,
        deviceId: fixture.approval.deviceId,
        claimExpiresAtMs: fixture.payload.expiresAtMs,
      },
    }),
    authorizeOwnerApprovalV1: async () => ({ kind: 'authorized' as const }),
  };
}

function requestBinding(
  method: string,
  pathname: string,
  bodyDigestB64u: DigestB64u,
  nowMs: number,
) {
  return {
    kind: 'linked_device_owner_request_binding_v1' as const,
    method: method as 'GET' | 'POST',
    pathname,
    bodyDigestB64u,
    expiresAtMs: nowMs + 1_000,
  };
}

async function invoke(
  routeService: DeviceLinkingRouteServiceV1,
  input: {
    readonly method: string;
    readonly pathname: string;
    readonly body?: unknown;
    readonly origin?: string;
  },
): Promise<Response> {
  const bodyText = input.body === undefined ? undefined : JSON.stringify(input.body);
  const headers = new Headers();
  headers.set(
    DEVICE_LINKING_REQUEST_PROOF_HEADER_V1,
    await requestProofHeader(input.method, input.pathname, bodyText),
  );
  if (input.origin) headers.set('origin', input.origin);
  if (bodyText !== undefined) headers.set('content-type', 'application/json');
  const request = new Request(`https://example.test${input.pathname}`, {
    method: input.method,
    ...(bodyText === undefined ? { headers } : { body: bodyText, headers }),
  });
  const context = {
    request,
    url: new URL(request.url),
    pathname: input.pathname,
    method: input.method,
    runtime: { kind: 'inline' as const },
    service: { deviceLinking: routeService },
    opts: {},
    logger: {},
    routeDefinitions: [],
  } as unknown as FetchRouterApiContext;
  const response = await handleDeviceLinking(context);
  if (!response) throw new Error('device-linking route did not match');
  return response;
}

async function requestProofHeader(
  method: string,
  pathname: string,
  bodyText: string | undefined,
): Promise<string> {
  const bodyDigestB64u = base64UrlEncode(
    await sha256Bytes(new TextEncoder().encode(bodyText ?? '')),
  );
  const publicKey = new Uint8Array(32).fill(8);
  const devicePublicKeyDigestB64u = base64UrlEncode(await sha256Bytes(publicKey));
  const rawLinkSessionId = linkSessionIdForRequest(pathname, bodyText);
  const proof = {
    kind: 'linked_device_request_proof_v1' as const,
    linkSessionId: decodeURIComponent(rawLinkSessionId),
    devicePublicKeyDigestB64u,
    requestNonceB64u: base64UrlEncode(new Uint8Array(32).fill(3)),
    method,
    canonicalPath: pathname,
    bodyDigestB64u,
    issuedAtMs: 2_000,
    expiresAtMs: 9_000,
    signatureB64u: base64UrlEncode(new Uint8Array(64).fill(4)),
  };
  return base64UrlEncode(new TextEncoder().encode(JSON.stringify(proof)));
}

function linkSessionIdForRequest(pathname: string, bodyText: string | undefined): Promise<string> {
  if (pathname.startsWith('/wallet/device-linking/v1/sessions/')) {
    return pathname.slice('/wallet/device-linking/v1/sessions/'.length).split('/')[0];
  }
  if (bodyText === undefined) throw new Error('create request body is required');
  const rawBody: unknown = JSON.parse(bodyText);
  if (rawBody === null || typeof rawBody !== 'object' || Array.isArray(rawBody)) {
    throw new Error('create request body must be an object');
  }
  const payload = Object.fromEntries(Object.entries(rawBody)).payload;
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('create request payload must be an object');
  }
  const linkSessionId = Object.fromEntries(Object.entries(payload)).linkSessionId;
  if (typeof linkSessionId !== 'string')
    throw new Error('create request link session id is required');
  return linkSessionId;
}
