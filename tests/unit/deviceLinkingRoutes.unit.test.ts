import { expect, test } from '@playwright/test';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
} from '@shared/signing-lanes';
import { parseWalletId } from '@shared/utils/domainIds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256Bytes } from '@shared/utils/digests';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import {
  LinkedDeviceSessionServiceV1,
  type LinkedDeviceOwnerAuthorizationPortV1,
} from '../../packages/sdk-server-ts/src/core/deviceLinking/linkedDeviceSession';
import {
  D1LinkedDeviceSessionStoreV1,
  type D1LinkedDeviceSessionScopeV1,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceSessionStore';
import {
  DEVICE_LINKING_REQUEST_PROOF_HEADER_V1,
  handleDeviceLinking,
  type DeviceLinkingRouteServiceV1,
  type DeviceLinkingRequestProofV1,
} from '../../packages/sdk-server-ts/src/router/transport/fetch/routes/deviceLinking';
import type { FetchRouterApiContext } from '../../packages/sdk-server-ts/src/router/transport/fetch/fetchRouter.types';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';

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

test('creates and polls a session projection without transcript or authorization material', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const store = new D1LinkedDeviceSessionStoreV1({ database: temporary.database, scope });
  const sessionService = new LinkedDeviceSessionServiceV1({
    store,
    authorization: ownerAuthorization(),
  });
  const routeService = routeServiceFor(sessionService, 3_000);

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
  expect(createdBody.session.state.state).toBe('displaying_qr');
  expect(createdBody.session).not.toHaveProperty('claimTranscript');
  expect(createdBody.session).not.toHaveProperty('approvalTranscript');

  const polled = await invoke(routeService, {
    method: 'GET',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}`,
  });
  expect(polled.status).toBe(200);
  const polledBody = await polled.json();
  expect(polledBody.session.state.state).toBe('displaying_qr');
  expect(polledBody.session).not.toHaveProperty('claimTranscript');
  expect(polledBody.session).not.toHaveProperty('deviceId');
});

test('projects the claimed device identity after owner claim', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const store = new D1LinkedDeviceSessionStoreV1({ database: temporary.database, scope });
  const sessionService = new LinkedDeviceSessionServiceV1({
    store,
    authorization: ownerAuthorization(),
  });
  const routeService = routeServiceFor(sessionService, 3_000, {
    authenticateOwnerRequestV1: async ({ request, method, pathname, bodyDigestB64u }) => ({
      kind: 'authorized' as const,
      body: await request.json(),
      binding: requestBinding(method, pathname, bodyDigestB64u, 3_000),
    }),
  });

  const created = await invoke(routeService, {
    method: 'POST',
    pathname: '/wallet/device-linking/v1/sessions',
    body: {
      kind: 'linked_device_session_create_request_v1',
      payload: fixture.payload,
    },
  });
  expect(created.status).toBe(200);

  const claimed = await invoke(routeService, {
    method: 'POST',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/claim`,
    body: fixture.claimRequest,
  });
  expect(claimed.status).toBe(200);
  const claimedBody = await claimed.json();
  expect(claimedBody.kind).toBe('linked_device_session_claim_v1');
  expect(claimedBody.linkSessionId).toBe(String(fixture.payload.linkSessionId));
  expect(claimedBody.deviceId).toBe(String(fixture.approval.deviceId));

  const approval = { ...fixture.approval, expiresAtMs: 9_000 };
  const approved = await invoke(routeService, {
    method: 'POST',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/approval`,
    body: approval,
  });
  expect(approved.status).toBe(200);
  const approvedBody = await approved.json();
  expect(approvedBody.outcome).toBe('pending');
  expect(approvedBody.state.state).toBe('awaiting_target_passkey');
  expect(approvedBody).not.toHaveProperty('manifestDigestB64u');

  const replayedApproval = await invoke(routeService, {
    method: 'POST',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/approval`,
    body: approval,
  });
  expect(replayedApproval.status).toBe(200);
  const replayedBody = await replayedApproval.json();
  expect(replayedBody.outcome).toBe('replayed');
  expect(replayedBody.replay.state).toBe('pending');
  expect(replayedBody.replay.session.state).toBe('awaiting_target_passkey');
});

test('authenticates owner before parsing claim and returns no session secrets', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const store = new D1LinkedDeviceSessionStoreV1({ database: temporary.database, scope });
  const sessionService = new LinkedDeviceSessionServiceV1({
    store,
    authorization: ownerAuthorization(),
  });
  let ownerAuthCalls = 0;
  const routeService = routeServiceFor(sessionService, 3_000, {
    authenticateOwnerRequestV1: async ({ request, method, pathname, bodyDigestB64u }) => {
      ownerAuthCalls += 1;
      return {
        kind: 'authorized' as const,
        body: await request.json(),
        binding: requestBinding(method, pathname, bodyDigestB64u, 3_000),
      };
    },
  });
  await invoke(routeService, {
    method: 'POST',
    pathname: '/wallet/device-linking/v1/sessions',
    body: {
      kind: 'linked_device_session_create_request_v1',
      payload: fixture.payload,
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

test('rejects a replayed device signature when the authenticated request body changes', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const store = new D1LinkedDeviceSessionStoreV1({ database: temporary.database, scope });
  const sessionService = new LinkedDeviceSessionServiceV1({
    store,
    authorization: ownerAuthorization(),
  });
  let firstProof: DeviceLinkingRequestProofV1 | undefined;
  const observed: Array<{ method: string; pathname: string; linkSessionId: string; bodyDigestB64u: string }> = [];
  const routeService = routeServiceFor(sessionService, 3_000, {
    authenticateDeviceRequestV1: async ({ request, method, pathname, linkSessionId, bodyDigestB64u, proof }) => {
      observed.push({ method, pathname, linkSessionId, bodyDigestB64u });
      const verifiedProof = firstProof ?? proof;
      firstProof = verifiedProof;
      return {
        kind: 'authorized' as const,
        body: await request.json(),
        // Simulates a verifier that signs one request and incorrectly reuses that proof.
        proof: verifiedProof,
      };
    },
  });
  await invoke(routeService, {
    method: 'POST',
    pathname: '/wallet/device-linking/v1/sessions',
    body: {
      kind: 'linked_device_session_create_request_v1',
      payload: fixture.payload,
    },
  });
  const firstCancel = {
    kind: 'linked_device_session_cancel_unclaimed_request_v1',
    linkSessionId: fixture.payload.linkSessionId,
    reason: 'user_cancelled',
    requestedAtMs: 3_000,
  } as const;
  const firstResponse = await invoke(routeService, {
    method: 'POST',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/cancel`,
    body: firstCancel,
  });
  expect(firstResponse.status).toBe(200);

  const substitutedBody = {
    requestedAtMs: firstCancel.requestedAtMs,
    reason: firstCancel.reason,
    linkSessionId: firstCancel.linkSessionId,
    kind: firstCancel.kind,
  };
  const replayResponse = await invoke(routeService, {
    method: 'POST',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/cancel`,
    body: substitutedBody,
  });
  expect(replayResponse.status).toBe(400);
  expect(observed).toHaveLength(2);
  expect(observed[0].method).toBe('POST');
  expect(observed[0].pathname).toContain('/cancel');
  expect(observed[0].linkSessionId).toBe(String(fixture.payload.linkSessionId));
  expect(observed[1].bodyDigestB64u).not.toBe(observed[0].bodyDigestB64u);
});

function routeServiceFor(
  sessionService: DeviceLinkingRouteServiceV1['sessionService'],
  nowMs: number,
  overrides: Partial<DeviceLinkingRouteServiceV1> = {},
): DeviceLinkingRouteServiceV1 {
  const routeSessionService: DeviceLinkingRouteServiceV1['sessionService'] = {
    createUnclaimedSessionV1: sessionService.createUnclaimedSessionV1.bind(sessionService),
    claimSessionV1: sessionService.claimSessionV1.bind(sessionService),
    recordOwnerApprovalV1: sessionService.recordOwnerApprovalV1.bind(sessionService),
    cancelSessionV1: sessionService.cancelSessionV1.bind(sessionService),
    getSessionV1: (input) =>
      typeof input === 'string'
        ? sessionService.getSessionV1({ linkSessionId: input, nowMs: 1 })
        : sessionService.getSessionV1(input),
  };
  const defaults: DeviceLinkingRouteServiceV1 = {
    sessionService: routeSessionService,
    nowV1: () => nowMs,
    verifyPublicSessionProofV1: async () => ({ kind: 'authorized' as const }),
    authenticateOwnerRequestV1: async ({ request, method, pathname, bodyDigestB64u }) => ({
      kind: 'authorized' as const,
      body: await request.json(),
      binding: requestBinding(method, pathname, 'link-session:r103', bodyDigestB64u, nowMs),
    }),
    authenticateDeviceRequestV1: async ({ proof }) => ({
      kind: 'authorized' as const,
      body: null,
      proof,
    }),
    registerTargetCredentialV1: async () => {
      throw new Error('credential adapter not configured for this test');
    },
    acknowledgeReceiptV1: async () => {
      throw new Error('receipt adapter not configured for this test');
    },
    retryCommittedDeliveryV1: async () => {
      throw new Error('retry adapter not configured for this test');
    },
  };
  return { ...defaults, ...overrides };
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
  input: { readonly method: string; readonly pathname: string; readonly body?: unknown },
): Promise<Response> {
  const bodyText = input.body === undefined ? undefined : JSON.stringify(input.body);
  const headers = new Headers();
  headers.set(DEVICE_LINKING_REQUEST_PROOF_HEADER_V1, await requestProofHeader(input.method, input.pathname, bodyText));
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
    mePath: '/me',
    routeDefinitions: [],
  } as unknown as FetchRouterApiContext;
  const response = await handleDeviceLinking(context);
  if (!response) throw new Error('device-linking route did not match');
  return response;
}

async function requestProofHeader(method: string, pathname: string, bodyText: string | undefined): Promise<string> {
  const bodyDigestB64u = base64UrlEncode(
    await sha256Bytes(new TextEncoder().encode(bodyText ?? '')),
  );
  const devicePublicKeyDigestB64u = base64UrlEncode(
    await sha256Bytes(new Uint8Array(32).fill(8)),
  );
  const rawLinkSessionId = pathname.startsWith('/wallet/device-linking/v1/sessions/')
    ? pathname.slice('/wallet/device-linking/v1/sessions/'.length).split('/')[0]
    : 'link-session:r103';
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

function ownerAuthorization(): LinkedDeviceOwnerAuthorizationPortV1 {
  return {
    authorizeOwnerClaimV1: async () => ({
      kind: 'authorized' as const,
      identity: {
        walletId: parseWalletId('wallet:r103').value,
        enrollmentId: parseLinkedDeviceEnrollmentId('enrollment:r103').value,
        deviceId: parseLinkedDeviceId('device:r103').value,
        claimExpiresAtMs: 9_000,
      },
    }),
    authorizeOwnerApprovalV1: async () => ({ kind: 'authorized' as const }),
  };
}
