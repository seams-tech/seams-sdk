import { expect, test } from '@playwright/test';
import { buildLinkedDeviceSessionClaimV1 } from '@shared/device-linking/parsers';
import {
  computeLinkedDeviceApprovalDigestV1,
  computeLinkedDeviceSessionClaimDigestV1,
} from '@shared/device-linking/digests';
import {
  handleDeviceLinkingGatewayCompletion,
  LINKED_DEVICE_GATEWAY_COMPLETION_BASE_V1,
  type DeviceLinkingGatewayCompletionServiceV1,
} from '../../packages/sdk-server-ts/src/router/transport/fetch/routes/deviceLinkingGateway';
import { parseLinkedDeviceSessionRecordV1 } from '../../packages/sdk-server-ts/src/core/deviceLinking/linkedDeviceSession';
import type { FetchRouterApiContext } from '../../packages/sdk-server-ts/src/router/transport/fetch/fetchRouter.types';
import type { RouterApiServiceBag } from '../../packages/sdk-server-ts/src/router/framework/authServicePort';
import { createFetchRouter } from '../../packages/sdk-server-ts/src/router/transport/fetch/createFetchRouter';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';

test('authenticates the Gateway before parsing completion JSON', async () => {
  let parsedBody = false;
  const service = completionService({
    authenticateGatewayRequestV1: async () => ({
      kind: 'denied' as const,
      code: 'unauthorized' as const,
      message: 'Gateway authentication is required',
    }),
    parseBody: () => {
      parsedBody = true;
    },
  });
  const response = await invoke(service, {
    pathname: `${LINKED_DEVICE_GATEWAY_COMPLETION_BASE_V1}/link-session:r103/commit`,
    bodyText: '{malformed',
  });
  expect(response.status).toBe(401);
  expect(parsedBody).toBe(false);
});

test('mounts the private Gateway route and fails closed when it is omitted', async () => {
  const path = `${LINKED_DEVICE_GATEWAY_COMPLETION_BASE_V1}/link-session:r103/commit`;
  const request = new Request(`https://example.test${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{malformed',
  });
  const authDeniedService = completionService({
    authenticateGatewayRequestV1: async () => ({
      kind: 'denied' as const,
      code: 'unauthorized' as const,
      message: 'Gateway authentication is required',
    }),
  });
  const configured = createFetchRouter(
    { deviceLinkingGateway: authDeniedService } as unknown as RouterApiServiceBag,
    {},
    { kind: 'inline' },
  );
  await expect(configured(request)).resolves.toHaveProperty('status', 401);

  const omitted = createFetchRouter({} as RouterApiServiceBag, {}, { kind: 'inline' });
  await expect(omitted(request.clone())).resolves.toHaveProperty('status', 501);
});

test('replays committed completion without invoking a public device route', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const records = await buildCompletionRecords(fixture);
  let calls = 0;
  const service = completionService({
    authenticateGatewayRequestV1: authenticatedBody,
    sessionService: {
      markCommittedCompletionRequiredV1: async () => {
        calls += 1;
        return {
          outcome: calls === 1 ? ('applied' as const) : ('replayed' as const),
          record: records.committed,
        };
      },
    },
  });
  const body = JSON.stringify({
    kind: 'linked_device_gateway_commit_request_v1',
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: records.committed.revision - 1,
    transcriptSetDigestB64u: fixture.approval.policyDigestB64u,
    requestedAtMs: 5_000,
  });
  const first = await invoke(service, {
    pathname: `${LINKED_DEVICE_GATEWAY_COMPLETION_BASE_V1}/${fixture.payload.linkSessionId}/commit`,
    bodyText: body,
  });
  expect(first.status).toBe(200);
  expect(await first.json()).toMatchObject({
    ok: true,
    outcome: 'applied',
    state: { state: 'committed_completion_required' },
  });
  const replay = await invoke(service, {
    pathname: `${LINKED_DEVICE_GATEWAY_COMPLETION_BASE_V1}/${fixture.payload.linkSessionId}/commit`,
    bodyText: body,
  });
  expect(replay.status).toBe(200);
  expect(await replay.json()).toMatchObject({
    ok: true,
    outcome: 'replayed',
    state: { state: 'committed_completion_required' },
  });
  expect(calls).toBe(2);
});

test('returns the exact aggregate receipt for activation and replay', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const records = await buildCompletionRecords(fixture);
  let calls = 0;
  let observedReceipt = false;
  const service = completionService({
    authenticateGatewayRequestV1: authenticatedBody,
    sessionService: {
      recordAggregateActivationV1: async ({ receipt }) => {
        calls += 1;
        observedReceipt =
          receipt.orderedChildReceipts.length === fixture.receipt.orderedChildReceipts.length;
        return {
          outcome: calls === 1 ? ('applied' as const) : ('replayed' as const),
          record: records.active,
        };
      },
    },
  });
  const bodyText = JSON.stringify({
    kind: 'linked_device_gateway_activation_request_v1',
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: records.active.revision - 1,
    receipt: fixture.receipt,
    requestedAtMs: 5_000,
  });
  const first = await invoke(service, {
    pathname: `${LINKED_DEVICE_GATEWAY_COMPLETION_BASE_V1}/${fixture.payload.linkSessionId}/activate`,
    bodyText,
  });
  expect(first.status).toBe(200);
  const firstBody = await first.json();
  expect(firstBody).toEqual({ ok: true, outcome: 'applied', receipt: fixture.receipt });
  expect(firstBody).not.toHaveProperty('claimTranscript');
  const replay = await invoke(service, {
    pathname: `${LINKED_DEVICE_GATEWAY_COMPLETION_BASE_V1}/${fixture.payload.linkSessionId}/activate`,
    bodyText,
  });
  expect(replay.status).toBe(200);
  expect(await replay.json()).toEqual({ ok: true, outcome: 'replayed', receipt: fixture.receipt });
  expect(observedReceipt).toBe(true);
  expect(calls).toBe(2);
});

function completionService(
  overrides: Partial<DeviceLinkingGatewayCompletionServiceV1> & {
    readonly parseBody?: () => void;
  } = {},
): DeviceLinkingGatewayCompletionServiceV1 {
  const parseBody = overrides.parseBody;
  const service: DeviceLinkingGatewayCompletionServiceV1 = {
    sessionService: {
      markCommittedCompletionRequiredV1: async () => {
        throw new Error('commit adapter not configured');
      },
      recordAggregateActivationV1: async () => {
        throw new Error('activation adapter not configured');
      },
    },
    nowV1: () => 5_000,
    authenticateGatewayRequestV1: async ({ request, bodyDigestB64u, method, pathname }) => ({
      kind: 'authorized' as const,
      body: parseBody
        ? (parseBody(), JSON.parse(await request.text()))
        : JSON.parse(await request.text()),
      binding: {
        kind: 'linked_device_gateway_request_binding_v1' as const,
        method: method as 'POST',
        pathname,
        bodyDigestB64u,
        expiresAtMs: 6_000,
      },
    }),
  };
  return {
    ...service,
    ...overrides,
    sessionService: { ...service.sessionService, ...overrides.sessionService },
  };
}

async function authenticatedBody({
  request,
  bodyDigestB64u,
  method,
  pathname,
}: Parameters<DeviceLinkingGatewayCompletionServiceV1['authenticateGatewayRequestV1']>[0]) {
  return {
    kind: 'authorized' as const,
    body: JSON.parse(await request.text()),
    binding: {
      kind: 'linked_device_gateway_request_binding_v1' as const,
      method: method as 'POST',
      pathname,
      bodyDigestB64u,
      expiresAtMs: 6_000,
    },
  };
}

async function invoke(
  service: DeviceLinkingGatewayCompletionServiceV1,
  input: { readonly pathname: string; readonly bodyText: string },
): Promise<Response> {
  const request = new Request(`https://example.test${input.pathname}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: input.bodyText,
  });
  const context = {
    request,
    url: new URL(request.url),
    pathname: input.pathname,
    method: 'POST',
    runtime: { kind: 'inline' as const },
    service: {},
    opts: {},
    logger: {},
    mePath: '/me',
    routeDefinitions: [],
  } as unknown as FetchRouterApiContext;
  const response = await handleDeviceLinkingGatewayCompletion(context, service);
  if (!response) throw new Error('gateway completion route did not match');
  return response;
}

async function buildCompletionRecords(fixture: ReturnType<typeof buildR103DeviceLinkFixture>) {
  const claim = buildLinkedDeviceSessionClaimV1({
    linkSessionId: fixture.payload.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
    claimedAtMs: 3_001,
    claimExpiresAtMs: 8_000,
  });
  const approval = { ...fixture.approval, expiresAtMs: 8_000 };
  const claimDigestB64u = await computeLinkedDeviceSessionClaimDigestV1(claim);
  const approvalDigestB64u = await computeLinkedDeviceApprovalDigestV1(approval);
  const transcript = {
    claimTranscript: { digestB64u: claimDigestB64u, value: claim },
    approvalTranscript: { digestB64u: approvalDigestB64u, value: approval },
  } as const;
  const committed = parseLinkedDeviceSessionRecordV1({
    version: 'linked_device_session_v1',
    linkSessionId: fixture.payload.linkSessionId,
    qrPayload: fixture.payload,
    state: {
      state: 'committed_completion_required',
      linkSessionId: fixture.payload.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      transcriptSetDigestB64u: fixture.approval.policyDigestB64u,
    },
    revision: 3,
    ...transcript,
    createdAtMs: 3_000,
    updatedAtMs: 5_000,
  });
  const active = parseLinkedDeviceSessionRecordV1({
    version: 'linked_device_session_v1',
    linkSessionId: fixture.payload.linkSessionId,
    qrPayload: fixture.payload,
    state: {
      state: 'active',
      linkSessionId: fixture.payload.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      activatedAtMs: fixture.receipt.activatedAtMs,
    },
    revision: 4,
    ...transcript,
    aggregateReceipt: fixture.receipt,
    createdAtMs: 3_000,
    updatedAtMs: fixture.receipt.activatedAtMs,
  });
  return { committed, active };
}
