import { expect, test } from '@playwright/test';
import { parseLinkedDeviceEnrollmentId, parseLinkedDeviceId } from '@shared/signing-lanes';
import { parseAuthorizedOperationId } from '@shared/authorization/capabilityKinds';
import {
  parseWalletSessionId,
  parseWalletSessionAuthorizationId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { parseWalletId } from '@shared/utils/domainIds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256Bytes } from '@shared/utils/digests';
import {
  buildLinkedDeviceSessionClaimV1,
  parseLinkedDeviceWalletSessionDeliveryV1,
} from '@shared/device-linking/parsers';
import {
  computeLinkedDeviceApprovalDigestV1,
  computeLinkedDeviceSessionClaimDigestV1,
} from '@shared/device-linking/digests';
import {
  ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
  decodeJwtPayloadRecord,
} from '@shared/utils/sessionTokens';
import {
  buildR103DeviceLinkFixture,
  buildR103OwnerEnrollmentCeremonyReaderV1,
  buildR103ProvisioningFixture,
} from './helpers/deviceLinkContracts.fixtures';
import {
  LinkedDeviceSessionServiceV1,
  type LinkedDeviceAggregateActivationVerifierV1,
  type LinkedDeviceOwnerAuthorizationPortV1,
  parseLinkedDeviceSessionRecordV1,
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
  buildLaneEnrollmentManifestV1,
  parseRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';
import {
  buildR103ActiveLinkedDeviceSessionRecordV1,
  buildR103IssuedLinkedDeviceWalletSessionV1,
  LinkedDeviceJwtSessionAdapterV1,
} from './helpers/deviceLinkingServer.fixtures';

const scope: D1LinkedDeviceSessionScopeV1 = {
  namespace: 'signer',
  orgId: 'org_route_test',
  projectId: 'project_route_test',
  envId: 'env_route_test',
};

let temporary: TemporaryD1Database | undefined;

const aggregateActivationVerifier = {
  verifyAggregateActivationV1: async () => ({ kind: 'verified' as const }),
} satisfies LinkedDeviceAggregateActivationVerifierV1;

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
    ownerEnrollmentCeremonies: buildR103OwnerEnrollmentCeremonyReaderV1(fixture.approval),
    store,
    authorization: ownerAuthorization(),
    aggregateActivationVerifier,
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
    ownerEnrollmentCeremonies: buildR103OwnerEnrollmentCeremonyReaderV1(fixture.approval),
    store,
    authorization: ownerAuthorization(),
    aggregateActivationVerifier,
  });
  const routeService = routeServiceFor(sessionService, 3_000, {
    authenticateOwnerRequestV1: async ({ request, method, pathname, bodyDigestB64u }) => ({
      kind: 'authorized' as const,
      body: method === 'GET' ? null : await request.json(),
      owner: ownerRequestContext(),
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

  const deliveredApproval = await invoke(routeService, {
    method: 'GET',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/approval`,
  });
  expect(deliveredApproval.status).toBe(200);
  const deliveredApprovalBody = await deliveredApproval.json();
  expect(deliveredApprovalBody.kind).toBe('linked_device_approval_delivery_v1');
  expect(deliveredApprovalBody.approval).toEqual(approval);
});

test('owner target-ready GET authenticates before parsing and returns the exact R102 jobs', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const provisioning = buildR103ProvisioningFixture(fixture);
  const sourceJob = provisioning.deliveries.orderedChildren[0]?.job;
  if (!sourceJob) throw new Error('source fixture has no job');
  const authorizedOperationId = parseAuthorizedOperationId(String(fixture.approval.operationId));
  if (!authorizedOperationId.ok) throw new Error(authorizedOperationId.error.message);
  const job = parseRotatableSigningLaneJobV1({
    ...sourceJob,
    expiresAtMs: 8_000,
    authorization: {
      kind: 'linked_device_enrollment',
      authorizedOperationId: authorizedOperationId.value,
      linkedDeviceEnrollmentId: fixture.approval.enrollmentId,
      linkedDevicePermissionDigestB64u: fixture.approval.policyDigestB64u,
    },
  });
  const manifest = buildLaneEnrollmentManifestV1({
    enrollmentId: job.enrollmentId,
    walletId: job.walletId,
    authorization: job.authorization,
    orderedChildren: [
      {
        operationId: job.operationId,
        walletKeyId: job.walletKeyId,
        keyFamily: job.keyFamily,
        sourceLaneId: job.source.laneId,
        sourceLaneShareEpoch: job.source.laneShareEpoch,
        sourceRevocationEpoch: job.source.revocationEpoch,
        sourceMaterialActivation: job.source.materialActivation,
        targetLaneId: job.target.laneId,
        targetLaneShareEpoch: job.target.laneShareEpoch,
        targetMaterialActivationId: job.targetMaterialActivationId,
        holderParticipantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
        signingWorkerParticipantBindingDigestB64u:
          job.targetSigningWorker.participantBindingDigestB64u,
      },
    ],
    createdAtMs: 1_000,
    expiresAtMs: 9_000,
  });
  const targetReady = {
    kind: 'linked_device_target_ready_r102_input_v1' as const,
    linkSessionId: fixture.approval.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    manifest,
    children: [job] as const,
  };
  let ownerAuthCalls = 0;
  const store = new D1LinkedDeviceSessionStoreV1({ database: temporary.database, scope });
  const sessionService = new LinkedDeviceSessionServiceV1({
    ownerEnrollmentCeremonies: buildR103OwnerEnrollmentCeremonyReaderV1(fixture.approval),
    store,
    authorization: ownerAuthorization(),
    aggregateActivationVerifier,
  });
  const routeService = routeServiceFor(sessionService, 3_000, {
    authenticateOwnerRequestV1: async ({ request, method, pathname, bodyDigestB64u }) => {
      ownerAuthCalls += 1;
      return {
        kind: 'authorized' as const,
        body: method === 'GET' ? null : await request.json(),
        owner: ownerRequestContext(),
        binding: requestBinding(method, pathname, bodyDigestB64u, 3_000),
      };
    },
    sourceHandoff: {
      getTargetReadyV1: async () => targetReady,
      submitPreparedProvisioningDeliveriesV1: async () => {
        throw new Error('prepared delivery submission is not used in this test');
      },
    },
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
  const approved = await invoke(routeService, {
    method: 'POST',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/approval`,
    body: { ...fixture.approval, expiresAtMs: 9_000 },
  });
  expect(approved.status).toBe(200);
  const response = await invoke(routeService, {
    method: 'GET',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/target-ready`,
  });
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual(targetReady);
  expect(ownerAuthCalls).toBe(3);
});

test('authenticates owner before parsing claim and returns no session secrets', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const store = new D1LinkedDeviceSessionStoreV1({ database: temporary.database, scope });
  const sessionService = new LinkedDeviceSessionServiceV1({
    ownerEnrollmentCeremonies: buildR103OwnerEnrollmentCeremonyReaderV1(fixture.approval),
    store,
    authorization: ownerAuthorization(),
    aggregateActivationVerifier,
  });
  let ownerAuthCalls = 0;
  const routeService = routeServiceFor(sessionService, 3_000, {
    authenticateOwnerRequestV1: async ({ request, method, pathname, bodyDigestB64u }) => {
      ownerAuthCalls += 1;
      return {
        kind: 'authorized' as const,
        body: await request.json(),
        owner: ownerRequestContext(),
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
    ownerEnrollmentCeremonies: buildR103OwnerEnrollmentCeremonyReaderV1(fixture.approval),
    store,
    authorization: ownerAuthorization(),
    aggregateActivationVerifier,
  });
  let firstProof: DeviceLinkingRequestProofV1 | undefined;
  const observed: Array<{
    method: string;
    pathname: string;
    linkSessionId: string;
    bodyDigestB64u: string;
  }> = [];
  const routeService = routeServiceFor(sessionService, 3_000, {
    authenticateDeviceRequestV1: async ({
      request,
      method,
      pathname,
      linkSessionId,
      bodyDigestB64u,
      proof,
    }) => {
      observed.push({ method, pathname, linkSessionId, bodyDigestB64u });
      const verifiedProof = firstProof ?? proof;
      firstProof = verifiedProof;
      return {
        kind: 'authorized' as const,
        body: await request.json(),
        owner: ownerRequestContext(),
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

test('delivers one authenticated linked Wallet Session JWT for each approved key family', async () => {
  const fixture = buildR103DeviceLinkFixture();
  for (const keyFamily of ['ed25519', 'ecdsa_secp256k1'] as const) {
    const active = await buildR103ActiveLinkedDeviceSessionRecordV1(fixture, keyFamily);
    const issued = await buildR103IssuedLinkedDeviceWalletSessionV1(active);
    let authorizationReads = 0;
    const routeService = routeServiceFor(
      sessionServiceForRecord(active),
      active.aggregateReceipt.activatedAtMs + 1,
      {
        readWalletSessionAuthorizationV1: async () => {
          authorizationReads += 1;
          return { kind: 'active' as const, authorization: issued };
        },
      },
    );
    const response = await invoke(routeService, {
      method: 'GET',
      pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/wallet-session`,
      sessionAdapter: new LinkedDeviceJwtSessionAdapterV1(),
    });

    expect(response.status).toBe(200);
    const delivery = parseLinkedDeviceWalletSessionDeliveryV1(await response.json());
    expect(authorizationReads).toBe(1);
    expect(delivery.walletId).toBe(active.state.walletId);
    expect(delivery.enrollmentId).toBe(active.state.enrollmentId);
    expect(delivery.orderedTokens).toHaveLength(1);
    expect(delivery.orderedTokens[0]).toMatchObject({
      walletKeyId: active.approvalTranscript.value.orderedKeyBindings[0].walletKeyId,
      keyFamily,
    });
    const claims = decodeJwtPayloadRecord(delivery.orderedTokens[0].walletSessionJwt);
    expect(claims?.kind).toBe(
      keyFamily === 'ed25519'
        ? ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND
        : ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
    );
    expect(claims?.authorizationKind).toBe('linked_device_wallet_session');
  }

  const active = await buildR103ActiveLinkedDeviceSessionRecordV1(fixture);
  const unavailable = await invoke(
    routeServiceFor(sessionServiceForRecord(active), active.aggregateReceipt.activatedAtMs + 1),
    {
      method: 'GET',
      pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/wallet-session`,
    },
  );
  expect(unavailable.status).toBe(409);
  expect(await unavailable.json()).toMatchObject({ code: 'authorization_unavailable' });
});

test('operator recovery is a separate authority and stays fail-closed without it', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const active = await buildR103ActiveLinkedDeviceSessionRecordV1(fixture);
  const recoveryDevicePublicKey = new Uint8Array(32).fill(9);
  const recoveryRequest = {
    kind: 'linked_device_session_operator_recovery_request_v1' as const,
    linkSessionId: fixture.payload.linkSessionId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    devicePublicKeyB64u: base64UrlEncode(recoveryDevicePublicKey),
    devicePublicKeyDigestB64u: base64UrlEncode(await sha256Bytes(recoveryDevicePublicKey)),
    reason: 'original_link_session_lost' as const,
    requestedAtMs: 4_000,
  };
  const pathname = `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/operator-recovery`;
  const unavailable = await invoke(routeServiceFor(sessionServiceForRecord(active), 4_000), {
    method: 'POST',
    pathname,
    body: recoveryRequest,
  });
  expect(unavailable.status).toBe(501);
  expect(await unavailable.json()).toMatchObject({ code: 'not_supported' });

  let operatorAuthCalls = 0;
  const configured = await invoke(
    routeServiceFor(sessionServiceForRecord(active), 4_000, {
      operatorRecovery: {
        authenticateOperatorRecoveryRequestV1: async ({
          request,
          method,
          pathname: requestPath,
          bodyDigestB64u,
        }) => {
          operatorAuthCalls += 1;
          return {
            kind: 'authorized' as const,
            body: await request.json(),
            owner: ownerRequestContext(),
            binding: {
              kind: 'linked_device_operator_request_binding_v1' as const,
              method: method as 'POST',
              pathname: requestPath,
              bodyDigestB64u,
              expiresAtMs: 5_000,
            },
          };
        },
      },
    }),
    { method: 'POST', pathname, body: recoveryRequest },
  );
  expect(configured.status).toBe(409);
  expect(await configured.json()).toMatchObject({
    outcome: 'invalid_state',
    state: 'active',
  });
  expect(operatorAuthCalls).toBe(1);
});

test('operator recovery binds a fresh proof key before retrying committed delivery', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const claim = buildLinkedDeviceSessionClaimV1({
    linkSessionId: fixture.payload.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
    claimedAtMs: 1_500,
    claimExpiresAtMs: 9_000,
  });
  let persisted = parseLinkedDeviceSessionRecordV1({
    version: 'linked_device_session_v1',
    linkSessionId: fixture.payload.linkSessionId,
    qrPayload: fixture.payload,
    state: {
      state: 'committed_completion_required',
      linkSessionId: fixture.payload.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      keyManifestDigestB64u: fixture.receipt.manifestDigestB64u,
      transcriptSetDigestB64u: fixture.approval.policyDigestB64u,
    },
    revision: 3,
    claimTranscript: {
      digestB64u: await computeLinkedDeviceSessionClaimDigestV1(claim),
      value: claim,
    },
    approvalTranscript: {
      digestB64u: await computeLinkedDeviceApprovalDigestV1(fixture.approval),
      value: fixture.approval,
      sourceKeyManifestDigestB64u: fixture.receipt.manifestDigestB64u,
    },
    createdAtMs: 1_000,
    updatedAtMs: 4_000,
  });
  let bindCalls = 0;
  let retriedSession: typeof persisted | undefined;
  const baseSessionService = sessionServiceForRecord(persisted);
  const sessionService: DeviceLinkingRouteServiceV1['sessionService'] = {
    ...baseSessionService,
    getSessionV1: async () => persisted,
    bindRecoveryContinuationV1: async ({ continuation }) => {
      bindCalls += 1;
      if (persisted.recovery.kind === 'bound') return { outcome: 'replayed', record: persisted };
      persisted = parseLinkedDeviceSessionRecordV1({
        ...persisted,
        recovery: { kind: 'bound', continuation },
        revision: persisted.revision + 1,
        updatedAtMs: 5_000,
      });
      return { outcome: 'applied', record: persisted };
    },
  };
  const recoveryDevicePublicKey = new Uint8Array(32).fill(9);
  const recoveryRequest = {
    kind: 'linked_device_session_operator_recovery_request_v1' as const,
    linkSessionId: fixture.payload.linkSessionId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    devicePublicKeyB64u: base64UrlEncode(recoveryDevicePublicKey),
    devicePublicKeyDigestB64u: base64UrlEncode(await sha256Bytes(recoveryDevicePublicKey)),
    reason: 'original_link_session_lost' as const,
    requestedAtMs: 4_500,
  };
  const pathname = `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/operator-recovery`;
  const routeService = routeServiceFor(sessionService, 5_000, {
    authenticateDeviceRequestV1: async ({ request, method, expectedDevicePublicKeyB64u, proof }) =>
      expectedDevicePublicKeyB64u === recoveryRequest.devicePublicKeyB64u
        ? {
            kind: 'authorized' as const,
            body: method === 'GET' ? null : await request.json(),
            owner: ownerRequestContext(),
            proof,
          }
        : {
            kind: 'denied' as const,
            code: 'invalid' as const,
            message: 'device request-proof key is not bound to this session',
          },
    operatorRecovery: {
      authenticateOperatorRecoveryRequestV1: async ({
        request,
        method,
        pathname: requestPath,
        bodyDigestB64u,
      }) => ({
        kind: 'authorized' as const,
        body: await request.json(),
        owner: ownerRequestContext(),
        binding: {
          kind: 'linked_device_operator_request_binding_v1' as const,
          method: method as 'POST',
          pathname: requestPath,
          bodyDigestB64u,
          expiresAtMs: 6_000,
        },
      }),
    },
    retryCommittedDeliveryV1: async ({ session }) => {
      retriedSession = session;
      return { outcome: 'applied', record: session };
    },
  });
  const response = await invoke(routeService, {
    method: 'POST',
    pathname,
    body: recoveryRequest,
  });
  expect(response.status).toBe(200);
  expect(bindCalls).toBe(1);
  expect(retriedSession?.recovery.kind).toBe('bound');
  expect(
    retriedSession?.recovery.kind === 'bound' && retriedSession.recovery.continuation,
  ).toMatchObject({
    deviceId: fixture.approval.deviceId,
    enrollmentId: fixture.approval.enrollmentId,
    linkSessionId: fixture.payload.linkSessionId,
    devicePublicKeyB64u: recoveryRequest.devicePublicKeyB64u,
    devicePublicKeyDigestB64u: recoveryRequest.devicePublicKeyDigestB64u,
  });
  const retryBody = {
    kind: 'linked_device_session_retry_committed_delivery_request_v1' as const,
    linkSessionId: fixture.payload.linkSessionId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    requestedAtMs: 4_500,
  };
  const freshRetry = await invoke(routeService, {
    requestProofKey: recoveryDevicePublicKey,
    method: 'POST',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/retry`,
    body: retryBody,
  });
  expect(freshRetry.status).toBe(200);
  persisted = parseLinkedDeviceSessionRecordV1({
    ...persisted,
    state: {
      state: 'active',
      linkSessionId: fixture.payload.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      activatedAtMs: fixture.receipt.activatedAtMs,
    },
    aggregateReceipt: fixture.receipt,
    revision: persisted.revision + 1,
    updatedAtMs: 5_100,
  });
  const activeFreshGet = await invoke(routeService, {
    requestProofKey: recoveryDevicePublicKey,
    method: 'GET',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}`,
  });
  expect(activeFreshGet.status).toBe(200);
  const activeOldGet = await invoke(routeService, {
    method: 'GET',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}`,
  });
  expect(activeOldGet.status).toBe(400);
  const oldRetry = await invoke(routeService, {
    method: 'POST',
    pathname: `/wallet/device-linking/v1/sessions/${fixture.payload.linkSessionId}/retry`,
    body: retryBody,
  });
  expect(oldRetry.status).toBe(400);
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
    recordTargetCredentialV1: sessionService.recordTargetCredentialV1.bind(sessionService),
    bindRecoveryContinuationV1: sessionService.bindRecoveryContinuationV1.bind(sessionService),
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
    resolveNearAccountIdForEd25519WalletKeyV1: async () => 'wallet-r103.testnet',
    authenticateOwnerRequestV1: async ({ request, method, pathname, bodyDigestB64u }) => ({
      kind: 'authorized' as const,
      body: await request.json(),
      owner: ownerRequestContext(),
      binding: requestBinding(method, pathname, 'link-session:r103', bodyDigestB64u, nowMs),
    }),
    authenticateDeviceRequestV1: async ({ proof }) => ({
      kind: 'authorized' as const,
      body: null,
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
    acknowledgeReceiptV1: async () => {
      throw new Error('receipt adapter not configured for this test');
    },
    retryCommittedDeliveryV1: async () => {
      throw new Error('retry adapter not configured for this test');
    },
    readWalletSessionAuthorizationV1: async () => ({ kind: 'unavailable' as const }),
    provisioning: {
      provisionLinkedDeviceV1: async () => {
        throw new Error('provisioning adapter not configured for this test');
      },
      recordHolderDeliveriesV1: async () => {
        throw new Error('holder delivery adapter not configured for this test');
      },
    },
    provisioningVerifier: {
      verifyProvisioningDeliveriesV1: async () => undefined,
      verifyHolderDeliveriesV1: async () => undefined,
    },
    sourceHandoff: {
      getTargetReadyV1: async () => null,
      submitPreparedProvisioningDeliveriesV1: async () => {
        throw new Error('source handoff adapter not configured for this test');
      },
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
  input: {
    readonly method: string;
    readonly pathname: string;
    readonly body?: unknown;
    readonly requestProofKey?: Uint8Array;
    readonly sessionAdapter?: LinkedDeviceJwtSessionAdapterV1;
  },
): Promise<Response> {
  const bodyText = input.body === undefined ? undefined : JSON.stringify(input.body);
  const headers = new Headers();
  headers.set(
    DEVICE_LINKING_REQUEST_PROOF_HEADER_V1,
    await requestProofHeader(input.method, input.pathname, bodyText, input.requestProofKey),
  );
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
    opts: input.sessionAdapter ? { session: input.sessionAdapter } : {},
    logger: {},
    mePath: '/me',
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
  devicePublicKey: Uint8Array = new Uint8Array(32).fill(8),
): Promise<string> {
  const bodyDigestB64u = base64UrlEncode(
    await sha256Bytes(new TextEncoder().encode(bodyText ?? '')),
  );
  const devicePublicKeyDigestB64u = base64UrlEncode(await sha256Bytes(devicePublicKey));
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

function sessionServiceForRecord(
  record: Awaited<ReturnType<typeof buildR103ActiveLinkedDeviceSessionRecordV1>>,
): DeviceLinkingRouteServiceV1['sessionService'] {
  return {
    createUnclaimedSessionV1: async () => {
      throw new Error('session creation is outside the active delivery fixture');
    },
    claimSessionV1: async () => {
      throw new Error('session claim is outside the active delivery fixture');
    },
    recordOwnerApprovalV1: async () => {
      throw new Error('session approval is outside the active delivery fixture');
    },
    recordTargetCredentialV1: async () => {
      throw new Error('target registration is outside the active delivery fixture');
    },
    bindRecoveryContinuationV1: async () => {
      throw new Error('recovery continuation is outside the active delivery fixture');
    },
    cancelSessionV1: async () => {
      throw new Error('session cancellation is outside the active delivery fixture');
    },
    getSessionV1: async () => record,
  };
}

/**
 * The verified owner Wallet Session context the routes authenticate with.
 * Approval reads the source key manifest from here, so a stub that omits it no
 * longer stands in for a real owner request.
 */
function ownerRequestContext() {
  return {
    walletId: parseWalletId('wallet:r103').value,
    walletSessionId: parseWalletSessionId('ws:r103').value,
    authorizationId: parseWalletSessionAuthorizationId('wsa:r103').value,
    expiresAtMs: 9_000,
    keyManifestDigestB64u: parseDigestB64u('Lcwi4R-zFWWooZJB2zonKJtBMlynySPIjt55tietXWE'),
    curve: 'ed25519' as const,
  };
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
