import { expect, test } from '@playwright/test';
import {
  computeLinkedDevicePublicKeyDigestV1,
} from '../../packages/sdk-server-ts/src/core/deviceLinking/requestProof';
import { createD1LinkedDeviceRouteServiceV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking';
import { D1LinkedDeviceAggregateActivationVerifierV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceAggregateActivationVerifier';
import type { LinkedDeviceOwnerAuthorizationPortV1 } from '../../packages/sdk-server-ts/src/core/deviceLinking/linkedDeviceSession';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseLinkDeviceSessionId,
} from '@shared/signing-lanes/ids';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseWalletId } from '@shared/utils/domainIds';
import { buildSignedDeviceRequestProofFixtureV1 } from './helpers/deviceRequestProof.fixtures';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';

const scope = {
  namespace: 'signer',
  orgId: 'org_route_service_test',
  projectId: 'project_route_service_test',
  envId: 'env_route_service_test',
} as const;
const linkSessionId = parseLinkDeviceSessionId('link-session:route-service').value;
const nowMs = 1_000;
let temporary: TemporaryD1Database | undefined;

test.afterEach(() => {
  if (temporary) cleanupTemporaryD1Database(temporary.tempDir);
  temporary = undefined;
});

test('rejects linked activation when the R102 enrollment is absent', async () => {
  const verifier = new D1LinkedDeviceAggregateActivationVerifierV1({
    lifecycleStore: {
      getEnrollment: async () => null,
      getProtocol: async () => null,
      listEnrollmentProductEpochs: async () => [],
    },
  });
  const enrollmentId = parseLinkedDeviceEnrollmentId('linked-device-enrollment-missing');
  const walletId = parseWalletId('wallet-route-service').value;
  const deviceId = parseLinkedDeviceId('device-route-service').value;
  if (!enrollmentId.ok) throw new Error('fixture enrollment id is invalid');
  const result = await verifier.verifyAggregateActivationV1({
    enrollmentId: enrollmentId.value,
    walletId,
    deviceId,
    manifestDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32))),
    orderedChildReceipts: [],
  });
  expect(result).toEqual({ kind: 'rejected', message: 'R102 lane enrollment is not admitted' });
});

test('composes D1 session and proof stores and authenticates before reading JSON', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = await buildSignedDeviceRequestProofFixtureV1({
    linkSessionId,
    canonicalPath: '/wallet/device-linking/v1/sessions/link-session:route-service/cancel',
    bodyText: '{"ok":true}',
    issuedAtMs: 950,
    expiresAtMs: 1_050,
    nonceByte: 18,
  });
  const publicKeyB64u = base64UrlEncode(fixture.publicKey);
  const { proof } = fixture;
  const routeService = createD1LinkedDeviceRouteServiceV1({
    database: temporary.database,
    scope,
    ownerAuthorization: ownerAuthorization(),
    authenticateOwnerRequestV1: async () => ({
      kind: 'denied' as const,
      code: 'unauthorized' as const,
      message: 'owner auth is not used in this test',
    }),
    registerTargetCredentialV1: async () => {
      throw new Error('credential adapter not configured');
    },
    acknowledgeReceiptV1: async () => {
      throw new Error('receipt adapter not configured');
    },
    retryCommittedDeliveryV1: async () => {
      throw new Error('retry adapter not configured');
    },
    nowV1: () => nowMs,
  });
  const request = new Request('https://example.test/wallet/device-linking/v1/sessions/link-session:route-service/cancel', {
    method: 'POST',
    body: '{"ok":true}',
  });
  const result = await routeService.authenticateDeviceRequestV1({
    request,
    method: 'POST',
    pathname: '/wallet/device-linking/v1/sessions/link-session:route-service/cancel',
    linkSessionId: String(linkSessionId),
    bodyDigestB64u: proof.bodyDigestB64u,
    expectedDevicePublicKeyB64u: publicKeyB64u,
    expectedDevicePublicKeyDigestB64u: await computeLinkedDevicePublicKeyDigestV1(publicKeyB64u),
    proof,
    requestedAtMs: nowMs,
  });
  expect(result.kind).toBe('authorized');
  if (result.kind === 'authorized') expect(result.body).toEqual({ ok: true });
});

test('forwards authenticated session reads through core expiry projection', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  let clockMs = 3_000;
  const routeService = createD1LinkedDeviceRouteServiceV1({
    database: temporary.database,
    scope,
    ownerAuthorization: ownerAuthorization(),
    authenticateOwnerRequestV1: async () => ({
      kind: 'denied' as const,
      code: 'unauthorized' as const,
      message: 'owner auth is not used in this test',
    }),
    registerTargetCredentialV1: async () => {
      throw new Error('credential adapter not configured');
    },
    acknowledgeReceiptV1: async () => {
      throw new Error('receipt adapter not configured');
    },
    retryCommittedDeliveryV1: async () => {
      throw new Error('retry adapter not configured');
    },
    nowV1: () => clockMs,
  });

  const created = await routeService.sessionService.createUnclaimedSessionV1({
    payload: fixture.payload,
    nowMs: clockMs,
  });
  expect(created.outcome).toBe('applied');

  const rawBeforeExpiry = await routeService.sessionService.getSessionV1(fixture.payload.linkSessionId);
  expect(rawBeforeExpiry?.state.state).toBe('displaying_qr');

  clockMs = fixture.payload.expiresAtMs + 1;
  const projectedAfterExpiry = await routeService.sessionService.getSessionV1({
    linkSessionId: fixture.payload.linkSessionId,
    nowMs: clockMs,
  });
  expect(projectedAfterExpiry?.state.state).toBe('expired_unclaimed');
});

function ownerAuthorization(): LinkedDeviceOwnerAuthorizationPortV1 {
  return {
    authorizeOwnerClaimV1: async () => {
      throw new Error('owner claim auth is not used in this test');
    },
    authorizeOwnerApprovalV1: async () => ({ kind: 'authorized' as const }),
  };
}
