import { expect, test } from '@playwright/test';
import { computeLinkedDevicePublicKeyDigestV1 } from '../../packages/wallet-server/src/core/deviceLinking/requestProof';
import type { LinkedDeviceOwnerAuthorizationPortV1 } from '../../packages/wallet-server/src/core/deviceLinking/linkedDeviceSession';
import {
  createD1LinkedDeviceRouteServiceV1,
  type D1LinkedDeviceSessionScopeV1,
} from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking';
import { parseLinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { base64UrlEncode } from '@shared/utils/base64';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import { buildSignedDeviceRequestProofFixtureV1 } from './helpers/deviceRequestProof.fixtures';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';

const scope: D1LinkedDeviceSessionScopeV1 = {
  namespace: 'signer',
  orgId: 'org_route_service_test',
  projectId: 'project_route_service_test',
  envId: 'env_route_service_test',
};

const linkSessionId = parseLinkDeviceSessionId('link-session:route-service').value;
const nowMs = 1_000;
let temporary: TemporaryD1Database | undefined;

test.afterEach(() => {
  if (temporary) cleanupTemporaryD1Database(temporary.tempDir);
  temporary = undefined;
});

test('composes D1 session and proof stores before reading authenticated JSON', async () => {
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
  const routeService = createD1LinkedDeviceRouteServiceV1({
    database: temporary.database,
    scope,
    ownerAuthorization: ownerAuthorization(),
    authenticateOwnerRequestV1: async () => ({
      kind: 'denied' as const,
      code: 'unauthorized' as const,
      message: 'owner auth is not used in this test',
    }),
    targetCredential: targetCredentialNotConfigured(),
    nowV1: () => nowMs,
  });
  const request = new Request(
    'https://example.test/wallet/device-linking/v1/sessions/link-session:route-service/cancel',
    { method: 'POST', body: '{"ok":true}' },
  );
  const result = await routeService.authenticateDeviceRequestV1({
    request,
    method: 'POST',
    pathname: '/wallet/device-linking/v1/sessions/link-session:route-service/cancel',
    linkSessionId: String(linkSessionId),
    bodyDigestB64u: fixture.proof.bodyDigestB64u,
    expectedDevicePublicKeyB64u: publicKeyB64u,
    expectedDevicePublicKeyDigestB64u: await computeLinkedDevicePublicKeyDigestV1(publicKeyB64u),
    proof: fixture.proof,
    requestedAtMs: nowMs,
  });
  expect(result.kind).toBe('authorized');
  if (result.kind === 'authorized') expect(result.body).toEqual({ ok: true });
  expect(routeService.ed25519ExportRoot).toBeDefined();
});

test('expires a precommit session through the composed service read boundary', async () => {
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
    targetCredential: targetCredentialNotConfigured(),
    nowV1: () => clockMs,
  });

  const created = await routeService.sessionService.createUnclaimedSessionV1({
    payload: fixture.payload,
    nowMs: clockMs,
  });
  expect(created.outcome).toBe('applied');
  const beforeExpiry = await routeService.sessionService.getSessionV1({
    linkSessionId: fixture.payload.linkSessionId,
    nowMs: clockMs,
  });
  expect(beforeExpiry?.state.state).toBe('displaying_qr');

  clockMs = fixture.payload.expiresAtMs + 1;
  const afterExpiry = await routeService.sessionService.getSessionV1({
    linkSessionId: fixture.payload.linkSessionId,
    nowMs: clockMs,
  });
  expect(afterExpiry?.state.state).toBe('expired');
});

function ownerAuthorization(): LinkedDeviceOwnerAuthorizationPortV1 {
  return {
    authorizeOwnerClaimV1: async () => ({
      kind: 'denied' as const,
      code: 'unauthorized' as const,
      message: 'owner claim auth is not used in this test',
    }),
    authorizeOwnerApprovalV1: async () => ({
      kind: 'denied' as const,
      code: 'unauthorized' as const,
      message: 'owner approval auth is not used in this test',
    }),
  };
}

function targetCredentialNotConfigured() {
  return {
    getTargetPreparationV1: async () => {
      throw new Error('target preparation adapter not configured');
    },
    registerTargetCredentialV1: async () => {
      throw new Error('credential adapter not configured');
    },
  };
}
