import { expect, test } from '@playwright/test';
import { computeLinkedDevicePublicKeyDigestV1 } from '../../packages/wallet-server/src/core/deviceLinking/requestProof';
import { createD1LinkedDeviceRouteServiceV1 } from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking';
import { D1LinkedDeviceAggregateActivationVerifierV1 } from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceAggregateActivationVerifier';
import { D1LinkedDeviceProvisioningVerifierV1 } from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceProvisioningVerifier';
import type { LinkedDeviceOwnerAuthorizationPortV1 } from '../../packages/wallet-server/src/core/deviceLinking/linkedDeviceSession';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseLinkDeviceSessionId,
} from '@shared/signing-lanes/ids';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseWalletId } from '@shared/utils/domainIds';
import { buildSignedDeviceRequestProofFixtureV1 } from './helpers/deviceRequestProof.fixtures';
import {
  buildR103DeviceLinkFixture,
  buildR103ProvisioningFixture,
} from './helpers/deviceLinkContracts.fixtures';
import {
  buildR102HolderDeliveryReceipt,
  buildR102ManifestChild,
  buildR102ProtocolCommitReceipt,
  buildR102PreparingEnrollmentAdmissionRecordFixture,
  buildR102CommittedAwaitingHolderDeliveryProtocolAdmissionRecordFixture,
} from './helpers/r102LaneGateway.fixtures';
import {
  buildLaneEnrollmentManifestV1,
  parseRotatableSigningLaneJobV1,
} from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import { encodeLaneProtocolCommitReceiptV1 } from '../../packages/shared-ts/src/signing-lanes/rotationDigests';
import { sha256Bytes } from '../../packages/shared-ts/src/utils/digests';
import { parseLinkedDeviceProvisioningDeliveriesV1 } from '../../packages/shared-ts/src/device-linking/parsers';
import { parseTenantId } from '@shared/authorization/capabilityKinds';
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

test('binds deliveries and holder receipts to the persisted child operation', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const job = linkedJobForFixture('persisted-child-operation', fixture);
  const receipt = buildR102ProtocolCommitReceipt(job);
  const receiptDigestB64u = base64UrlEncode(
    await sha256Bytes(encodeLaneProtocolCommitReceiptV1(receipt)),
  );
  const manifest = buildLaneEnrollmentManifestV1({
    enrollmentId: job.enrollmentId,
    walletId: job.walletId,
    authorization: job.authorization,
    orderedChildren: [buildR102ManifestChild(job)],
    createdAtMs: 1_000,
    expiresAtMs: 100_000,
  });
  const enrollment = buildR102PreparingEnrollmentAdmissionRecordFixture(
    manifest,
    fixture.receipt.manifestDigestB64u,
    1_000,
  );
  const protocol = buildR102CommittedAwaitingHolderDeliveryProtocolAdmissionRecordFixture(
    job,
    receipt,
    receiptDigestB64u,
  );
  const verifier = new D1LinkedDeviceProvisioningVerifierV1({
    lifecycleStore: {
      getEnrollment: async () => enrollment,
      getProtocol: async () => protocol,
    },
  });
  const deliveries = provisioningDeliveries(fixture, job, receipt);
  await expect(
    verifier.verifyProvisioningDeliveriesV1({ deliveries, approval: fixture.approval }),
  ).resolves.toBeUndefined();
  await expect(
    verifier.verifyHolderDeliveriesV1({
      acknowledgement: {
        kind: 'linked_device_holder_delivery_acknowledgement_v1',
        linkSessionId: fixture.approval.linkSessionId,
        enrollmentId: fixture.approval.enrollmentId,
        deviceId: fixture.approval.deviceId,
        orderedHolderDeliveryReceipts: [buildR102HolderDeliveryReceipt(job)],
        acknowledgedAtMs: 3_000,
      },
      approval: fixture.approval,
    }),
  ).resolves.toBeUndefined();

  const substitutedJob = linkedJobForFixture('substituted-child-operation', fixture);
  const substitutedReceipt = buildR102ProtocolCommitReceipt(substitutedJob);
  await expect(
    verifier.verifyProvisioningDeliveriesV1({
      deliveries: provisioningDeliveries(fixture, substitutedJob, substitutedReceipt),
      approval: fixture.approval,
    }),
  ).rejects.toThrow('delivery job differs from its persisted job');
  await expect(
    verifier.verifyHolderDeliveriesV1({
      acknowledgement: {
        kind: 'linked_device_holder_delivery_acknowledgement_v1',
        linkSessionId: fixture.approval.linkSessionId,
        enrollmentId: fixture.approval.enrollmentId,
        deviceId: fixture.approval.deviceId,
        orderedHolderDeliveryReceipts: [buildR102HolderDeliveryReceipt(substitutedJob)],
        acknowledgedAtMs: 3_000,
      },
      approval: fixture.approval,
    }),
  ).rejects.toThrow('holder receipt differs from its persisted child operation');
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
    ...linkedAuthorizationNotConfigured(),
    ownerAuthorization: ownerAuthorization(),
    authenticateOwnerRequestV1: async () => ({
      kind: 'denied' as const,
      code: 'unauthorized' as const,
      message: 'owner auth is not used in this test',
    }),
    targetCredential: targetCredentialNotConfigured(),
    provisioning: provisioningNotConfigured(),
    sourceHandoff: sourceHandoffNotConfigured(),
    nowV1: () => nowMs,
  });
  const request = new Request(
    'https://example.test/wallet/device-linking/v1/sessions/link-session:route-service/cancel',
    {
      method: 'POST',
      body: '{"ok":true}',
    },
  );
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
  // Refactor 103 Phase 8: the composition wires the custody transfer store.
  // Without it the routes answer 501 and linking dies after the owner has
  // already asserted — the port is optional in the type, so only this proves
  // the D1 composition actually provides it.
  expect(routeService.custodyTransfer).toBeDefined();
});

test('forwards authenticated session reads through core expiry projection', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  let clockMs = 3_000;
  const routeService = createD1LinkedDeviceRouteServiceV1({
    database: temporary.database,
    scope,
    ...linkedAuthorizationNotConfigured(),
    ownerAuthorization: ownerAuthorization(),
    authenticateOwnerRequestV1: async () => ({
      kind: 'denied' as const,
      code: 'unauthorized' as const,
      message: 'owner auth is not used in this test',
    }),
    targetCredential: targetCredentialNotConfigured(),
    provisioning: provisioningNotConfigured(),
    sourceHandoff: sourceHandoffNotConfigured(),
    nowV1: () => clockMs,
  });

  const created = await routeService.sessionService.createUnclaimedSessionV1({
    payload: fixture.payload,
    nowMs: clockMs,
  });
  expect(created.outcome).toBe('applied');

  const rawBeforeExpiry = await routeService.sessionService.getSessionV1(
    fixture.payload.linkSessionId,
  );
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

function linkedAuthorizationNotConfigured() {
  const tenantId = parseTenantId('tenant-route-service-test');
  if (!tenantId.ok) throw new Error(tenantId.error.message);
  return {
    tenantId: tenantId.value,
    expectedOrigin: 'https://wallet.example.test',
    authorizationService: {
      getLinkedDeviceWalletSessionStatus: async () => {
        throw new Error('linked authorization adapter not configured');
      },
      issueLinkedDeviceWalletSession: async () => {
        throw new Error('linked authorization adapter not configured');
      },
      readLinkedDeviceWalletSessionAuthorization: async () => {
        throw new Error('linked authorization adapter not configured');
      },
    },
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

function provisioningNotConfigured() {
  return {
    provisionLinkedDeviceV1: async () => {
      throw new Error('provisioning adapter not configured');
    },
    recordHolderDeliveriesV1: async () => {
      throw new Error('holder delivery adapter not configured');
    },
  };
}

function sourceHandoffNotConfigured() {
  return {
    getTargetReadyV1: async () => null,
    prepareProvisioningDeliveriesV1: async () => {
      throw new Error('source handoff adapter not configured');
    },
    submitPreparedProvisioningDeliveriesV1: async () => {
      throw new Error('source handoff adapter not configured');
    },
  };
}

function linkedJobForFixture(
  operationId: string,
  fixture: ReturnType<typeof buildR103DeviceLinkFixture>,
) {
  const source = buildR103ProvisioningFixture(fixture).deliveries.orderedChildren[0].job;
  return parseRotatableSigningLaneJobV1({
    ...source,
    operationId,
    idempotencyKey: `idempotency:${operationId}`,
    authorization: {
      kind: 'linked_device_enrollment',
      authorizedOperationId: source.authorization.authorizedOperationId,
      linkedDeviceEnrollmentId: fixture.approval.enrollmentId,
      linkedDevicePermissionDigestB64u: fixture.approval.policyDigestB64u,
    },
  });
}

function provisioningDeliveries(
  fixture: ReturnType<typeof buildR103DeviceLinkFixture>,
  job: ReturnType<typeof linkedJobForFixture>,
  receipt: ReturnType<typeof buildR102ProtocolCommitReceipt>,
) {
  return parseLinkedDeviceProvisioningDeliveriesV1({
    kind: 'linked_device_provisioning_deliveries_v1',
    linkSessionId: fixture.approval.linkSessionId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    manifest: buildLaneEnrollmentManifestV1({
      enrollmentId: job.enrollmentId,
      walletId: job.walletId,
      authorization: job.authorization,
      orderedChildren: [buildR102ManifestChild(job)],
      createdAtMs: fixture.approval.approvedAtMs,
      expiresAtMs: fixture.approval.expiresAtMs,
    }),
    orderedChildren: [
      {
        kind: 'linked_device_provisioning_child_v1',
        job,
        protocolCommitReceipt: receipt,
        holderPackage: {
          kind: 'ed25519_yao_lane_holder_package_set_v1',
          deriverAEncryptedPackageJson: '{}',
          deriverBEncryptedPackageJson: '{}',
        },
        expectedVersion: 2,
      },
    ],
  });
}
