import { expect, test } from '@playwright/test';
import { parseAuthorizedOperationId } from '@shared/authorization/capabilityKinds';
import {
  buildLinkedDeviceTargetCredentialRegistrationV1,
  buildLinkedDeviceTargetPreparationV1,
  parseLinkedDeviceProvisioningDeliveriesV1,
} from '../../packages/shared-ts/src/device-linking/parsers';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceProvisioningCommandV1,
} from '../../packages/shared-ts/src/device-linking/contracts';
import {
  buildLaneEnrollmentManifestV1,
  parseRotatableSigningLaneJobV1,
} from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import { computeLaneEnrollmentManifestDigestV1 } from '../../packages/shared-ts/src/signing-lanes/rotationDigests';
import { computeLinkedDeviceTargetPreparationDigestV1 } from '../../packages/shared-ts/src/device-linking/digests';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  buildR103DeviceLinkFixture,
  buildR103ProvisioningFixture,
} from './helpers/deviceLinkContracts.fixtures';
import { buildR102ProtocolCommitReceipt } from './helpers/r102LaneGateway.fixtures';
import { LinkedDeviceSessionServiceV1 } from '../../packages/sdk-server-ts/src/core/deviceLinking/linkedDeviceSession';
import { D1LinkedDeviceSessionStoreV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceSessionStore';
import { D1LinkedDeviceSourceHandoffProviderV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceSourceHandoffProvider';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';

const scope = {
  namespace: 'signer',
  orgId: 'org_source_handoff_test',
  projectId: 'project_source_handoff_test',
  envId: 'env_source_handoff_test',
} as const;

let temporary: TemporaryD1Database | undefined;

test.afterEach(() => {
  if (temporary) cleanupTemporaryD1Database(temporary.tempDir);
  temporary = undefined;
});

test('persists exact target-ready input, accepts one delivery submission, and replays it', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const approval = { ...fixture.approval, expiresAtMs: 9_000 };
  const store = new D1LinkedDeviceSessionStoreV1({ database: temporary.database, scope });
  const service = new LinkedDeviceSessionServiceV1({
    store,
    authorization: ownerAuthorization(),
    aggregateActivationVerifier: {
      verifyAggregateActivationV1: async () => ({ kind: 'verified' as const }),
    },
  });
  expect(
    (await service.createUnclaimedSessionV1({ payload: fixture.payload, nowMs: 3_000 })).outcome,
  ).toBe('applied');
  expect(
    (await service.claimSessionV1({ payload: fixture.claimRequest.payload, nowMs: 3_000 })).outcome,
  ).toBe('applied');
  expect((await service.recordOwnerApprovalV1({ approval, nowMs: 3_000 })).outcome).toBe('applied');
  const session = await service.getSessionV1({
    linkSessionId: fixture.approval.linkSessionId,
    nowMs: 3_000,
  });
  if (!session || session.state.state !== 'awaiting_target_passkey') {
    throw new Error('source handoff fixture session is not awaiting a target passkey');
  }
  const handoff = await buildSourceHandoffFixture(approval);
  await persistRegisteredTargetCredential(temporary.database, handoff);
  const provider = new D1LinkedDeviceSourceHandoffProviderV1({
    database: temporary.database,
    scope,
  });
  await expect(
    provider.persistTargetReadyV1({
      targetReady: handoff.targetReady,
      session,
      approval,
      requestedAtMs: 3_000,
    }),
  ).resolves.toEqual(handoff.targetReady);
  const submission = {
    kind: 'linked_device_provisioning_deliveries_submission_v1' as const,
    linkSessionId: approval.linkSessionId,
    walletId: approval.walletId,
    enrollmentId: approval.enrollmentId,
    deviceId: approval.deviceId,
    manifestDigestB64u: handoff.manifestDigestB64u,
    deliveries: handoff.deliveries,
  };
  await expect(
    provider.submitPreparedProvisioningDeliveriesV1({
      submission,
      session,
      approval,
      requestedAtMs: 3_001,
    }),
  ).resolves.toEqual(submission);
  await expect(
    provider.submitPreparedProvisioningDeliveriesV1({
      submission,
      session,
      approval,
      requestedAtMs: 3_002,
    }),
  ).resolves.toEqual(submission);
  await expect(
    provider.submitPreparedProvisioningDeliveriesV1({
      submission: {
        ...submission,
        deliveries: {
          ...submission.deliveries,
          orderedChildren: [
            {
              ...submission.deliveries.orderedChildren[0],
              expectedVersion: submission.deliveries.orderedChildren[0].expectedVersion + 1,
            },
          ],
        },
      },
      session,
      approval,
      requestedAtMs: 3_003,
    }),
  ).rejects.toThrow(/conflict|differs from target-ready/);
  const command: LinkedDeviceProvisioningCommandV1 = {
    kind: 'linked_device_provisioning_command_v1',
    linkSessionId: approval.linkSessionId,
    enrollmentId: approval.enrollmentId,
    deviceId: approval.deviceId,
  };
  await expect(
    provider.prepareProvisioningDeliveriesV1({
      command,
      session,
      approval,
      requestedAtMs: 3_004,
    }),
  ).resolves.toEqual(handoff.deliveries);
  await expect(
    provider.getTargetReadyV1({ session, approval, requestedAtMs: 9_500 }),
  ).rejects.toThrow(/expired|does not match approved session/);
  const provisioning = await service.recordTargetCredentialV1({
    linkSessionId: approval.linkSessionId,
    expectedRevision: session.revision,
    keyManifestDigestB64u: handoff.manifestDigestB64u,
    nowMs: 8_000,
  });
  expect(provisioning.outcome).toBe('applied');
  if (provisioning.outcome !== 'applied') throw new Error('expected provisioning session');
  const committed = await service.markCommittedCompletionRequiredV1({
    linkSessionId: approval.linkSessionId,
    expectedRevision: provisioning.record.revision,
    transcriptSetDigestB64u: fixture.receipt.aggregateReceiptDigestB64u,
    nowMs: 8_001,
  });
  expect(committed.outcome).toBe('applied');
  if (committed.outcome !== 'applied') throw new Error('expected committed session');
  await expect(
    provider.getTargetReadyV1({
      session: committed.record,
      approval,
      requestedAtMs: 9_500,
    }),
  ).resolves.toEqual(handoff.targetReady);
  await expect(
    provider.prepareProvisioningDeliveriesV1({
      command,
      session: committed.record,
      approval,
      requestedAtMs: 9_500,
    }),
  ).resolves.toEqual(handoff.deliveries);
});

async function buildSourceHandoffFixture(approval: LinkedDeviceApprovalV1) {
  const source = buildR103ProvisioningFixture({
    ...buildR103DeviceLinkFixture(),
    approval,
  }).deliveries.orderedChildren[0];
  if (!source) throw new Error('source handoff fixture has no child');
  const authorizedOperationId = parseAuthorizedOperationId(String(approval.operationId));
  if (!authorizedOperationId.ok) throw new Error(authorizedOperationId.error.message);
  const job = parseRotatableSigningLaneJobV1({
    ...source.job,
    expiresAtMs: 8_000,
    authorization: {
      kind: 'linked_device_enrollment',
      authorizedOperationId: authorizedOperationId.value,
      linkedDeviceEnrollmentId: approval.enrollmentId,
      linkedDevicePermissionDigestB64u: approval.policyDigestB64u,
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
  const deliveries = parseLinkedDeviceProvisioningDeliveriesV1({
    kind: 'linked_device_provisioning_deliveries_v1',
    linkSessionId: approval.linkSessionId,
    enrollmentId: approval.enrollmentId,
    deviceId: approval.deviceId,
    manifest,
    orderedChildren: [
      {
        kind: 'linked_device_provisioning_child_v1',
        job,
        protocolCommitReceipt: buildR102ProtocolCommitReceipt(job),
        holderPackage: {
          kind: 'ed25519_yao_lane_holder_package_set_v1',
          deriverAEncryptedPackageJson: '{}',
          deriverBEncryptedPackageJson: '{}',
        },
        expectedVersion: 2,
      },
    ],
  });
  const targetReady = {
    kind: 'linked_device_target_ready_r102_input_v1' as const,
    linkSessionId: approval.linkSessionId,
    walletId: approval.walletId,
    enrollmentId: approval.enrollmentId,
    deviceId: approval.deviceId,
    manifest,
    children: [job] as const,
  };
  const manifestDigestB64u = parseDigestB64u(await computeLaneEnrollmentManifestDigestV1(manifest));
  return { targetReady, deliveries, manifestDigestB64u, job };
}

async function persistRegisteredTargetCredential(
  database: TemporaryD1Database['database'],
  handoff: Awaited<ReturnType<typeof buildSourceHandoffFixture>>,
): Promise<void> {
  const rpId = parseWebAuthnRpId('wallet.example.test');
  if (!rpId.ok) throw new Error(rpId.error.message);
  const preparation = buildLinkedDeviceTargetPreparationV1({
    linkSessionId: handoff.targetReady.linkSessionId,
    walletId: handoff.targetReady.walletId,
    enrollmentId: handoff.targetReady.enrollmentId,
    deviceId: handoff.targetReady.deviceId,
    rpId: rpId.value,
    userHandleB64u: base64UrlEncode(new Uint8Array([1, 2, 3])),
    challengeB64u: handoff.targetReady.manifest.authorization.linkedDevicePermissionDigestB64u,
    orderedChildren: [
      {
        kind: 'linked_device_target_preparation_child_v1',
        operationId: handoff.job.operationId,
        walletKeyId: handoff.job.walletKeyId,
        keyFamily: handoff.job.keyFamily,
        targetLaneId: handoff.job.target.laneId,
        targetLaneShareEpoch: handoff.job.target.laneShareEpoch,
        targetMaterialActivationId: handoff.job.targetMaterialActivationId,
        targetHolderParticipantId: handoff.job.targetHolder.participantId,
      },
    ],
    issuedAtMs: 1_000,
    expiresAtMs: 9_000,
  });
  const registration = buildLinkedDeviceTargetCredentialRegistrationV1({
    linkSessionId: handoff.targetReady.linkSessionId,
    walletId: handoff.targetReady.walletId,
    enrollmentId: handoff.targetReady.enrollmentId,
    deviceId: handoff.targetReady.deviceId,
    targetPreparationDigestB64u: await computeLinkedDeviceTargetPreparationDigestV1(preparation),
    webauthnRegistration: {
      kind: 'linked_device_webauthn_registration_v1',
      credentialIdB64u: base64UrlEncode(new Uint8Array(32).fill(6)),
      authenticatorAttachment: 'platform',
      clientDataJsonB64u: 'AQID',
      attestationObjectB64u: 'BAUG',
      transports: ['internal'],
    },
    orderedHolderRegistrations: [
      {
        kind: 'linked_device_target_holder_registration_v1',
        operationId: handoff.job.operationId,
        walletKeyId: handoff.job.walletKeyId,
        keyFamily: handoff.job.keyFamily,
        targetLaneId: handoff.job.target.laneId,
        targetLaneShareEpoch: handoff.job.target.laneShareEpoch,
        targetMaterialActivationId: handoff.job.targetMaterialActivationId,
        holderParticipant: {
          kind: 'lane_holder_participant_v1',
          ...handoff.job.targetHolder,
        },
      },
    ],
    registeredAtMs: 3_000,
  });
  await database
    .prepare(
      `INSERT INTO linked_device_target_credentials (
         namespace, org_id, project_id, env_id, link_session_id,
         wallet_id, enrollment_id, device_id, state,
         preparation_digest_b64u, preparation_json, registration_json,
         credential_id_b64u, credential_public_key_b64u, credential_counter,
         key_manifest_digest_b64u, prepared_at_ms, expires_at_ms, registered_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'registered', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(handoff.targetReady.linkSessionId),
      String(handoff.targetReady.walletId),
      String(handoff.targetReady.enrollmentId),
      String(handoff.targetReady.deviceId),
      await computeLinkedDeviceTargetPreparationDigestV1(preparation),
      JSON.stringify(preparation),
      JSON.stringify(registration),
      registration.webauthnRegistration.credentialIdB64u,
      base64UrlEncode(new Uint8Array(32).fill(9)),
      0,
      handoff.manifestDigestB64u,
      1_000,
      9_000,
      3_000,
    )
    .run();
}

function ownerAuthorization() {
  const fixture = buildR103DeviceLinkFixture();
  return {
    authorizeOwnerClaimV1: async () => ({
      kind: 'authorized' as const,
      identity: {
        walletId: fixture.approval.walletId,
        enrollmentId: fixture.approval.enrollmentId,
        deviceId: fixture.approval.deviceId,
        claimExpiresAtMs: 10_000,
      },
    }),
    authorizeOwnerApprovalV1: async () => ({ kind: 'authorized' as const }),
  };
}
