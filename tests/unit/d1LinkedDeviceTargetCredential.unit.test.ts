import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  LinkedDeviceSessionServiceV1,
  type LinkedDeviceAggregateActivationVerifierV1,
  type LinkedDeviceOwnerAuthorizationPortV1,
} from '../../packages/sdk-server-ts/src/core/deviceLinking/linkedDeviceSession';
import {
  D1LinkedDeviceSessionStoreV1,
  type D1LinkedDeviceSessionScopeV1,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceSessionStore';
import { D1LinkedDeviceTargetCredentialProviderV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceTargetCredentialProvider';
import { D1LinkedDeviceSourceHandoffProviderV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceSourceHandoffProvider';
import { D1LinkedDeviceProvisioningProviderV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceProvisioningProvider';
import { createLinkedDeviceR102ProvisioningExecutionV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/linkedDeviceR102ProvisioningExecution';
import {
  createD1LinkedDeviceCredentialResolverV1,
  D1LinkedDeviceTargetAuthenticatorStoreV1,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceTargetAuthenticatorStore';
import {
  buildR103DeviceLinkFixture,
  buildR103ProvisioningFixture,
  buildR103TargetCredentialFixture,
  buildR103TargetReadySourceFixture,
} from './helpers/deviceLinkContracts.fixtures';
import { computeLaneEnrollmentManifestDigestV1 } from '../../packages/shared-ts/src/signing-lanes/rotationDigests';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  buildR102ActiveProductEpoch,
  buildR102ServerActivationReceipt,
} from './helpers/r102LaneGateway.fixtures';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';

const scope: D1LinkedDeviceSessionScopeV1 = {
  namespace: 'signer',
  orgId: 'org_target_credential',
  projectId: 'project_target_credential',
  envId: 'env_target_credential',
};

const aggregateActivationVerifier = {
  verifyAggregateActivationV1: async () => ({ kind: 'verified' as const }),
} satisfies LinkedDeviceAggregateActivationVerifierV1;

let temporary: TemporaryD1Database | undefined;

test.afterEach(() => {
  if (temporary) cleanupTemporaryD1Database(temporary.tempDir);
  temporary = undefined;
});

test('persists verified attestation and exact public child records before provisioning CAS', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const approval = { ...fixture.approval, expiresAtMs: 8_000 };
  const approvedFixture = { ...fixture, approval };
  const target = await buildR103TargetCredentialFixture(approvedFixture);
  const handoff = buildR103TargetReadySourceFixture(approvedFixture);
  const keyManifestDigestB64u = parseDigestB64u(
    await computeLaneEnrollmentManifestDigestV1(handoff.targetReady.manifest),
  );
  const store = new D1LinkedDeviceSessionStoreV1({ database: temporary.database, scope });
  const sessionService = new LinkedDeviceSessionServiceV1({
    store,
    authorization: ownerAuthorization(fixture),
    aggregateActivationVerifier,
  });
  await sessionService.createUnclaimedSessionV1({ payload: fixture.payload, nowMs: 3_000 });
  await sessionService.claimSessionV1({ payload: fixture.payload, nowMs: 3_001 });
  const approvalResult = await sessionService.recordOwnerApprovalV1({
    approval,
    nowMs: 3_002,
  });
  expect(approvalResult.outcome).toBe('applied');
  if (approvalResult.outcome !== 'applied') throw new Error('expected approved session');

  let verificationCount = 0;
  let commitCount = 0;
  const provider = new D1LinkedDeviceTargetCredentialProviderV1({
    database: temporary.database,
    scope,
    preparationSource: {
      createTargetPreparationV1: async () => target.preparation,
    },
    verifier: {
      verifyRegistrationV1: async () => {
        verificationCount += 1;
        return {
          kind: 'verified',
          credential: {
            credentialIdB64u: target.registration.webauthnRegistration.credentialIdB64u,
            credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(77).fill(9)),
            counter: 0,
          },
        };
      },
    },
    committer: {
      commitVerifiedTargetV1: async () => {
        commitCount += 1;
        return { keyManifestDigestB64u, targetReady: handoff.targetReady };
      },
    },
    sourceHandoff: new D1LinkedDeviceSourceHandoffProviderV1({
      database: temporary.database,
      scope,
    }),
  });
  const preparation = await provider.getTargetPreparationV1({
    session: approvalResult.record,
    approval,
    requestedAtMs: 3_003,
  });
  expect(preparation).toEqual(target.preparation);
  const registered = await provider.registerTargetCredentialV1({
    registration: target.registration,
    preparation,
    session: approvalResult.record,
    approval,
    requestedAtMs: 3_004,
  });
  expect(registered).toEqual({
    outcome: 'applied',
    keyManifestDigestB64u,
  });
  if (registered.outcome === 'invalid_input') throw new Error(registered.message);
  await temporary.database
    .prepare(
      `DELETE FROM linked_device_source_handoffs
         WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
           AND link_session_id = ?`,
    )
    .bind(
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(fixture.approval.linkSessionId),
    )
    .run();
  await temporary.database
    .prepare(
      `UPDATE linked_device_target_commit_reservations
          SET state = 'reserved', committed_at_ms = NULL, key_manifest_digest_b64u = NULL
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND link_session_id = ?`,
    )
    .bind(
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(fixture.approval.linkSessionId),
    )
    .run();
  await expect(
    provider.registerTargetCredentialV1({
      registration: target.registration,
      preparation,
      session: approvalResult.record,
      approval,
      requestedAtMs: 3_005,
    }),
  ).resolves.toEqual({ outcome: 'replayed', keyManifestDigestB64u });
  await expect(
    temporary.database
      .prepare(
        `SELECT state, key_manifest_digest_b64u
           FROM linked_device_target_commit_reservations
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ?`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        String(fixture.approval.linkSessionId),
      )
      .first(),
  ).resolves.toMatchObject({
    state: 'committed',
    key_manifest_digest_b64u: keyManifestDigestB64u,
  });
  const transitioned = await sessionService.recordTargetCredentialV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: approvalResult.record.revision,
    keyManifestDigestB64u: registered.keyManifestDigestB64u,
    nowMs: 3_004,
  });
  expect(transitioned.outcome).toBe('applied');
  if (transitioned.outcome !== 'applied') throw new Error('expected provisioning transition');
  expect(transitioned.record.state).toEqual({
    state: 'provisioning',
    linkSessionId: fixture.payload.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    keyManifestDigestB64u,
  });

  const provisioningFixture = buildR103ProvisioningFixture(fixture);
  const delivery = provisioningFixture.deliveries.orderedChildren[0];
  const activeProduct = await buildR102ActiveProductEpoch(delivery.job);
  let prepareCount = 0;
  let activationCount = 0;
  let aggregateCommitCount = 0;
  const r102Execution = createLinkedDeviceR102ProvisioningExecutionV1({
    sourcePreparation: {
      prepareProvisioningDeliveriesV1: async () => {
        prepareCount += 1;
        return provisioningFixture.deliveries;
      },
    },
    products: {
      getProductEpoch: async () => activeProduct,
    },
    lifecycle: {
      activateLaneServerMaterialV1: async () => {
        activationCount += 1;
        return {
          outcome: 'applied',
          version: 4,
          commandDigestB64u: fixture.receipt.aggregateReceiptDigestB64u,
          record: {
            job: delivery.job,
            lifecycle: {
              state: 'ready_for_parent_visibility',
              startedAtMs: 3_000,
              committedAtMs: 3_001,
              transcriptHashB64u: delivery.protocolCommitReceipt.transcriptHashB64u,
              protocolCommitReceiptDigestB64u: fixture.receipt.aggregateReceiptDigestB64u,
              holderDeliveryReceiptDigestB64u: fixture.receipt.aggregateReceiptDigestB64u,
              holderReceiptAtMs: 3_005,
              serverActivationReceiptDigestB64u: fixture.receipt.aggregateReceiptDigestB64u,
              serverActivatedAtMs: 3_006,
            },
          },
        };
      },
    },
    gateway: {
      recordLaneHolderDeliveryV1: async () => ({
        outcome: 'applied',
        version: 3,
        commandDigestB64u: fixture.receipt.aggregateReceiptDigestB64u,
        record: {
          job: delivery.job,
          lifecycle: {
            state: 'awaiting_server_activation',
            startedAtMs: 3_000,
            committedAtMs: 3_001,
            transcriptHashB64u: delivery.protocolCommitReceipt.transcriptHashB64u,
            protocolCommitReceiptDigestB64u: fixture.receipt.aggregateReceiptDigestB64u,
            holderDeliveryReceiptDigestB64u: fixture.receipt.aggregateReceiptDigestB64u,
            holderReceiptAtMs: 3_005,
          },
        },
      }),
      commitLaneEnrollmentActivationV1: async (command) => {
        aggregateCommitCount += 1;
        return {
          kind: 'lane_enrollment_activation_result_v1',
          outcome: 'applied',
          enrollmentId: command.enrollmentId,
          version: 5,
          commandDigestB64u: fixture.receipt.aggregateReceiptDigestB64u,
          receipt: {
            kind: 'aggregate_lane_activation_receipt_v1',
            enrollmentId: command.enrollmentId,
            walletId: command.walletId,
            manifestDigestB64u: command.manifestDigestB64u,
            orderedChildReceipts: command.orderedChildReceipts,
            activatedAtMs: command.activatedAtMs,
          },
          lifecycle: {
            state: 'active',
            manifestDigestB64u: command.manifestDigestB64u,
            aggregateReceiptDigestB64u: fixture.receipt.aggregateReceiptDigestB64u,
            activatedAtMs: command.activatedAtMs,
          },
          productEpochs: [activeProduct],
        };
      },
    },
  });
  const provisioning = new D1LinkedDeviceProvisioningProviderV1({
    database: temporary.database,
    scope,
    execution: r102Execution,
  });
  for (let replay = 0; replay < 2; replay += 1) {
    expect(
      await provisioning.provisionLinkedDeviceV1({
        command: provisioningFixture.command,
        session: transitioned.record,
        approval,
        requestedAtMs: 3_005 + replay,
      }),
    ).toEqual(provisioningFixture.deliveries);
  }
  let activatedReceipt: Awaited<ReturnType<typeof provisioning.recordHolderDeliveriesV1>> | null =
    null;
  for (let replay = 0; replay < 2; replay += 1) {
    const current = await provisioning.recordHolderDeliveriesV1({
      acknowledgement: provisioningFixture.acknowledgement,
      session: transitioned.record,
      approval,
      requestedAtMs: 3_010 + replay,
    });
    activatedReceipt ??= current;
    expect(current).toEqual(activatedReceipt);
  }
  expect(activatedReceipt).toMatchObject({
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    orderedChildReceipts: [
      {
        walletKeyId: delivery.job.walletKeyId,
        targetLaneId: delivery.job.target.laneId,
        materialActivation: buildR102ServerActivationReceipt(delivery.job).targetMaterialActivation,
      },
    ],
  });
  expect({ prepareCount, activationCount, aggregateCommitCount }).toEqual({
    prepareCount: 1,
    activationCount: 1,
    aggregateCommitCount: 1,
  });

  const persisted = await temporary.database
    .prepare(
      `SELECT state, registration_json, credential_public_key_b64u
         FROM linked_device_target_credentials
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND link_session_id = ?`,
    )
    .bind(scope.namespace, scope.orgId, scope.projectId, scope.envId, fixture.payload.linkSessionId)
    .first<Record<string, unknown>>();
  expect(persisted?.state).toBe('registered');
  expect(JSON.parse(String(persisted?.registration_json))).toEqual(target.registration);
  expect(String(persisted?.registration_json)).not.toContain('clientExtensionResults');
  expect(String(persisted?.registration_json)).not.toContain('prf');
  expect(persisted?.credential_public_key_b64u).toBeTruthy();

  const authenticatorStore = new D1LinkedDeviceTargetAuthenticatorStoreV1({
    database: temporary.database,
    scope,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
  });
  const credentialId = await authenticatorStore.readLinkedDeviceCredentialIdV1({
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
  });
  expect(credentialId).toBe(target.registration.webauthnRegistration.credentialIdB64u);
  const authenticator = await authenticatorStore.get(
    `linked-device:${fixture.approval.deviceId}`,
    target.registration.webauthnRegistration.credentialIdB64u,
  );
  expect(authenticator).toMatchObject({
    version: 'webauthn_authenticator_v1',
    credentialIdB64u: target.registration.webauthnRegistration.credentialIdB64u,
    counter: 0,
  });
  if (!authenticator) throw new Error('expected persisted linked-device authenticator');
  await authenticatorStore.put(`linked-device:${fixture.approval.deviceId}`, {
    ...authenticator,
    counter: 1,
    updatedAtMs: 3_005,
  });
  expect(
    await authenticatorStore.get(
      `linked-device:${fixture.approval.deviceId}`,
      target.registration.webauthnRegistration.credentialIdB64u,
    ),
  ).toMatchObject({ counter: 1 });
  expect(
    await authenticatorStore.readLinkedDeviceCredentialIdV1({
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: 'device:unrelated',
    }),
  ).toBeNull();
  expect(
    await createD1LinkedDeviceCredentialResolverV1({
      database: temporary.database,
      scope,
    }).readLinkedDeviceCredentialIdV1({
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
    }),
  ).toBe(target.registration.webauthnRegistration.credentialIdB64u);

  const replayed = await provider.registerTargetCredentialV1({
    registration: target.registration,
    preparation,
    session: transitioned.record,
    approval,
    requestedAtMs: 7_500,
  });
  expect(replayed).toEqual({
    outcome: 'replayed',
    keyManifestDigestB64u,
  });
  expect(verificationCount).toBe(1);
  expect(commitCount).toBe(2);

  await temporary.database
    .prepare(
      `UPDATE linked_device_target_commit_reservations
          SET key_manifest_digest_b64u = ?
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND link_session_id = ? AND state = 'committed'`,
    )
    .bind(
      fixture.receipt.manifestDigestB64u,
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(fixture.approval.linkSessionId),
    )
    .run();
  await expect(
    provider.registerTargetCredentialV1({
      registration: target.registration,
      preparation,
      session: transitioned.record,
      approval,
      requestedAtMs: 7_500,
    }),
  ).resolves.toMatchObject({
    outcome: 'invalid_input',
    message: expect.stringMatching(/reservation manifest digest changed/),
  });

  const conflicting = await provider.registerTargetCredentialV1({
    registration: {
      ...target.registration,
      webauthnRegistration: {
        ...target.registration.webauthnRegistration,
        transports: ['usb'],
      },
    },
    preparation,
    session: transitioned.record,
    approval,
    requestedAtMs: 7_500,
  });
  expect(conflicting.outcome).toBe('invalid_input');
});

function ownerAuthorization(
  fixture: ReturnType<typeof buildR103DeviceLinkFixture>,
): LinkedDeviceOwnerAuthorizationPortV1 {
  return {
    authorizeOwnerClaimV1: async () => ({
      kind: 'authorized',
      identity: {
        walletId: fixture.approval.walletId,
        enrollmentId: fixture.approval.enrollmentId,
        deviceId: fixture.approval.deviceId,
        claimExpiresAtMs: 9_000,
      },
    }),
    authorizeOwnerApprovalV1: async () => ({ kind: 'authorized' }),
  };
}
