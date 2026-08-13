import { expect, test } from '@playwright/test';
import { parseAuthorizedOperationId } from '@shared/authorization/capabilityKinds';
import {
  buildLinkedDeviceEnrollmentReceiptV1,
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
import {
  computeLinkedDeviceProvisioningDeliveriesDigestV1,
  computeLinkedDeviceTargetPreparationDigestV1,
} from '../../packages/shared-ts/src/device-linking/digests';
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
import { D1LinkedDeviceProvisioningProviderV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceProvisioningProvider';
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
  const provisioning = await service.recordTargetCredentialV1({
    linkSessionId: approval.linkSessionId,
    expectedRevision: session.revision,
    keyManifestDigestB64u: handoff.manifestDigestB64u,
    nowMs: 3_001,
  });
  expect(provisioning.outcome).toBe('applied');
  if (provisioning.outcome !== 'applied') throw new Error('expected provisioning session');
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
      session: provisioning.record,
      approval,
      requestedAtMs: 3_002,
    }),
  ).resolves.toEqual(submission);
  const committed = await store.getSessionV1(approval.linkSessionId);
  expect(committed?.state).toEqual({
    state: 'committed_completion_required',
    linkSessionId: approval.linkSessionId,
    walletId: approval.walletId,
    enrollmentId: approval.enrollmentId,
    keyManifestDigestB64u: handoff.manifestDigestB64u,
    transcriptSetDigestB64u: await computeLinkedDeviceProvisioningDeliveriesDigestV1(
      handoff.deliveries,
    ),
  });
  if (!committed || committed.state.state !== 'committed_completion_required') {
    throw new Error('expected committed session');
  }
  await expect(
    provider.submitPreparedProvisioningDeliveriesV1({
      submission,
      session: provisioning.record,
      approval,
      requestedAtMs: 3_003,
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
      session: provisioning.record,
      approval,
      requestedAtMs: 3_004,
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
      session: provisioning.record,
      approval,
      requestedAtMs: 3_005,
    }),
  ).resolves.toEqual(handoff.deliveries);
  await expect(
    provider.getTargetReadyV1({ session, approval, requestedAtMs: 9_500 }),
  ).rejects.toThrow(/expired|does not match approved session/);
  await expect(
    provider.getTargetReadyV1({
      session: committed,
      approval,
      requestedAtMs: 9_500,
    }),
  ).resolves.toEqual(handoff.targetReady);
  await expect(
    provider.prepareProvisioningDeliveriesV1({
      command,
      session: committed,
      approval,
      requestedAtMs: 9_500,
    }),
  ).resolves.toEqual(handoff.deliveries);
});

test('delivery submission replay heals a persisted-output crash gap', async () => {
  const scenario = await createProvisioningHandoffScenario();
  const deliveriesDigestB64u = await persistPreparedDeliveriesCrashGap(
    temporaryDatabase(),
    scenario.handoff,
    3_010,
  );

  expect((await scenario.store.getSessionV1(scenario.approval.linkSessionId))?.state.state).toBe(
    'provisioning',
  );
  await expect(
    scenario.sourceHandoff.submitPreparedProvisioningDeliveriesV1({
      submission: scenario.submission,
      session: scenario.provisioningSession,
      approval: scenario.approval,
      requestedAtMs: 3_011,
    }),
  ).resolves.toEqual(scenario.submission);
  await expectCommittedDigest(scenario.store, scenario.approval.linkSessionId, deliveriesDigestB64u);
});

test('provision replay heals a persisted-output crash gap', async () => {
  const scenario = await createProvisioningHandoffScenario();
  const deliveriesDigestB64u = await persistPreparedDeliveriesCrashGap(
    temporaryDatabase(),
    scenario.handoff,
    3_010,
  );
  const provisioning = createProvisioningProvider(scenario);

  await expect(
    provisioning.provisionLinkedDeviceV1({
      command: scenario.command,
      session: scenario.provisioningSession,
      approval: scenario.approval,
      requestedAtMs: 3_011,
    }),
  ).resolves.toEqual(scenario.handoff.deliveries);
  await expectCommittedDigest(scenario.store, scenario.approval.linkSessionId, deliveriesDigestB64u);
});

test('holder delivery heals a persisted-output crash gap', async () => {
  const scenario = await createProvisioningHandoffScenario();
  const provisioning = createProvisioningProvider(scenario);
  await persistProvisioningReplayCrashGap(temporaryDatabase(), scenario, 3_010);
  const deliveriesDigestB64u = await persistPreparedDeliveriesCrashGap(
    temporaryDatabase(),
    scenario.handoff,
    3_011,
  );

  await expect(
    provisioning.recordHolderDeliveriesV1({
      acknowledgement: scenario.provisioningFixture.acknowledgement,
      session: scenario.provisioningSession,
      approval: scenario.approval,
      requestedAtMs: 3_012,
    }),
  ).resolves.toEqual(scenario.receipt);
  await expectCommittedDigest(scenario.store, scenario.approval.linkSessionId, deliveriesDigestB64u);
});

test('cancellation heals a persisted-output crash gap and preserves committed recovery', async () => {
  const scenario = await createProvisioningHandoffScenario();
  const deliveriesDigestB64u = await persistPreparedDeliveriesCrashGap(
    temporaryDatabase(),
    scenario.handoff,
    3_010,
  );

  await expect(
    scenario.service.cancelSessionV1({
      linkSessionId: scenario.approval.linkSessionId,
      expectedRevision: scenario.provisioningSession.revision,
      nowMs: 3_011,
    }),
  ).resolves.toMatchObject({
    outcome: 'invalid_state',
    state: 'committed_completion_required',
  });
  await expectCommittedDigest(scenario.store, scenario.approval.linkSessionId, deliveriesDigestB64u);
});

test('expiry heals a persisted-output crash gap and preserves committed recovery', async () => {
  const scenario = await createProvisioningHandoffScenario();
  const deliveriesDigestB64u = await persistPreparedDeliveriesCrashGap(
    temporaryDatabase(),
    scenario.handoff,
    3_010,
  );

  await expect(
    scenario.service.expireSessionV1({
      linkSessionId: scenario.approval.linkSessionId,
      expectedRevision: scenario.provisioningSession.revision,
      nowMs: 10_000,
    }),
  ).resolves.toMatchObject({
    outcome: 'invalid_state',
    state: 'committed_completion_required',
  });
  await expectCommittedDigest(scenario.store, scenario.approval.linkSessionId, deliveriesDigestB64u);
});

test('delivery replay rejects a parent commitment digest mismatch', async () => {
  const scenario = await createProvisioningHandoffScenario();
  const wrongCommit = await scenario.service.markCommittedCompletionRequiredV1({
    linkSessionId: scenario.approval.linkSessionId,
    expectedRevision: scenario.provisioningSession.revision,
    transcriptSetDigestB64u: scenario.fixture.receipt.aggregateReceiptDigestB64u,
    nowMs: 3_010,
  });
  expect(wrongCommit.outcome).toBe('applied');
  if (wrongCommit.outcome !== 'applied') throw new Error('expected mismatched committed fixture');
  await persistPreparedDeliveriesCrashGap(temporaryDatabase(), scenario.handoff, 3_011);

  await expect(
    scenario.sourceHandoff.submitPreparedProvisioningDeliveriesV1({
      submission: scenario.submission,
      session: wrongCommit.record,
      approval: scenario.approval,
      requestedAtMs: 3_012,
    }),
  ).rejects.toThrow('committed linked-device output digest changed');
});

test('waits for deliveries submitted after provisioning preparation starts', async () => {
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
  await provider.persistTargetReadyV1({
    targetReady: handoff.targetReady,
    session,
    approval,
    requestedAtMs: 3_000,
  });
  const command: LinkedDeviceProvisioningCommandV1 = {
    kind: 'linked_device_provisioning_command_v1',
    linkSessionId: approval.linkSessionId,
    enrollmentId: approval.enrollmentId,
    deviceId: approval.deviceId,
  };
  const preparing = provider.prepareProvisioningDeliveriesV1({
    command,
    session,
    approval,
    requestedAtMs: 3_004,
  });
  await waitForTestDelay(40);
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
      requestedAtMs: 3_005,
    }),
  ).resolves.toEqual(submission);
  await expect(preparing).resolves.toEqual(handoff.deliveries);
});

async function createProvisioningHandoffScenario() {
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
  await service.createUnclaimedSessionV1({ payload: fixture.payload, nowMs: 3_000 });
  await service.claimSessionV1({ payload: fixture.claimRequest.payload, nowMs: 3_001 });
  const approved = await service.recordOwnerApprovalV1({ approval, nowMs: 3_002 });
  if (approved.outcome !== 'applied') throw new Error('expected approved session');
  const handoff = await buildSourceHandoffFixture(approval);
  await persistRegisteredTargetCredential(temporary.database, handoff);
  const sourceHandoff = new D1LinkedDeviceSourceHandoffProviderV1({
    database: temporary.database,
    scope,
  });
  await sourceHandoff.persistTargetReadyV1({
    targetReady: handoff.targetReady,
    session: approved.record,
    approval,
    requestedAtMs: 3_003,
  });
  const provisioning = await service.recordTargetCredentialV1({
    linkSessionId: approval.linkSessionId,
    expectedRevision: approved.record.revision,
    keyManifestDigestB64u: handoff.manifestDigestB64u,
    nowMs: 3_004,
  });
  if (provisioning.outcome !== 'applied') throw new Error('expected provisioning session');
  const provisioningFixture = buildR103ProvisioningFixture({ ...fixture, approval });
  const receipt = buildLinkedDeviceEnrollmentReceiptV1({
    enrollmentId: approval.enrollmentId,
    walletId: approval.walletId,
    deviceId: approval.deviceId,
    manifestDigestB64u: handoff.manifestDigestB64u,
    aggregateReceiptDigestB64u: fixture.receipt.aggregateReceiptDigestB64u,
    orderedChildReceipts: fixture.receipt.orderedChildReceipts,
    activatedAtMs: 3_012,
  });
  return {
    fixture,
    approval,
    handoff,
    store,
    service,
    sourceHandoff,
    provisioningSession: provisioning.record,
    provisioningFixture,
    receipt,
    submission: {
      kind: 'linked_device_provisioning_deliveries_submission_v1' as const,
      linkSessionId: approval.linkSessionId,
      walletId: approval.walletId,
      enrollmentId: approval.enrollmentId,
      deviceId: approval.deviceId,
      manifestDigestB64u: handoff.manifestDigestB64u,
      deliveries: handoff.deliveries,
    },
    command: {
      kind: 'linked_device_provisioning_command_v1' as const,
      linkSessionId: approval.linkSessionId,
      enrollmentId: approval.enrollmentId,
      deviceId: approval.deviceId,
    },
  };
}

type ProvisioningHandoffScenario = Awaited<ReturnType<typeof createProvisioningHandoffScenario>>;

class ScenarioProvisioningExecution {
  constructor(private readonly scenario: ProvisioningHandoffScenario) {}

  async prepareProvisioningDeliveriesV1() {
    return this.scenario.handoff.deliveries;
  }

  async recordHolderDeliveriesAndActivateV1() {
    return this.scenario.receipt;
  }
}

function createProvisioningProvider(
  scenario: ProvisioningHandoffScenario,
): D1LinkedDeviceProvisioningProviderV1 {
  return new D1LinkedDeviceProvisioningProviderV1({
    database: temporaryDatabase(),
    scope,
    execution: new ScenarioProvisioningExecution(scenario),
  });
}

async function persistPreparedDeliveriesCrashGap(
  database: TemporaryD1Database['database'],
  handoff: Awaited<ReturnType<typeof buildSourceHandoffFixture>>,
  requestedAtMs: number,
) {
  const deliveriesDigestB64u = await computeLinkedDeviceProvisioningDeliveriesDigestV1(
    handoff.deliveries,
  );
  await database
    .prepare(
      `UPDATE linked_device_source_handoffs
          SET deliveries_json = ?, deliveries_digest_b64u = ?, updated_at_ms = ?
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND link_session_id = ?`,
    )
    .bind(
      JSON.stringify(handoff.deliveries),
      deliveriesDigestB64u,
      requestedAtMs,
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(handoff.targetReady.linkSessionId),
    )
    .run();
  return deliveriesDigestB64u;
}

async function persistProvisioningReplayCrashGap(
  database: TemporaryD1Database['database'],
  scenario: ProvisioningHandoffScenario,
  requestedAtMs: number,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO linked_device_provisioning_records (
         namespace, org_id, project_id, env_id, link_session_id,
         enrollment_id, wallet_id, device_id, manifest_digest_b64u,
         deliveries_json, created_at_ms, updated_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(scenario.approval.linkSessionId),
      String(scenario.approval.enrollmentId),
      String(scenario.approval.walletId),
      String(scenario.approval.deviceId),
      scenario.handoff.manifestDigestB64u,
      JSON.stringify(scenario.handoff.deliveries),
      requestedAtMs,
      requestedAtMs,
    )
    .run();
}

async function expectCommittedDigest(
  store: D1LinkedDeviceSessionStoreV1,
  linkSessionId: LinkedDeviceApprovalV1['linkSessionId'],
  deliveriesDigestB64u: Awaited<
    ReturnType<typeof computeLinkedDeviceProvisioningDeliveriesDigestV1>
  >,
): Promise<void> {
  await expect(store.getSessionV1(linkSessionId)).resolves.toMatchObject({
    state: {
      state: 'committed_completion_required',
      transcriptSetDigestB64u: deliveriesDigestB64u,
    },
  });
}

function temporaryDatabase(): TemporaryD1Database['database'] {
  if (!temporary) throw new Error('temporary D1 database is unavailable');
  return temporary.database;
}

async function waitForTestDelay(delayMs: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
}

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
