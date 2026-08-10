import { expect, test } from '@playwright/test';
import {
  computeLaneEnrollmentManifestDigestV1,
  computeRevokeSigningLaneDigestV1,
  encodeLaneHolderDeliveryReceiptV1,
  encodeLaneProtocolCommitReceiptV1,
  encodeLaneServerActivationReceiptV1,
} from '../../packages/shared-ts/src/signing-lanes/rotationDigests';
import { computeLaneParticipantSetBindingDigestV1 } from '../../packages/shared-ts/src/signing-lanes/participantDigest';
import {
  buildAggregateLaneActivationChildReceiptV1,
  buildCompleteSigningLaneRevocationV1,
  buildRevokeSigningLaneV1,
} from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import type {
  AggregateLaneActivationChildReceiptV1,
  LaneHolderDeliveryReceiptV1,
  LaneProtocolCommitReceiptV1,
  LaneServerActivationReceiptV1,
  RotatableSigningLaneJobV1,
} from '../../packages/shared-ts/src/signing-lanes/rotation';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { sha256Bytes } from '../../packages/shared-ts/src/utils/digests';
import {
  buildMpcMaterialActivationRef,
  parseCapabilityInstanceRef,
} from '../../packages/shared-ts/src/utils/domainIds';
import { CloudflareD1LaneEnrollmentGateway } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/signingLanes/d1LaneEnrollmentGateway';
import { CloudflareD1LaneLifecycleStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/signingLanes/d1LaneLifecycleStore';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import {
  buildR102HolderDeliveryReceipt,
  buildR102LaneEnrollmentFixture,
  buildR102MixedLaneEnrollmentFixture,
  buildR102ProtocolCommitReceipt,
  buildR102ServerActivationReceipt,
} from './helpers/r102LaneGateway.fixtures';
import { buildR102EcdsaServerRetirementReceipt } from './helpers/ecdsaServerRetirement.fixtures';

const scope = {
  namespace: 'r102-lifecycle-namespace',
  orgId: 'r102-lifecycle-org',
  projectId: 'r102-lifecycle-project',
  envId: 'r102-lifecycle-env',
} as const;

test.describe('R102 lane lifecycle D1 gateway', () => {
  test('prepares mixed children and atomically activates every child epoch', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
      const fixture = buildR102LaneEnrollmentFixture();
      const store = new CloudflareD1LaneLifecycleStore({
        database: temporary.database,
        scope,
        now: () => 1_000,
      });
      const gateway = new CloudflareD1LaneEnrollmentGateway({ lifecycleStore: store });

      const prepared = await gateway.prepareLaneEnrollmentV1(fixture);
      expect(prepared).toMatchObject({
        kind: 'lane_enrollment_preparation_result_v1',
        outcome: 'applied',
      });
      if (prepared.outcome === 'conflict')
        throw new Error('fixture enrollment admission conflicted');
      expect(prepared.orderedProtocols).toHaveLength(2);

      const orderedChildReceipts: AggregateLaneActivationChildReceiptV1[] = [];
      for (const job of fixture.children) {
        orderedChildReceipts.push(await completeChild(gateway, job));
      }
      const manifestDigestB64u = await computeLaneEnrollmentManifestDigestV1(fixture.manifest);
      const firstChild = orderedChildReceipts[0]!;
      const substitutedCapability = parseCapabilityInstanceRef('capability:r102-substituted');
      if (!substitutedCapability.ok) throw new Error(substitutedCapability.error.message);
      await expect(
        gateway.commitLaneEnrollmentActivationV1({
          kind: 'commit_lane_enrollment_activation_v1',
          enrollmentId: fixture.manifest.enrollmentId,
          walletId: fixture.manifest.walletId,
          manifestDigestB64u,
          orderedChildReceipts: [
            buildAggregateLaneActivationChildReceiptV1({
              operationId: firstChild.operationId,
              walletKeyId: firstChild.walletKeyId,
              targetLaneId: firstChild.targetLaneId,
              targetLaneShareEpoch: firstChild.targetLaneShareEpoch,
              targetMaterialActivation: buildMpcMaterialActivationRef({
                activationId: firstChild.targetMaterialActivation.activationId,
                capability: substitutedCapability.value,
                materialOwner: firstChild.targetMaterialActivation.materialOwner,
                keyBinding: firstChild.targetMaterialActivation.keyBinding,
                lifecycleBinding: firstChild.targetMaterialActivation.lifecycleBinding,
                signingWorker: firstChild.targetMaterialActivation.signingWorker,
              }),
              protocolCommitReceiptDigestB64u: firstChild.protocolCommitReceiptDigestB64u,
              holderDeliveryReceiptDigestB64u: firstChild.holderDeliveryReceiptDigestB64u,
              serverActivationReceiptDigestB64u: firstChild.serverActivationReceiptDigestB64u,
            }),
            orderedChildReceipts[1]!,
          ],
          activatedAtMs: 5_000,
        }),
      ).rejects.toThrow('product epoch is not pending or differs from aggregate receipt');
      const activated = await gateway.commitLaneEnrollmentActivationV1({
        kind: 'commit_lane_enrollment_activation_v1',
        enrollmentId: fixture.manifest.enrollmentId,
        walletId: fixture.manifest.walletId,
        manifestDigestB64u,
        orderedChildReceipts: [orderedChildReceipts[0]!, orderedChildReceipts[1]!],
        activatedAtMs: 5_000,
      });
      expect(activated).toMatchObject({
        kind: 'lane_enrollment_activation_result_v1',
        outcome: 'applied',
        lifecycle: { state: 'active' },
      });
      if (activated.outcome === 'conflict') throw new Error('fixture visibility commit conflicted');
      expect(activated.productEpochs).toHaveLength(2);
      expect(activated.productEpochs.every((epoch) => epoch.state === 'active')).toBe(true);
      for (const epoch of activated.productEpochs) {
        expect(epoch.revocationEpoch).toBe(0);
        expect(epoch.aggregateManifestDigestB64u).toBe(manifestDigestB64u);
        expect(epoch.holderParticipant.kind).toBe('lane_holder_participant_v1');
        expect(epoch.signingWorkerParticipant.kind).toBe('signing_worker_participant_v1');
        await expect(
          computeLaneParticipantSetBindingDigestV1({
            holderParticipant: epoch.holderParticipant,
            signingWorkerParticipant: epoch.signingWorkerParticipant,
          }),
        ).resolves.toBe(epoch.participantSetBindingDigestB64u);
      }
      const persisted = await store.listEnrollmentProductEpochs(fixture.manifest.enrollmentId);
      expect(persisted.map((epoch) => epoch.state)).toEqual(['active', 'active']);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('replays a receipt that survived before its lifecycle CAS', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
      const fixture = buildR102LaneEnrollmentFixture();
      const store = new CloudflareD1LaneLifecycleStore({
        database: temporary.database,
        scope,
        now: () => 1_000,
      });
      const gateway = new CloudflareD1LaneEnrollmentGateway({ lifecycleStore: store });
      await gateway.prepareLaneEnrollmentV1(fixture);
      const job = fixture.children[0];
      const receipt = buildR102ProtocolCommitReceipt(job);
      const receiptDigestB64u = await protocolCommitDigest(receipt);

      await expect(
        store.putProtocolCommitReceipt(receipt, receiptDigestB64u),
      ).resolves.toMatchObject({ outcome: 'applied' });
      await expect(
        gateway.recordLaneProtocolCommitV1({ receipt, expectedVersion: 1 }),
      ).resolves.toMatchObject({
        outcome: 'applied',
        record: { lifecycle: { state: 'committed_awaiting_holder_delivery' } },
      });
      await expect(
        gateway.recordLaneProtocolCommitV1({ receipt, expectedVersion: 1 }),
      ).resolves.toMatchObject({
        outcome: 'replayed',
        record: { lifecycle: { state: 'committed_awaiting_holder_delivery' } },
      });
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('fences one lane revocation and preserves an unrelated active lane', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
      const fixture = buildR102MixedLaneEnrollmentFixture();
      const store = new CloudflareD1LaneLifecycleStore({
        database: temporary.database,
        scope,
        now: () => 1_000,
      });
      const gateway = new CloudflareD1LaneEnrollmentGateway({ lifecycleStore: store });
      await activateFixture(gateway, fixture);
      const target = fixture.children[1];
      if (target.keyFamily !== 'ecdsa_secp256k1') throw new Error('fixture target must be ECDSA');
      if (target.target.operation !== 'create_lane')
        throw new Error('fixture target must be creation');
      const command = buildRevokeSigningLaneV1({
        walletId: target.walletId,
        walletKeyId: target.walletKeyId,
        laneId: target.target.laneId,
        laneShareEpoch: target.target.laneShareEpoch,
        expectedRevocationEpoch: 0,
        reason: 'user_revoked',
        retirementCorrelationId: 'correlation-r102-revocation-race',
        retirementRequestDigestB64u: base64UrlEncode(new Uint8Array(32).fill(8)),
        retirementEffectBindingDigestB64u: base64UrlEncode(new Uint8Array(32).fill(9)),
        requestedAtMs: 6_000,
      });
      const fenced = await gateway.fenceSigningLaneRevocationV1(command);
      expect(fenced).toMatchObject({
        kind: 'lane_signing_lane_revocation_fence_result_v1',
        outcome: 'applied',
        productEpoch: { state: 'revocation_pending', revocationEpoch: 1 },
      });
      await expect(gateway.fenceSigningLaneRevocationV1(command)).resolves.toMatchObject({
        outcome: 'replayed',
      });
      if (fenced.outcome !== 'applied') throw new Error('lane revocation fence was not applied');
      const targetActivation = buildR102ServerActivationReceipt(target).targetMaterialActivation;
      const retirementReceipt = await buildR102EcdsaServerRetirementReceipt(target, {
        materialActivation: targetActivation,
        revocationEpoch: command.expectedRevocationEpoch,
        retirementCorrelationId: command.retirementCorrelationId,
        retirementRequestDigestB64u: command.retirementRequestDigestB64u,
        lifecycleId: String(targetActivation.lifecycleBinding),
      });
      const completion = buildCompleteSigningLaneRevocationV1({
        command,
        expectedVersion: fenced.version,
        commandDigestB64u: await computeRevokeSigningLaneDigestV1(command),
        retirementReceipt,
        revokedAtMs: 7_000,
      });
      await expect(gateway.completeSigningLaneRevocationV1(completion)).resolves.toMatchObject({
        kind: 'lane_signing_lane_revocation_result_v1',
        outcome: 'applied',
        productEpoch: {
          state: 'revoked',
          revocationEpoch: 1,
          retirementEffectBindingDigestB64u: command.retirementEffectBindingDigestB64u,
          revocationReceiptDigestB64u: retirementReceipt.receiptDigestB64u,
        },
        retirementReceipt,
      });
      await expect(gateway.completeSigningLaneRevocationV1(completion)).resolves.toMatchObject({
        outcome: 'replayed',
      });
      const substitutedReceipt = await buildR102EcdsaServerRetirementReceipt(target, {
        materialActivation: targetActivation,
        revocationEpoch: command.expectedRevocationEpoch,
        retirementCorrelationId: command.retirementCorrelationId,
        retirementRequestDigestB64u: command.retirementRequestDigestB64u,
        lifecycleId: String(targetActivation.lifecycleBinding),
        retiredAt: '2026-08-11T00:00:01.000Z',
      });
      const substitutedCompletion = buildCompleteSigningLaneRevocationV1({
        command,
        expectedVersion: fenced.version,
        commandDigestB64u: await computeRevokeSigningLaneDigestV1(command),
        retirementReceipt: substitutedReceipt,
        revokedAtMs: 7_000,
      });
      await expect(
        gateway.completeSigningLaneRevocationV1(substitutedCompletion),
      ).resolves.toMatchObject({ outcome: 'conflict' });
      await expect(gateway.fenceSigningLaneRevocationV1(command)).resolves.toMatchObject({
        outcome: 'already_completed',
        retirementReceipt,
      });
      await expect(
        gateway.fenceSigningLaneRevocationV1({
          ...command,
          retirementCorrelationId: 'correlation-r102-revocation-substitution',
        }),
      ).resolves.toMatchObject({ outcome: 'conflict' });
      const unrelated = await store.getProductEpoch({
        walletId: fixture.manifest.walletId,
        walletKeyId: fixture.children[0].walletKeyId,
        laneId: targetLaneId(fixture.children[0]),
        laneShareEpoch: targetShareEpoch(fixture.children[0]),
      });
      expect(unrelated?.state).toBe('active');
      const tamperedReceipt = {
        ...retirementReceipt,
        receiptDigestB64u: base64UrlEncode(new Uint8Array(32).fill(12)),
      };
      await temporary.database
        .prepare(
          `UPDATE lane_receipts SET receipt_json = ?1 WHERE namespace = ?2 AND org_id = ?3 AND project_id = ?4 AND env_id = ?5 AND operation_id = ?6 AND receipt_kind = 'ecdsa_server_retirement'`,
        )
        .bind(
          JSON.stringify(tamperedReceipt),
          scope.namespace,
          scope.orgId,
          scope.projectId,
          scope.envId,
          String(target.operationId),
        )
        .run();
      await expect(gateway.fenceSigningLaneRevocationV1(command)).rejects.toThrow(
        'self-digest is invalid',
      );
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });
});

async function completeChild(
  gateway: CloudflareD1LaneEnrollmentGateway,
  job: RotatableSigningLaneJobV1,
): Promise<AggregateLaneActivationChildReceiptV1> {
  if (job.target.operation !== 'create_lane') throw new Error('fixture target must be creation');
  const protocolReceipt = buildR102ProtocolCommitReceipt(job);
  const protocol = await gateway.recordLaneProtocolCommitV1({
    receipt: protocolReceipt,
    expectedVersion: 1,
  });
  if (protocol.outcome === 'conflict') throw new Error('fixture protocol commit conflicted');
  const holderReceipt = buildR102HolderDeliveryReceipt(job);
  const holder = await gateway.recordLaneHolderDeliveryV1({
    receipt: holderReceipt,
    expectedVersion: protocol.version,
  });
  if (holder.outcome === 'conflict') throw new Error('fixture holder delivery conflicted');
  const serverReceipt = buildR102ServerActivationReceipt(job);
  const server = await gateway.activateLaneServerMaterialV1({
    receipt: serverReceipt,
    expectedVersion: holder.version,
  });
  if (server.outcome === 'conflict') throw new Error('fixture server activation conflicted');
  return {
    operationId: job.operationId,
    walletKeyId: job.walletKeyId,
    targetLaneId: job.target.laneId,
    targetLaneShareEpoch: job.target.laneShareEpoch,
    targetMaterialActivation: serverReceipt.targetMaterialActivation,
    protocolCommitReceiptDigestB64u: await receiptDigest(protocolReceipt),
    holderDeliveryReceiptDigestB64u: await receiptDigest(holderReceipt),
    serverActivationReceiptDigestB64u: await receiptDigest(serverReceipt),
  };
}

async function activateFixture(
  gateway: CloudflareD1LaneEnrollmentGateway,
  fixture: ReturnType<typeof buildR102LaneEnrollmentFixture>,
): Promise<void> {
  await gateway.prepareLaneEnrollmentV1(fixture);
  const childReceipts: AggregateLaneActivationChildReceiptV1[] = [];
  for (const job of fixture.children) childReceipts.push(await completeChild(gateway, job));
  const manifestDigestB64u = await computeLaneEnrollmentManifestDigestV1(fixture.manifest);
  await gateway.commitLaneEnrollmentActivationV1({
    kind: 'commit_lane_enrollment_activation_v1',
    enrollmentId: fixture.manifest.enrollmentId,
    walletId: fixture.manifest.walletId,
    manifestDigestB64u,
    orderedChildReceipts: [childReceipts[0]!, childReceipts[1]!],
    activatedAtMs: 5_000,
  });
}

async function protocolCommitDigest(receipt: LaneProtocolCommitReceiptV1): Promise<string> {
  return receiptDigest(receipt);
}

async function receiptDigest(
  receipt:
    | LaneProtocolCommitReceiptV1
    | LaneHolderDeliveryReceiptV1
    | LaneServerActivationReceiptV1,
): Promise<string> {
  const encoded = (() => {
    switch (receipt.kind) {
      case 'lane_protocol_commit_receipt_v1':
        return encodeLaneProtocolCommitReceiptV1(receipt);
      case 'lane_holder_delivery_receipt_v1':
        return encodeLaneHolderDeliveryReceiptV1(receipt);
      case 'lane_server_activation_receipt_v1':
        return encodeLaneServerActivationReceiptV1(receipt);
      default:
        return assertNeverReceipt(receipt);
    }
  })();
  return base64UrlEncode(await sha256Bytes(encoded));
}

function targetLaneId(job: RotatableSigningLaneJobV1) {
  if (job.target.operation !== 'create_lane') throw new Error('fixture target must be creation');
  return job.target.laneId;
}

function targetShareEpoch(job: RotatableSigningLaneJobV1) {
  if (job.target.operation !== 'create_lane') throw new Error('fixture target must be creation');
  return job.target.laneShareEpoch;
}

function assertNeverReceipt(value: never): never {
  throw new Error('unexpected fixture receipt');
}
