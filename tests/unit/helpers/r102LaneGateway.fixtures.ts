import {
  buildLaneEnrollmentManifestV1,
  buildLaneHolderDeliveryReceiptV1,
  buildLaneProtocolCommitReceiptV1,
  buildLaneServerActivationReceiptV1,
  parseRotatableSigningLaneJobV1,
} from '../../../packages/shared-ts/src/signing-lanes/rotationParsers';
import type {
  LaneEnrollmentManifestV1,
  LaneEnrollmentManifestChildV1,
  LaneHolderDeliveryReceiptV1,
  LaneProtocolCommitReceiptV1,
  LaneServerActivationReceiptV1,
  RotatableSigningLaneJobV1,
} from '../../../packages/shared-ts/src/signing-lanes/rotation';
import {
  buildMpcMaterialActivationRef,
  parseCapabilityInstanceRef,
  parseLaneEnrollmentId,
  parseLaneOperationId,
  parseLaneShareEpoch,
  parseMpcKeyBindingRef,
  parseMpcLifecycleBindingRef,
  parseMpcMaterialActivationId,
  parseMpcMaterialOwnerRef,
  parseMpcSigningWorkerRef,
  parseSigningLaneId,
  parseWalletId,
  parseWalletKeyId,
} from '../../../packages/shared-ts/src/utils/domainIds';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import type {
  LaneEnrollmentId,
  WalletKeyId,
} from '../../../packages/shared-ts/src/signing-lanes/ids';
import type { LaneEffectRecordV1 } from '../../../packages/sdk-server-ts/src/core/signingLanes/LaneEffectJournalStore';

function requiredId<T>(
  parser: (raw: unknown) => { ok: true; value: T } | { ok: false; error: { message: string } },
  raw: string,
): T {
  const result = parser(raw);
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

export function buildR102LaneEffectRecordFixture(): LaneEffectRecordV1 {
  return {
    kind: 'lane_effect_record_v1',
    effectId: 'effect-r102-fixture',
    enrollmentId: requiredId(parseLaneEnrollmentId, 'enrollment-r102-fixture'),
    operationId: requiredId(parseLaneOperationId, 'operation-r102-fixture'),
    walletId: requiredId(parseWalletId, 'wallet-r102-fixture'),
    walletKeyId: requiredId(parseWalletKeyId, 'wallet-key-r102-fixture'),
    laneId: requiredId(parseSigningLaneId, 'lane-r102-fixture'),
    laneShareEpoch: requiredId(parseLaneShareEpoch, 'epoch-r102-fixture'),
    effectKind: 'retire_server_material',
    requestDigestB64u: 'request-digest-r102-fixture',
    status: 'recorded',
    recordedAtMs: 1_000,
  };
}

export function buildR102LaneLockIdentitiesFixture(): {
  readonly walletKeyId: WalletKeyId;
  readonly enrollmentId: LaneEnrollmentId;
} {
  return {
    walletKeyId: requiredId(parseWalletKeyId, 'wallet-key-r102-lock'),
    enrollmentId: requiredId(parseLaneEnrollmentId, 'enrollment-r102-lock'),
  };
}

const DIGEST_B64U = base64UrlEncode(new Uint8Array(32));
const PUBLIC_KEY_B64U = base64UrlEncode(new Uint8Array(32).fill(7));
const HPKE_PUBLIC_KEY_B64U = base64UrlEncode(new Uint8Array([1, 2, 3, 4]));

export type R102LaneEnrollmentFixture = {
  readonly manifest: LaneEnrollmentManifestV1;
  readonly children: readonly [RotatableSigningLaneJobV1, RotatableSigningLaneJobV1];
};

export function buildR102LaneEnrollmentFixture(): R102LaneEnrollmentFixture {
  const enrollmentId = requiredId(parseLaneEnrollmentId, 'enrollment-r102-lifecycle');
  const walletId = requiredId(parseWalletId, 'wallet-r102-lifecycle');
  const children = [buildR102LaneJob('one'), buildR102LaneJob('two')] as const;
  const first = children[0];
  const manifest = buildLaneEnrollmentManifestV1({
    enrollmentId,
    walletId,
    authorization: first.authorization,
    orderedChildren: [buildR102ManifestChild(children[0]), buildR102ManifestChild(children[1])],
    createdAtMs: 1_000,
    expiresAtMs: 100_000,
  });
  return { manifest, children };
}

function buildR102ManifestChild(job: RotatableSigningLaneJobV1): LaneEnrollmentManifestChildV1 {
  if (job.target.operation !== 'create_lane') throw new Error('fixture target must be creation');
  return {
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
    signingWorkerParticipantBindingDigestB64u: job.targetSigningWorker.participantBindingDigestB64u,
  };
}

export function buildR102LaneJob(suffix: string): RotatableSigningLaneJobV1 {
  const enrollmentId = 'enrollment-r102-lifecycle';
  const walletId = 'wallet-r102-lifecycle';
  const raw = {
    kind: 'ed25519_yao_lane_job_v1',
    keyFamily: 'ed25519',
    operationId: `operation-r102-${suffix}`,
    enrollmentId,
    idempotencyKey: `idempotency-r102-${suffix}`,
    walletId,
    walletKeyId: `wallet-key-r102-${suffix}`,
    source: {
      laneId: `source-lane-r102-${suffix}`,
      laneKind: 'owner_passkey',
      laneShareEpoch: `source-epoch-r102-${suffix}`,
      revocationEpoch: 0,
      holderParticipantId: `source-holder-r102-${suffix}`,
      signingWorkerParticipantId: `source-worker-r102-${suffix}`,
      signingWorkerRecipientKeyId: `source-worker-key-r102-${suffix}`,
      participantBindingDigestB64u: DIGEST_B64U,
      materialActivation: buildR102MaterialActivation(`source-${suffix}`),
    },
    targetHolder: {
      participantId: `target-holder-r102-${suffix}`,
      participantBindingDigestB64u: DIGEST_B64U,
      custodyBindingId: `target-custody-r102-${suffix}`,
      custodyBindingDigestB64u: DIGEST_B64U,
      hpkePublicKeyB64u: HPKE_PUBLIC_KEY_B64U,
      hpkePublicKeyDigestB64u: DIGEST_B64U,
    },
    targetSigningWorker: {
      participantId: `target-worker-r102-${suffix}`,
      participantBindingDigestB64u: DIGEST_B64U,
      recipientKeyId: `target-worker-key-r102-${suffix}`,
      hpkePublicKeyB64u: HPKE_PUBLIC_KEY_B64U,
      hpkePublicKeyDigestB64u: DIGEST_B64U,
    },
    targetMaterialActivationId: `target-activation-r102-${suffix}`,
    protocolVersion: 'rotatable_signing_lane_protocol_v1',
    expiresAtMs: 100_000,
    target: {
      operation: 'create_lane',
      laneId: `target-lane-r102-${suffix}`,
      laneKind: 'linked_device',
      laneShareEpoch: `target-epoch-r102-${suffix}`,
      expectedTargetState: 'absent',
    },
    authorization: {
      kind: 'linked_device_enrollment',
      authorizedOperationId: `authorized-r102-${suffix}`,
      linkedDeviceEnrollmentId: `linked-device-r102-${suffix}`,
      linkedDevicePermissionDigestB64u: DIGEST_B64U,
    },
    yaoRequestKind: 'lane_provisioning',
    registeredPublicKeyB64u: PUBLIC_KEY_B64U,
    nearEd25519SigningKeyId: `near-key-r102-${suffix}`,
    keyCreationSignerSlot: 1,
    stableContextBindingB64u: DIGEST_B64U,
    yaoSuiteId: `yao-suite-r102-${suffix}`,
    circuitDigestB64u: DIGEST_B64U,
  };
  return parseRotatableSigningLaneJobV1(raw);
}

export function buildR102ProtocolCommitReceipt(
  job: RotatableSigningLaneJobV1,
  committedAtMs = 2_000,
): LaneProtocolCommitReceiptV1 {
  if (job.target.operation !== 'create_lane') throw new Error('fixture target must be creation');
  return buildLaneProtocolCommitReceiptV1({
    operationId: job.operationId,
    enrollmentId: job.enrollmentId,
    walletId: job.walletId,
    walletKeyId: job.walletKeyId,
    sourceLaneId: job.source.laneId,
    sourceLaneShareEpoch: job.source.laneShareEpoch,
    sourceRevocationEpoch: job.source.revocationEpoch,
    sourceMaterialActivation: job.source.materialActivation,
    targetLaneId: job.target.laneId,
    targetLaneShareEpoch: job.target.laneShareEpoch,
    targetMaterialActivationId: job.targetMaterialActivationId,
    keyFamily: job.keyFamily,
    publicIdentityDigestB64u: DIGEST_B64U,
    targetHolderPublicCommitmentB64u: PUBLIC_KEY_B64U,
    targetServerPublicCommitmentB64u: PUBLIC_KEY_B64U,
    targetHolderCiphertextDigestSetB64u: DIGEST_B64U,
    targetServerCiphertextDigestSetB64u: DIGEST_B64U,
    holderRecipientKeyDigestB64u: job.targetHolder.hpkePublicKeyDigestB64u,
    serverRecipientKeyDigestB64u: job.targetSigningWorker.hpkePublicKeyDigestB64u,
    transcriptHashB64u: DIGEST_B64U,
    committedAtMs,
  });
}

export function buildR102HolderDeliveryReceipt(
  job: RotatableSigningLaneJobV1,
  acknowledgedAtMs = 3_000,
): LaneHolderDeliveryReceiptV1 {
  if (job.target.operation !== 'create_lane') throw new Error('fixture target must be creation');
  return buildLaneHolderDeliveryReceiptV1({
    operationId: job.operationId,
    enrollmentId: job.enrollmentId,
    targetLaneId: job.target.laneId,
    targetLaneShareEpoch: job.target.laneShareEpoch,
    targetMaterialActivationId: job.targetMaterialActivationId,
    holderParticipantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
    holderRecipientKeyDigestB64u: job.targetHolder.hpkePublicKeyDigestB64u,
    holderCiphertextDigestSetB64u: DIGEST_B64U,
    sealedHolderRecordDigestB64u: DIGEST_B64U,
    transcriptHashB64u: DIGEST_B64U,
    acknowledgedAtMs,
  });
}

export function buildR102ServerActivationReceipt(
  job: RotatableSigningLaneJobV1,
  activatedAtMs = 4_000,
): LaneServerActivationReceiptV1 {
  if (job.target.operation !== 'create_lane') throw new Error('fixture target must be creation');
  return buildLaneServerActivationReceiptV1({
    operationId: job.operationId,
    enrollmentId: job.enrollmentId,
    targetLaneId: job.target.laneId,
    targetLaneShareEpoch: job.target.laneShareEpoch,
    targetMaterialActivation: buildR102MaterialActivation(
      String(job.targetMaterialActivationId),
      String(job.targetMaterialActivationId),
    ),
    signingWorkerParticipantBindingDigestB64u: job.targetSigningWorker.participantBindingDigestB64u,
    serverCiphertextDigestSetB64u: DIGEST_B64U,
    transcriptHashB64u: DIGEST_B64U,
    activatedAtMs,
  });
}

function buildR102MaterialActivation(suffix: string, activationIdValue?: string) {
  const activationId = requiredId(
    parseMpcMaterialActivationId,
    activationIdValue ?? `activation-r102-${suffix}`,
  );
  const capability = requiredId(parseCapabilityInstanceRef, `capability-r102-${suffix}`);
  const materialOwner = requiredId(parseMpcMaterialOwnerRef, `owner-r102-${suffix}`);
  const keyBinding = requiredId(parseMpcKeyBindingRef, `key-binding-r102-${suffix}`);
  const lifecycleBinding = requiredId(
    parseMpcLifecycleBindingRef,
    `lifecycle-binding-r102-${suffix}`,
  );
  const signingWorker = requiredId(parseMpcSigningWorkerRef, `worker-r102-${suffix}`);
  return buildMpcMaterialActivationRef({
    activationId,
    capability,
    materialOwner,
    keyBinding,
    lifecycleBinding,
    signingWorker,
  });
}
