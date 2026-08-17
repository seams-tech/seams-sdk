import {
  buildLaneEnrollmentManifestV1,
  buildLaneProductEpochActiveV1,
  buildLaneProductEpochRevokedV1,
  buildLaneHolderDeliveryReceiptV1,
  buildLaneProtocolCommitReceiptV1,
  buildLaneServerActivationReceiptV1,
  buildLaneProtocolRecordV1,
  parseLaneEnrollmentLifecycleV1,
  parseLaneProtocolLifecycleV1,
  parseRotatableSigningLaneJobV1,
} from '../../../packages/shared-ts/src/signing-lanes/rotationParsers';
import type {
  LaneEnrollmentManifestV1,
  LaneEnrollmentManifestChildV1,
  LaneHolderDeliveryReceiptV1,
  LaneProtocolCommitReceiptV1,
  LaneServerActivationReceiptV1,
  RotatableSigningLaneJobV1,
  LaneProductEpochActiveV1,
  LaneProductEpochRevokedV1,
  RevokeSigningLaneV1,
} from '../../../packages/shared-ts/src/signing-lanes/rotation';
import {
  parseLaneHolderParticipantRecordV1,
  parseSigningWorkerParticipantRecordV1,
} from '../../../packages/shared-ts/src/signing-lanes/participants';
import {
  buildLaneHolderParticipantRecordWithDigestV1,
  computeLaneParticipantSetBindingDigestV1,
} from '../../../packages/shared-ts/src/signing-lanes/participantDigest';
import { computeLaneEnrollmentManifestDigestV1 } from '../../../packages/shared-ts/src/signing-lanes/rotationDigests';
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
import {
  buildOwnerLaneParticipantContinuityV1,
  parseWalletSignerId,
} from '../../../packages/shared-ts/src/signing-lanes/ownerContinuity';
import { parseDigestB64u } from '../../../packages/shared-ts/src/utils/canonicalPrimitives';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import type {
  LaneEnrollmentId,
  WalletKeyId,
} from '../../../packages/shared-ts/src/signing-lanes/ids';
import type { LaneEffectRecordV1 } from '../../../packages/sdk-server-ts/src/core/signingLanes/LaneEffectJournalStore';
import type {
  LaneEnrollmentAdmissionRecord,
  LaneProtocolAdmissionRecord,
} from '../../../packages/sdk-server-ts/src/core/signingLanes/LaneLifecycleStore';
import {
  parseLaneSealedHolderRecordV1,
  type LaneSealedHolderRecordV1,
} from '../../../packages/sdk-web/src/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';

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

export async function bindR102TargetHolderParticipantV1(
  job: RotatableSigningLaneJobV1,
): Promise<RotatableSigningLaneJobV1> {
  const targetHolder = await buildLaneHolderParticipantRecordWithDigestV1({
    participantId: job.targetHolder.participantId,
    custody: {
      kind: 'lane_holder_custody_identity_v1',
      custodyBindingId: job.targetHolder.custodyBindingId,
      custodyBindingDigestB64u: job.targetHolder.custodyBindingDigestB64u,
    },
    hpkePublicKeyB64u: job.targetHolder.hpkePublicKeyB64u,
    hpkePublicKeyDigestB64u: job.targetHolder.hpkePublicKeyDigestB64u,
  });
  return parseRotatableSigningLaneJobV1({
    ...job,
    targetHolder: {
      ...job.targetHolder,
      participantBindingDigestB64u: targetHolder.participantBindingDigestB64u,
    },
  });
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
const SECP256K1_GENERATOR_B64U = base64UrlEncode(
  Uint8Array.from(
    Buffer.from('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'hex'),
  ),
);

function buildR102OwnerParticipantContinuity(suffix: string) {
  return buildOwnerLaneParticipantContinuityV1({
    signerId: parseWalletSignerId(`owner-signer-r102-${suffix}`),
    participantIds: [1, 2],
    signingWorkerId: requiredId(parseMpcSigningWorkerRef, `worker:owner-r102-${suffix}`),
    custodyKeyManifestDigestB64u: parseDigestB64u(DIGEST_B64U),
    sourceIdentityDigestB64u: parseDigestB64u(DIGEST_B64U),
  });
}

function buildR102Source(
  suffix: string,
  laneKind: 'owner_passkey' | 'linked_device',
  materialActivation: ReturnType<typeof buildR102MaterialActivation>,
) {
  if (laneKind === 'owner_passkey') {
    return {
      laneId: `source-lane-r102-${suffix}`,
      laneKind: 'owner_passkey' as const,
      laneShareEpoch: `source-epoch-r102-${suffix}`,
      revocationEpoch: 0,
      participantBindingDigestB64u: DIGEST_B64U,
      materialActivation,
      sourceKind: 'owner_registration' as const,
      ownerParticipantContinuity: buildR102OwnerParticipantContinuity(suffix),
    };
  }
  return {
    laneId: `source-lane-r102-${suffix}`,
    laneKind: 'linked_device' as const,
    laneShareEpoch: `source-epoch-r102-${suffix}`,
    revocationEpoch: 0,
    participantBindingDigestB64u: DIGEST_B64U,
    materialActivation,
    sourceKind: 'provisioned_lane' as const,
    holderParticipantId: `source-holder-r102-${suffix}`,
    signingWorkerParticipantId: `source-worker-r102-${suffix}`,
    signingWorkerRecipientKeyId: `source-worker-key-r102-${suffix}`,
  };
}

export type R102LaneEnrollmentFixture = {
  readonly manifest: LaneEnrollmentManifestV1;
  readonly children: readonly [RotatableSigningLaneJobV1, RotatableSigningLaneJobV1];
};

export function buildR102LaneEnrollmentFixture(): R102LaneEnrollmentFixture {
  const enrollmentId = requiredId(parseLaneEnrollmentId, 'enrollment-r102-lifecycle');
  const walletId = requiredId(parseWalletId, 'wallet-r102-lifecycle');
  const first = buildR102LaneJob('one');
  const children = [first, bindR102JobAuthorization(buildR102LaneJob('two'), first)] as const;
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

export async function buildR102EnrollmentAdmissionRecordFixture(
  fixture: R102LaneEnrollmentFixture,
): Promise<LaneEnrollmentAdmissionRecord> {
  const manifestDigestB64u = await computeLaneEnrollmentManifestDigestV1(fixture.manifest);
  return buildR102ActiveEnrollmentAdmissionRecordFixture(fixture.manifest, manifestDigestB64u);
}

export function buildR102ActiveEnrollmentAdmissionRecordFixture(
  manifest: LaneEnrollmentManifestV1,
  manifestDigestB64u: string,
): LaneEnrollmentAdmissionRecord {
  return {
    value: {
      manifest,
      lifecycle: parseLaneEnrollmentLifecycleV1({
        state: 'active',
        manifestDigestB64u,
        aggregateReceiptDigestB64u: DIGEST_B64U,
        activatedAtMs: 4_000,
      }),
    },
    version: 1,
    commandDigestB64u: DIGEST_B64U,
  };
}

export function buildR102PreparingEnrollmentAdmissionRecordFixture(
  manifest: LaneEnrollmentManifestV1,
  manifestDigestB64u: string,
): LaneEnrollmentAdmissionRecord {
  return {
    value: {
      manifest,
      lifecycle: parseLaneEnrollmentLifecycleV1({
        state: 'preparing',
        manifestDigestB64u,
        startedAtMs: 1_000,
      }),
    },
    version: 1,
    commandDigestB64u: manifestDigestB64u,
  };
}

export function buildR102ActiveProtocolAdmissionRecordFixture(
  job: RotatableSigningLaneJobV1,
): LaneProtocolAdmissionRecord {
  return {
    version: 1,
    commandDigestB64u: DIGEST_B64U,
    value: buildLaneProtocolRecordV1({
      job,
      lifecycle: parseLaneProtocolLifecycleV1({
        state: 'active',
        transcriptHashB64u: DIGEST_B64U,
        protocolCommitReceiptDigestB64u: DIGEST_B64U,
        holderDeliveryReceiptDigestB64u: DIGEST_B64U,
        serverActivationReceiptDigestB64u: DIGEST_B64U,
        aggregateActivationReceiptDigestB64u: DIGEST_B64U,
        activatedAtMs: 4_000,
      }),
    }),
  };
}

export function buildR102CommittedProtocolAdmissionRecordFixture(
  job: RotatableSigningLaneJobV1,
  transcriptHashB64u: string,
  receiptDigestB64u: string,
): LaneProtocolAdmissionRecord {
  return {
    version: 2,
    commandDigestB64u: receiptDigestB64u,
    value: buildLaneProtocolRecordV1({
      job,
      lifecycle: parseLaneProtocolLifecycleV1({
        state: 'committed_awaiting_holder_delivery',
        startedAtMs: 1_000,
        committedAtMs: 2_000,
        transcriptHashB64u,
        protocolCommitReceiptDigestB64u: receiptDigestB64u,
      }),
    }),
  };
}

export function buildR102ManifestChild(
  job: RotatableSigningLaneJobV1,
): LaneEnrollmentManifestChildV1 {
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

export function buildR102MixedLaneEnrollmentFixture(): R102LaneEnrollmentFixture {
  const enrollmentId = requiredId(parseLaneEnrollmentId, 'enrollment-r102-lifecycle');
  const walletId = requiredId(parseWalletId, 'wallet-r102-lifecycle');
  const first = buildR102LaneJob('ed25519');
  const children = [
    first,
    bindR102JobAuthorization(buildR102EcdsaLaneJob('ecdsa'), first),
  ] as const;
  const manifest = buildLaneEnrollmentManifestV1({
    enrollmentId,
    walletId,
    authorization: children[0].authorization,
    orderedChildren: [buildR102ManifestChild(children[0]), buildR102ManifestChild(children[1])],
    createdAtMs: 1_000,
    expiresAtMs: 100_000,
  });
  return { manifest, children };
}

function bindR102JobAuthorization(
  job: RotatableSigningLaneJobV1,
  authority: RotatableSigningLaneJobV1,
): RotatableSigningLaneJobV1 {
  return parseRotatableSigningLaneJobV1({
    ...job,
    authorization: authority.authorization,
  });
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
    source: buildR102Source(
      suffix,
      'owner_passkey',
      buildR102MaterialActivation(`source-${suffix}`),
    ),
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

export function buildR102EcdsaLaneJob(
  suffix: string,
  options: { readonly sourceLaneKind: 'owner_passkey' | 'linked_device' } = {
    sourceLaneKind: 'owner_passkey',
  },
): RotatableSigningLaneJobV1 {
  const sourceMaterialActivation = buildR102MaterialActivation(`source-${suffix}`);
  const target =
    options.sourceLaneKind === 'linked_device'
      ? {
          operation: 'refresh_lane',
          laneId: `source-lane-r102-${suffix}`,
          laneKind: 'linked_device',
          laneShareEpoch: `target-epoch-r102-${suffix}`,
          expectedTargetState: 'active_previous_epoch',
          priorMaterialActivation: sourceMaterialActivation,
        }
      : {
          operation: 'create_lane',
          laneId: `target-lane-r102-${suffix}`,
          laneKind: 'linked_device',
          laneShareEpoch: `target-epoch-r102-${suffix}`,
          expectedTargetState: 'absent',
        };
  const authorization =
    options.sourceLaneKind === 'linked_device'
      ? {
          kind: 'owner_lane_refresh',
          authorizedOperationId: `authorized-r102-${suffix}`,
          ownerLaneRefreshDigestB64u: DIGEST_B64U,
        }
      : {
          kind: 'linked_device_enrollment',
          authorizedOperationId: `authorized-r102-${suffix}`,
          linkedDeviceEnrollmentId: `linked-device-r102-${suffix}`,
          linkedDevicePermissionDigestB64u: DIGEST_B64U,
        };
  return parseRotatableSigningLaneJobV1({
    kind: 'ecdsa_additive_lane_job_v1',
    keyFamily: 'ecdsa_secp256k1',
    operationId: `operation-r102-${suffix}`,
    enrollmentId: 'enrollment-r102-lifecycle',
    idempotencyKey: `idempotency-r102-${suffix}`,
    walletId: 'wallet-r102-lifecycle',
    walletKeyId: `wallet-key-r102-${suffix}`,
    source: buildR102Source(suffix, options.sourceLaneKind, sourceMaterialActivation),
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
    target,
    authorization,
    evmFamilySigningKeySlotId: 'wallet-key:evm-family:wallet-r102-lifecycle:root-r102:version-1',
    thresholdPublicKey33B64u: SECP256K1_GENERATOR_B64U,
    evmAddress: '0x0000000000000000000000000000000000000001',
    sourceCapability: {
      manifestId: `manifest-source-r102-${suffix}`,
      manifestRevision: 1,
      serverGeneration: `server-generation-r102-${suffix}`,
      ecdsaThresholdKeyId: `threshold-key-r102-${suffix}`,
      relayerKeyId: `relayer-key-r102-${suffix}`,
    },
    targetCapability: {
      manifestId: `manifest-target-r102-${suffix}`,
      manifestRevision: 1,
      ecdsaThresholdKeyId: `threshold-key-r102-${suffix}`,
      orderedThresholdSessions: [
        {
          chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 1, networkSlug: 'mainnet' },
          thresholdSessionId: `threshold-session-r102-${suffix}`,
          participantBindingDigestB64u: DIGEST_B64U,
        },
      ],
    },
    sourceHolderVerifyingShare33B64u: SECP256K1_GENERATOR_B64U,
    sourceServerVerifyingShare33B64u: SECP256K1_GENERATOR_B64U,
    reshareChannelBindingDigestB64u: DIGEST_B64U,
    transcriptEncoding: 'ecdsa_additive_lane_transcript_v1',
  });
}

export function buildR102EcdsaRefreshJob(
  sourceJob: Extract<RotatableSigningLaneJobV1, { keyFamily: 'ecdsa_secp256k1' }>,
): Extract<
  RotatableSigningLaneJobV1,
  { keyFamily: 'ecdsa_secp256k1'; target: { operation: 'refresh_lane' } }
> {
  if (sourceJob.target.operation !== 'create_lane')
    throw new Error('refresh fixture source must be a created lane');
  const sourceMaterialActivation =
    buildR102ServerActivationReceipt(sourceJob).targetMaterialActivation;
  const parsed = parseRotatableSigningLaneJobV1({
    kind: 'ecdsa_additive_lane_job_v1',
    keyFamily: 'ecdsa_secp256k1',
    operationId: 'operation-r102-ecdsa-refresh',
    enrollmentId: 'enrollment-r102-refresh',
    idempotencyKey: 'idempotency-r102-ecdsa-refresh',
    walletId: sourceJob.walletId,
    walletKeyId: sourceJob.walletKeyId,
    source: {
      sourceKind: 'provisioned_lane',
      laneId: sourceJob.target.laneId,
      laneKind: sourceJob.target.laneKind,
      laneShareEpoch: sourceJob.target.laneShareEpoch,
      revocationEpoch: sourceJob.source.revocationEpoch,
      holderParticipantId: sourceJob.targetHolder.participantId,
      signingWorkerParticipantId: sourceJob.targetSigningWorker.participantId,
      signingWorkerRecipientKeyId: sourceJob.targetSigningWorker.recipientKeyId,
      participantBindingDigestB64u: sourceJob.targetSigningWorker.participantBindingDigestB64u,
      materialActivation: sourceMaterialActivation,
    },
    targetHolder: {
      participantId: 'target-holder-r102-ecdsa-refresh',
      participantBindingDigestB64u: DIGEST_B64U,
      custodyBindingId: 'target-custody-r102-ecdsa-refresh',
      custodyBindingDigestB64u: DIGEST_B64U,
      hpkePublicKeyB64u: HPKE_PUBLIC_KEY_B64U,
      hpkePublicKeyDigestB64u: DIGEST_B64U,
    },
    targetSigningWorker: {
      participantId: 'target-worker-r102-ecdsa-refresh',
      participantBindingDigestB64u: DIGEST_B64U,
      recipientKeyId: 'target-worker-key-r102-ecdsa-refresh',
      hpkePublicKeyB64u: HPKE_PUBLIC_KEY_B64U,
      hpkePublicKeyDigestB64u: DIGEST_B64U,
    },
    targetMaterialActivationId: 'target-activation-r102-ecdsa-refresh',
    protocolVersion: 'rotatable_signing_lane_protocol_v1',
    expiresAtMs: 200_000,
    target: {
      operation: 'refresh_lane',
      laneId: sourceJob.target.laneId,
      laneKind: sourceJob.target.laneKind,
      laneShareEpoch: 'target-epoch-r102-ecdsa-refresh',
      expectedTargetState: 'active_previous_epoch',
      priorMaterialActivation: sourceMaterialActivation,
    },
    authorization: {
      kind: 'owner_lane_refresh',
      authorizedOperationId: 'authorized-r102-ecdsa-refresh',
      ownerLaneRefreshDigestB64u: base64UrlEncode(new Uint8Array(32).fill(13)),
    },
    evmFamilySigningKeySlotId: sourceJob.evmFamilySigningKeySlotId,
    thresholdPublicKey33B64u: sourceJob.thresholdPublicKey33B64u,
    evmAddress: sourceJob.evmAddress,
    sourceCapability: {
      manifestId: sourceJob.targetCapability.manifestId,
      manifestRevision: sourceJob.targetCapability.manifestRevision,
      serverGeneration: sourceJob.sourceCapability.serverGeneration,
      ecdsaThresholdKeyId: sourceJob.targetCapability.ecdsaThresholdKeyId,
      relayerKeyId: sourceJob.sourceCapability.relayerKeyId,
    },
    targetCapability: sourceJob.targetCapability,
    sourceHolderVerifyingShare33B64u: sourceJob.sourceHolderVerifyingShare33B64u,
    sourceServerVerifyingShare33B64u: sourceJob.sourceServerVerifyingShare33B64u,
    reshareChannelBindingDigestB64u: sourceJob.reshareChannelBindingDigestB64u,
    transcriptEncoding: sourceJob.transcriptEncoding,
  });
  if (!isEcdsaRefreshJob(parsed))
    throw new Error('refresh fixture parser changed its exact branch');
  return parsed;
}

function isEcdsaRefreshJob(
  job: RotatableSigningLaneJobV1,
): job is Extract<
  RotatableSigningLaneJobV1,
  { keyFamily: 'ecdsa_secp256k1'; target: { operation: 'refresh_lane' } }
> {
  return job.keyFamily === 'ecdsa_secp256k1' && job.target.operation === 'refresh_lane';
}

export function buildR102ProtocolCommitReceipt(
  job: RotatableSigningLaneJobV1,
  committedAtMs = 2_000,
): LaneProtocolCommitReceiptV1 {
  const publicCommitmentB64u =
    job.keyFamily === 'ecdsa_secp256k1' ? SECP256K1_GENERATOR_B64U : PUBLIC_KEY_B64U;
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
    targetHolderPublicCommitmentB64u: publicCommitmentB64u,
    targetServerPublicCommitmentB64u: publicCommitmentB64u,
    targetHolderCiphertextDigestSetB64u: DIGEST_B64U,
    targetServerCiphertextDigestSetB64u: DIGEST_B64U,
    holderRecipientKeyDigestB64u: job.targetHolder.hpkePublicKeyDigestB64u,
    serverRecipientKeyDigestB64u: job.targetSigningWorker.hpkePublicKeyDigestB64u,
    transcriptHashB64u: DIGEST_B64U,
    committedAtMs,
  });
}

export function buildR103SealedHolderRecord(
  job: RotatableSigningLaneJobV1,
  receipt: LaneProtocolCommitReceiptV1,
): LaneSealedHolderRecordV1 {
  return parseLaneSealedHolderRecordV1({
    kind: 'lane_sealed_holder_record_v1',
    operationId: job.operationId,
    enrollmentId: job.enrollmentId,
    walletId: job.walletId,
    walletKeyId: job.walletKeyId,
    laneId: job.target.laneId,
    laneShareEpoch: job.target.laneShareEpoch,
    targetMaterialActivationId: job.targetMaterialActivationId,
    holderParticipantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
    custodyBindingId: job.targetHolder.custodyBindingId,
    holderRecipientKeyDigestB64u: receipt.holderRecipientKeyDigestB64u,
    holderCiphertextDigestSetB64u: receipt.targetHolderCiphertextDigestSetB64u,
    sealedHolderRecordDigestB64u: DIGEST_B64U,
    transcriptHashB64u: receipt.transcriptHashB64u,
    sealedHolderMaterialB64u: base64UrlEncode(new Uint8Array([1])),
    acknowledgedAtMs: 4_000,
    storedAtMs: 4_000,
  });
}

export function buildR102HolderDeliveryReceipt(
  job: RotatableSigningLaneJobV1,
  acknowledgedAtMs = 3_000,
): LaneHolderDeliveryReceiptV1 {
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
  const signingWorker = requiredId(
    parseMpcSigningWorkerRef,
    String(job.targetSigningWorker.participantId),
  );
  return buildLaneServerActivationReceiptV1({
    operationId: job.operationId,
    enrollmentId: job.enrollmentId,
    targetLaneId: job.target.laneId,
    targetLaneShareEpoch: job.target.laneShareEpoch,
    targetMaterialActivation: buildMpcMaterialActivationRef({
      activationId: job.targetMaterialActivationId,
      capability: job.source.materialActivation.capability,
      materialOwner: job.source.materialActivation.materialOwner,
      keyBinding: job.source.materialActivation.keyBinding,
      lifecycleBinding: job.source.materialActivation.lifecycleBinding,
      signingWorker,
    }),
    signingWorkerParticipantBindingDigestB64u: job.targetSigningWorker.participantBindingDigestB64u,
    serverCiphertextDigestSetB64u: DIGEST_B64U,
    transcriptHashB64u: DIGEST_B64U,
    activatedAtMs,
  });
}

export async function buildR102ActiveProductEpoch(
  job: RotatableSigningLaneJobV1,
): Promise<LaneProductEpochActiveV1> {
  if (job.target.operation !== 'create_lane') throw new Error('fixture target must be creation');
  const holderParticipant = parseLaneHolderParticipantRecordV1({
    kind: 'lane_holder_participant_v1',
    participantId: job.targetHolder.participantId,
    custodyBindingId: job.targetHolder.custodyBindingId,
    custodyBindingDigestB64u: job.targetHolder.custodyBindingDigestB64u,
    hpkePublicKeyB64u: job.targetHolder.hpkePublicKeyB64u,
    hpkePublicKeyDigestB64u: job.targetHolder.hpkePublicKeyDigestB64u,
    participantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
  });
  const signingWorkerParticipant = parseSigningWorkerParticipantRecordV1({
    kind: 'signing_worker_participant_v1',
    participantId: job.targetSigningWorker.participantId,
    recipientKeyId: job.targetSigningWorker.recipientKeyId,
    hpkePublicKeyB64u: job.targetSigningWorker.hpkePublicKeyB64u,
    hpkePublicKeyDigestB64u: job.targetSigningWorker.hpkePublicKeyDigestB64u,
    participantBindingDigestB64u: job.targetSigningWorker.participantBindingDigestB64u,
  });
  return buildLaneProductEpochActiveV1({
    walletId: job.walletId,
    walletKeyId: job.walletKeyId,
    laneId: job.target.laneId,
    laneKind: job.target.laneKind,
    laneShareEpoch: job.target.laneShareEpoch,
    keyFamily: job.keyFamily,
    enrollmentId: job.enrollmentId,
    operationId: job.operationId,
    targetMaterialActivationId: job.targetMaterialActivationId,
    materialActivation: buildR102ServerActivationReceipt(job).targetMaterialActivation,
    publicIdentityDigestB64u: DIGEST_B64U,
    holderParticipant,
    signingWorkerParticipant,
    participantSetBindingDigestB64u: await computeLaneParticipantSetBindingDigestV1({
      holderParticipant,
      signingWorkerParticipant,
    }),
    revocationEpoch: job.source.revocationEpoch,
    createdAtMs: 1_000,
    aggregateManifestDigestB64u: DIGEST_B64U,
    aggregateActivationReceiptDigestB64u: DIGEST_B64U,
    activatedAtMs: 4_000,
  });
}

export function buildR102RevokedProductEpoch(
  active: LaneProductEpochActiveV1,
  command: RevokeSigningLaneV1,
): LaneProductEpochRevokedV1 {
  return buildLaneProductEpochRevokedV1({
    walletId: active.walletId,
    walletKeyId: active.walletKeyId,
    laneId: active.laneId,
    laneKind: active.laneKind,
    laneShareEpoch: active.laneShareEpoch,
    keyFamily: active.keyFamily,
    enrollmentId: active.enrollmentId,
    operationId: active.operationId,
    targetMaterialActivationId: active.targetMaterialActivationId,
    materialActivation: active.materialActivation,
    publicIdentityDigestB64u: active.publicIdentityDigestB64u,
    holderParticipant: active.holderParticipant,
    signingWorkerParticipant: active.signingWorkerParticipant,
    participantSetBindingDigestB64u: active.participantSetBindingDigestB64u,
    revocationEpoch: command.expectedRevocationEpoch + 1,
    createdAtMs: active.createdAtMs,
    revocationReason: command.reason,
    retirementEffectBindingDigestB64u: command.retirementEffectBindingDigestB64u,
    revocationReceiptDigestB64u: command.retirementRequestDigestB64u,
    revokedAtMs: command.requestedAtMs,
  });
}

function buildR102MaterialActivation(
  suffix: string,
  activationIdValue?: string,
  signingWorkerValue?: string,
) {
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
  const signingWorker = requiredId(
    parseMpcSigningWorkerRef,
    signingWorkerValue ?? `worker-r102-${suffix}`,
  );
  return buildMpcMaterialActivationRef({
    activationId,
    capability,
    materialOwner,
    keyBinding,
    lifecycleBinding,
    signingWorker,
  });
}
