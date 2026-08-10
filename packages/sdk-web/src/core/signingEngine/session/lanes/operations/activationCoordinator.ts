import type {
  AggregateLaneActivationChildReceiptV1,
  AggregateLaneActivationReceiptV1,
  CommitLaneEnrollmentActivationV1,
  LaneHolderDeliveryReceiptV1,
  LaneProtocolCommitReceiptV1,
  LaneServerActivationReceiptV1,
  RotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotation';
import {
  parseLaneEnrollmentManifestV1,
  parseLaneHolderDeliveryReceiptV1,
  parseLaneProtocolCommitReceiptV1,
  parseLaneServerActivationReceiptV1,
  parseRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';
import {
  computeAggregateLaneActivationReceiptDigestV1,
  computeLaneEnrollmentManifestDigestV1,
  encodeLaneHolderDeliveryReceiptV1,
  encodeLaneProtocolCommitReceiptV1,
  encodeLaneServerActivationReceiptV1,
} from '@shared/signing-lanes/rotationDigests';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256Bytes } from '@shared/utils/digests';

export type LaneActivationChildInputV1 = {
  readonly job: unknown;
  readonly protocolCommitReceipt: unknown;
  readonly holderDeliveryReceipt: unknown;
  readonly serverActivationReceipt: unknown;
};

export type LaneActivationEffectPlanV1 = {
  readonly manifestDigestB64u: string;
  readonly orderedChildren: readonly [
    LaneActivationChildInputV1,
    ...LaneActivationChildInputV1[],
  ];
  readonly aggregateActivationReceipt: AggregateLaneActivationReceiptV1;
  readonly aggregateActivationReceiptDigestB64u: string;
  readonly commitCommand: CommitLaneEnrollmentActivationV1;
};

function nonEmpty<T>(values: readonly T[], label: string): [T, ...T[]] {
  if (!values.length) throw new Error(`${label} must be non-empty`);
  return values as [T, ...T[]];
}

function assertIdentity(
  job: RotatableSigningLaneJobV1,
  protocol: LaneProtocolCommitReceiptV1,
  holder: LaneHolderDeliveryReceiptV1,
  server: LaneServerActivationReceiptV1,
): void {
  if (
    String(job.operationId) !== String(protocol.operationId) ||
    String(job.enrollmentId) !== String(protocol.enrollmentId) ||
    String(job.walletId) !== String(protocol.walletId) ||
    String(job.walletKeyId) !== String(protocol.walletKeyId) ||
    String(job.source.laneId) !== String(protocol.sourceLaneId) ||
    String(job.target.laneId) !== String(protocol.targetLaneId) ||
    String(job.target.laneShareEpoch) !== String(protocol.targetLaneShareEpoch) ||
    String(job.targetMaterialActivationId) !== String(protocol.targetMaterialActivationId) ||
    job.keyFamily !== protocol.keyFamily ||
    String(holder.operationId) !== String(job.operationId) ||
    String(holder.enrollmentId) !== String(job.enrollmentId) ||
    String(holder.targetLaneId) !== String(job.target.laneId) ||
    String(holder.targetLaneShareEpoch) !== String(job.target.laneShareEpoch) ||
    String(holder.targetMaterialActivationId) !== String(job.targetMaterialActivationId) ||
    String(server.operationId) !== String(job.operationId) ||
    String(server.enrollmentId) !== String(job.enrollmentId) ||
    String(server.targetLaneId) !== String(job.target.laneId) ||
    String(server.targetLaneShareEpoch) !== String(job.target.laneShareEpoch) ||
    String(server.targetMaterialActivation.activationId) !==
      String(job.targetMaterialActivationId) ||
    holder.transcriptHashB64u !== protocol.transcriptHashB64u ||
    server.transcriptHashB64u !== protocol.transcriptHashB64u ||
    holder.holderParticipantBindingDigestB64u !==
      job.targetHolder.participantBindingDigestB64u ||
    server.signingWorkerParticipantBindingDigestB64u !==
      job.targetSigningWorker.participantBindingDigestB64u
  ) {
    throw new Error('lane activation receipt identity mismatch');
  }
}

async function digestBytes(value: Uint8Array): Promise<string> {
  return base64UrlEncode(await sha256Bytes(value));
}

async function protocolDigest(value: LaneProtocolCommitReceiptV1): Promise<string> {
  return await digestBytes(encodeLaneProtocolCommitReceiptV1(value));
}

async function holderDigest(value: LaneHolderDeliveryReceiptV1): Promise<string> {
  return await digestBytes(encodeLaneHolderDeliveryReceiptV1(value));
}

async function serverDigest(value: LaneServerActivationReceiptV1): Promise<string> {
  return await digestBytes(encodeLaneServerActivationReceiptV1(value));
}

async function aggregateChild(args: {
  readonly job: RotatableSigningLaneJobV1;
  readonly protocol: LaneProtocolCommitReceiptV1;
  readonly holder: LaneHolderDeliveryReceiptV1;
  readonly server: LaneServerActivationReceiptV1;
}): Promise<AggregateLaneActivationChildReceiptV1> {
  return {
    operationId: args.job.operationId,
    walletKeyId: args.job.walletKeyId,
    targetLaneId: args.job.target.laneId,
    targetLaneShareEpoch: args.job.target.laneShareEpoch,
    targetMaterialActivation: args.server.targetMaterialActivation,
    protocolCommitReceiptDigestB64u: await protocolDigest(args.protocol),
    holderDeliveryReceiptDigestB64u: await holderDigest(args.holder),
    serverActivationReceiptDigestB64u: await serverDigest(args.server),
  };
}

export async function buildLaneActivationEffectPlanV1(args: {
  readonly manifest: unknown;
  readonly children: readonly LaneActivationChildInputV1[];
  readonly activatedAtMs: number;
}): Promise<LaneActivationEffectPlanV1> {
  const manifest = parseLaneEnrollmentManifestV1(args.manifest);
  if (!Number.isSafeInteger(args.activatedAtMs) || args.activatedAtMs < 0) {
    throw new Error('activatedAtMs must be a non-negative safe integer');
  }
  if (!args.children.length || args.children.length !== manifest.orderedChildren.length) {
    throw new Error('lane activation children must match the manifest exactly');
  }
  const parsedChildren: LaneActivationChildInputV1[] = [];
  const aggregateChildren: AggregateLaneActivationChildReceiptV1[] = [];
  for (const [index, child] of args.children.entries()) {
    const job = parseRotatableSigningLaneJobV1(child.job);
    const protocol = parseLaneProtocolCommitReceiptV1(child.protocolCommitReceipt);
    const holder = parseLaneHolderDeliveryReceiptV1(child.holderDeliveryReceipt);
    const server = parseLaneServerActivationReceiptV1(child.serverActivationReceipt);
    const manifestChild = manifest.orderedChildren[index];
    if (!manifestChild || String(manifestChild.operationId) !== String(job.operationId)) {
      throw new Error(`lane activation child ${index} is out of manifest order`);
    }
    assertIdentity(job, protocol, holder, server);
    parsedChildren.push({
      job,
      protocolCommitReceipt: protocol,
      holderDeliveryReceipt: holder,
      serverActivationReceipt: server,
    });
    aggregateChildren.push(await aggregateChild({ job, protocol, holder, server }));
  }
  const manifestDigestB64u = await computeLaneEnrollmentManifestDigestV1(manifest);
  const aggregateActivationReceipt: AggregateLaneActivationReceiptV1 = {
    kind: 'aggregate_lane_activation_receipt_v1',
    enrollmentId: manifest.enrollmentId,
    walletId: manifest.walletId,
    manifestDigestB64u,
    orderedChildReceipts: nonEmpty(aggregateChildren, 'orderedChildReceipts'),
    activatedAtMs: args.activatedAtMs,
  };
  const aggregateActivationReceiptDigestB64u =
    await computeAggregateLaneActivationReceiptDigestV1(aggregateActivationReceipt);
  return {
    manifestDigestB64u,
    orderedChildren: nonEmpty(parsedChildren, 'orderedChildren'),
    aggregateActivationReceipt,
    aggregateActivationReceiptDigestB64u,
    commitCommand: {
      kind: 'commit_lane_enrollment_activation_v1',
      enrollmentId: manifest.enrollmentId,
      walletId: manifest.walletId,
      manifestDigestB64u,
      orderedChildReceipts: aggregateActivationReceipt.orderedChildReceipts,
      activatedAtMs: args.activatedAtMs,
    },
  };
}

export const planLaneActivationV1 = buildLaneActivationEffectPlanV1;
