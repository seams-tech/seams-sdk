import type {
  LaneEnrollmentGatewayV1,
  LaneHolderDeliveryReceiptV1,
  LaneProtocolCasResultV1,
  LaneProtocolCommitReceiptV1,
  RotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotation';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import {
  parseLaneHolderDeliveryReceiptV1,
  parseLaneProtocolCommitReceiptV1,
  parseRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';
import type { LaneHolderRecipientWorkerV1 } from '@shared/signing-lanes/rotation';
import type {
  LaneSealedHolderMaterialRepositoryV1,
  LaneSealedHolderRecordLookupV1,
} from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import {
  sealLaneHolderMaterialV1,
  type OpenLaneHolderRecipientV1,
  type SealedLaneHolderRecipientV1,
} from './recipientPreparation';

export type LaneHolderDeliveryResultV1 = {
  readonly holderDeliveryReceipt: LaneHolderDeliveryReceiptV1;
  readonly gatewayResult: LaneProtocolCasResultV1;
  readonly state: SealedLaneHolderRecipientV1;
  readonly replayed: boolean;
};

function nonEmpty(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${label} is required`);
  return value.trim();
}

function timestamp(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return Number(value);
}

function parseJob(value: unknown): RotatableSigningLaneJobV1 {
  return parseRotatableSigningLaneJobV1(value);
}

function parseCommit(value: unknown): LaneProtocolCommitReceiptV1 {
  return parseLaneProtocolCommitReceiptV1(value);
}

function lookupForJob(job: RotatableSigningLaneJobV1): LaneSealedHolderRecordLookupV1 {
  return {
    operationId: job.operationId,
    enrollmentId: job.enrollmentId,
    targetLaneId: job.target.laneId,
    targetLaneShareEpoch: job.target.laneShareEpoch,
    targetMaterialActivationId: job.targetMaterialActivationId,
  };
}

function assertCommitJobIdentity(
  job: RotatableSigningLaneJobV1,
  commit: LaneProtocolCommitReceiptV1,
): void {
  if (
    String(job.operationId) !== String(commit.operationId) ||
    String(job.enrollmentId) !== String(commit.enrollmentId) ||
    String(job.walletId) !== String(commit.walletId) ||
    String(job.walletKeyId) !== String(commit.walletKeyId) ||
    String(job.source.laneId) !== String(commit.sourceLaneId) ||
    String(job.target.laneId) !== String(commit.targetLaneId) ||
    String(job.target.laneShareEpoch) !== String(commit.targetLaneShareEpoch) ||
    String(job.targetMaterialActivationId) !== String(commit.targetMaterialActivationId) ||
    job.keyFamily !== commit.keyFamily
  ) {
    throw new Error('holder delivery job and protocol receipt are not identical');
  }
}

function sealedStateFromRecord(
  job: RotatableSigningLaneJobV1,
  commit: LaneProtocolCommitReceiptV1,
  record: Awaited<ReturnType<LaneSealedHolderMaterialRepositoryV1['get']>>,
): SealedLaneHolderRecipientV1 {
  if (!record) throw new Error('sealed holder record is missing');
  if (
    String(record.operationId) !== String(job.operationId) ||
    String(record.enrollmentId) !== String(job.enrollmentId) ||
    String(record.walletId) !== String(job.walletId) ||
    String(record.walletKeyId) !== String(job.walletKeyId) ||
    String(record.laneId) !== String(job.target.laneId) ||
    String(record.laneShareEpoch) !== String(job.target.laneShareEpoch) ||
    String(record.targetMaterialActivationId) !== String(job.targetMaterialActivationId) ||
    record.transcriptHashB64u !== commit.transcriptHashB64u ||
    record.holderRecipientKeyDigestB64u !== job.targetHolder.hpkePublicKeyDigestB64u ||
    record.holderCiphertextDigestSetB64u !== commit.targetHolderCiphertextDigestSetB64u
  ) {
    throw new Error('sealed holder record does not match the exact protocol commitment');
  }
  const holderDeliveryReceipt = parseLaneHolderDeliveryReceiptV1({
    kind: 'lane_holder_delivery_receipt_v1',
    operationId: record.operationId,
    enrollmentId: record.enrollmentId,
    targetLaneId: record.laneId,
    targetLaneShareEpoch: record.laneShareEpoch,
    targetMaterialActivationId: record.targetMaterialActivationId,
    holderParticipantBindingDigestB64u: record.holderParticipantBindingDigestB64u,
    holderRecipientKeyDigestB64u: record.holderRecipientKeyDigestB64u,
    holderCiphertextDigestSetB64u: record.holderCiphertextDigestSetB64u,
    sealedHolderRecordDigestB64u: record.sealedHolderRecordDigestB64u,
    transcriptHashB64u: record.transcriptHashB64u,
    acknowledgedAtMs: record.acknowledgedAtMs,
  });
  return {
    state: 'sealed',
    operationId: record.operationId,
    enrollmentId: record.enrollmentId,
    walletId: record.walletId,
    walletKeyId: record.walletKeyId,
    targetLaneId: record.laneId,
    targetLaneShareEpoch: record.laneShareEpoch,
    targetMaterialActivationId: record.targetMaterialActivationId,
    holderParticipantBindingDigestB64u: record.holderParticipantBindingDigestB64u,
    holderRecipientKeyDigestB64u: record.holderRecipientKeyDigestB64u,
    holderCiphertextDigestSetB64u: record.holderCiphertextDigestSetB64u,
    sealedHolderRecordDigestB64u: record.sealedHolderRecordDigestB64u,
    transcriptHashB64u: record.transcriptHashB64u,
    sealedHolderMaterialB64u: record.sealedHolderMaterialB64u,
    acknowledgedAtMs: record.acknowledgedAtMs,
    holderDeliveryReceipt,
  };
}

async function assertReplayCiphertext(
  record: NonNullable<Awaited<ReturnType<LaneSealedHolderMaterialRepositoryV1['get']>>>,
  ciphertext: string,
): Promise<void> {
  const digest = base64UrlEncode(await sha256BytesUtf8(ciphertext));
  if (record.holderCiphertextDigestSetB64u !== digest) {
    throw new Error('holder redelivery attempted to substitute ciphertext');
  }
}

async function recordHolderDelivery(args: {
  readonly gateway: LaneEnrollmentGatewayV1;
  readonly receipt: LaneHolderDeliveryReceiptV1;
  readonly expectedVersion: number;
}): Promise<LaneProtocolCasResultV1> {
  return await args.gateway.recordLaneHolderDeliveryV1({
    receipt: args.receipt,
    expectedVersion: args.expectedVersion,
  });
}

async function replaySealedHolderDelivery(args: {
  readonly job: RotatableSigningLaneJobV1;
  readonly commit: LaneProtocolCommitReceiptV1;
  readonly record: NonNullable<Awaited<ReturnType<LaneSealedHolderMaterialRepositoryV1['get']>>>;
  readonly gateway: LaneEnrollmentGatewayV1;
  readonly expectedVersion: number;
}): Promise<LaneHolderDeliveryResultV1> {
  const state = sealedStateFromRecord(args.job, args.commit, args.record);
  return {
    holderDeliveryReceipt: state.holderDeliveryReceipt,
    gatewayResult: await recordHolderDelivery({
      gateway: args.gateway,
      receipt: state.holderDeliveryReceipt,
      expectedVersion: args.expectedVersion,
    }),
    state,
    replayed: true,
  };
}

export async function deliverLaneHolderPackageV1(args: {
  readonly job: unknown;
  readonly protocolCommitReceipt: unknown;
  readonly holderCiphertextB64u: unknown;
  readonly expectedVersion: number;
  readonly recipient: OpenLaneHolderRecipientV1;
  readonly worker: LaneHolderRecipientWorkerV1;
  readonly gateway: LaneEnrollmentGatewayV1;
  readonly repository: LaneSealedHolderMaterialRepositoryV1;
  readonly nowMs: () => number;
}): Promise<LaneHolderDeliveryResultV1> {
  const job = parseJob(args.job);
  const commit = parseCommit(args.protocolCommitReceipt);
  assertCommitJobIdentity(job, commit);
  const holderCiphertextB64u = nonEmpty(args.holderCiphertextB64u, 'holderCiphertextB64u');
  const existing = await args.repository.get(lookupForJob(job));
  if (existing) {
    await assertReplayCiphertext(existing, holderCiphertextB64u);
    return await replaySealedHolderDelivery({
      job,
      commit,
      record: existing,
      gateway: args.gateway,
      expectedVersion: args.expectedVersion,
    });
  }
  const state = await sealLaneHolderMaterialV1({
    state: args.recipient,
    job,
    protocolCommitReceipt: commit,
    holderCiphertextB64u,
    repository: args.repository,
    worker: args.worker,
    acknowledgedAtMs: timestamp(args.nowMs(), 'nowMs'),
  });
  return {
    holderDeliveryReceipt: state.holderDeliveryReceipt,
    gatewayResult: await recordHolderDelivery({
      gateway: args.gateway,
      receipt: state.holderDeliveryReceipt,
      expectedVersion: args.expectedVersion,
    }),
    state,
    replayed: false,
  };
}

export const deliverCommittedLaneHolderPackageV1 = deliverLaneHolderPackageV1;
