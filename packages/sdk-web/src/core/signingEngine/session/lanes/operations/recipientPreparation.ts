import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import type {
  LaneHolderDeliveryReceiptV1,
  LaneHolderRecipientHandleV1,
  LaneHolderRecipientWorkerV1,
  LaneProtocolCommitReceiptV1,
  RotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotation';
import {
  parseLaneProtocolCommitReceiptV1,
  parseRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';
import type {
  LaneEnrollmentId,
  LaneOperationId,
  LaneShareEpoch,
  SigningLaneId,
} from '@shared/signing-lanes/ids';
import type { MpcMaterialActivationId, WalletId, WalletKeyId } from '@shared/utils/domainIds';
import type {
  LaneSealedHolderMaterialRepositoryV1,
  LaneSealedHolderRecordV1,
} from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';

export type OpenLaneHolderRecipientV1 = {
  readonly state: 'open';
  readonly operationId: LaneOperationId;
  readonly enrollmentId: LaneEnrollmentId;
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly targetLaneId: SigningLaneId;
  readonly targetLaneShareEpoch: LaneShareEpoch;
  readonly targetMaterialActivationId: MpcMaterialActivationId;
  readonly holderParticipantBindingDigestB64u: string;
  readonly holderRecipientKeyDigestB64u: string;
  readonly recipientKeyId: LaneHolderRecipientHandleV1;
};

export type SealedLaneHolderRecipientV1 = {
  readonly state: 'sealed';
  readonly operationId: LaneOperationId;
  readonly enrollmentId: LaneEnrollmentId;
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly targetLaneId: SigningLaneId;
  readonly targetLaneShareEpoch: LaneShareEpoch;
  readonly targetMaterialActivationId: MpcMaterialActivationId;
  readonly holderParticipantBindingDigestB64u: string;
  readonly holderRecipientKeyDigestB64u: string;
  readonly recipientKeyId: LaneHolderRecipientHandleV1;
  readonly holderCiphertextDigestSetB64u: string;
  readonly sealedHolderRecordDigestB64u: string;
  readonly transcriptHashB64u: string;
  readonly holderCiphertextB64u: string;
  readonly acknowledgedAtMs: number;
  readonly holderDeliveryReceipt: LaneHolderDeliveryReceiptV1;
};

export type DiscardedLaneHolderRecipientV1 = {
  readonly state: 'discarded';
  readonly operationId: LaneOperationId;
  readonly enrollmentId: LaneEnrollmentId;
  readonly recipientKeyId: LaneHolderRecipientHandleV1;
};

export type LaneHolderRecipientPreparationV1 =
  | OpenLaneHolderRecipientV1
  | SealedLaneHolderRecipientV1
  | DiscardedLaneHolderRecipientV1;

function nonEmpty(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function recipientHandle(value: unknown): LaneHolderRecipientHandleV1 {
  return nonEmpty(value, 'recipientKeyId') as LaneHolderRecipientHandleV1;
}

function digest(value: unknown, label: string): string {
  try {
    return parseDigestB64u(value);
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function safeTimestamp(value: unknown, label: string): number {
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

function assertJobCommitIdentity(
  job: RotatableSigningLaneJobV1,
  receipt: LaneProtocolCommitReceiptV1,
): void {
  if (
    String(job.operationId) !== String(receipt.operationId) ||
    String(job.enrollmentId) !== String(receipt.enrollmentId) ||
    String(job.walletId) !== String(receipt.walletId) ||
    String(job.walletKeyId) !== String(receipt.walletKeyId) ||
    String(job.source.laneId) !== String(receipt.sourceLaneId) ||
    String(job.source.laneShareEpoch) !== String(receipt.sourceLaneShareEpoch) ||
    String(job.source.revocationEpoch) !== String(receipt.sourceRevocationEpoch) ||
    String(job.target.laneId) !== String(receipt.targetLaneId) ||
    String(job.target.laneShareEpoch) !== String(receipt.targetLaneShareEpoch) ||
    String(job.targetMaterialActivationId) !== String(receipt.targetMaterialActivationId) ||
    job.keyFamily !== receipt.keyFamily
  ) {
    throw new Error('lane protocol receipt does not match its exact job');
  }
}

function targetIdentity(job: RotatableSigningLaneJobV1): {
  readonly operationId: LaneOperationId;
  readonly enrollmentId: LaneEnrollmentId;
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly targetLaneId: SigningLaneId;
  readonly targetLaneShareEpoch: LaneShareEpoch;
  readonly targetMaterialActivationId: MpcMaterialActivationId;
  readonly holderParticipantBindingDigestB64u: string;
  readonly holderRecipientKeyDigestB64u: string;
} {
  return {
    operationId: job.operationId,
    enrollmentId: job.enrollmentId,
    walletId: job.walletId,
    walletKeyId: job.walletKeyId,
    targetLaneId: job.target.laneId,
    targetLaneShareEpoch: job.target.laneShareEpoch,
    targetMaterialActivationId: job.targetMaterialActivationId,
    holderParticipantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
    holderRecipientKeyDigestB64u: job.targetHolder.hpkePublicKeyDigestB64u,
  };
}

async function ciphertextDigest(ciphertextB64u: string): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(ciphertextB64u));
}

function assertCiphertextDigest(
  commit: LaneProtocolCommitReceiptV1,
  computedDigestB64u: string,
): void {
  if (commit.targetHolderCiphertextDigestSetB64u !== computedDigestB64u) {
    throw new Error('holder ciphertext digest does not match the protocol commitment');
  }
}

function holderDeliveryReceipt(
  identity: ReturnType<typeof targetIdentity>,
  commit: LaneProtocolCommitReceiptV1,
  ciphertextDigestB64u: string,
  sealedHolderRecordDigestB64u: string,
  acknowledgedAtMs: number,
): LaneHolderDeliveryReceiptV1 {
  return {
    kind: 'lane_holder_delivery_receipt_v1',
    operationId: identity.operationId,
    enrollmentId: identity.enrollmentId,
    targetLaneId: identity.targetLaneId,
    targetLaneShareEpoch: identity.targetLaneShareEpoch,
    targetMaterialActivationId: identity.targetMaterialActivationId,
    holderParticipantBindingDigestB64u: identity.holderParticipantBindingDigestB64u,
    holderRecipientKeyDigestB64u: identity.holderRecipientKeyDigestB64u,
    holderCiphertextDigestSetB64u: ciphertextDigestB64u,
    sealedHolderRecordDigestB64u,
    transcriptHashB64u: commit.transcriptHashB64u,
    acknowledgedAtMs,
  };
}

function assertOpenState(state: LaneHolderRecipientPreparationV1): asserts state is OpenLaneHolderRecipientV1 {
  if (state.state !== 'open') {
    throw new Error(`lane holder recipient cannot transition from ${state.state}`);
  }
}

export async function prepareLaneHolderRecipientV1(args: {
  readonly job: unknown;
  readonly worker: LaneHolderRecipientWorkerV1;
}): Promise<OpenLaneHolderRecipientV1> {
  const job = parseJob(args.job);
  const recipient = await args.worker.createLaneHolderRecipientV1(job.targetHolder);
  const recipientKeyId = recipientHandle(recipient.recipientKeyId);
  const identity = targetIdentity(job);
  return { state: 'open', ...identity, recipientKeyId };
}

export const openLaneHolderRecipientV1 = prepareLaneHolderRecipientV1;
export const createLaneHolderRecipientV1 = prepareLaneHolderRecipientV1;

export async function sealLaneHolderMaterialV1(args: {
  readonly state: OpenLaneHolderRecipientV1;
  readonly job: unknown;
  readonly protocolCommitReceipt: unknown;
  readonly holderCiphertextB64u: unknown;
  readonly repository: LaneSealedHolderMaterialRepositoryV1;
  readonly worker: LaneHolderRecipientWorkerV1;
  readonly acknowledgedAtMs: number;
}): Promise<SealedLaneHolderRecipientV1> {
  const job = parseJob(args.job);
  assertOpenState(args.state);
  const commit = parseCommit(args.protocolCommitReceipt);
  assertJobCommitIdentity(job, commit);
  const identity = targetIdentity(job);
  if (
    args.state.operationId !== identity.operationId ||
    args.state.enrollmentId !== identity.enrollmentId ||
    args.state.targetLaneId !== identity.targetLaneId ||
    args.state.targetLaneShareEpoch !== identity.targetLaneShareEpoch ||
    args.state.targetMaterialActivationId !== identity.targetMaterialActivationId ||
    args.state.holderRecipientKeyDigestB64u !== identity.holderRecipientKeyDigestB64u
  ) {
    throw new Error('open holder recipient state does not match its job');
  }
  const ciphertextB64u = nonEmpty(args.holderCiphertextB64u, 'holderCiphertextB64u');
  const ciphertextDigestB64u = await ciphertextDigest(ciphertextB64u);
  assertCiphertextDigest(commit, ciphertextDigestB64u);
  const sealed = await args.worker.openAndSealLaneHolderPackageV1({
    ciphertextB64u,
    recipientKeyId: args.state.recipientKeyId,
    targetLaneId: identity.targetLaneId,
    targetLaneShareEpoch: identity.targetLaneShareEpoch,
  });
  const sealedHolderRecordDigestB64u = digest(
    sealed.sealedHolderRecordDigestB64u,
    'sealedHolderRecordDigestB64u',
  );
  const acknowledgedAtMs = safeTimestamp(args.acknowledgedAtMs, 'acknowledgedAtMs');
  const deliveryReceipt = holderDeliveryReceipt(
    identity,
    commit,
    ciphertextDigestB64u,
    sealedHolderRecordDigestB64u,
    acknowledgedAtMs,
  );
  const record: LaneSealedHolderRecordV1 = {
    kind: 'lane_sealed_holder_record_v1',
    operationId: identity.operationId,
    enrollmentId: identity.enrollmentId,
    walletId: identity.walletId,
    walletKeyId: identity.walletKeyId,
    laneId: identity.targetLaneId,
    laneShareEpoch: identity.targetLaneShareEpoch,
    targetMaterialActivationId: identity.targetMaterialActivationId,
    holderParticipantBindingDigestB64u: identity.holderParticipantBindingDigestB64u,
    recipientKeyId: args.state.recipientKeyId,
    holderRecipientKeyDigestB64u: identity.holderRecipientKeyDigestB64u,
    holderCiphertextDigestSetB64u: ciphertextDigestB64u,
    sealedHolderRecordDigestB64u,
    transcriptHashB64u: commit.transcriptHashB64u,
    holderCiphertextB64u: ciphertextB64u,
    acknowledgedAtMs,
    storedAtMs: acknowledgedAtMs,
  };
  await args.repository.put(record);
  return {
    state: 'sealed',
    ...identity,
    recipientKeyId: args.state.recipientKeyId,
    holderCiphertextDigestSetB64u: ciphertextDigestB64u,
    sealedHolderRecordDigestB64u,
    transcriptHashB64u: commit.transcriptHashB64u,
    holderCiphertextB64u: ciphertextB64u,
    acknowledgedAtMs,
    holderDeliveryReceipt: deliveryReceipt,
  };
}

export const sealLaneHolderRecipientV1 = sealLaneHolderMaterialV1;

export async function discardLaneHolderRecipientV1(
  state: OpenLaneHolderRecipientV1,
  worker: LaneHolderRecipientWorkerV1,
): Promise<DiscardedLaneHolderRecipientV1> {
  await worker.discardLaneHolderRecipientV1({
    recipientKeyId: state.recipientKeyId,
    operationId: state.operationId,
  });
  return {
    state: 'discarded',
    operationId: state.operationId,
    enrollmentId: state.enrollmentId,
    recipientKeyId: state.recipientKeyId,
  };
}
