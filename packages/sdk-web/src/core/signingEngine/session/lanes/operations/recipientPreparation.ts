import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  LaneHolderDeliveryReceiptV1,
  LaneHolderPackageWireV1,
  LaneHolderRecipientHandleV1,
  LaneHolderRecipientWorkerV1,
  LaneProtocolCommitReceiptV1,
  RotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotation';
import {
  parseHpkePublicKeyB64u,
  parseSigningWorkerRecipientKeyDigestB64u,
} from '@shared/signing-lanes/participants';
import { parseLaneHolderRecipientHandleV1 } from '@shared/utils/domainIds';
import type {
  LaneEnrollmentId,
  LaneOperationId,
  LaneShareEpoch,
  SigningLaneId,
} from '@shared/signing-lanes/ids';
import type { MpcMaterialActivationId, WalletId, WalletKeyId } from '@shared/utils/domainIds';
import type { LaneHolderCustodyBindingId } from '@shared/signing-lanes/participants';
import type {
  LaneSealedHolderMaterialRepositoryV1,
  LaneSealedHolderRecordV1,
} from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';

export type LaneHolderRecipientCreationInputV1 = Parameters<
  LaneHolderRecipientWorkerV1['createLaneHolderRecipientV1']
>[0];

export type OpenLaneHolderRecipientV1 = {
  readonly state: 'open';
  readonly operationId: LaneOperationId;
  readonly enrollmentId: LaneEnrollmentId;
  readonly targetLaneId: SigningLaneId;
  readonly targetLaneShareEpoch: LaneShareEpoch;
  readonly holderParticipantBindingDigestB64u: string;
  readonly custodyBindingId: LaneHolderCustodyBindingId;
  readonly custodyBindingDigestB64u: string;
  readonly recipientHandle: LaneHolderRecipientHandleV1;
  readonly hpkePublicKeyB64u: string;
  readonly hpkePublicKeyDigestB64u: string;
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
  readonly custodyBindingId: LaneHolderCustodyBindingId;
  readonly holderRecipientKeyDigestB64u: string;
  readonly holderCiphertextDigestSetB64u: string;
  readonly sealedHolderRecordDigestB64u: string;
  readonly transcriptHashB64u: string;
  readonly sealedHolderMaterialB64u: string;
  readonly acknowledgedAtMs: number;
  readonly holderDeliveryReceipt: LaneHolderDeliveryReceiptV1;
};

export type DiscardedLaneHolderRecipientV1 = {
  readonly state: 'discarded';
  readonly operationId: LaneOperationId;
  readonly enrollmentId: LaneEnrollmentId;
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

function parseHandle(value: unknown): LaneHolderRecipientHandleV1 {
  const result = parseLaneHolderRecipientHandleV1(value);
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function parseHpkePublicKey(value: unknown): string {
  const result = parseHpkePublicKeyB64u(value);
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function parseRecipientKeyDigest(value: unknown): string {
  const result = parseSigningWorkerRecipientKeyDigestB64u(value);
  if (result.ok) return result.value;
  throw new Error(result.error.message);
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

function assertCreationTargetMatchesJob(
  state: OpenLaneHolderRecipientV1,
  job: RotatableSigningLaneJobV1,
): void {
  if (
    String(state.operationId) !== String(job.operationId) ||
    String(state.enrollmentId) !== String(job.enrollmentId) ||
    String(state.targetLaneId) !== String(job.target.laneId) ||
    String(state.targetLaneShareEpoch) !== String(job.target.laneShareEpoch) ||
    state.holderParticipantBindingDigestB64u !== job.targetHolder.participantBindingDigestB64u ||
    state.custodyBindingId !== job.targetHolder.custodyBindingId ||
    state.custodyBindingDigestB64u !== job.targetHolder.custodyBindingDigestB64u ||
    state.hpkePublicKeyB64u !== job.targetHolder.hpkePublicKeyB64u ||
    state.hpkePublicKeyDigestB64u !== job.targetHolder.hpkePublicKeyDigestB64u
  ) {
    throw new Error('recipient descriptor does not match the exact lane job');
  }
}

function holderDeliveryReceipt(args: {
  readonly job: RotatableSigningLaneJobV1;
  readonly commit: LaneProtocolCommitReceiptV1;
  readonly verifiedHolderCiphertextDigestSetB64u: string;
  readonly sealedHolderRecordDigestB64u: string;
  readonly acknowledgedAtMs: number;
}): LaneHolderDeliveryReceiptV1 {
  return {
    kind: 'lane_holder_delivery_receipt_v1',
    operationId: args.job.operationId,
    enrollmentId: args.job.enrollmentId,
    targetLaneId: args.job.target.laneId,
    targetLaneShareEpoch: args.job.target.laneShareEpoch,
    targetMaterialActivationId: args.job.targetMaterialActivationId,
    holderParticipantBindingDigestB64u: args.job.targetHolder.participantBindingDigestB64u,
    holderRecipientKeyDigestB64u: args.job.targetHolder.hpkePublicKeyDigestB64u,
    holderCiphertextDigestSetB64u: args.verifiedHolderCiphertextDigestSetB64u,
    sealedHolderRecordDigestB64u: args.sealedHolderRecordDigestB64u,
    transcriptHashB64u: args.commit.transcriptHashB64u,
    acknowledgedAtMs: args.acknowledgedAtMs,
  };
}

async function discardAfterFailure(
  state: OpenLaneHolderRecipientV1,
  worker: LaneHolderRecipientWorkerV1,
  error: unknown,
): Promise<never> {
  await worker
    .discardLaneHolderRecipientV1({
      recipientHandle: state.recipientHandle,
      operationId: state.operationId,
    })
    .catch(() => undefined);
  throw error instanceof Error ? error : new Error(String(error));
}

export async function prepareLaneHolderRecipientV1(args: {
  readonly input: LaneHolderRecipientCreationInputV1;
  readonly worker: LaneHolderRecipientWorkerV1;
}): Promise<OpenLaneHolderRecipientV1> {
  const descriptor = await args.worker.createLaneHolderRecipientV1(args.input);
  const recipientHandle = parseHandle(descriptor.recipientHandle);
  try {
    const hpkePublicKeyB64u = parseHpkePublicKey(descriptor.hpkePublicKeyB64u);
    const hpkePublicKeyDigestB64u = parseRecipientKeyDigest(descriptor.hpkePublicKeyDigestB64u);
    return {
      state: 'open',
      operationId: args.input.operationId,
      enrollmentId: args.input.enrollmentId,
      targetLaneId: args.input.targetLaneId,
      targetLaneShareEpoch: args.input.targetLaneShareEpoch,
      holderParticipantBindingDigestB64u: args.input.targetHolderParticipantBindingDigestB64u,
      custodyBindingId: args.input.custodyBindingId,
      custodyBindingDigestB64u: args.input.custodyBindingDigestB64u,
      recipientHandle,
      hpkePublicKeyB64u,
      hpkePublicKeyDigestB64u,
    };
  } catch (error) {
    await args.worker
      .discardLaneHolderRecipientV1({
        recipientHandle,
        operationId: args.input.operationId,
      })
      .catch(() => undefined);
    throw error instanceof Error ? error : new Error(String(error));
  }
}

export const openLaneHolderRecipientV1 = prepareLaneHolderRecipientV1;
export const createLaneHolderRecipientV1 = prepareLaneHolderRecipientV1;

export async function sealLaneHolderMaterialV1(args: {
  readonly state: OpenLaneHolderRecipientV1;
  readonly job: RotatableSigningLaneJobV1;
  readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
  readonly holderPackage: LaneHolderPackageWireV1;
  readonly repository: LaneSealedHolderMaterialRepositoryV1;
  readonly worker: LaneHolderRecipientWorkerV1;
  readonly acknowledgedAtMs: number;
}): Promise<SealedLaneHolderRecipientV1> {
  let recipientReleased = false;
  try {
    const job = args.job;
    const commit = args.protocolCommitReceipt;
    assertJobCommitIdentity(job, commit);
    assertCreationTargetMatchesJob(args.state, job);
    const holderPackage = args.holderPackage;
    const sealed = await args.worker.openAndSealLaneHolderPackageV1({
      job,
      protocolCommitReceipt: commit,
      holderPackage,
      recipientHandle: args.state.recipientHandle,
    });
    const verifiedHolderCiphertextDigestSetB64u = digest(
      sealed.verifiedHolderCiphertextDigestSetB64u,
      'verifiedHolderCiphertextDigestSetB64u',
    );
    if (commit.targetHolderCiphertextDigestSetB64u !== verifiedHolderCiphertextDigestSetB64u) {
      throw new Error('holder package digest does not match the protocol commitment');
    }
    const sealedHolderRecordDigestB64u = digest(
      sealed.sealedHolderRecordDigestB64u,
      'sealedHolderRecordDigestB64u',
    );
    const sealedHolderMaterialB64u = nonEmpty(
      sealed.sealedHolderMaterialB64u,
      'sealedHolderMaterialB64u',
    );
    await args.worker.discardLaneHolderRecipientV1({
      recipientHandle: args.state.recipientHandle,
      operationId: args.state.operationId,
    });
    recipientReleased = true;
    const acknowledgedAtMs = safeTimestamp(args.acknowledgedAtMs, 'acknowledgedAtMs');
    const deliveryReceipt = holderDeliveryReceipt({
      job,
      commit,
      verifiedHolderCiphertextDigestSetB64u,
      sealedHolderRecordDigestB64u,
      acknowledgedAtMs,
    });
    const record: LaneSealedHolderRecordV1 = {
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
      holderRecipientKeyDigestB64u: job.targetHolder.hpkePublicKeyDigestB64u,
      holderCiphertextDigestSetB64u: verifiedHolderCiphertextDigestSetB64u,
      sealedHolderRecordDigestB64u,
      transcriptHashB64u: commit.transcriptHashB64u,
      sealedHolderMaterialB64u,
      acknowledgedAtMs,
      storedAtMs: acknowledgedAtMs,
    };
    await args.repository.put(record);
    return {
      state: 'sealed',
      operationId: job.operationId,
      enrollmentId: job.enrollmentId,
      walletId: job.walletId,
      walletKeyId: job.walletKeyId,
      targetLaneId: job.target.laneId,
      targetLaneShareEpoch: job.target.laneShareEpoch,
      targetMaterialActivationId: job.targetMaterialActivationId,
      holderParticipantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
      custodyBindingId: job.targetHolder.custodyBindingId,
      holderRecipientKeyDigestB64u: job.targetHolder.hpkePublicKeyDigestB64u,
      holderCiphertextDigestSetB64u: verifiedHolderCiphertextDigestSetB64u,
      sealedHolderRecordDigestB64u,
      transcriptHashB64u: commit.transcriptHashB64u,
      sealedHolderMaterialB64u,
      acknowledgedAtMs,
      holderDeliveryReceipt: deliveryReceipt,
    };
  } catch (error) {
    if (recipientReleased) {
      throw error instanceof Error ? error : new Error(String(error));
    }
    return await discardAfterFailure(args.state, args.worker, error);
  }
}

export const sealLaneHolderRecipientV1 = sealLaneHolderMaterialV1;

export async function discardLaneHolderRecipientV1(args: {
  readonly state: OpenLaneHolderRecipientV1;
  readonly worker: LaneHolderRecipientWorkerV1;
}): Promise<DiscardedLaneHolderRecipientV1> {
  await args.worker.discardLaneHolderRecipientV1({
    recipientHandle: args.state.recipientHandle,
    operationId: args.state.operationId,
  });
  return {
    state: 'discarded',
    operationId: args.state.operationId,
    enrollmentId: args.state.enrollmentId,
  };
}
