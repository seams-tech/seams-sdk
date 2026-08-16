import type {
  LaneEnrollmentPreparationResultV1,
  LaneEnrollmentManifestV1,
  LaneHolderPackageWireV1,
  LaneProtocolCasResultV1,
  LaneProtocolCommitReceiptV1,
  RotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotation';
import {
  parseLaneEnrollmentManifestV1,
  parseLaneProtocolCommitReceiptV1,
  parseRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';
import { encodeLaneProtocolCommitReceiptV1 } from '@shared/signing-lanes/rotationDigests';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256Bytes } from '@shared/utils/digests';
import { prepareEcdsaAdditiveLaneHolderRoundV1 } from '@/core/signingEngine/threshold/crypto/ecdsaLaneWasm';
import {
  completeEd25519YaoLaneV1,
  prepareEd25519YaoLaneV1,
} from '@/core/signingEngine/threshold/crypto/ed25519YaoLaneWasm';
import type { LaneOperationSourcePortsV1 } from './ports';

export type PreparedLaneProtocolOperationV1 = {
  readonly manifest: LaneEnrollmentManifestV1;
  readonly children: readonly [RotatableSigningLaneJobV1, ...RotatableSigningLaneJobV1[]];
  readonly committedChildren: readonly [
    PreparedLaneProtocolChildV1,
    ...PreparedLaneProtocolChildV1[],
  ];
  readonly gatewayPreparation: LaneEnrollmentPreparationResultV1;
};

export type PreparedLaneProtocolChildV1 = {
  readonly job: RotatableSigningLaneJobV1;
  readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
  readonly protocolCommitResult: LaneProtocolCasResultV1;
  readonly holderPackage: LaneHolderPackageWireV1;
};

function nonEmptyJobs(
  children: readonly RotatableSigningLaneJobV1[],
): [RotatableSigningLaneJobV1, ...RotatableSigningLaneJobV1[]] {
  if (children.length === 0) throw new Error('lane enrollment must contain at least one child');
  const [first, ...rest] = children;
  if (!first) throw new Error('lane enrollment must contain at least one child');
  return [first, ...rest];
}

function nonEmptyCommittedChildren(
  children: readonly PreparedLaneProtocolChildV1[],
): [PreparedLaneProtocolChildV1, ...PreparedLaneProtocolChildV1[]] {
  if (children.length === 0) throw new Error('lane enrollment produced no protocol commitments');
  const [first, ...rest] = children;
  if (!first) throw new Error('lane enrollment produced no protocol commitments');
  return [first, ...rest];
}

function assertChildMatchesManifest(
  manifest: LaneEnrollmentManifestV1,
  children: readonly RotatableSigningLaneJobV1[],
): void {
  if (manifest.orderedChildren.length !== children.length) {
    throw new Error('lane enrollment child count does not match its manifest');
  }
  children.forEach((child, index) => {
    const expected = manifest.orderedChildren[index];
    if (!expected) throw new Error('lane enrollment manifest child is missing');
    if (
      String(expected.operationId) !== String(child.operationId) ||
      String(expected.walletKeyId) !== String(child.walletKeyId) ||
      expected.keyFamily !== child.keyFamily ||
      String(expected.sourceLaneId) !== String(child.source.laneId) ||
      String(expected.sourceLaneShareEpoch) !== String(child.source.laneShareEpoch) ||
      String(expected.targetLaneId) !== String(child.target.laneId) ||
      String(expected.targetLaneShareEpoch) !== String(child.target.laneShareEpoch) ||
      String(expected.targetMaterialActivationId) !== String(child.targetMaterialActivationId) ||
      expected.holderParticipantBindingDigestB64u !==
        child.targetHolder.participantBindingDigestB64u ||
      expected.signingWorkerParticipantBindingDigestB64u !==
        child.targetSigningWorker.participantBindingDigestB64u
    ) {
      throw new Error(`lane enrollment child ${index} does not match its manifest`);
    }
    if (
      String(child.enrollmentId) !== String(manifest.enrollmentId) ||
      String(child.walletId) !== String(manifest.walletId)
    ) {
      throw new Error(`lane enrollment child ${index} has the wrong parent identity`);
    }
  });
}

function assertUniqueChildOperations(children: readonly RotatableSigningLaneJobV1[]): void {
  const operations = children.map((child) => String(child.operationId));
  if (new Set(operations).size !== operations.length) {
    throw new Error('lane enrollment has duplicate child operation IDs');
  }
}

function assertProtocolCommitMatchesJob(
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
    throw new Error('lane protocol commit receipt does not match its job');
  }
}

async function commitEcdsaChild(args: {
  readonly child: Extract<RotatableSigningLaneJobV1, { keyFamily: 'ecdsa_secp256k1' }>;
  readonly expectedVersion: number;
  readonly ports: LaneOperationSourcePortsV1;
}): Promise<{
  readonly receipt: LaneProtocolCommitReceiptV1;
  readonly protocolCasResult: LaneProtocolCasResultV1;
  readonly holderPackage: LaneHolderPackageWireV1;
}> {
  const prepared = await prepareEcdsaAdditiveLaneHolderRoundV1(args.ports.wasm.ecdsa, args.child);
  const committed = await args.ports.protocolCommitter.executeAndRecordEcdsaAdditiveLaneV1({
    job: args.child,
    holderRound: prepared.holderRound,
    holderPackage: prepared.holderPackage,
    encryptedDeltaPackageJson: prepared.encryptedDeltaPackageJson,
    expectedVersion: args.expectedVersion,
  });
  const receipt = parseLaneProtocolCommitReceiptV1(committed.receipt);
  assertProtocolCommitMatchesJob(args.child, receipt);
  if (
    receipt.targetHolderPublicCommitmentB64u !==
    prepared.holderRound.targetHolderPublicCommitment33B64u
  ) {
    throw new Error('ECDSA protocol receipt changed the holder commitment');
  }
  await assertRecordedProtocolCommit(args.child, receipt, committed.protocolCasResult);
  return {
    receipt,
    protocolCasResult: committed.protocolCasResult,
    holderPackage: prepared.holderPackage,
  };
}

async function commitEd25519Child(args: {
  readonly child: Extract<RotatableSigningLaneJobV1, { keyFamily: 'ed25519' }>;
  readonly expectedVersion: number;
  readonly ports: LaneOperationSourcePortsV1;
}): Promise<{
  readonly receipt: LaneProtocolCommitReceiptV1;
  readonly protocolCasResult: LaneProtocolCasResultV1;
  readonly holderPackage: LaneHolderPackageWireV1;
}> {
  const prepared = await prepareEd25519YaoLaneV1(args.ports.wasm.ed25519Yao, args.child);
  const committed = await args.ports.protocolCommitter.executeAndRecordEd25519YaoLaneV1({
    job: args.child,
    requestJson: prepared.requestJson,
    expectedVersion: args.expectedVersion,
  });
  const completion = await completeEd25519YaoLaneV1(args.ports.wasm.ed25519Yao, {
    job: args.child,
    responseJson: committed.responseJson,
  });
  const serverReceipt = parseLaneProtocolCommitReceiptV1(committed.receipt);
  assertProtocolCommitMatchesJob(args.child, serverReceipt);
  if (!laneProtocolCommitReceiptsEqual(completion.protocolCommitReceipt, serverReceipt)) {
    throw new Error('Ed25519 client verification and server commitment disagree');
  }
  await assertRecordedProtocolCommit(args.child, serverReceipt, committed.protocolCasResult);
  return {
    receipt: serverReceipt,
    protocolCasResult: committed.protocolCasResult,
    holderPackage: completion.holderPackage,
  };
}

async function commitChild(
  child: RotatableSigningLaneJobV1,
  expectedVersion: number,
  ports: LaneOperationSourcePortsV1,
): Promise<{
  readonly receipt: LaneProtocolCommitReceiptV1;
  readonly protocolCasResult: LaneProtocolCasResultV1;
  readonly holderPackage: LaneHolderPackageWireV1;
}> {
  switch (child.keyFamily) {
    case 'ecdsa_secp256k1':
      return await commitEcdsaChild({ child, expectedVersion, ports });
    case 'ed25519':
      return await commitEd25519Child({ child, expectedVersion, ports });
    default:
      return assertNever(child);
  }
}

function assertProtocolRecordMatchesChild(
  child: RotatableSigningLaneJobV1,
  record: RotatableSigningLaneJobV1,
): void {
  if (
    String(child.operationId) !== String(record.operationId) ||
    String(child.enrollmentId) !== String(record.enrollmentId) ||
    String(child.walletId) !== String(record.walletId) ||
    String(child.walletKeyId) !== String(record.walletKeyId) ||
    child.keyFamily !== record.keyFamily ||
    String(child.source.laneId) !== String(record.source.laneId) ||
    String(child.source.laneShareEpoch) !== String(record.source.laneShareEpoch) ||
    String(child.source.revocationEpoch) !== String(record.source.revocationEpoch) ||
    String(child.target.laneId) !== String(record.target.laneId) ||
    String(child.target.laneShareEpoch) !== String(record.target.laneShareEpoch) ||
    String(child.targetMaterialActivationId) !== String(record.targetMaterialActivationId)
  ) {
    throw new Error('Gateway protocol record does not match its exact child job');
  }
}

async function assertRecordedProtocolCommit(
  child: RotatableSigningLaneJobV1,
  receipt: LaneProtocolCommitReceiptV1,
  result: LaneProtocolCasResultV1,
): Promise<void> {
  if (result.outcome === 'conflict') {
    throw new Error(`Gateway rejected protocol commitment for ${String(child.operationId)}`);
  }
  assertProtocolRecordMatchesChild(child, result.record.job);
  const receiptDigestB64u = base64UrlEncode(
    await sha256Bytes(encodeLaneProtocolCommitReceiptV1(receipt)),
  );
  if (
    result.record.lifecycle.state !== 'committed_awaiting_holder_delivery' &&
    result.record.lifecycle.state !== 'awaiting_server_activation' &&
    result.record.lifecycle.state !== 'ready_for_parent_visibility' &&
    result.record.lifecycle.state !== 'active' &&
    result.record.lifecycle.state !== 'committed_completion_required'
  ) {
    throw new Error('Gateway protocol record did not commit its exact receipt');
  }
  if (
    result.commandDigestB64u !== receiptDigestB64u ||
    result.record.lifecycle.protocolCommitReceiptDigestB64u !== receiptDigestB64u
  ) {
    throw new Error('Gateway protocol commitment result does not bind the exact receipt');
  }
}

function laneProtocolCommitReceiptsEqual(
  left: LaneProtocolCommitReceiptV1,
  right: LaneProtocolCommitReceiptV1,
): boolean {
  const leftBytes = encodeLaneProtocolCommitReceiptV1(left);
  const rightBytes = encodeLaneProtocolCommitReceiptV1(right);
  if (leftBytes.length !== rightBytes.length) return false;
  let difference = 0;
  for (let index = 0; index < leftBytes.length; index += 1) {
    difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }
  return difference === 0;
}

function hasEcdsaChild(children: readonly RotatableSigningLaneJobV1[]): boolean {
  return children.some((child) => child.keyFamily === 'ecdsa_secp256k1');
}

function assertNever(value: never): never {
  throw new Error(`Unsupported lane curve: ${String(value)}`);
}

export async function prepareAndCommitSourceLaneOperationV1(args: {
  readonly manifest: unknown;
  readonly children: readonly unknown[];
  readonly ports: LaneOperationSourcePortsV1;
}): Promise<PreparedLaneProtocolOperationV1> {
  const manifest = parseLaneEnrollmentManifestV1(args.manifest);
  const children = nonEmptyJobs(
    args.children.map((child) => parseRotatableSigningLaneJobV1(child)),
  );
  assertChildMatchesManifest(manifest, children);
  assertUniqueChildOperations(children);
  if (hasEcdsaChild(children)) {
    for (const child of children) {
      if (child.keyFamily !== 'ecdsa_secp256k1') continue;
      await args.ports.reconcileEcdsaActivationJournalV1({
        walletId: child.walletId,
        walletKeyId: child.walletKeyId,
        source: child.source,
      });
    }
  }
  const gatewayPreparation = await args.ports.gateway.prepareLaneEnrollmentV1({
    manifest,
    children,
  });
  if (gatewayPreparation.outcome === 'conflict') {
    throw new Error('Gateway rejected lane enrollment preparation');
  }
  if (gatewayPreparation.orderedProtocols.length !== children.length) {
    throw new Error('Gateway preparation protocol order does not match the manifest');
  }
  const committedChildren: PreparedLaneProtocolChildV1[] = [];
  for (const [index, child] of children.entries()) {
    const preparedProtocol = gatewayPreparation.orderedProtocols[index];
    if (!preparedProtocol) throw new Error(`Gateway preparation child ${index} is missing`);
    assertProtocolRecordMatchesChild(child, preparedProtocol.record.job);
    const committed = await commitChild(child, preparedProtocol.version, args.ports);
    committedChildren.push({
      job: child,
      protocolCommitReceipt: committed.receipt,
      protocolCommitResult: committed.protocolCasResult,
      holderPackage: committed.holderPackage,
    });
  }
  return {
    manifest,
    children,
    committedChildren: nonEmptyCommittedChildren(committedChildren),
    gatewayPreparation,
  };
}

export const runSourceLaneOperationV1 = prepareAndCommitSourceLaneOperationV1;
