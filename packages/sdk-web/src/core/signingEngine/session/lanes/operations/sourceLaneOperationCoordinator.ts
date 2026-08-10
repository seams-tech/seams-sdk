import type {
  LaneEnrollmentPreparationResultV1,
  LaneEnrollmentManifestV1,
  LaneProtocolCasResultV1,
  LaneProtocolCommitReceiptV1,
  RotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotation';
import {
  parseLaneEnrollmentManifestV1,
  parseLaneProtocolCommitReceiptV1,
  parseRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';
import {
  completeEcdsaAdditiveLaneServerRoundV1,
  prepareEcdsaAdditiveLaneHolderRoundV1,
} from '@/core/signingEngine/threshold/crypto/ecdsaLaneWasm';
import {
  completeEd25519YaoLaneV1,
  executeEd25519YaoLaneRequestJsonV1,
  prepareEd25519YaoLaneV1,
} from '@/core/signingEngine/threshold/crypto/ed25519YaoLaneWasm';
import type { LaneOperationSourcePortsV1 } from './ports';

export type PreparedLaneProtocolOperationV1 = {
  readonly manifest: LaneEnrollmentManifestV1;
  readonly children: readonly [RotatableSigningLaneJobV1, ...RotatableSigningLaneJobV1[]];
  readonly protocolCommitReceipts: readonly [
    LaneProtocolCommitReceiptV1,
    ...LaneProtocolCommitReceiptV1[],
  ];
  readonly protocolCommitResults: readonly [LaneProtocolCasResultV1, ...LaneProtocolCasResultV1[]];
  readonly gatewayPreparation: LaneEnrollmentPreparationResultV1;
};

function nonEmptyJobs(
  children: readonly RotatableSigningLaneJobV1[],
): [RotatableSigningLaneJobV1, ...RotatableSigningLaneJobV1[]] {
  if (children.length === 0) throw new Error('lane enrollment must contain at least one child');
  const [first, ...rest] = children;
  if (!first) throw new Error('lane enrollment must contain at least one child');
  return [first, ...rest];
}

function nonEmptyReceipts(
  receipts: readonly LaneProtocolCommitReceiptV1[],
): [LaneProtocolCommitReceiptV1, ...LaneProtocolCommitReceiptV1[]] {
  if (receipts.length === 0) throw new Error('lane enrollment produced no protocol receipts');
  const [first, ...rest] = receipts;
  if (!first) throw new Error('lane enrollment produced no protocol receipts');
  return [first, ...rest];
}

function nonEmptyCasResults(
  results: readonly LaneProtocolCasResultV1[],
): [LaneProtocolCasResultV1, ...LaneProtocolCasResultV1[]] {
  if (results.length === 0) throw new Error('lane enrollment produced no protocol CAS results');
  const [first, ...rest] = results;
  if (!first) throw new Error('lane enrollment produced no protocol CAS results');
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
  readonly ports: LaneOperationSourcePortsV1;
}): Promise<LaneProtocolCommitReceiptV1> {
  const holderRound = await prepareEcdsaAdditiveLaneHolderRoundV1(args.ports.wasm.ecdsa, args.child);
  const serverRound = await completeEcdsaAdditiveLaneServerRoundV1(args.ports.wasm.ecdsa, {
    job: args.child,
    holderRound,
  });
  if (serverRound.preambleHashB64u !== holderRound.preambleHashB64u) {
    throw new Error('ECDSA server round is bound to a different preamble');
  }
  const rawReceipt = await args.ports.protocolCommitter.commitEcdsaAdditiveLaneV1({
    job: args.child,
    holderRound,
    serverRound,
  });
  const receipt = parseLaneProtocolCommitReceiptV1(rawReceipt);
  assertProtocolCommitMatchesJob(args.child, receipt);
  if (
    receipt.targetHolderPublicCommitmentB64u !== holderRound.targetHolderPublicCommitment33B64u ||
    receipt.targetServerPublicCommitmentB64u !== serverRound.targetServerPublicCommitment33B64u
  ) {
    throw new Error('ECDSA protocol receipt commitments do not match its transcript rounds');
  }
  return receipt;
}

async function commitEd25519Child(args: {
  readonly child: Extract<RotatableSigningLaneJobV1, { keyFamily: 'ed25519' }>;
  readonly ports: LaneOperationSourcePortsV1;
}): Promise<LaneProtocolCommitReceiptV1> {
  const prepared = await prepareEd25519YaoLaneV1(args.ports.wasm.ed25519Yao, args.child);
  const response = await executeEd25519YaoLaneRequestJsonV1(args.ports.wasm.ed25519Yao, prepared);
  const receipt = await completeEd25519YaoLaneV1(args.ports.wasm.ed25519Yao, {
    job: args.child,
    responseJson: response.responseJson,
  });
  const rawCommitReceipt = await args.ports.protocolCommitter.commitEd25519YaoLaneV1({
    job: args.child,
    protocolReceipt: receipt,
  });
  const committed = parseLaneProtocolCommitReceiptV1(rawCommitReceipt);
  assertProtocolCommitMatchesJob(args.child, committed);
  if (committed.transcriptHashB64u !== receipt.transcriptHashB64u) {
    throw new Error('Ed25519 protocol receipt changed during Gateway commitment');
  }
  return committed;
}

async function commitChild(
  child: RotatableSigningLaneJobV1,
  ports: LaneOperationSourcePortsV1,
): Promise<LaneProtocolCommitReceiptV1> {
  switch (child.keyFamily) {
    case 'ecdsa_secp256k1':
      return await commitEcdsaChild({ child, ports });
    case 'ed25519':
      return await commitEd25519Child({ child, ports });
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

async function recordProtocolCommit(args: {
  readonly child: RotatableSigningLaneJobV1;
  readonly receipt: LaneProtocolCommitReceiptV1;
  readonly expectedVersion: number;
  readonly gateway: LaneOperationSourcePortsV1['gateway'];
}): Promise<LaneProtocolCasResultV1> {
  const result = await args.gateway.recordLaneProtocolCommitV1({
    receipt: args.receipt,
    expectedVersion: args.expectedVersion,
  });
  if (result.outcome === 'conflict') {
    throw new Error(`Gateway rejected protocol commitment for ${String(args.child.operationId)}`);
  }
  assertProtocolRecordMatchesChild(args.child, result.record.job);
  if (
    result.record.lifecycle.state !== 'committed_awaiting_holder_delivery' &&
    result.record.lifecycle.state !== 'awaiting_server_activation' &&
    result.record.lifecycle.state !== 'ready_for_parent_visibility' &&
    result.record.lifecycle.state !== 'active' &&
    result.record.lifecycle.state !== 'committed_completion_required'
  ) {
    throw new Error('Gateway protocol record did not commit its exact receipt');
  }
  return result;
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
  const children = nonEmptyJobs(args.children.map((child) => parseRotatableSigningLaneJobV1(child)));
  assertChildMatchesManifest(manifest, children);
  assertUniqueChildOperations(children);
  if (hasEcdsaChild(children)) {
    for (const child of children) {
      if (child.keyFamily !== 'ecdsa_secp256k1') continue;
      await args.ports.reconcileEcdsaActivationJournalV1({
        walletKeyId: child.walletKeyId,
        laneId: child.source.laneId,
        laneShareEpoch: child.source.laneShareEpoch,
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
  const receipts: LaneProtocolCommitReceiptV1[] = [];
  const protocolCommitResults: LaneProtocolCasResultV1[] = [];
  for (const [index, child] of children.entries()) {
    const preparedProtocol = gatewayPreparation.orderedProtocols[index];
    if (!preparedProtocol) throw new Error(`Gateway preparation child ${index} is missing`);
    assertProtocolRecordMatchesChild(child, preparedProtocol.record.job);
    const receipt = await commitChild(child, args.ports);
    receipts.push(receipt);
    protocolCommitResults.push(
      await recordProtocolCommit({
        child,
        receipt,
        expectedVersion: preparedProtocol.version,
        gateway: args.ports.gateway,
      }),
    );
  }
  return {
    manifest,
    children,
    protocolCommitReceipts: nonEmptyReceipts(receipts),
    protocolCommitResults: nonEmptyCasResults(protocolCommitResults),
    gatewayPreparation,
  };
}

export const runSourceLaneOperationV1 = prepareAndCommitSourceLaneOperationV1;
