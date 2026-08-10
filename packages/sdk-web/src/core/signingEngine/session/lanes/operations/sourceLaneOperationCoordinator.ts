import type {
  LaneEnrollmentManifestV1,
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
  readonly gatewayPreparation: unknown;
};

function nonEmptyJobs(
  children: readonly RotatableSigningLaneJobV1[],
): [RotatableSigningLaneJobV1, ...RotatableSigningLaneJobV1[]] {
  if (children.length === 0) throw new Error('lane enrollment must contain at least one child');
  return children as [RotatableSigningLaneJobV1, ...RotatableSigningLaneJobV1[]];
}

function nonEmptyReceipts(
  receipts: readonly LaneProtocolCommitReceiptV1[],
): [LaneProtocolCommitReceiptV1, ...LaneProtocolCommitReceiptV1[]] {
  if (receipts.length === 0) throw new Error('lane enrollment produced no protocol receipts');
  return receipts as [LaneProtocolCommitReceiptV1, ...LaneProtocolCommitReceiptV1[]];
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
  const receipts: LaneProtocolCommitReceiptV1[] = [];
  for (const child of children) {
    receipts.push(await commitChild(child, args.ports));
  }
  return {
    manifest,
    children,
    protocolCommitReceipts: nonEmptyReceipts(receipts),
    gatewayPreparation,
  };
}

export const runSourceLaneOperationV1 = prepareAndCommitSourceLaneOperationV1;
