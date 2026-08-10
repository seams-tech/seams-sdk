import type {
  Ed25519YaoLaneClientCompletionV1,
  Ed25519YaoLaneJobV1,
  LaneProtocolCommitReceiptV1,
  WasmEd25519YaoLaneClientV1,
} from '@shared/signing-lanes/rotation';
import {
  parseLaneHolderPackageWireV1,
  parseLaneProtocolCommitReceiptV1,
  parseRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';

function parseEdJob(value: unknown): Ed25519YaoLaneJobV1 {
  const parsed = parseRotatableSigningLaneJobV1(value);
  if (parsed.keyFamily !== 'ed25519') {
    throw new Error('Ed25519 Yao lane WASM requires an Ed25519 lane job');
  }
  return parsed;
}

function requestJson(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error('Yao lane request JSON is required');
  }
  return value;
}

function responseJson(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error('Yao lane response JSON is required');
  }
  return value;
}

function parseCommitReceipt(value: unknown): LaneProtocolCommitReceiptV1 {
  const receipt = parseLaneProtocolCommitReceiptV1(value);
  if (receipt.keyFamily !== 'ed25519') {
    throw new Error('Yao lane protocol receipt has the wrong key family');
  }
  return receipt;
}

export async function prepareEd25519YaoLaneV1(
  wasm: WasmEd25519YaoLaneClientV1,
  input: unknown,
): Promise<{ readonly requestJson: string }> {
  const job = parseEdJob(input);
  const result = await wasm.prepare(job);
  return { requestJson: requestJson(result.requestJson) };
}

export async function completeEd25519YaoLaneV1(
  wasm: WasmEd25519YaoLaneClientV1,
  input: { readonly job: unknown; readonly responseJson: unknown },
): Promise<Ed25519YaoLaneClientCompletionV1> {
  const job = parseEdJob(input.job);
  const completion = await wasm.complete({
    job,
    responseJson: responseJson(input.responseJson),
  });
  const receipt = parseCommitReceipt(completion.protocolCommitReceipt);
  const holderPackage = parseLaneHolderPackageWireV1(completion.holderPackage);
  if (holderPackage.kind !== 'ed25519_yao_lane_holder_package_set_v1') {
    throw new Error('Yao lane completion returned the wrong holder package family');
  }
  assertReceiptJobIdentity(receipt, job);
  return { protocolCommitReceipt: receipt, holderPackage };
}

function assertReceiptJobIdentity(
  receipt: LaneProtocolCommitReceiptV1,
  job: Ed25519YaoLaneJobV1,
): void {
  if (
    String(receipt.operationId) !== String(job.operationId) ||
    String(receipt.enrollmentId) !== String(job.enrollmentId) ||
    String(receipt.walletId) !== String(job.walletId) ||
    String(receipt.walletKeyId) !== String(job.walletKeyId) ||
    String(receipt.sourceLaneId) !== String(job.source.laneId) ||
    String(receipt.targetLaneId) !== String(job.target.laneId) ||
    String(receipt.targetLaneShareEpoch) !== String(job.target.laneShareEpoch) ||
    String(receipt.targetMaterialActivationId) !== String(job.targetMaterialActivationId)
  ) {
    throw new Error('Yao lane protocol receipt does not match its job');
  }
}

export type Ed25519YaoLaneWasmAdapterV1 = WasmEd25519YaoLaneClientV1;

export function createEd25519YaoLaneWasmAdapterV1(
  wasm: WasmEd25519YaoLaneClientV1,
): Ed25519YaoLaneWasmAdapterV1 {
  return {
    async prepare(input) {
      return await prepareEd25519YaoLaneV1(wasm, input);
    },
    async complete(input) {
      return await completeEd25519YaoLaneV1(wasm, input);
    },
  };
}

export const createEd25519YaoLaneWasmAdapter = createEd25519YaoLaneWasmAdapterV1;
