import type {
  LaneHolderPackageWireV1,
  LaneHolderRecipientHandleV1,
  LaneHolderRecipientWorkerV1,
  RotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotation';
import type { LaneProtocolCommitReceiptV1 } from '@shared/signing-lanes/rotation';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parseLaneHolderRecipientHandleV1,
  parseLaneOperationId,
} from '@shared/utils/domainIds';
import {
  parseLaneHolderPackageWireV1,
  parseLaneProtocolCommitReceiptV1,
  parseRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';
import {
  parseHpkePublicKeyB64u,
  parseSigningWorkerRecipientKeyDigestB64u,
  type HpkePublicKeyB64u,
  type SigningWorkerRecipientKeyDigestB64u,
} from '@shared/signing-lanes/participants';
import type { LaneOperationId } from '@shared/signing-lanes/ids';

type CreateRecipientInputV1 = Parameters<
  LaneHolderRecipientWorkerV1['createLaneHolderRecipientV1']
>[0];

export type LaneWorkerChannelRequestV1 =
  | {
      readonly kind: 'lane_holder_recipient_create_v1';
      readonly input: CreateRecipientInputV1;
    }
  | {
      readonly kind: 'lane_holder_package_open_seal_v1';
      readonly job: RotatableSigningLaneJobV1;
      readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
      readonly holderPackage: LaneHolderPackageWireV1;
      readonly recipientHandle: LaneHolderRecipientHandleV1;
    }
  | {
      readonly kind: 'lane_holder_package_verify_v1';
      readonly job: RotatableSigningLaneJobV1;
      readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
      readonly holderPackage: LaneHolderPackageWireV1;
    }
  | {
      readonly kind: 'lane_holder_recipient_discard_v1';
      readonly recipientHandle: LaneHolderRecipientHandleV1;
      readonly operationId: LaneOperationId;
  }
  | {
      readonly kind: 'lane_material_invalidate_v1';
      readonly walletKeyId: Parameters<LaneHolderRecipientWorkerV1['invalidateLaneMaterialV1']>[0]['walletKeyId'];
      readonly laneId: Parameters<LaneHolderRecipientWorkerV1['invalidateLaneMaterialV1']>[0]['laneId'];
      readonly laneShareEpoch: Parameters<LaneHolderRecipientWorkerV1['invalidateLaneMaterialV1']>[0]['laneShareEpoch'];
      readonly materialActivation: Parameters<LaneHolderRecipientWorkerV1['invalidateLaneMaterialV1']>[0]['materialActivation'];
    };

export type LaneWorkerChannelTransportV1 = {
  request(input: LaneWorkerChannelRequestV1): Promise<unknown>;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  return value;
}

function nonEmpty(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function parseHandle(value: unknown): LaneHolderRecipientHandleV1 {
  const result = parseLaneHolderRecipientHandleV1(value);
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function parseOperationId(value: unknown): CreateRecipientInputV1['operationId'] {
  const result = parseLaneOperationId(value);
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function parseJob(value: unknown): RotatableSigningLaneJobV1 {
  return parseRotatableSigningLaneJobV1(value);
}

function parseCommit(value: unknown): LaneProtocolCommitReceiptV1 {
  return parseLaneProtocolCommitReceiptV1(value);
}

function parseHpkeKey(value: unknown): HpkePublicKeyB64u {
  const result = parseHpkePublicKeyB64u(value);
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function parseRecipientDigest(value: unknown): SigningWorkerRecipientKeyDigestB64u {
  const result = parseSigningWorkerRecipientKeyDigestB64u(value);
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function parseDigest(value: unknown, label: string): DigestB64u {
  try {
    return parseDigestB64u(value);
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function parseOpaqueB64u(value: unknown, label: string): string {
  const normalized = nonEmpty(value, label);
  try {
    const bytes = base64UrlDecode(normalized);
    if (base64UrlEncode(bytes) !== normalized) throw new Error('must be canonical base64url');
    return normalized;
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function parseCreateResponse(value: unknown): Awaited<ReturnType<LaneHolderRecipientWorkerV1['createLaneHolderRecipientV1']>> {
  const response = requireRecord(value, 'lane recipient-create response');
  const fields = Object.keys(response);
  if (
    fields.length !== 3 ||
    !fields.includes('recipientHandle') ||
    !fields.includes('hpkePublicKeyB64u') ||
    !fields.includes('hpkePublicKeyDigestB64u')
  ) {
    throw new Error('lane recipient-create response has invalid fields');
  }
  return {
    recipientHandle: parseHandle(response.recipientHandle),
    hpkePublicKeyB64u: parseHpkeKey(response.hpkePublicKeyB64u),
    hpkePublicKeyDigestB64u: parseRecipientDigest(response.hpkePublicKeyDigestB64u),
  };
}

function parseSealResponse(value: unknown): Awaited<ReturnType<LaneHolderRecipientWorkerV1['openAndSealLaneHolderPackageV1']>> {
  const response = requireRecord(value, 'lane holder-seal response');
  const fields = Object.keys(response);
  if (
    fields.length !== 3 ||
    !fields.includes('sealedHolderMaterialB64u') ||
    !fields.includes('sealedHolderRecordDigestB64u') ||
    !fields.includes('verifiedHolderCiphertextDigestSetB64u')
  ) {
    throw new Error('lane holder-seal response has invalid fields');
  }
  return {
    sealedHolderMaterialB64u: parseOpaqueB64u(
      response.sealedHolderMaterialB64u,
      'sealedHolderMaterialB64u',
    ),
    sealedHolderRecordDigestB64u: parseDigest(
      response.sealedHolderRecordDigestB64u,
      'sealedHolderRecordDigestB64u',
    ),
    verifiedHolderCiphertextDigestSetB64u: parseDigest(
      response.verifiedHolderCiphertextDigestSetB64u,
      'verifiedHolderCiphertextDigestSetB64u',
    ),
  };
}

function parseVerifyResponse(
  value: unknown,
): Awaited<ReturnType<LaneHolderRecipientWorkerV1['verifyLaneHolderPackageCommitmentV1']>> {
  const response = requireRecord(value, 'lane holder-package verify response');
  const fields = Object.keys(response);
  if (fields.length !== 1 || !fields.includes('verifiedHolderCiphertextDigestSetB64u')) {
    throw new Error('lane holder-package verify response has invalid fields');
  }
  return {
    verifiedHolderCiphertextDigestSetB64u: parseDigest(
      response.verifiedHolderCiphertextDigestSetB64u,
      'verifiedHolderCiphertextDigestSetB64u',
    ),
  };
}

export function createLaneWorkerChannelsV1(
  transport: LaneWorkerChannelTransportV1,
): LaneHolderRecipientWorkerV1 {
  return {
    async createLaneHolderRecipientV1(input) {
      return parseCreateResponse(
        await transport.request({
          kind: 'lane_holder_recipient_create_v1',
          input,
        }),
      );
    },
    async openAndSealLaneHolderPackageV1(input) {
      return parseSealResponse(
        await transport.request({
          kind: 'lane_holder_package_open_seal_v1',
          job: parseJob(input.job),
          protocolCommitReceipt: parseCommit(input.protocolCommitReceipt),
          holderPackage: parseLaneHolderPackageWireV1(input.holderPackage),
          recipientHandle: parseHandle(input.recipientHandle),
        }),
      );
    },
    async verifyLaneHolderPackageCommitmentV1(input) {
      return parseVerifyResponse(
        await transport.request({
          kind: 'lane_holder_package_verify_v1',
          job: parseJob(input.job),
          protocolCommitReceipt: parseCommit(input.protocolCommitReceipt),
          holderPackage: parseLaneHolderPackageWireV1(input.holderPackage),
        }),
      );
    },
    async discardLaneHolderRecipientV1(input) {
      await transport.request({
        kind: 'lane_holder_recipient_discard_v1',
        recipientHandle: parseHandle(input.recipientHandle),
        operationId: parseOperationId(input.operationId),
      });
    },
    async invalidateLaneMaterialV1(input) {
      await transport.request({
        kind: 'lane_material_invalidate_v1',
        walletKeyId: input.walletKeyId,
        laneId: input.laneId,
        laneShareEpoch: input.laneShareEpoch,
        materialActivation: input.materialActivation,
      });
    },
  };
}

export const createLaneHolderRecipientWorkerChannelsV1 = createLaneWorkerChannelsV1;
