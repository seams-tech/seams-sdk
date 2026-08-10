import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  LaneHolderRecipientWorkerV1,
  LaneHolderRecipientHandleV1,
  LaneTargetHolderV1,
} from '@shared/signing-lanes/rotation';
import type {
  LaneOperationId,
  LaneShareEpoch,
  SigningLaneId,
  WalletKeyId,
} from '@shared/signing-lanes/ids';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';

export type LaneWorkerChannelRequestV1 =
  | {
      readonly kind: 'lane_holder_recipient_create_v1';
      readonly targetHolder: LaneTargetHolderV1;
    }
  | {
      readonly kind: 'lane_holder_package_open_seal_v1';
      readonly ciphertextB64u: string;
      readonly recipientKeyId: string;
      readonly targetLaneId: SigningLaneId;
      readonly targetLaneShareEpoch: LaneShareEpoch;
    }
  | {
      readonly kind: 'lane_holder_recipient_discard_v1';
      readonly recipientKeyId: string;
      readonly operationId: LaneOperationId;
    }
  | {
      readonly kind: 'lane_material_invalidate_v1';
      readonly walletKeyId: WalletKeyId;
      readonly laneId: SigningLaneId;
      readonly laneShareEpoch: LaneShareEpoch;
      readonly materialActivation: MpcMaterialActivationRef;
    };

export type LaneWorkerChannelTransportV1 = {
  request(input: LaneWorkerChannelRequestV1): Promise<unknown>;
};

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function nonEmpty(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function recipientHandle(value: unknown): LaneHolderRecipientHandleV1 {
  const normalized = nonEmpty(value, 'recipientKeyId');
  return normalized as LaneHolderRecipientHandleV1;
}

function digest(value: unknown, label: string): string {
  try {
    return parseDigestB64u(value);
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function parseCreateResponse(value: unknown): {
  readonly recipientKeyId: LaneHolderRecipientHandleV1;
} {
  const response = record(value, 'lane recipient-create response');
  if (Object.keys(response).length !== 1 || !Object.hasOwn(response, 'recipientKeyId')) {
    throw new Error('lane recipient-create response has invalid fields');
  }
  return { recipientKeyId: recipientHandle(response.recipientKeyId) };
}

function parseSealResponse(value: unknown): { readonly sealedHolderRecordDigestB64u: string } {
  const response = record(value, 'lane holder-seal response');
  if (
    Object.keys(response).length !== 1 ||
    !Object.hasOwn(response, 'sealedHolderRecordDigestB64u')
  ) {
    throw new Error('lane holder-seal response has invalid fields');
  }
  return {
    sealedHolderRecordDigestB64u: digest(
      response.sealedHolderRecordDigestB64u,
      'sealedHolderRecordDigestB64u',
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
          targetHolder: input,
        }),
      );
    },
    async openAndSealLaneHolderPackageV1(input) {
      const ciphertextB64u = nonEmpty(input.ciphertextB64u, 'ciphertextB64u');
      const recipientKeyId = recipientHandle(input.recipientKeyId);
      return parseSealResponse(
        await transport.request({
          kind: 'lane_holder_package_open_seal_v1',
          ciphertextB64u,
          recipientKeyId,
          targetLaneId: input.targetLaneId,
          targetLaneShareEpoch: input.targetLaneShareEpoch,
        }),
      );
    },
    async discardLaneHolderRecipientV1(input) {
      const recipientKeyId = recipientHandle(input.recipientKeyId);
      const operationId = nonEmpty(input.operationId, 'operationId') as LaneOperationId;
      await transport.request({
        kind: 'lane_holder_recipient_discard_v1',
        recipientKeyId,
        operationId,
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
