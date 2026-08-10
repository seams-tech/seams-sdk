import type {
  LaneEnrollmentId,
  LaneOperationId,
  LaneShareEpoch,
  SigningLaneId,
  WalletKeyId,
} from '@shared/signing-lanes/ids';
import type { LaneHolderRecipientHandleV1 } from '@shared/signing-lanes/rotation';
import type { MpcMaterialActivationId, WalletId } from '@shared/utils/domainIds';
import {
  signingSessionSealsRepository,
  type SigningSessionSealsRepository,
} from './signingSessionSeals';

export type LaneSealedHolderRecordV1 = {
  readonly kind: 'lane_sealed_holder_record_v1';
  readonly operationId: LaneOperationId;
  readonly enrollmentId: LaneEnrollmentId;
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly laneId: SigningLaneId;
  readonly laneShareEpoch: LaneShareEpoch;
  readonly targetMaterialActivationId: MpcMaterialActivationId;
  readonly holderParticipantBindingDigestB64u: string;
  readonly recipientKeyId: LaneHolderRecipientHandleV1;
  readonly holderRecipientKeyDigestB64u: string;
  readonly holderCiphertextDigestSetB64u: string;
  readonly sealedHolderRecordDigestB64u: string;
  readonly transcriptHashB64u: string;
  readonly holderCiphertextB64u: string;
  readonly acknowledgedAtMs: number;
  readonly storedAtMs: number;
};

export type LaneSealedHolderRecordLookupV1 = {
  readonly operationId: LaneOperationId;
  readonly enrollmentId: LaneEnrollmentId;
  readonly targetLaneId: SigningLaneId;
  readonly targetLaneShareEpoch: LaneShareEpoch;
  readonly targetMaterialActivationId: MpcMaterialActivationId;
};

export type LaneSealedHolderMaterialRepositoryV1 = {
  put(record: LaneSealedHolderRecordV1): Promise<void>;
  get(input: LaneSealedHolderRecordLookupV1): Promise<LaneSealedHolderRecordV1 | null>;
  delete(input: LaneSealedHolderRecordLookupV1): Promise<void>;
};

const STORE_KEY_PREFIX = 'r102_lane_holder_v1';

function nonEmpty(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function recipientHandle(value: unknown): LaneHolderRecipientHandleV1 {
  return nonEmpty(value, 'recipientKeyId') as LaneHolderRecipientHandleV1;
}

function storeKey(input: LaneSealedHolderRecordLookupV1): string {
  return [
    STORE_KEY_PREFIX,
    nonEmpty(input.enrollmentId, 'enrollmentId'),
    nonEmpty(input.operationId, 'operationId'),
    nonEmpty(input.targetLaneId, 'targetLaneId'),
    nonEmpty(input.targetLaneShareEpoch, 'targetLaneShareEpoch'),
    nonEmpty(input.targetMaterialActivationId, 'targetMaterialActivationId'),
  ].join(':');
}

function assertSafeTimestamp(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return Number(value);
}

function parseRecord(value: unknown): LaneSealedHolderRecordV1 {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('lane sealed holder record must be an object');
  }
  const record = value as Record<string, unknown>;
  const expectedFields = [
    'kind',
    'operationId',
    'enrollmentId',
    'walletId',
    'walletKeyId',
    'laneId',
    'laneShareEpoch',
    'targetMaterialActivationId',
    'holderParticipantBindingDigestB64u',
    'recipientKeyId',
    'holderRecipientKeyDigestB64u',
    'holderCiphertextDigestSetB64u',
    'sealedHolderRecordDigestB64u',
    'transcriptHashB64u',
    'holderCiphertextB64u',
    'acknowledgedAtMs',
    'storedAtMs',
  ] as const;
  const actualFields = Object.keys(record).filter((field) => field !== 'store_key');
  if (
    actualFields.length !== expectedFields.length ||
    expectedFields.some((field) => !actualFields.includes(field))
  ) {
    throw new Error('lane sealed holder record has invalid fields');
  }
  if (record.kind !== 'lane_sealed_holder_record_v1') {
    throw new Error('lane sealed holder record kind is invalid');
  }
  return {
    kind: 'lane_sealed_holder_record_v1',
    operationId: nonEmpty(record.operationId, 'operationId') as LaneOperationId,
    enrollmentId: nonEmpty(record.enrollmentId, 'enrollmentId') as LaneEnrollmentId,
    walletId: nonEmpty(record.walletId, 'walletId') as WalletId,
    walletKeyId: nonEmpty(record.walletKeyId, 'walletKeyId') as WalletKeyId,
    laneId: nonEmpty(record.laneId, 'laneId') as SigningLaneId,
    laneShareEpoch: nonEmpty(record.laneShareEpoch, 'laneShareEpoch') as LaneShareEpoch,
    targetMaterialActivationId: nonEmpty(
      record.targetMaterialActivationId,
      'targetMaterialActivationId',
    ) as MpcMaterialActivationId,
    holderParticipantBindingDigestB64u: nonEmpty(
      record.holderParticipantBindingDigestB64u,
      'holderParticipantBindingDigestB64u',
    ),
    recipientKeyId: recipientHandle(record.recipientKeyId),
    holderRecipientKeyDigestB64u: nonEmpty(
      record.holderRecipientKeyDigestB64u,
      'holderRecipientKeyDigestB64u',
    ),
    holderCiphertextDigestSetB64u: nonEmpty(
      record.holderCiphertextDigestSetB64u,
      'holderCiphertextDigestSetB64u',
    ),
    sealedHolderRecordDigestB64u: nonEmpty(
      record.sealedHolderRecordDigestB64u,
      'sealedHolderRecordDigestB64u',
    ),
    transcriptHashB64u: nonEmpty(record.transcriptHashB64u, 'transcriptHashB64u'),
    holderCiphertextB64u: nonEmpty(record.holderCiphertextB64u, 'holderCiphertextB64u'),
    acknowledgedAtMs: assertSafeTimestamp(record.acknowledgedAtMs, 'acknowledgedAtMs'),
    storedAtMs: assertSafeTimestamp(record.storedAtMs, 'storedAtMs'),
  };
}

function lookupMatches(
  record: LaneSealedHolderRecordV1,
  input: LaneSealedHolderRecordLookupV1,
): boolean {
  return (
    String(record.operationId) === String(input.operationId) &&
    String(record.enrollmentId) === String(input.enrollmentId) &&
    String(record.laneId) === String(input.targetLaneId) &&
    String(record.laneShareEpoch) === String(input.targetLaneShareEpoch) &&
    String(record.targetMaterialActivationId) === String(input.targetMaterialActivationId)
  );
}

function rowForRecord(record: LaneSealedHolderRecordV1): Record<string, unknown> {
  return {
    store_key: storeKey({
      operationId: record.operationId,
      enrollmentId: record.enrollmentId,
      targetLaneId: record.laneId,
      targetLaneShareEpoch: record.laneShareEpoch,
      targetMaterialActivationId: record.targetMaterialActivationId,
    }),
    ...record,
  };
}

export class LaneSealedHolderMaterialRepository implements LaneSealedHolderMaterialRepositoryV1 {
  private readonly volatileRecords = new Map<string, LaneSealedHolderRecordV1>();

  constructor(
    private readonly seals: SigningSessionSealsRepository = signingSessionSealsRepository,
  ) {}

  async put(recordInput: LaneSealedHolderRecordV1): Promise<void> {
    const record = parseRecord(recordInput);
    const key = storeKey({
      operationId: record.operationId,
      enrollmentId: record.enrollmentId,
      targetLaneId: record.laneId,
      targetLaneShareEpoch: record.laneShareEpoch,
      targetMaterialActivationId: record.targetMaterialActivationId,
    });
    const current = this.volatileRecords.get(key);
    if (current && JSON.stringify(current) !== JSON.stringify(record)) {
      throw new Error('lane sealed holder record conflicts with its exact store key');
    }
    this.volatileRecords.set(key, record);
    await this.seals.putSealedRecord(rowForRecord(record));
  }

  async get(input: LaneSealedHolderRecordLookupV1): Promise<LaneSealedHolderRecordV1 | null> {
    const key = storeKey(input);
    const volatile = this.volatileRecords.get(key);
    if (volatile) return volatile;
    const entries = await this.seals.collectAllRawSealedRecordEntries();
    for (const entry of entries) {
      if (String(entry.primaryKey) !== key) continue;
      const parsed = parseRecord(entry.value);
      if (!lookupMatches(parsed, input)) {
        throw new Error('lane sealed holder record key does not match its content');
      }
      this.volatileRecords.set(key, parsed);
      return parsed;
    }
    return null;
  }

  async delete(input: LaneSealedHolderRecordLookupV1): Promise<void> {
    const key = storeKey(input);
    this.volatileRecords.delete(key);
    await this.seals.deleteSealedRecords([key]);
  }
}

export const laneSealedHolderMaterialRepository = new LaneSealedHolderMaterialRepository();

export function laneSealedHolderStoreKeyV1(input: LaneSealedHolderRecordLookupV1): string {
  return storeKey(input);
}
