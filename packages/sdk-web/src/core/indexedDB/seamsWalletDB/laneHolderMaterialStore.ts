import type {
  LaneEnrollmentId,
  LaneOperationId,
  LaneShareEpoch,
  SigningLaneId,
  WalletKeyId,
} from '@shared/signing-lanes/ids';
import {
  parseLaneEnrollmentId,
  parseLaneOperationId,
  parseLaneShareEpoch,
  parseMpcMaterialActivationId,
  parseSigningLaneId,
  parseWalletId,
  parseWalletKeyId,
  type MpcMaterialActivationId,
  type WalletId,
} from '@shared/utils/domainIds';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parseLaneHolderCustodyBindingId,
  type LaneHolderCustodyBindingId,
} from '@shared/signing-lanes/participants';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
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
  readonly custodyBindingId: LaneHolderCustodyBindingId;
  readonly holderRecipientKeyDigestB64u: string;
  readonly holderCiphertextDigestSetB64u: string;
  readonly sealedHolderRecordDigestB64u: string;
  readonly transcriptHashB64u: string;
  readonly sealedHolderMaterialB64u: string;
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
  listForEnrollmentV1(input: {
    readonly enrollmentId: LaneEnrollmentId;
  }): Promise<readonly LaneSealedHolderRecordV1[]>;
  delete(input: LaneSealedHolderRecordLookupV1): Promise<void>;
};

const STORE_KEY_PREFIX = 'r102_lane_holder_v1';

function nonEmpty(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function storeKey(input: LaneSealedHolderRecordLookupV1): string {
  return JSON.stringify([
    STORE_KEY_PREFIX,
    nonEmpty(input.enrollmentId, 'enrollmentId'),
    nonEmpty(input.operationId, 'operationId'),
    nonEmpty(input.targetLaneId, 'targetLaneId'),
    nonEmpty(input.targetLaneShareEpoch, 'targetLaneShareEpoch'),
    nonEmpty(input.targetMaterialActivationId, 'targetMaterialActivationId'),
  ]);
}

function assertSafeTimestamp(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return Number(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parsed<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (result.ok) return result.value;
  throw new Error(`${label} ${result.error.message}`);
}

function parsedDigest(value: unknown, label: string): string {
  try {
    return parseDigestB64u(value);
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function parsedOpaqueB64u(value: unknown, label: string): string {
  const normalized = nonEmpty(value, label);
  try {
    const bytes = base64UrlDecode(normalized);
    if (base64UrlEncode(bytes) !== normalized) throw new Error('must be canonical base64url');
    return normalized;
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function parseRecord(value: unknown): LaneSealedHolderRecordV1 {
  if (!isRecord(value)) throw new Error('lane sealed holder record must be an object');
  const record = value;
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
    'custodyBindingId',
    'holderRecipientKeyDigestB64u',
    'holderCiphertextDigestSetB64u',
    'sealedHolderRecordDigestB64u',
    'transcriptHashB64u',
    'sealedHolderMaterialB64u',
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
    operationId: parsed(parseLaneOperationId(record.operationId), 'operationId'),
    enrollmentId: parsed(parseLaneEnrollmentId(record.enrollmentId), 'enrollmentId'),
    walletId: parsed(parseWalletId(record.walletId), 'walletId'),
    walletKeyId: parsed(parseWalletKeyId(record.walletKeyId), 'walletKeyId'),
    laneId: parsed(parseSigningLaneId(record.laneId), 'laneId'),
    laneShareEpoch: parsed(parseLaneShareEpoch(record.laneShareEpoch), 'laneShareEpoch'),
    targetMaterialActivationId: parsed(
      parseMpcMaterialActivationId(record.targetMaterialActivationId),
      'targetMaterialActivationId',
    ),
    holderParticipantBindingDigestB64u: parsedDigest(
      record.holderParticipantBindingDigestB64u,
      'holderParticipantBindingDigestB64u',
    ),
    custodyBindingId: parsed(
      parseLaneHolderCustodyBindingId(record.custodyBindingId),
      'custodyBindingId',
    ),
    holderRecipientKeyDigestB64u: parsedDigest(
      record.holderRecipientKeyDigestB64u,
      'holderRecipientKeyDigestB64u',
    ),
    holderCiphertextDigestSetB64u: parsedDigest(
      record.holderCiphertextDigestSetB64u,
      'holderCiphertextDigestSetB64u',
    ),
    sealedHolderRecordDigestB64u: parsedDigest(
      record.sealedHolderRecordDigestB64u,
      'sealedHolderRecordDigestB64u',
    ),
    transcriptHashB64u: parsedDigest(record.transcriptHashB64u, 'transcriptHashB64u'),
    sealedHolderMaterialB64u: parsedOpaqueB64u(
      record.sealedHolderMaterialB64u,
      'sealedHolderMaterialB64u',
    ),
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
    const persisted = await this.seals.putSealedRecord(rowForRecord(record));
    if (!persisted) {
      throw new Error('Canonical lane holder material persistence is unavailable');
    }
    this.volatileRecords.set(key, record);
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

  async listForEnrollmentV1(input: {
    readonly enrollmentId: LaneEnrollmentId;
  }): Promise<readonly LaneSealedHolderRecordV1[]> {
    const enrollmentId = parsed(parseLaneEnrollmentId(input.enrollmentId), 'enrollmentId');
    const records = new Map<string, LaneSealedHolderRecordV1>();
    for (const [key, record] of this.volatileRecords) {
      if (record.enrollmentId === enrollmentId) records.set(key, record);
    }
    const entries = await this.seals.collectAllRawSealedRecordEntries();
    for (const entry of entries) {
      if (!isRecord(entry.value) || entry.value.kind !== 'lane_sealed_holder_record_v1') {
        continue;
      }
      if (typeof entry.primaryKey !== 'string') {
        throw new Error('lane sealed holder record store key is invalid');
      }
      const record = parseRecord(entry.value);
      const key = storeKey({
        operationId: record.operationId,
        enrollmentId: record.enrollmentId,
        targetLaneId: record.laneId,
        targetLaneShareEpoch: record.laneShareEpoch,
        targetMaterialActivationId: record.targetMaterialActivationId,
      });
      if (key !== entry.primaryKey) {
        throw new Error('lane sealed holder record key does not match its content');
      }
      if (record.enrollmentId === enrollmentId) {
        records.set(key, record);
        this.volatileRecords.set(key, record);
      }
    }
    return [...records.values()].sort((left, right) =>
      storeKey({
        operationId: left.operationId,
        enrollmentId: left.enrollmentId,
        targetLaneId: left.laneId,
        targetLaneShareEpoch: left.laneShareEpoch,
        targetMaterialActivationId: left.targetMaterialActivationId,
      }).localeCompare(
        storeKey({
          operationId: right.operationId,
          enrollmentId: right.enrollmentId,
          targetLaneId: right.laneId,
          targetLaneShareEpoch: right.laneShareEpoch,
          targetMaterialActivationId: right.targetMaterialActivationId,
        }),
      ),
    );
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
