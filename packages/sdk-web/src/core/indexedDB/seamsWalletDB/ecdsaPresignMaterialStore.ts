import { unwrap } from 'idb';
import { seamsWalletDB } from '../singletons';
import { SEAMS_WALLET_DB_VERSION, SEAMS_WALLET_STORES } from '../schemaNames';
import { SeamsWalletDBManager } from './manager';
import {
  equalEcdsaClientPresignPoolIdentity,
  FIXED_ECDSA_PRESIGN_PROTOCOL_ID,
  parseEcdsaClientPresignPoolIdentity,
  type EcdsaClientPresignPoolIdentity,
} from '../../signingEngine/workerManager/ecdsaPresignPoolIdentity';

const KEY_STORE = SEAMS_WALLET_STORES.ecdsaPresignSealingKeys;
const RECORD_STORE = SEAMS_WALLET_STORES.ecdsaPresignRecords;
const PRIMARY_KEY_ID = 'primary';
const MATERIAL_SIZE = 97;
const BIG_R_SIZE = 33;
const SCALAR_SIZE = 32;
const GROUP_KEY_SIZE = 33;
const AES_GCM_IV_SIZE = 12;

type StoredSealingKey = {
  readonly id: typeof PRIMARY_KEY_ID;
  readonly key: CryptoKey;
};

type PresignRecordHeader = {
  readonly version: 1;
  readonly protocolId: typeof FIXED_ECDSA_PRESIGN_PROTOCOL_ID;
  readonly materialHandle: string;
  readonly presignSessionId: string;
  readonly presignatureId: string;
  readonly poolIdentity: EcdsaClientPresignPoolIdentity;
  readonly groupPublicKey33: ArrayBuffer;
  readonly bigR33: ArrayBuffer;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};

type PendingAdmissionPresignRecord = PresignRecordHeader & {
  readonly state: 'pending_admission';
  readonly revision: -1;
  readonly iv12: ArrayBuffer;
  readonly ciphertext: ArrayBuffer;
  readonly terminalAtMs?: never;
  readonly reason?: never;
};

type AvailablePresignRecord = PresignRecordHeader & {
  readonly state: 'available';
  readonly revision: 0;
  readonly iv12: ArrayBuffer;
  readonly ciphertext: ArrayBuffer;
  readonly terminalAtMs?: never;
  readonly reason?: never;
};

type ReservedPresignRecord = PresignRecordHeader & {
  readonly state: 'reserved';
  readonly revision: 1;
  readonly requestBinding: string;
  readonly reservationId: string;
  readonly reservedAtMs: number;
  readonly leaseExpiresAtMs: number;
  readonly iv12: ArrayBuffer;
  readonly ciphertext: ArrayBuffer;
};

type CommittedPresignRecord = PresignRecordHeader & {
  readonly state: 'committed_use';
  readonly revision: 2;
  readonly requestBinding: string;
  readonly reservationId: string;
  readonly reservedAtMs: number;
  readonly leaseExpiresAtMs: number;
  readonly committedAtMs: number;
  readonly iv12: ArrayBuffer;
  readonly ciphertext: ArrayBuffer;
};

type TombstoneReason =
  | 'released_to_online'
  | 'binding_rejected'
  | 'material_expired'
  | 'persistence_failure'
  | 'generation_aborted'
  | 'crash_recovery'
  | 'ambiguous_delivery'
  | 'key_epoch_retired'
  | 'activation_epoch_retired';

export type ClientPresignPoolRetirementReason = Extract<
  TombstoneReason,
  'key_epoch_retired' | 'activation_epoch_retired'
>;

type TombstonePresignRecord = PresignRecordHeader & {
  readonly state: 'tombstone';
  readonly revision: 3;
  readonly terminalAtMs: number;
  readonly reason: TombstoneReason;
  readonly iv12?: never;
  readonly ciphertext?: never;
};

type PresignRecord =
  | PendingAdmissionPresignRecord
  | AvailablePresignRecord
  | ReservedPresignRecord
  | CommittedPresignRecord
  | TombstonePresignRecord;

export type DurableClientPresignMaterial = {
  readonly bigR33: Uint8Array;
  readonly kShare32: Uint8Array;
  readonly sigmaShare32: Uint8Array;
};

export type DurableClientPresignatureRef = {
  readonly presignatureId: string;
  readonly materialHandle: string;
  readonly bigR33: Uint8Array;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};

export type StoreClientPresignMaterialInput = DurableClientPresignMaterial & {
  readonly materialHandle: string;
  readonly presignSessionId: string;
  readonly poolIdentity: EcdsaClientPresignPoolIdentity;
  readonly groupPublicKey33: Uint8Array;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};

export type AdmitClientPresignMaterialInput = {
  readonly materialHandle: string;
  readonly expectedPresignatureId: string;
  readonly poolIdentity: EcdsaClientPresignPoolIdentity;
  readonly nowMs: number;
};

export type AdmitClientPresignMaterialResult =
  | { readonly ok: true; readonly presignatureId: string }
  | {
      readonly ok: false;
      readonly code:
        | 'not_found'
        | 'already_consumed'
        | 'invalid_state'
        | 'binding_rejected'
        | 'material_expired'
        | 'persistence_failure';
    };

export type TakeClientPresignMaterialInput = {
  readonly materialHandle: string;
  readonly poolIdentity: EcdsaClientPresignPoolIdentity;
  readonly requestBinding: string;
  readonly reservationId: string;
  readonly expectedBigR33: Uint8Array;
  readonly groupPublicKey33: Uint8Array;
  readonly nowMs: number;
};

export type ClientPresignUseBinding = {
  readonly materialHandle: string;
  readonly poolIdentity: EcdsaClientPresignPoolIdentity;
  readonly requestBinding: string;
  readonly reservationId: string;
  readonly nowMs: number;
};

export type ReserveClientPresignMaterialInput = ClientPresignUseBinding & {
  readonly leaseExpiresAtMs: number;
};

export type ClientPresignLifecycleResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly code:
        | 'not_found'
        | 'invalid_state'
        | 'binding_rejected'
        | 'material_expired'
        | 'persistence_failure';
    };

export type TakeClientPresignMaterialResult =
  | { readonly ok: true; readonly material: DurableClientPresignMaterial }
  | {
      readonly ok: false;
      readonly code:
        | 'not_found'
        | 'already_consumed'
        | 'invalid_state'
        | 'binding_rejected'
        | 'material_expired'
        | 'persistence_failure';
    };

function requireNonEmpty(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function requireBytes(value: Uint8Array, length: number, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new Error(`${label} must be ${length} bytes`);
  }
  return value;
}

function requireTimestamp(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${label} is invalid`);
  return value;
}

function requirePoolIdentity(
  value: EcdsaClientPresignPoolIdentity,
): EcdsaClientPresignPoolIdentity {
  return parseEcdsaClientPresignPoolIdentity(value);
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isStoredSealingKey(value: unknown): value is StoredSealingKey {
  if (!isObjectRecord(value) || !isObjectRecord(value.key)) return false;
  const key = value.key as unknown as CryptoKey;
  return (
    value.id === PRIMARY_KEY_ID &&
    key.type === 'secret' &&
    key.extractable === false &&
    key.algorithm.name === 'AES-GCM' &&
    key.usages.includes('encrypt') &&
    key.usages.includes('decrypt')
  );
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('IndexedDB request failed'));
  });
}

function transactionResult(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () =>
      reject(transaction.error || new Error('IndexedDB transaction aborted'));
    transaction.onerror = () =>
      reject(transaction.error || new Error('IndexedDB transaction failed'));
  });
}

function deleteMaterialDatabase(dbName: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(dbName);
    request.onsuccess = () => resolve();
    request.onerror = () =>
      reject(request.error || new Error('Failed to delete presign IndexedDB'));
    request.onblocked = () => reject(new Error('Presign IndexedDB deletion is blocked'));
  });
}

function appendU32(output: number[], value: number): void {
  output.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function appendLengthPrefixed(output: number[], value: Uint8Array): void {
  appendU32(output, value.length);
  output.push(...value);
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function presignatureId(bigR33: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bigR33);
  return `presig-${base64UrlEncode(new Uint8Array(digest))}`;
}

function additionalData(header: PresignRecordHeader): Uint8Array {
  const output: number[] = [];
  const encoder = new TextEncoder();
  appendLengthPrefixed(output, encoder.encode(header.protocolId));
  appendLengthPrefixed(output, encoder.encode(header.materialHandle));
  appendLengthPrefixed(output, encoder.encode(header.presignSessionId));
  appendLengthPrefixed(output, encoder.encode(header.presignatureId));
  appendLengthPrefixed(output, encoder.encode(header.poolIdentity.poolKey));
  appendLengthPrefixed(output, encoder.encode(header.poolIdentity.walletKeyId));
  appendLengthPrefixed(output, encoder.encode(header.poolIdentity.walletId));
  appendLengthPrefixed(output, encoder.encode(header.poolIdentity.signingScopeB64u));
  appendLengthPrefixed(output, encoder.encode(header.poolIdentity.pairRole));
  appendLengthPrefixed(output, encoder.encode(header.poolIdentity.keyEpoch));
  appendLengthPrefixed(output, encoder.encode(header.poolIdentity.activationEpoch));
  appendLengthPrefixed(output, encoder.encode(header.poolIdentity.protocolId));
  appendLengthPrefixed(output, new Uint8Array(header.groupPublicKey33));
  appendLengthPrefixed(output, new Uint8Array(header.bigR33));
  return new Uint8Array(output);
}

function materialPlaintext(material: DurableClientPresignMaterial): Uint8Array {
  const plaintext = new Uint8Array(MATERIAL_SIZE);
  plaintext.set(material.bigR33, 0);
  plaintext.set(material.kShare32, BIG_R_SIZE);
  plaintext.set(material.sigmaShare32, BIG_R_SIZE + SCALAR_SIZE);
  return plaintext;
}

function materialFromPlaintext(plaintext: Uint8Array): DurableClientPresignMaterial {
  if (plaintext.length !== MATERIAL_SIZE) throw new Error('Invalid decrypted presign material');
  return {
    bigR33: plaintext.slice(0, BIG_R_SIZE),
    kShare32: plaintext.slice(BIG_R_SIZE, BIG_R_SIZE + SCALAR_SIZE),
    sigmaShare32: plaintext.slice(BIG_R_SIZE + SCALAR_SIZE, MATERIAL_SIZE),
  };
}

function parsePoolIdentity(raw: unknown): EcdsaClientPresignPoolIdentity | null {
  try {
    return parseEcdsaClientPresignPoolIdentity(raw);
  } catch {
    return null;
  }
}

function parseRecord(raw: unknown): PresignRecord | null {
  if (!isObjectRecord(raw)) return null;
  const poolIdentity = parsePoolIdentity(raw.poolIdentity);
  if (
    raw.version !== 1 ||
    raw.protocolId !== FIXED_ECDSA_PRESIGN_PROTOCOL_ID ||
    typeof raw.materialHandle !== 'string' ||
    !raw.materialHandle.trim() ||
    typeof raw.presignSessionId !== 'string' ||
    !raw.presignSessionId.trim() ||
    typeof raw.presignatureId !== 'string' ||
    !raw.presignatureId.trim() ||
    !poolIdentity ||
    !(raw.groupPublicKey33 instanceof ArrayBuffer) ||
    raw.groupPublicKey33.byteLength !== GROUP_KEY_SIZE ||
    !(raw.bigR33 instanceof ArrayBuffer) ||
    raw.bigR33.byteLength !== BIG_R_SIZE ||
    typeof raw.createdAtMs !== 'number' ||
    !Number.isSafeInteger(raw.createdAtMs) ||
    typeof raw.expiresAtMs !== 'number' ||
    !Number.isSafeInteger(raw.expiresAtMs) ||
    raw.expiresAtMs <= raw.createdAtMs
  ) {
    return null;
  }
  const header: PresignRecordHeader = {
    version: 1,
    protocolId: FIXED_ECDSA_PRESIGN_PROTOCOL_ID,
    materialHandle: raw.materialHandle,
    presignSessionId: raw.presignSessionId,
    presignatureId: raw.presignatureId,
    poolIdentity,
    groupPublicKey33: raw.groupPublicKey33,
    bigR33: raw.bigR33,
    createdAtMs: raw.createdAtMs,
    expiresAtMs: raw.expiresAtMs,
  };
  if (
    raw.state === 'pending_admission' &&
    raw.revision === -1 &&
    raw.iv12 instanceof ArrayBuffer &&
    raw.iv12.byteLength === AES_GCM_IV_SIZE &&
    raw.ciphertext instanceof ArrayBuffer
  ) {
    return {
      ...header,
      state: 'pending_admission',
      revision: -1,
      iv12: raw.iv12,
      ciphertext: raw.ciphertext,
    };
  }
  if (
    raw.state === 'available' &&
    raw.revision === 0 &&
    raw.iv12 instanceof ArrayBuffer &&
    raw.iv12.byteLength === AES_GCM_IV_SIZE &&
    raw.ciphertext instanceof ArrayBuffer
  ) {
    return {
      ...header,
      state: 'available',
      revision: 0,
      iv12: raw.iv12,
      ciphertext: raw.ciphertext,
    };
  }
  const validReservation =
    typeof raw.requestBinding === 'string' &&
    raw.requestBinding.trim().length > 0 &&
    typeof raw.reservationId === 'string' &&
    raw.reservationId.trim().length > 0 &&
    typeof raw.reservedAtMs === 'number' &&
    Number.isSafeInteger(raw.reservedAtMs) &&
    typeof raw.leaseExpiresAtMs === 'number' &&
    Number.isSafeInteger(raw.leaseExpiresAtMs) &&
    raw.reservedAtMs >= header.createdAtMs &&
    raw.leaseExpiresAtMs > raw.reservedAtMs &&
    raw.leaseExpiresAtMs <= header.expiresAtMs;
  if (
    raw.state === 'reserved' &&
    raw.revision === 1 &&
    validReservation &&
    raw.iv12 instanceof ArrayBuffer &&
    raw.iv12.byteLength === AES_GCM_IV_SIZE &&
    raw.ciphertext instanceof ArrayBuffer
  ) {
    return {
      ...header,
      state: 'reserved',
      revision: 1,
      requestBinding: raw.requestBinding as string,
      reservationId: raw.reservationId as string,
      reservedAtMs: raw.reservedAtMs as number,
      leaseExpiresAtMs: raw.leaseExpiresAtMs as number,
      iv12: raw.iv12,
      ciphertext: raw.ciphertext,
    };
  }
  if (
    raw.state === 'committed_use' &&
    raw.revision === 2 &&
    validReservation &&
    typeof raw.committedAtMs === 'number' &&
    Number.isSafeInteger(raw.committedAtMs) &&
    raw.committedAtMs >= Number(raw.reservedAtMs) &&
    raw.committedAtMs < Number(raw.leaseExpiresAtMs) &&
    raw.iv12 instanceof ArrayBuffer &&
    raw.iv12.byteLength === AES_GCM_IV_SIZE &&
    raw.ciphertext instanceof ArrayBuffer
  ) {
    return {
      ...header,
      state: 'committed_use',
      revision: 2,
      requestBinding: raw.requestBinding as string,
      reservationId: raw.reservationId as string,
      reservedAtMs: raw.reservedAtMs as number,
      leaseExpiresAtMs: raw.leaseExpiresAtMs as number,
      committedAtMs: raw.committedAtMs,
      iv12: raw.iv12,
      ciphertext: raw.ciphertext,
    };
  }
  if (
    raw.state === 'tombstone' &&
    raw.revision === 3 &&
    typeof raw.terminalAtMs === 'number' &&
    Number.isSafeInteger(raw.terminalAtMs) &&
    (raw.reason === 'released_to_online' ||
      raw.reason === 'binding_rejected' ||
      raw.reason === 'material_expired' ||
      raw.reason === 'persistence_failure' ||
      raw.reason === 'generation_aborted' ||
      raw.reason === 'crash_recovery' ||
      raw.reason === 'ambiguous_delivery' ||
      raw.reason === 'key_epoch_retired' ||
      raw.reason === 'activation_epoch_retired')
  ) {
    return {
      ...header,
      state: 'tombstone',
      revision: 3,
      terminalAtMs: raw.terminalAtMs,
      reason: raw.reason,
    };
  }
  return null;
}

function tombstone(
  record:
    | PendingAdmissionPresignRecord
    | AvailablePresignRecord
    | ReservedPresignRecord
    | CommittedPresignRecord,
  reason: TombstoneReason,
  terminalAtMs: number,
): TombstonePresignRecord {
  return {
    version: record.version,
    protocolId: record.protocolId,
    materialHandle: record.materialHandle,
    presignSessionId: record.presignSessionId,
    presignatureId: record.presignatureId,
    poolIdentity: record.poolIdentity,
    groupPublicKey33: record.groupPublicKey33,
    bigR33: record.bigR33,
    createdAtMs: record.createdAtMs,
    expiresAtMs: record.expiresAtMs,
    state: 'tombstone',
    revision: 3,
    terminalAtMs,
    reason,
  };
}

export class IndexedDbClientPresignMaterialStore {
  private readonly manager: SeamsWalletDBManager;
  private dbPromise: Promise<IDBDatabase> | null = null;
  private keyPromise: Promise<CryptoKey> | null = null;

  constructor(dbName?: string) {
    this.manager = dbName
      ? new SeamsWalletDBManager({
          dbName,
          dbVersion: SEAMS_WALLET_DB_VERSION,
        })
      : seamsWalletDB;
  }

  private database(): Promise<IDBDatabase> {
    this.dbPromise ??= this.manager.getDB().then((db) => unwrap(db) as IDBDatabase);
    return this.dbPromise;
  }

  private sealingKey(): Promise<CryptoKey> {
    this.keyPromise ??= this.loadOrCreateSealingKey();
    return this.keyPromise;
  }

  private async readSealingKey(db: IDBDatabase): Promise<CryptoKey | null> {
    const transaction = db.transaction(KEY_STORE, 'readonly');
    const stored = await requestResult(transaction.objectStore(KEY_STORE).get(PRIMARY_KEY_ID));
    await transactionResult(transaction);
    return isStoredSealingKey(stored) ? stored.key : null;
  }

  private async loadOrCreateSealingKey(): Promise<CryptoKey> {
    const db = await this.database();
    const existing = await this.readSealingKey(db);
    if (existing) return existing;

    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
      'encrypt',
      'decrypt',
    ]);
    const write = db.transaction(KEY_STORE, 'readwrite');
    write.objectStore(KEY_STORE).add({ id: PRIMARY_KEY_ID, key } satisfies StoredSealingKey);
    try {
      await transactionResult(write);
      return key;
    } catch {
      const winningKey = await this.readSealingKey(db);
      if (winningKey) return winningKey;
      throw new Error('Failed to establish the presign material sealing key');
    }
  }

  async putPendingAdmission(input: StoreClientPresignMaterialInput): Promise<string> {
    const materialHandle = requireNonEmpty(input.materialHandle, 'materialHandle');
    const presignSessionId = requireNonEmpty(input.presignSessionId, 'presignSessionId');
    const poolIdentity = requirePoolIdentity(input.poolIdentity);
    const bigR33 = requireBytes(input.bigR33, BIG_R_SIZE, 'bigR33');
    const kShare32 = requireBytes(input.kShare32, SCALAR_SIZE, 'kShare32');
    const sigmaShare32 = requireBytes(input.sigmaShare32, SCALAR_SIZE, 'sigmaShare32');
    const groupPublicKey33 = requireBytes(
      input.groupPublicKey33,
      GROUP_KEY_SIZE,
      'groupPublicKey33',
    );
    const createdAtMs = requireTimestamp(input.createdAtMs, 'createdAtMs');
    const expiresAtMs = requireTimestamp(input.expiresAtMs, 'expiresAtMs');
    if (expiresAtMs <= createdAtMs) throw new Error('presign material expiry must follow creation');
    const computedPresignatureId = await presignatureId(bigR33);

    const header: PresignRecordHeader = {
      version: 1,
      protocolId: FIXED_ECDSA_PRESIGN_PROTOCOL_ID,
      materialHandle,
      presignSessionId,
      presignatureId: computedPresignatureId,
      poolIdentity,
      groupPublicKey33: groupPublicKey33.slice().buffer,
      bigR33: bigR33.slice().buffer,
      createdAtMs,
      expiresAtMs,
    };
    const plaintext = materialPlaintext({ bigR33, kShare32, sigmaShare32 });
    const iv12 = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_SIZE));
    try {
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv12, additionalData: additionalData(header) },
        await this.sealingKey(),
        plaintext,
      );
      const record: PendingAdmissionPresignRecord = {
        ...header,
        state: 'pending_admission',
        revision: -1,
        iv12: iv12.buffer,
        ciphertext,
      };
      const db = await this.database();
      const transaction = db.transaction(RECORD_STORE, 'readwrite');
      const store = transaction.objectStore(RECORD_STORE);
      const existing = await requestResult(store.get(materialHandle));
      if (existing !== undefined) {
        transaction.abort();
        throw new Error('presign material handle already exists');
      }
      store.add(record);
      await transactionResult(transaction);
      return computedPresignatureId;
    } finally {
      plaintext.fill(0);
    }
  }

  async admit(input: AdmitClientPresignMaterialInput): Promise<AdmitClientPresignMaterialResult> {
    const materialHandle = requireNonEmpty(input.materialHandle, 'materialHandle');
    const expectedPresignatureId = requireNonEmpty(
      input.expectedPresignatureId,
      'expectedPresignatureId',
    );
    const poolIdentity = requirePoolIdentity(input.poolIdentity);
    const nowMs = requireTimestamp(input.nowMs, 'nowMs');
    let db: IDBDatabase;
    try {
      db = await this.database();
    } catch {
      return { ok: false, code: 'persistence_failure' };
    }
    const transaction = db.transaction(RECORD_STORE, 'readwrite');
    const store = transaction.objectStore(RECORD_STORE);
    try {
      const record = parseRecord(await requestResult(store.get(materialHandle)));
      if (!record) {
        await transactionResult(transaction);
        return { ok: false, code: 'not_found' };
      }
      if (record.state === 'tombstone') {
        await transactionResult(transaction);
        return { ok: false, code: 'already_consumed' };
      }
      if (!equalEcdsaClientPresignPoolIdentity(record.poolIdentity, poolIdentity)) {
        store.put(tombstone(record, 'binding_rejected', nowMs));
        await transactionResult(transaction);
        return { ok: false, code: 'binding_rejected' };
      }
      if (record.state === 'available') {
        if (record.presignatureId !== expectedPresignatureId) {
          store.put(tombstone(record, 'binding_rejected', nowMs));
          await transactionResult(transaction);
          return { ok: false, code: 'binding_rejected' };
        }
        await transactionResult(transaction);
        return { ok: true, presignatureId: record.presignatureId };
      }
      if (nowMs >= record.expiresAtMs) {
        store.put(tombstone(record, 'material_expired', nowMs));
        await transactionResult(transaction);
        return { ok: false, code: 'material_expired' };
      }
      if (record.presignatureId !== expectedPresignatureId) {
        store.put(tombstone(record, 'binding_rejected', nowMs));
        await transactionResult(transaction);
        return { ok: false, code: 'binding_rejected' };
      }
      const available: AvailablePresignRecord = {
        version: record.version,
        protocolId: record.protocolId,
        materialHandle: record.materialHandle,
        presignSessionId: record.presignSessionId,
        presignatureId: record.presignatureId,
        poolIdentity: record.poolIdentity,
        groupPublicKey33: record.groupPublicKey33,
        bigR33: record.bigR33,
        createdAtMs: record.createdAtMs,
        expiresAtMs: record.expiresAtMs,
        state: 'available',
        revision: 0,
        iv12: record.iv12,
        ciphertext: record.ciphertext,
      };
      store.put(available);
      await transactionResult(transaction);
      return { ok: true, presignatureId: available.presignatureId };
    } catch {
      try {
        transaction.abort();
      } catch {}
      return { ok: false, code: 'persistence_failure' };
    }
  }

  async destroy(
    materialHandleInput: string,
    poolIdentityInput: EcdsaClientPresignPoolIdentity,
    nowMsInput: number,
  ): Promise<boolean> {
    const materialHandle = requireNonEmpty(materialHandleInput, 'materialHandle');
    const poolIdentity = requirePoolIdentity(poolIdentityInput);
    const nowMs = requireTimestamp(nowMsInput, 'nowMs');
    let db: IDBDatabase;
    try {
      db = await this.database();
    } catch {
      return false;
    }
    const transaction = db.transaction(RECORD_STORE, 'readwrite');
    const store = transaction.objectStore(RECORD_STORE);
    try {
      const record = parseRecord(await requestResult(store.get(materialHandle)));
      if (!record) {
        await transactionResult(transaction);
        return false;
      }
      if (record.state === 'tombstone') {
        await transactionResult(transaction);
        return true;
      }
      if (!equalEcdsaClientPresignPoolIdentity(record.poolIdentity, poolIdentity)) {
        store.put(tombstone(record, 'binding_rejected', nowMs));
        await transactionResult(transaction);
        return false;
      }
      store.put(tombstone(record, 'generation_aborted', nowMs));
      await transactionResult(transaction);
      return true;
    } catch {
      try {
        transaction.abort();
      } catch {}
      return false;
    }
  }

  async reserve(input: ReserveClientPresignMaterialInput): Promise<ClientPresignLifecycleResult> {
    const materialHandle = requireNonEmpty(input.materialHandle, 'materialHandle');
    const poolIdentity = requirePoolIdentity(input.poolIdentity);
    const requestBinding = requireNonEmpty(input.requestBinding, 'requestBinding');
    const reservationId = requireNonEmpty(input.reservationId, 'reservationId');
    const nowMs = requireTimestamp(input.nowMs, 'nowMs');
    const leaseExpiresAtMs = requireTimestamp(input.leaseExpiresAtMs, 'leaseExpiresAtMs');
    let db: IDBDatabase;
    try {
      db = await this.database();
    } catch {
      return { ok: false, code: 'persistence_failure' };
    }
    const transaction = db.transaction(RECORD_STORE, 'readwrite');
    const store = transaction.objectStore(RECORD_STORE);
    try {
      const record = parseRecord(await requestResult(store.get(materialHandle)));
      if (!record) {
        await transactionResult(transaction);
        return { ok: false, code: 'not_found' };
      }
      if (record.state !== 'available') {
        await transactionResult(transaction);
        return { ok: false, code: 'invalid_state' };
      }
      if (!equalEcdsaClientPresignPoolIdentity(record.poolIdentity, poolIdentity)) {
        store.put(tombstone(record, 'binding_rejected', nowMs));
        await transactionResult(transaction);
        return { ok: false, code: 'binding_rejected' };
      }
      if (nowMs >= record.expiresAtMs || leaseExpiresAtMs > record.expiresAtMs) {
        store.put(tombstone(record, 'material_expired', nowMs));
        await transactionResult(transaction);
        return { ok: false, code: 'material_expired' };
      }
      if (leaseExpiresAtMs <= nowMs) {
        store.put(tombstone(record, 'binding_rejected', nowMs));
        await transactionResult(transaction);
        return { ok: false, code: 'binding_rejected' };
      }
      const reserved: ReservedPresignRecord = {
        version: record.version,
        protocolId: record.protocolId,
        materialHandle: record.materialHandle,
        presignSessionId: record.presignSessionId,
        presignatureId: record.presignatureId,
        poolIdentity: record.poolIdentity,
        groupPublicKey33: record.groupPublicKey33,
        bigR33: record.bigR33,
        createdAtMs: record.createdAtMs,
        expiresAtMs: record.expiresAtMs,
        state: 'reserved',
        revision: 1,
        requestBinding,
        reservationId,
        reservedAtMs: nowMs,
        leaseExpiresAtMs,
        iv12: record.iv12,
        ciphertext: record.ciphertext,
      };
      store.put(reserved);
      await transactionResult(transaction);
      return { ok: true };
    } catch {
      try {
        transaction.abort();
      } catch {}
      return { ok: false, code: 'persistence_failure' };
    }
  }

  async commit(input: ClientPresignUseBinding): Promise<ClientPresignLifecycleResult> {
    const materialHandle = requireNonEmpty(input.materialHandle, 'materialHandle');
    const poolIdentity = requirePoolIdentity(input.poolIdentity);
    const requestBinding = requireNonEmpty(input.requestBinding, 'requestBinding');
    const reservationId = requireNonEmpty(input.reservationId, 'reservationId');
    const nowMs = requireTimestamp(input.nowMs, 'nowMs');
    let db: IDBDatabase;
    try {
      db = await this.database();
    } catch {
      return { ok: false, code: 'persistence_failure' };
    }
    const transaction = db.transaction(RECORD_STORE, 'readwrite');
    const store = transaction.objectStore(RECORD_STORE);
    try {
      const record = parseRecord(await requestResult(store.get(materialHandle)));
      if (!record) {
        await transactionResult(transaction);
        return { ok: false, code: 'not_found' };
      }
      if (record.state !== 'reserved') {
        await transactionResult(transaction);
        return { ok: false, code: 'invalid_state' };
      }
      const bindingMatches =
        equalEcdsaClientPresignPoolIdentity(record.poolIdentity, poolIdentity) &&
        record.requestBinding === requestBinding &&
        record.reservationId === reservationId;
      if (!bindingMatches) {
        store.put(tombstone(record, 'binding_rejected', nowMs));
        await transactionResult(transaction);
        return { ok: false, code: 'binding_rejected' };
      }
      if (nowMs >= record.leaseExpiresAtMs || nowMs >= record.expiresAtMs) {
        store.put(tombstone(record, 'material_expired', nowMs));
        await transactionResult(transaction);
        return { ok: false, code: 'material_expired' };
      }
      const committed: CommittedPresignRecord = {
        version: record.version,
        protocolId: record.protocolId,
        materialHandle: record.materialHandle,
        presignSessionId: record.presignSessionId,
        presignatureId: record.presignatureId,
        poolIdentity: record.poolIdentity,
        groupPublicKey33: record.groupPublicKey33,
        bigR33: record.bigR33,
        createdAtMs: record.createdAtMs,
        expiresAtMs: record.expiresAtMs,
        state: 'committed_use',
        revision: 2,
        requestBinding: record.requestBinding,
        reservationId: record.reservationId,
        reservedAtMs: record.reservedAtMs,
        leaseExpiresAtMs: record.leaseExpiresAtMs,
        committedAtMs: nowMs,
        iv12: record.iv12,
        ciphertext: record.ciphertext,
      };
      store.put(committed);
      await transactionResult(transaction);
      return { ok: true };
    } catch {
      try {
        transaction.abort();
      } catch {}
      return { ok: false, code: 'persistence_failure' };
    }
  }

  async takeForOnline(
    input: TakeClientPresignMaterialInput,
  ): Promise<TakeClientPresignMaterialResult> {
    const materialHandle = requireNonEmpty(input.materialHandle, 'materialHandle');
    const poolIdentity = requirePoolIdentity(input.poolIdentity);
    const requestBinding = requireNonEmpty(input.requestBinding, 'requestBinding');
    const reservationId = requireNonEmpty(input.reservationId, 'reservationId');
    const expectedBigR33 = requireBytes(input.expectedBigR33, BIG_R_SIZE, 'expectedBigR33');
    const groupPublicKey33 = requireBytes(
      input.groupPublicKey33,
      GROUP_KEY_SIZE,
      'groupPublicKey33',
    );
    const nowMs = requireTimestamp(input.nowMs, 'nowMs');
    let key: CryptoKey;
    let db: IDBDatabase;
    try {
      key = await this.sealingKey();
      db = await this.database();
    } catch {
      return { ok: false, code: 'persistence_failure' };
    }
    const transaction = db.transaction(RECORD_STORE, 'readwrite');
    const store = transaction.objectStore(RECORD_STORE);
    let record: PresignRecord | null;
    try {
      record = parseRecord(await requestResult(store.get(materialHandle)));
      if (!record) {
        await transactionResult(transaction);
        return { ok: false, code: 'not_found' };
      }
      if (record.state === 'tombstone') {
        await transactionResult(transaction);
        return { ok: false, code: 'already_consumed' };
      }
      if (record.state !== 'committed_use') {
        await transactionResult(transaction);
        return { ok: false, code: 'invalid_state' };
      }
      const storedBigR33 = new Uint8Array(record.bigR33);
      const storedGroupPublicKey33 = new Uint8Array(record.groupPublicKey33);
      const bindingMatches =
        equalEcdsaClientPresignPoolIdentity(record.poolIdentity, poolIdentity) &&
        record.requestBinding === requestBinding &&
        record.reservationId === reservationId &&
        equalBytes(storedBigR33, expectedBigR33) &&
        equalBytes(storedGroupPublicKey33, groupPublicKey33);
      const reason: TombstoneReason =
        nowMs >= record.expiresAtMs || nowMs >= record.leaseExpiresAtMs
          ? 'material_expired'
          : bindingMatches
            ? 'released_to_online'
            : 'binding_rejected';
      store.put(tombstone(record, reason, nowMs));
      await transactionResult(transaction);
      if (reason !== 'released_to_online') return { ok: false, code: reason };

      let decrypted: ArrayBuffer;
      try {
        decrypted = await crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: new Uint8Array(record.iv12),
            additionalData: additionalData(record),
          },
          key,
          record.ciphertext,
        );
      } catch {
        return { ok: false, code: 'persistence_failure' };
      }
      const plaintext = new Uint8Array(decrypted);
      try {
        return { ok: true, material: materialFromPlaintext(plaintext) };
      } finally {
        plaintext.fill(0);
      }
    } catch {
      try {
        transaction.abort();
      } catch {}
      return { ok: false, code: 'persistence_failure' };
    }
  }

  async listAvailable(
    poolIdentityInput: EcdsaClientPresignPoolIdentity,
    nowMsInput: number,
  ): Promise<DurableClientPresignatureRef[]> {
    const poolIdentity = requirePoolIdentity(poolIdentityInput);
    const nowMs = requireTimestamp(nowMsInput, 'nowMs');
    const db = await this.database();
    const transaction = db.transaction(RECORD_STORE, 'readwrite');
    const store = transaction.objectStore(RECORD_STORE);
    const refs: DurableClientPresignatureRef[] = [];
    try {
      const rawRecords = await requestResult(store.getAll());
      for (const raw of rawRecords) {
        const record = parseRecord(raw);
        if (!record || !equalEcdsaClientPresignPoolIdentity(record.poolIdentity, poolIdentity)) {
          continue;
        }
        if (record.state === 'available') {
          if (nowMs >= record.expiresAtMs) {
            store.put(tombstone(record, 'material_expired', nowMs));
            continue;
          }
          refs.push({
            presignatureId: record.presignatureId,
            materialHandle: record.materialHandle,
            bigR33: new Uint8Array(record.bigR33),
            createdAtMs: record.createdAtMs,
            expiresAtMs: record.expiresAtMs,
          });
          continue;
        }
        if (record.state === 'pending_admission' && nowMs >= record.expiresAtMs) {
          store.put(tombstone(record, 'material_expired', nowMs));
          continue;
        }
        if (record.state === 'reserved' && nowMs >= record.leaseExpiresAtMs) {
          store.put(tombstone(record, 'crash_recovery', nowMs));
          continue;
        }
        if (record.state === 'committed_use' && nowMs >= record.leaseExpiresAtMs) {
          store.put(tombstone(record, 'ambiguous_delivery', nowMs));
        }
      }
      await transactionResult(transaction);
      refs.sort((left, right) => left.createdAtMs - right.createdAtMs);
      return refs;
    } catch (error: unknown) {
      try {
        transaction.abort();
      } catch {}
      throw error;
    }
  }

  async retirePool(
    poolIdentityInput: EcdsaClientPresignPoolIdentity,
    reason: ClientPresignPoolRetirementReason,
    nowMsInput: number,
  ): Promise<number> {
    const poolIdentity = requirePoolIdentity(poolIdentityInput);
    const nowMs = requireTimestamp(nowMsInput, 'nowMs');
    const db = await this.database();
    const transaction = db.transaction(RECORD_STORE, 'readwrite');
    const store = transaction.objectStore(RECORD_STORE);
    let retiredCount = 0;
    try {
      const rawRecords = await requestResult(store.getAll());
      for (const raw of rawRecords) {
        const record = parseRecord(raw);
        if (
          !record ||
          record.state === 'tombstone' ||
          !equalEcdsaClientPresignPoolIdentity(record.poolIdentity, poolIdentity)
        ) {
          continue;
        }
        store.put(tombstone(record, reason, nowMs));
        retiredCount += 1;
      }
      await transactionResult(transaction);
      return retiredCount;
    } catch (error: unknown) {
      try {
        transaction.abort();
      } catch {}
      throw error;
    }
  }

  close(): void {
    this.manager.close();
    this.dbPromise = null;
    this.keyPromise = null;
  }

  async deleteDatabaseForTests(): Promise<void> {
    const dbName = this.manager.getDbName();
    this.close();
    await deleteMaterialDatabase(dbName);
  }
}
