import {
  parseLinkedDeviceWalletSessionDeliveryV1,
  type LinkedDeviceWalletSessionDeliveryV1,
  type LinkedDeviceWalletSessionTokenV1,
} from '@shared/device-linking';
import { alphabetizeStringify } from '@shared/utils/digests';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  SIGNING_SESSION_SEAL_ALG,
  SIGNING_SESSION_SEAL_GROUP_ID,
} from '@shared/utils/signingSessionSeal';
import type { LinkedDeviceEnrollmentId, WalletKeyId } from '@shared/signing-lanes/ids';
import { SEAMS_WALLET_INDEXES, SEAMS_WALLET_STORES } from '../schemaNames';
import { seamsWalletDB } from '../singletons';
import type { SeamsWalletDBManager } from './manager';

export type LinkedDeviceSealedRefreshMaterialV1 = {
  readonly kind: 'linked_device_sealed_refresh_material_v1';
  readonly algorithm: typeof SIGNING_SESSION_SEAL_ALG;
  readonly groupId: typeof SIGNING_SESSION_SEAL_GROUP_ID;
  readonly walletId: string;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: string;
  readonly walletSessionId: string;
  readonly credentialIdB64u: string;
  readonly sealedSecretB64u: string;
  readonly keyVersion: string | null;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly remainingUses: number;
};

type StoredLinkedDeviceWalletSessionRowV1 = {
  readonly enrollment_id: string;
  readonly wallet_id: string;
  readonly device_id: string;
  readonly expires_at_ms: number;
  readonly delivery: LinkedDeviceWalletSessionDeliveryV1;
  readonly sealed_refresh: LinkedDeviceSealedRefreshMaterialV1 | null;
};

type LinkedDeviceWalletSessionWriteStore = {
  index(name: typeof SEAMS_WALLET_INDEXES.walletId): {
    getAll(query: string): Promise<unknown[]>;
  };
  delete(key: string): Promise<unknown>;
  put(row: StoredLinkedDeviceWalletSessionRowV1): Promise<unknown>;
};

export type LinkedDeviceWalletSessionReadResultV1 =
  | {
      readonly kind: 'found';
      readonly delivery: LinkedDeviceWalletSessionDeliveryV1;
    }
  | {
      readonly kind: 'missing' | 'expired' | 'corrupt' | 'ambiguous' | 'persistence_unavailable';
      readonly delivery?: never;
    };

export type LinkedDeviceWalletSessionTokenReadResultV1 =
  | {
      readonly kind: 'found';
      readonly delivery: LinkedDeviceWalletSessionDeliveryV1;
      readonly token: LinkedDeviceWalletSessionTokenV1;
    }
  | {
      readonly kind: 'missing' | 'expired' | 'corrupt' | 'ambiguous' | 'persistence_unavailable';
      readonly delivery?: never;
      readonly token?: never;
    };

export type LinkedDeviceSealedRefreshReadResultV1 =
  | {
      readonly kind: 'found';
      readonly delivery: LinkedDeviceWalletSessionDeliveryV1;
      readonly sealedRefresh: LinkedDeviceSealedRefreshMaterialV1;
    }
  | {
      readonly kind:
        | 'missing'
        | 'expired'
        | 'ambiguous'
        | 'corrupt'
        | 'persistence_unavailable';
      readonly delivery?: never;
      readonly sealedRefresh?: never;
    };

const STORE = SEAMS_WALLET_STORES.linkedDeviceWalletSessions;
const STORED_ROW_FIELDS = [
  'enrollment_id',
  'wallet_id',
  'device_id',
  'expires_at_ms',
  'delivery',
  'sealed_refresh',
] as const;

// Lock invalidates refresh material synchronously. The IndexedDB write can
// finish later, so reads in the same runtime must observe the lock boundary
// immediately and wait for a new sealed refresh before restoring a session.
const lockedLinkedDeviceEnrollments = new Set<string>();

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactFields(record: Record<string, unknown>, fields: readonly string[]): boolean {
  const actual = Object.keys(record);
  return actual.length === fields.length && actual.every((field) => fields.includes(field));
}

function nonEmptyString(value: unknown): string {
  const parsed = typeof value === 'string' ? value.trim() : '';
  if (!parsed) throw new Error('value is required');
  return parsed;
}

function canonicalBase64Url(value: unknown): string {
  const parsed = nonEmptyString(value);
  if (base64UrlEncode(base64UrlDecode(parsed)) !== parsed) {
    throw new Error('value is not canonical base64url');
  }
  return parsed;
}

function nonNegativeSafeInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new Error('value must be a non-negative safe integer');
  }
  return Number(value);
}

function positiveSafeInteger(value: unknown): number {
  const parsed = nonNegativeSafeInteger(value);
  if (parsed === 0) throw new Error('value must be positive');
  return parsed;
}

function parseSealedRefresh(
  raw: unknown,
  delivery: LinkedDeviceWalletSessionDeliveryV1,
): LinkedDeviceSealedRefreshMaterialV1 | null {
  if (raw === null) return null;
  if (!isRecord(raw)) throw new Error('sealed refresh must be an object');
  const fields = [
    'kind',
    'algorithm',
    'groupId',
    'walletId',
    'enrollmentId',
    'deviceId',
    'walletSessionId',
    'credentialIdB64u',
    'sealedSecretB64u',
    'keyVersion',
    'issuedAtMs',
    'expiresAtMs',
    'remainingUses',
  ] as const;
  if (!hasExactFields(raw, fields)) throw new Error('sealed refresh fields are invalid');
  if (
    raw.kind !== 'linked_device_sealed_refresh_material_v1' ||
    raw.algorithm !== SIGNING_SESSION_SEAL_ALG ||
    raw.groupId !== SIGNING_SESSION_SEAL_GROUP_ID
  ) {
    throw new Error('sealed refresh protocol is invalid');
  }
  const enrollmentId = nonEmptyString(raw.enrollmentId);
  if (enrollmentId !== delivery.enrollmentId) {
    throw new Error('sealed refresh enrollment identity does not match its Wallet Session');
  }
  const parsed: LinkedDeviceSealedRefreshMaterialV1 = {
    kind: 'linked_device_sealed_refresh_material_v1',
    algorithm: SIGNING_SESSION_SEAL_ALG,
    groupId: SIGNING_SESSION_SEAL_GROUP_ID,
    walletId: nonEmptyString(raw.walletId),
    enrollmentId: delivery.enrollmentId,
    deviceId: nonEmptyString(raw.deviceId),
    walletSessionId: nonEmptyString(raw.walletSessionId),
    credentialIdB64u: canonicalBase64Url(raw.credentialIdB64u),
    sealedSecretB64u: canonicalBase64Url(raw.sealedSecretB64u),
    keyVersion: raw.keyVersion === null ? null : nonEmptyString(raw.keyVersion),
    issuedAtMs: nonNegativeSafeInteger(raw.issuedAtMs),
    expiresAtMs: positiveSafeInteger(raw.expiresAtMs),
    remainingUses: nonNegativeSafeInteger(raw.remainingUses),
  };
  if (
    parsed.walletId !== delivery.walletId ||
    parsed.enrollmentId !== delivery.enrollmentId ||
    parsed.deviceId !== delivery.deviceId ||
    parsed.walletSessionId !== delivery.walletSessionId ||
    parsed.expiresAtMs > delivery.expiresAtMs
  ) {
    throw new Error('sealed refresh identity does not match its Wallet Session');
  }
  return parsed;
}

function parseStoredRow(raw: unknown): StoredLinkedDeviceWalletSessionRowV1 | null {
  if (!isRecord(raw) || !hasExactFields(raw, STORED_ROW_FIELDS)) return null;
  try {
    const delivery = parseLinkedDeviceWalletSessionDeliveryV1(raw.delivery);
    if (
      raw.enrollment_id !== delivery.enrollmentId ||
      raw.wallet_id !== delivery.walletId ||
      raw.device_id !== delivery.deviceId ||
      raw.expires_at_ms !== delivery.expiresAtMs
    ) {
      return null;
    }
    return {
      enrollment_id: delivery.enrollmentId,
      wallet_id: delivery.walletId,
      device_id: delivery.deviceId,
      expires_at_ms: delivery.expiresAtMs,
      delivery,
      sealed_refresh: parseSealedRefresh(raw.sealed_refresh, delivery),
    };
  } catch {
    return null;
  }
}

function toStoredRow(
  delivery: LinkedDeviceWalletSessionDeliveryV1,
): StoredLinkedDeviceWalletSessionRowV1 {
  return {
    enrollment_id: delivery.enrollmentId,
    wallet_id: delivery.walletId,
    device_id: delivery.deviceId,
    expires_at_ms: delivery.expiresAtMs,
    delivery,
    sealed_refresh: null,
  };
}

async function replaceCurrentWalletSessionRow(
  store: LinkedDeviceWalletSessionWriteStore,
  row: StoredLinkedDeviceWalletSessionRowV1,
): Promise<void> {
  const walletRows = await store.index(SEAMS_WALLET_INDEXES.walletId).getAll(row.wallet_id);
  for (const walletRow of walletRows) {
    if (!isRecord(walletRow)) continue;
    const enrollmentId = walletRow.enrollment_id;
    if (typeof enrollmentId === 'string' && enrollmentId !== row.enrollment_id) {
      await store.delete(enrollmentId);
    }
  }
  await store.put(row);
}

function rowWithSealedRefresh(
  row: StoredLinkedDeviceWalletSessionRowV1,
  sealedRefresh: LinkedDeviceSealedRefreshMaterialV1 | null,
): StoredLinkedDeviceWalletSessionRowV1 {
  return {
    enrollment_id: row.enrollment_id,
    wallet_id: row.wallet_id,
    device_id: row.device_id,
    expires_at_ms: row.expires_at_ms,
    delivery: row.delivery,
    sealed_refresh: sealedRefresh,
  };
}

async function clearOtherWalletSealedRefreshes(
  store: LinkedDeviceWalletSessionWriteStore,
  currentEnrollmentId: string,
  walletId: string,
): Promise<void> {
  const walletRows = await store.index(SEAMS_WALLET_INDEXES.walletId).getAll(walletId);
  for (const walletRow of walletRows) {
    const parsed = parseStoredRow(walletRow);
    if (!parsed) throw new Error('Stored linked-device Wallet Session is corrupt');
    if (parsed.enrollment_id === currentEnrollmentId || parsed.sealed_refresh === null) continue;
    await store.put(rowWithSealedRefresh(parsed, null));
  }
}

function deliveriesEqual(
  left: LinkedDeviceWalletSessionDeliveryV1,
  right: LinkedDeviceWalletSessionDeliveryV1,
): boolean {
  return alphabetizeStringify(left) === alphabetizeStringify(right);
}

export class LinkedDeviceWalletSessionRepositoryV1 {
  constructor(private readonly manager: SeamsWalletDBManager = seamsWalletDB) {}

  async putExactActiveDeliveryV1(
    raw: LinkedDeviceWalletSessionDeliveryV1,
  ): Promise<LinkedDeviceWalletSessionDeliveryV1> {
    const delivery = parseLinkedDeviceWalletSessionDeliveryV1(raw);
    const db = await this.manager.getDB();
    const tx = db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    try {
      const existingRaw = await store.get(delivery.enrollmentId);
      if (existingRaw !== undefined) {
        const existing = parseStoredRow(existingRaw);
        if (!existing) throw new Error('Stored linked-device Wallet Session is corrupt');
        if (!deliveriesEqual(existing.delivery, delivery)) {
          throw new Error('Linked-device Wallet Session replay does not match');
        }
        await replaceCurrentWalletSessionRow(store, existing);
        await tx.done;
        return existing.delivery;
      }
      await replaceCurrentWalletSessionRow(store, toStoredRow(delivery));
      await tx.done;
      return delivery;
    } catch (error) {
      try {
        tx.abort();
      } catch {}
      await tx.done.catch(() => undefined);
      throw error;
    }
  }

  async replaceExactRenewedDeliveryV1(
    raw: LinkedDeviceWalletSessionDeliveryV1,
  ): Promise<LinkedDeviceWalletSessionDeliveryV1> {
    const renewed = parseLinkedDeviceWalletSessionDeliveryV1(raw);
    const db = await this.manager.getDB();
    const tx = db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    try {
      const existingRaw = await store.get(renewed.enrollmentId);
      if (existingRaw === undefined) {
        throw new Error('Linked-device Wallet Session renewal has no persisted session');
      }
      const existing = parseStoredRow(existingRaw);
      if (!existing) {
        throw new Error('Stored linked-device Wallet Session is corrupt');
      }
      if (
        existing.delivery.tenantId !== renewed.tenantId ||
        existing.delivery.walletId !== renewed.walletId ||
        existing.delivery.enrollmentId !== renewed.enrollmentId ||
        existing.delivery.deviceId !== renewed.deviceId
      ) {
        throw new Error('Linked-device Wallet Session renewal identity changed');
      }
      await replaceCurrentWalletSessionRow(store, toStoredRow(renewed));
      await tx.done;
      return renewed;
    } catch (error) {
      try {
        tx.abort();
      } catch {}
      await tx.done.catch(() => undefined);
      throw error;
    }
  }

  async readActiveForEnrollmentV1(input: {
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly nowMs: number;
  }): Promise<LinkedDeviceWalletSessionReadResultV1> {
    if (!Number.isSafeInteger(input.nowMs) || input.nowMs <= 0) {
      throw new Error('Linked-device Wallet Session read time is invalid');
    }
    const result = await this.readForEnrollmentV1(input.enrollmentId);
    if (result.kind !== 'found') return result;
    return result.delivery.expiresAtMs <= input.nowMs ? { kind: 'expired' } : result;
  }

  async readForEnrollmentV1(
    enrollmentId: LinkedDeviceEnrollmentId,
  ): Promise<LinkedDeviceWalletSessionReadResultV1> {
    try {
      const db = await this.manager.getDB();
      const raw = await db.get(STORE, enrollmentId);
      if (raw === undefined) return { kind: 'missing' };
      const row = parseStoredRow(raw);
      return row ? { kind: 'found', delivery: row.delivery } : { kind: 'corrupt' };
    } catch {
      return { kind: 'persistence_unavailable' };
    }
  }

  async readUniqueActiveForWalletV1(input: {
    readonly walletId?: string;
    readonly nowMs: number;
  }): Promise<LinkedDeviceWalletSessionReadResultV1> {
    if (!Number.isSafeInteger(input.nowMs) || input.nowMs <= 0) {
      throw new Error('Linked-device Wallet Session read time is invalid');
    }
    try {
      const db = await this.manager.getDB();
      const index = db
        .transaction(STORE, 'readonly')
        .objectStore(STORE)
        .index(SEAMS_WALLET_INDEXES.walletId);
      const rows = input.walletId ? await index.getAll(input.walletId) : await index.getAll();
      if (rows.length === 0) return { kind: 'missing' };
      const active: LinkedDeviceWalletSessionDeliveryV1[] = [];
      for (const row of rows) {
        const parsed = parseStoredRow(row);
        if (!parsed) return { kind: 'corrupt' };
        if (parsed.delivery.expiresAtMs > input.nowMs) active.push(parsed.delivery);
      }
      if (active.length === 0) return { kind: 'expired' };
      if (active.length > 1) return { kind: 'ambiguous' };
      const delivery = active[0];
      return delivery ? { kind: 'found', delivery } : { kind: 'missing' };
    } catch {
      return { kind: 'persistence_unavailable' };
    }
  }

  async readUniqueForWalletV1(input: {
    readonly walletId?: string;
  }): Promise<LinkedDeviceWalletSessionReadResultV1> {
    try {
      const db = await this.manager.getDB();
      const index = db
        .transaction(STORE, 'readonly')
        .objectStore(STORE)
        .index(SEAMS_WALLET_INDEXES.walletId);
      const rows = input.walletId ? await index.getAll(input.walletId) : await index.getAll();
      if (rows.length === 0) return { kind: 'missing' };
      if (rows.length > 1) return { kind: 'ambiguous' };
      const row = parseStoredRow(rows[0]);
      return row ? { kind: 'found', delivery: row.delivery } : { kind: 'corrupt' };
    } catch {
      return { kind: 'persistence_unavailable' };
    }
  }

  async clearEnrollmentV1(enrollmentId: LinkedDeviceEnrollmentId): Promise<void> {
    const db = await this.manager.getDB();
    await db.delete(STORE, enrollmentId);
    lockedLinkedDeviceEnrollments.delete(String(enrollmentId));
  }

  async putSealedRefreshV1(
    raw: LinkedDeviceSealedRefreshMaterialV1,
  ): Promise<LinkedDeviceSealedRefreshMaterialV1> {
    const db = await this.manager.getDB();
    const tx = db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    try {
      const storedRaw = await store.get(raw.enrollmentId);
      const stored = parseStoredRow(storedRaw);
      if (!stored) throw new Error('Linked-device Wallet Session is unavailable for sealing');
      const sealedRefresh = parseSealedRefresh(raw, stored.delivery);
      if (!sealedRefresh) throw new Error('Linked-device sealed refresh material is required');
      await clearOtherWalletSealedRefreshes(store, stored.enrollment_id, stored.wallet_id);
      await store.put(rowWithSealedRefresh(stored, sealedRefresh));
      await tx.done;
      lockedLinkedDeviceEnrollments.delete(String(sealedRefresh.enrollmentId));
      return sealedRefresh;
    } catch (error) {
      try {
        tx.abort();
      } catch {}
      await tx.done.catch(() => undefined);
      throw error;
    }
  }

  async clearSealedRefreshV1(enrollmentId: LinkedDeviceEnrollmentId): Promise<void> {
    lockedLinkedDeviceEnrollments.add(String(enrollmentId));
    const db = await this.manager.getDB();
    const tx = db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    try {
      const storedRaw = await store.get(enrollmentId);
      if (storedRaw === undefined) {
        await tx.done;
        return;
      }
      const stored = parseStoredRow(storedRaw);
      if (!stored) throw new Error('Stored linked-device Wallet Session is corrupt');
      await store.put(rowWithSealedRefresh(stored, null));
      await tx.done;
    } catch (error) {
      try {
        tx.abort();
      } catch {}
      await tx.done.catch(() => undefined);
      throw error;
    }
  }

  async readActiveSealedRefreshV1(input: {
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSealedRefreshReadResultV1> {
    if (!Number.isSafeInteger(input.nowMs) || input.nowMs <= 0) {
      throw new Error('Linked-device sealed refresh read time is invalid');
    }
    if (lockedLinkedDeviceEnrollments.has(String(input.enrollmentId))) {
      return { kind: 'missing' };
    }
    try {
      const db = await this.manager.getDB();
      const raw = await db.get(STORE, input.enrollmentId);
      if (lockedLinkedDeviceEnrollments.has(String(input.enrollmentId))) {
        return { kind: 'missing' };
      }
      if (raw === undefined) return { kind: 'missing' };
      const row = parseStoredRow(raw);
      if (!row) return { kind: 'corrupt' };
      if (row.delivery.expiresAtMs <= input.nowMs) return { kind: 'expired' };
      if (!row.sealed_refresh) return { kind: 'missing' };
      if (
        row.sealed_refresh.expiresAtMs <= input.nowMs ||
        row.sealed_refresh.remainingUses <= 0
      ) {
        return { kind: 'expired' };
      }
      return {
        kind: 'found',
        delivery: row.delivery,
        sealedRefresh: row.sealed_refresh,
      };
    } catch {
      return { kind: 'persistence_unavailable' };
    }
  }

  async readUniqueActiveSealedRefreshForWalletV1(input: {
    readonly walletId?: string;
    readonly nowMs: number;
  }): Promise<LinkedDeviceSealedRefreshReadResultV1> {
    if (!Number.isSafeInteger(input.nowMs) || input.nowMs <= 0) {
      throw new Error('Linked-device sealed refresh read time is invalid');
    }
    try {
      const db = await this.manager.getDB();
      const rows = await db
        .transaction(STORE, 'readonly')
        .objectStore(STORE)
        .index(SEAMS_WALLET_INDEXES.walletId)
        .getAll(input.walletId);
      if (rows.length === 0) return { kind: 'missing' };
      const active: Array<{
        readonly delivery: LinkedDeviceWalletSessionDeliveryV1;
        readonly sealedRefresh: LinkedDeviceSealedRefreshMaterialV1;
      }> = [];
      let sawExpired = false;
      for (const row of rows) {
        const parsed = parseStoredRow(row);
        if (!parsed) return { kind: 'corrupt' };
        if (lockedLinkedDeviceEnrollments.has(String(parsed.enrollment_id))) continue;
        if (!parsed.sealed_refresh) continue;
        if (
          parsed.delivery.expiresAtMs <= input.nowMs ||
          parsed.sealed_refresh.expiresAtMs <= input.nowMs ||
          parsed.sealed_refresh.remainingUses <= 0
        ) {
          sawExpired = true;
          continue;
        }
        active.push({ delivery: parsed.delivery, sealedRefresh: parsed.sealed_refresh });
      }
      if (active.length > 1) return { kind: 'ambiguous' };
      const found = active[0];
      if (found) {
        return {
          kind: 'found',
          delivery: found.delivery,
          sealedRefresh: found.sealedRefresh,
        };
      }
      return sawExpired ? { kind: 'expired' } : { kind: 'missing' };
    } catch {
      return { kind: 'persistence_unavailable' };
    }
  }

  async readTokenForWalletKeyV1(input: {
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly walletKeyId: WalletKeyId;
    readonly keyFamily: LinkedDeviceWalletSessionTokenV1['keyFamily'];
    readonly nowMs: number;
  }): Promise<LinkedDeviceWalletSessionTokenReadResultV1> {
    const result = await this.readActiveForEnrollmentV1(input);
    if (result.kind !== 'found') return result;
    const token = result.delivery.orderedTokens.find(
      (candidate) =>
        candidate.walletKeyId === input.walletKeyId && candidate.keyFamily === input.keyFamily,
    );
    if (!token) return { kind: 'missing' };
    return { kind: 'found', delivery: result.delivery, token };
  }
}

export const linkedDeviceWalletSessions = new LinkedDeviceWalletSessionRepositoryV1();
