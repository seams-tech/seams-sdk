import {
  parseLinkedDeviceWalletSessionDeliveryV1,
  type LinkedDeviceWalletSessionDeliveryV1,
  type LinkedDeviceWalletSessionTokenV1,
} from '@shared/device-linking';
import { alphabetizeStringify } from '@shared/utils/digests';
import type { LinkedDeviceEnrollmentId, WalletKeyId } from '@shared/signing-lanes/ids';
import { SEAMS_WALLET_STORES } from '../schemaNames';
import { seamsWalletDB } from '../singletons';
import type { SeamsWalletDBManager } from './manager';

type StoredLinkedDeviceWalletSessionRowV1 = {
  readonly enrollment_id: string;
  readonly wallet_id: string;
  readonly device_id: string;
  readonly expires_at_ms: number;
  readonly delivery: LinkedDeviceWalletSessionDeliveryV1;
};

export type LinkedDeviceWalletSessionReadResultV1 =
  | {
      readonly kind: 'found';
      readonly delivery: LinkedDeviceWalletSessionDeliveryV1;
    }
  | {
      readonly kind: 'missing' | 'expired' | 'corrupt' | 'persistence_unavailable';
      readonly delivery?: never;
    };

export type LinkedDeviceWalletSessionTokenReadResultV1 =
  | {
      readonly kind: 'found';
      readonly delivery: LinkedDeviceWalletSessionDeliveryV1;
      readonly token: LinkedDeviceWalletSessionTokenV1;
    }
  | {
      readonly kind: 'missing' | 'expired' | 'corrupt' | 'persistence_unavailable';
      readonly delivery?: never;
      readonly token?: never;
    };

const STORE = SEAMS_WALLET_STORES.linkedDeviceWalletSessions;
const STORED_ROW_FIELDS = [
  'enrollment_id',
  'wallet_id',
  'device_id',
  'expires_at_ms',
  'delivery',
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactFields(record: Record<string, unknown>, fields: readonly string[]): boolean {
  const actual = Object.keys(record);
  return actual.length === fields.length && actual.every((field) => fields.includes(field));
}

function parseStoredRow(raw: unknown): LinkedDeviceWalletSessionDeliveryV1 | null {
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
    return delivery;
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
  };
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
        if (!deliveriesEqual(existing, delivery)) {
          throw new Error('Linked-device Wallet Session replay does not match');
        }
        await tx.done;
        return existing;
      }
      await store.put(toStoredRow(delivery));
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

  async readActiveForEnrollmentV1(input: {
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly nowMs: number;
  }): Promise<LinkedDeviceWalletSessionReadResultV1> {
    if (!Number.isSafeInteger(input.nowMs) || input.nowMs <= 0) {
      throw new Error('Linked-device Wallet Session read time is invalid');
    }
    try {
      const db = await this.manager.getDB();
      const raw = await db.get(STORE, input.enrollmentId);
      if (raw === undefined) return { kind: 'missing' };
      const delivery = parseStoredRow(raw);
      if (!delivery) return { kind: 'corrupt' };
      if (delivery.expiresAtMs <= input.nowMs) return { kind: 'expired' };
      return { kind: 'found', delivery };
    } catch {
      return { kind: 'persistence_unavailable' };
    }
  }

  async clearEnrollmentV1(enrollmentId: LinkedDeviceEnrollmentId): Promise<void> {
    const db = await this.manager.getDB();
    await db.delete(STORE, enrollmentId);
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
