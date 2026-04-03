import { openDB, type IDBPDatabase } from 'idb';
import { toTrimmedString } from '@shared/utils/validation';
import type { KeyMaterialKind, KeyMaterialRecord } from '../accountKeyMaterialDB.types';
import {
  buildEnvelopeAAD,
  normalizeStoredPayloadRecord as normalizeStoredPayloadRecordValue,
  normalizePayloadEnvelope,
  sanitizePayload,
} from './envelope';
import { DB_CONFIG, type PasskeyAccountKeyMaterialDBConfig, upgradePasskeyAccountKeyMaterialDBSchema } from './schema';

export type {
  KeyMaterialAlgorithm,
  KeyMaterialKind,
  KeyMaterialPayloadEnvelope,
  KeyMaterialPayloadEnvelopeAAD,
  KeyMaterialRecord,
} from '../accountKeyMaterialDB.types';

export class AccountKeyMaterialDBManager {
  private config: PasskeyAccountKeyMaterialDBConfig;
  private db: IDBPDatabase | null = null;
  private disabled = false;

  constructor(config: PasskeyAccountKeyMaterialDBConfig = DB_CONFIG) {
    this.config = config;
  }

  getDbName(): string {
    return this.config.dbName;
  }

  setDbName(dbName: string): void {
    const next = toTrimmedString(dbName || '');
    if (!next || next === this.config.dbName) return;
    try {
      (this.db as any)?.close?.();
    } catch {}
    this.db = null;
    this.config = { ...this.config, dbName: next };
  }

  isDisabled(): boolean {
    return this.disabled;
  }

  setDisabled(disabled: boolean): void {
    const next = !!disabled;
    if (next === this.disabled) return;
    this.disabled = next;
    if (next) {
      try {
        (this.db as any)?.close?.();
      } catch {}
      this.db = null;
    }
  }

  /**
   * Get database connection, initializing if necessary
   */
  private async getDB(): Promise<IDBPDatabase> {
    if (this.disabled) {
      throw new Error('[AccountKeyMaterialDBManager] IndexedDB is disabled in this environment.');
    }
    if (this.db) {
      return this.db;
    }

    this.db = await openDB(this.config.dbName, this.config.dbVersion, {
      upgrade(db, _oldVersion, _newVersion, tx): void {
        upgradePasskeyAccountKeyMaterialDBSchema(db, tx);
      },
      blocked() {
        console.warn('PasskeyAccountKeyMaterialDB connection is blocked.');
      },
      blocking() {
        console.warn('PasskeyAccountKeyMaterialDB connection is blocking another connection.');
      },
      terminated: () => {
        console.warn('PasskeyAccountKeyMaterialDB connection has been terminated.');
        this.db = null;
      },
    });

    return this.db;
  }

  async storeKeyMaterial(data: KeyMaterialRecord): Promise<void> {
    const db = await this.getDB();
    const profileId = toTrimmedString(data.profileId || '');
    const signerId = toTrimmedString(data.signerId || '');
    const wrapKeySalt = toTrimmedString(data.wrapKeySalt || '');
    const chainIdKey = toTrimmedString(data.chainIdKey || '').toLowerCase();
    const keyKind = toTrimmedString(data.keyKind || '');
    const algorithm = toTrimmedString(data.algorithm || '');
    const publicKey = toTrimmedString(data.publicKey || '');
    if (!profileId) {
      throw new Error('PasskeyAccountKeyMaterialDB: Missing profileId for key material record');
    }
    if (!Number.isSafeInteger(data.deviceNumber) || data.deviceNumber < 1) {
      throw new Error('PasskeyAccountKeyMaterialDB: Invalid deviceNumber for key material record');
    }
    if (!chainIdKey) {
      throw new Error('PasskeyAccountKeyMaterialDB: Missing chainIdKey for key material record');
    }
    if (!keyKind) {
      throw new Error('PasskeyAccountKeyMaterialDB: Missing keyKind for key material record');
    }
    if (!algorithm) {
      throw new Error('PasskeyAccountKeyMaterialDB: Missing algorithm for key material record');
    }
    if (!publicKey) {
      throw new Error('PasskeyAccountKeyMaterialDB: Missing publicKey for key material record');
    }
    if (typeof data.timestamp !== 'number') {
      throw new Error('PasskeyAccountKeyMaterialDB: Missing timestamp for key material record');
    }
    if (!Number.isSafeInteger(data.schemaVersion) || data.schemaVersion < 1) {
      throw new Error('PasskeyAccountKeyMaterialDB: Invalid schemaVersion for key material record');
    }

    const payload = sanitizePayload(data.payload);
    const expectedAAD = buildEnvelopeAAD({
      profileId,
      deviceNumber: data.deviceNumber,
      chainIdKey,
      keyKind,
      schemaVersion: data.schemaVersion,
      ...(signerId ? { signerId } : {}),
    });
    const payloadEnvelope = normalizePayloadEnvelope(
      data.payloadEnvelope,
      expectedAAD,
      `${profileId}/${data.deviceNumber}/${chainIdKey}/${keyKind}`,
    );

    const toStore: KeyMaterialRecord = {
      profileId,
      deviceNumber: data.deviceNumber,
      chainIdKey,
      keyKind,
      algorithm,
      publicKey,
      ...(signerId ? { signerId } : {}),
      ...(wrapKeySalt ? { wrapKeySalt } : {}),
      ...(payload ? { payload } : {}),
      ...(payloadEnvelope ? { payloadEnvelope } : {}),
      timestamp: data.timestamp,
      schemaVersion: data.schemaVersion,
    };
    await db.put(this.config.storeName, toStore);
  }

  async getKeyMaterial(
    profileId: string,
    deviceNumber: number,
    chainIdKey: string,
    keyKind: KeyMaterialKind,
  ): Promise<KeyMaterialRecord | null> {
    const db = await this.getDB();
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedChainIdKey = toTrimmedString(chainIdKey || '').toLowerCase();
    const normalizedKeyKind = toTrimmedString(keyKind || '');
    if (!normalizedProfileId || !normalizedChainIdKey || !normalizedKeyKind) return null;
    const rec = (await db.get(this.config.storeName, [
      normalizedProfileId,
      deviceNumber,
      normalizedChainIdKey,
      normalizedKeyKind,
    ])) as KeyMaterialRecord | undefined;
    if (!rec) return null;
    return normalizeStoredPayloadRecordValue(rec);
  }

  async listKeyMaterialByProfileAndDevice(
    profileId: string,
    deviceNumber: number,
    chainIdKey?: string,
  ): Promise<KeyMaterialRecord[]> {
    const db = await this.getDB();
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedChainIdKey = toTrimmedString(chainIdKey || '').toLowerCase();
    if (!normalizedProfileId) return [];
    if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) return [];

    const tx = db.transaction(this.config.storeName, 'readonly');
    const rows = (await tx.store
      .index('profileId_deviceNumber')
      .getAll([normalizedProfileId, deviceNumber])) as KeyMaterialRecord[];
    await tx.done;

    const hydratedRows = (rows || [])
      .map((row) => normalizeStoredPayloadRecordValue(row))
      .filter((row): row is KeyMaterialRecord => !!row);
    if (!normalizedChainIdKey) return hydratedRows;
    return hydratedRows.filter(
      (row) => String(row.chainIdKey).trim().toLowerCase() === normalizedChainIdKey,
    );
  }

  async deleteKeyMaterial(
    profileId: string,
    deviceNumber: number,
    chainIdKey: string,
    keyKind: KeyMaterialKind,
  ): Promise<void> {
    const db = await this.getDB();
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedChainIdKey = toTrimmedString(chainIdKey || '').toLowerCase();
    const normalizedKeyKind = toTrimmedString(keyKind || '');
    if (!normalizedProfileId || !normalizedChainIdKey || !normalizedKeyKind) return;
    if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) return;
    await db.delete(this.config.storeName, [
      normalizedProfileId,
      deviceNumber,
      normalizedChainIdKey,
      normalizedKeyKind,
    ]);
  }
}
