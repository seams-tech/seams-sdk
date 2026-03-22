import { openDB, type IDBPDatabase } from 'idb';
import { toTrimmedString } from '@shared/utils/validation';
import type {
  ClientShareDerivation,
  PasskeyChainIdKeyKind,
  PasskeyChainIdKeyMaterial,
  ThresholdEd25519_2p_V1Material,
} from '../passkeyNearKeysDB.types';
import {
  buildEnvelopeAAD,
  normalizeStoredPayloadRecord as normalizeStoredPayloadRecordValue,
  normalizePayloadEnvelope,
  sanitizePayload,
} from './envelope';
import { DB_CONFIG, type PasskeyNearKeysDBConfig, upgradePasskeyNearKeysDBSchema } from './schema';

export type {
  ClientShareDerivation,
  PasskeyChainIdKeyAlgorithm,
  PasskeyChainIdKeyKind,
  PasskeyChainIdKeyMaterial,
  PasskeyChainIdKeyPayloadEnvelope,
  PasskeyChainIdKeyPayloadEnvelopeAAD,
  PasskeyNearKeyMaterial,
  PasskeyNearKeyMaterialKind,
  ThresholdEd25519_2p_V1Material,
} from '../passkeyNearKeysDB.types';

export class PasskeyNearKeysDBManager {
  private config: PasskeyNearKeysDBConfig;
  private db: IDBPDatabase | null = null;
  private disabled = false;

  constructor(config: PasskeyNearKeysDBConfig = DB_CONFIG) {
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
      throw new Error('[PasskeyNearKeysDBManager] IndexedDB is disabled in this environment.');
    }
    if (this.db) {
      return this.db;
    }

    this.db = await openDB(this.config.dbName, this.config.dbVersion, {
      upgrade(db, _oldVersion, _newVersion, tx): void {
        upgradePasskeyNearKeysDBSchema(db, tx);
      },
      blocked() {
        console.warn('PasskeyNearKeysDB connection is blocked.');
      },
      blocking() {
        console.warn('PasskeyNearKeysDB connection is blocking another connection.');
      },
      terminated: () => {
        console.warn('PasskeyNearKeysDB connection has been terminated.');
        this.db = null;
      },
    });

    return this.db;
  }

  async storeKeyMaterial(data: PasskeyChainIdKeyMaterial): Promise<void> {
    const db = await this.getDB();
    const profileId = toTrimmedString(data.profileId || '');
    const signerId = toTrimmedString(data.signerId || '');
    const wrapKeySalt = toTrimmedString(data.wrapKeySalt || '');
    const chainIdKey = toTrimmedString(data.chainIdKey || '').toLowerCase();
    const keyKind = toTrimmedString(data.keyKind || '');
    const algorithm = toTrimmedString(data.algorithm || '');
    const publicKey = toTrimmedString(data.publicKey || '');
    if (!profileId) {
      throw new Error('PasskeyNearKeysDB: Missing profileId for key material record');
    }
    if (!Number.isSafeInteger(data.deviceNumber) || data.deviceNumber < 1) {
      throw new Error('PasskeyNearKeysDB: Invalid deviceNumber for key material record');
    }
    if (!chainIdKey) {
      throw new Error('PasskeyNearKeysDB: Missing chainIdKey for key material record');
    }
    if (!keyKind) {
      throw new Error('PasskeyNearKeysDB: Missing keyKind for key material record');
    }
    if (!algorithm) {
      throw new Error('PasskeyNearKeysDB: Missing algorithm for key material record');
    }
    if (!publicKey) {
      throw new Error('PasskeyNearKeysDB: Missing publicKey for key material record');
    }
    if (typeof data.timestamp !== 'number') {
      throw new Error('PasskeyNearKeysDB: Missing timestamp for key material record');
    }
    if (!Number.isSafeInteger(data.schemaVersion) || data.schemaVersion < 1) {
      throw new Error('PasskeyNearKeysDB: Invalid schemaVersion for key material record');
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

    const toStore: PasskeyChainIdKeyMaterial = {
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
    keyKind: PasskeyChainIdKeyKind,
  ): Promise<PasskeyChainIdKeyMaterial | null> {
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
    ])) as PasskeyChainIdKeyMaterial | undefined;
    if (!rec) return null;
    return normalizeStoredPayloadRecordValue(rec);
  }

  async listKeyMaterialByProfileAndDevice(
    profileId: string,
    deviceNumber: number,
    chainIdKey?: string,
  ): Promise<PasskeyChainIdKeyMaterial[]> {
    const db = await this.getDB();
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedChainIdKey = toTrimmedString(chainIdKey || '').toLowerCase();
    if (!normalizedProfileId) return [];
    if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) return [];

    const tx = db.transaction(this.config.storeName, 'readonly');
    const rows = (await tx.store
      .index('profileId_deviceNumber')
      .getAll([normalizedProfileId, deviceNumber])) as PasskeyChainIdKeyMaterial[];
    await tx.done;

    const hydratedRows = (rows || [])
      .map((row) => normalizeStoredPayloadRecordValue(row))
      .filter((row): row is PasskeyChainIdKeyMaterial => !!row);
    if (!normalizedChainIdKey) return hydratedRows;
    return hydratedRows.filter(
      (row) => String(row.chainIdKey).trim().toLowerCase() === normalizedChainIdKey,
    );
  }

  async deleteKeyMaterial(
    profileId: string,
    deviceNumber: number,
    chainIdKey: string,
    keyKind: PasskeyChainIdKeyKind,
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
