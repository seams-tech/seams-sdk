import { IndexedDBManager } from '../../core/indexedDB';
import type { PendingEmailRecovery } from '../../core/types/emailRecovery';

export interface PendingStore {
  get(accountId: string, nearPublicKey?: string): Promise<PendingEmailRecovery | null>;
  set(record: PendingEmailRecovery): Promise<void>;
  clear(accountId: string, nearPublicKey?: string): Promise<void>;
  touchIndex(accountId: string, nearPublicKey: string): Promise<void>;
}

type EmailRecoveryPendingStoreOptions = {
  getPendingTtlMs: () => number;
  now?: () => number;
};

export class EmailRecoveryPendingStore implements PendingStore {
  private getPendingTtlMs: () => number;
  private now: () => number;

  constructor(options: EmailRecoveryPendingStoreOptions) {
    this.getPendingTtlMs = options.getPendingTtlMs;
    this.now = options.now ?? Date.now;
  }

  private getPendingIndexKey(accountId: string): string {
    return `pendingEmailRecovery:${accountId}`;
  }

  private getPendingRecordKey(accountId: string, nearPublicKey: string): string {
    return `${this.getPendingIndexKey(accountId)}:${nearPublicKey}`;
  }

  async get(accountId: string, nearPublicKey?: string): Promise<PendingEmailRecovery | null> {
    const pendingTtlMs = this.getPendingTtlMs();
    const indexKey = this.getPendingIndexKey(accountId);
    const indexedNearPublicKey = await IndexedDBManager.getAppState<string>(indexKey);
    const resolvedNearPublicKey = nearPublicKey ?? indexedNearPublicKey;
    if (!resolvedNearPublicKey) {
      return null;
    }

    const recordKey = this.getPendingRecordKey(accountId, resolvedNearPublicKey);
    const record = await IndexedDBManager.getAppState<PendingEmailRecovery>(recordKey);
    const shouldClearIndex = indexedNearPublicKey === resolvedNearPublicKey;
    if (!record) {
      if (shouldClearIndex) {
        await IndexedDBManager.setAppState(indexKey, undefined as any).catch(() => {});
      }
      return null;
    }

    if (this.now() - record.createdAt > pendingTtlMs) {
      await IndexedDBManager.setAppState(recordKey, undefined as any).catch(() => {});
      if (shouldClearIndex) {
        await IndexedDBManager.setAppState(indexKey, undefined as any).catch(() => {});
      }
      return null;
    }

    if (record.nearPublicKey) {
      await this.touchIndex(accountId, record.nearPublicKey);
    }
    return record;
  }

  async set(record: PendingEmailRecovery): Promise<void> {
    const nearPublicKey = record.nearPublicKey;
    if (!nearPublicKey) {
      throw new Error(
        '[EmailRecoveryPendingStore] Missing nearPublicKey (required to persist pending record)',
      );
    }
    const key = this.getPendingRecordKey(record.accountId, nearPublicKey);
    await IndexedDBManager.setAppState(key, record);
    await this.touchIndex(record.accountId, nearPublicKey);
  }

  async clear(accountId: string, nearPublicKey?: string): Promise<void> {
    const indexKey = this.getPendingIndexKey(accountId);
    const idx = await IndexedDBManager
      .getAppState<string>(indexKey)
      .catch(() => undefined);

    const resolvedNearPublicKey = nearPublicKey || idx || '';
    if (resolvedNearPublicKey) {
      await IndexedDBManager
        .setAppState(this.getPendingRecordKey(accountId, resolvedNearPublicKey), undefined as any)
        .catch(() => {});
    }

    if (!nearPublicKey || idx === nearPublicKey) {
      await IndexedDBManager.setAppState(indexKey, undefined as any).catch(() => {});
    }
  }

  async touchIndex(accountId: string, nearPublicKey: string): Promise<void> {
    await IndexedDBManager
      .setAppState(this.getPendingIndexKey(accountId), nearPublicKey)
      .catch(() => {});
  }
}
