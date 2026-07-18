const DATABASE_NAME = 'seams_router_ab_ecdsa_role_local_session_v1';
const DATABASE_VERSION = 1;
const KEY_STORE = 'sealing_keys';
const MATERIAL_STORE = 'active_material';
const PRIMARY_KEY_ID = 'primary';
const AES_GCM_IV_BYTES = 12;

type StoredSealingKey = {
  readonly id: typeof PRIMARY_KEY_ID;
  readonly key: CryptoKey;
};

type ActiveMaterialHeader = {
  readonly version: 1;
  readonly durableMaterialRef: string;
  readonly bindingDigest: string;
  readonly lifecycleId: string;
  readonly transcriptDigestB64u: string;
  readonly activationDigestB64u: string;
  readonly activatedAtMs: number;
  readonly expiresAtMs: number;
};

type ActiveMaterialRecord = ActiveMaterialHeader & {
  readonly iv12: ArrayBuffer;
  readonly ciphertext: ArrayBuffer;
};

export type StoreActiveEcdsaRoleLocalMaterialInput = ActiveMaterialHeader & {
  readonly stateBlobB64u: string;
};

export type RestoreActiveEcdsaRoleLocalMaterialResult =
  | {
      readonly ok: true;
      readonly stateBlobB64u: string;
      readonly lifecycleId: string;
      readonly transcriptDigestB64u: string;
      readonly activationDigestB64u: string;
      readonly activatedAtMs: number;
      readonly expiresAtMs: number;
    }
  | {
      readonly ok: false;
      readonly reason: 'missing' | 'expired' | 'binding_mismatch' | 'corrupt';
    };

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed'));
  });
}

function transactionResult(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () =>
      reject(transaction.error ?? new Error('IndexedDB transaction failed'));
    transaction.onabort = () =>
      reject(transaction.error ?? new Error('IndexedDB transaction aborted'));
  });
}

function openMaterialDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(KEY_STORE)) {
        db.createObjectStore(KEY_STORE, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(MATERIAL_STORE)) {
        db.createObjectStore(MATERIAL_STORE, { keyPath: 'durableMaterialRef' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error ?? new Error('Failed to open ECDSA role-local material database'));
  });
}

function requireNonEmpty(value: unknown, label: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function requireTimestamp(value: unknown, label: string): number {
  const normalized = Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 1) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return normalized;
}

function activeMaterialHeader(input: StoreActiveEcdsaRoleLocalMaterialInput): ActiveMaterialHeader {
  return {
    version: 1,
    durableMaterialRef: requireNonEmpty(input.durableMaterialRef, 'durableMaterialRef'),
    bindingDigest: requireNonEmpty(input.bindingDigest, 'bindingDigest'),
    lifecycleId: requireNonEmpty(input.lifecycleId, 'lifecycleId'),
    transcriptDigestB64u: requireNonEmpty(
      input.transcriptDigestB64u,
      'transcriptDigestB64u',
    ),
    activationDigestB64u: requireNonEmpty(
      input.activationDigestB64u,
      'activationDigestB64u',
    ),
    activatedAtMs: requireTimestamp(input.activatedAtMs, 'activatedAtMs'),
    expiresAtMs: requireTimestamp(input.expiresAtMs, 'expiresAtMs'),
  };
}

function additionalData(header: ActiveMaterialHeader): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify([
      header.version,
      header.durableMaterialRef,
      header.bindingDigest,
      header.lifecycleId,
      header.transcriptDigestB64u,
      header.activationDigestB64u,
      header.activatedAtMs,
      header.expiresAtMs,
    ]),
  );
}

function isStoredSealingKey(value: unknown): value is StoredSealingKey {
  if (!value || typeof value !== 'object') return false;
  const record = value as Record<string, unknown>;
  return record.id === PRIMARY_KEY_ID && record.key instanceof CryptoKey;
}

function parseActiveMaterialRecord(value: unknown): ActiveMaterialRecord | null {
  if (!value || typeof value !== 'object') return null;
  const record = value as Record<string, unknown>;
  if (
    record.version !== 1 ||
    !(record.iv12 instanceof ArrayBuffer) ||
    record.iv12.byteLength !== AES_GCM_IV_BYTES ||
    !(record.ciphertext instanceof ArrayBuffer)
  ) {
    return null;
  }
  try {
    const header: ActiveMaterialHeader = {
      version: 1,
      durableMaterialRef: requireNonEmpty(record.durableMaterialRef, 'durableMaterialRef'),
      bindingDigest: requireNonEmpty(record.bindingDigest, 'bindingDigest'),
      lifecycleId: requireNonEmpty(record.lifecycleId, 'lifecycleId'),
      transcriptDigestB64u: requireNonEmpty(
        record.transcriptDigestB64u,
        'transcriptDigestB64u',
      ),
      activationDigestB64u: requireNonEmpty(
        record.activationDigestB64u,
        'activationDigestB64u',
      ),
      activatedAtMs: requireTimestamp(record.activatedAtMs, 'activatedAtMs'),
      expiresAtMs: requireTimestamp(record.expiresAtMs, 'expiresAtMs'),
    };
    return {
      ...header,
      iv12: record.iv12,
      ciphertext: record.ciphertext,
    };
  } catch {
    return null;
  }
}

export class IndexedDbEcdsaRoleLocalSessionMaterialStore {
  private dbPromise: Promise<IDBDatabase> | null = null;
  private keyPromise: Promise<CryptoKey> | null = null;

  private database(): Promise<IDBDatabase> {
    this.dbPromise ??= openMaterialDatabase();
    return this.dbPromise;
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
    const transaction = db.transaction(KEY_STORE, 'readwrite');
    transaction.objectStore(KEY_STORE).add({
      id: PRIMARY_KEY_ID,
      key,
    } satisfies StoredSealingKey);
    try {
      await transactionResult(transaction);
      return key;
    } catch {
      const winningKey = await this.readSealingKey(db);
      if (winningKey) return winningKey;
      throw new Error('Failed to establish ECDSA role-local material sealing key');
    }
  }

  private sealingKey(): Promise<CryptoKey> {
    this.keyPromise ??= this.loadOrCreateSealingKey();
    return this.keyPromise;
  }

  async putActive(input: StoreActiveEcdsaRoleLocalMaterialInput): Promise<void> {
    const header = activeMaterialHeader(input);
    const stateBlobB64u = requireNonEmpty(input.stateBlobB64u, 'stateBlobB64u');
    if (header.expiresAtMs <= header.activatedAtMs) {
      throw new Error('ECDSA role-local material expiry must follow activation');
    }
    const plaintext = new TextEncoder().encode(stateBlobB64u);
    const iv12 = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
    try {
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv12, additionalData: additionalData(header) },
        await this.sealingKey(),
        plaintext,
      );
      const record: ActiveMaterialRecord = {
        ...header,
        iv12: iv12.slice().buffer,
        ciphertext,
      };
      const db = await this.database();
      const transaction = db.transaction(MATERIAL_STORE, 'readwrite');
      transaction.objectStore(MATERIAL_STORE).put(record);
      await transactionResult(transaction);
    } finally {
      plaintext.fill(0);
    }
  }

  async burn(durableMaterialRefValue: string): Promise<void> {
    const durableMaterialRef = requireNonEmpty(
      durableMaterialRefValue,
      'durableMaterialRef',
    );
    const db = await this.database();
    const transaction = db.transaction(MATERIAL_STORE, 'readwrite');
    transaction.objectStore(MATERIAL_STORE).delete(durableMaterialRef);
    await transactionResult(transaction);
  }

  async restoreActive(input: {
    readonly durableMaterialRef: string;
    readonly expectedBindingDigest: string;
    readonly nowMs: number;
  }): Promise<RestoreActiveEcdsaRoleLocalMaterialResult> {
    const durableMaterialRef = requireNonEmpty(
      input.durableMaterialRef,
      'durableMaterialRef',
    );
    const expectedBindingDigest = requireNonEmpty(
      input.expectedBindingDigest,
      'expectedBindingDigest',
    );
    const db = await this.database();
    const transaction = db.transaction(MATERIAL_STORE, 'readonly');
    const raw = await requestResult(
      transaction.objectStore(MATERIAL_STORE).get(durableMaterialRef),
    );
    const record = parseActiveMaterialRecord(raw);
    await transactionResult(transaction);
    if (!record) {
      if (raw !== undefined) await this.burn(durableMaterialRef);
      return { ok: false, reason: raw === undefined ? 'missing' : 'corrupt' };
    }
    if (record.bindingDigest !== expectedBindingDigest) {
      await this.burn(durableMaterialRef);
      return { ok: false, reason: 'binding_mismatch' };
    }
    if (input.nowMs >= record.expiresAtMs) {
      await this.burn(durableMaterialRef);
      return { ok: false, reason: 'expired' };
    }
    try {
      const plaintext = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: new Uint8Array(record.iv12),
          additionalData: additionalData(record),
        },
        await this.sealingKey(),
        record.ciphertext,
      );
      const bytes = new Uint8Array(plaintext);
      try {
        return {
          ok: true,
          stateBlobB64u: requireNonEmpty(
            new TextDecoder().decode(bytes),
            'restored stateBlobB64u',
          ),
          lifecycleId: record.lifecycleId,
          transcriptDigestB64u: record.transcriptDigestB64u,
          activationDigestB64u: record.activationDigestB64u,
          activatedAtMs: record.activatedAtMs,
          expiresAtMs: record.expiresAtMs,
        };
      } finally {
        bytes.fill(0);
      }
    } catch {
      await this.burn(durableMaterialRef);
      return { ok: false, reason: 'corrupt' };
    }
  }
}
