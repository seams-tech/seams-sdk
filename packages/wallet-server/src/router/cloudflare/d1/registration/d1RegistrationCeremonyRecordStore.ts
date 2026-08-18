import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';
import { alphabetizeStringify } from '@shared/utils/digests';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../../../storage/tenantRoute';
import { isD1DatabaseLike } from '../../../../storage/d1Sql';

const TABLE_NAME = 'registration_ceremony_records';
const CAS_GUARD_SQL = `INSERT INTO registration_ceremony_cas_guard (guard_id)
SELECT 1
 WHERE changes() = 0`;

export type D1RegistrationCeremonyRecordScope = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

export type D1RegistrationCeremonyRecordStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly scope: D1RegistrationCeremonyRecordScope;
  readonly keyPrefix: string;
};

export type D1RegistrationCeremonyStoredRecord = {
  readonly value: Record<string, unknown>;
  readonly version: number;
  readonly expiresAtMs: number;
};

export type D1RegistrationCeremonyRecordMutation = {
  readonly scope: string;
  readonly id: string;
  readonly value: Record<string, unknown>;
  readonly expiresAtMs: number;
};

export type D1RegistrationCeremonyAtomicBranchClaim = {
  readonly value: Record<string, unknown>;
  readonly version: number;
  readonly expiresAtMs: number;
};

type StoredRow = {
  readonly version?: unknown;
  readonly record_json?: unknown;
  readonly expires_at_ms?: unknown;
};

export class D1RegistrationCeremonyRecordConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'D1RegistrationCeremonyRecordConflictError';
  }
}

export class D1RegistrationCeremonyRecordStore {
  private readonly database: D1DatabaseLike;
  private readonly tenantScope: D1RegistrationCeremonyRecordScope;
  private readonly keyPrefix: string;

  constructor(options: D1RegistrationCeremonyRecordStoreOptions) {
    if (!isD1DatabaseLike(options.database)) {
      throw new Error('Registration ceremony D1 database is required');
    }
    this.database = options.database;
    this.tenantScope = normalizeTenantScope(options.scope);
    this.keyPrefix = normalizeKeyPart(options.keyPrefix, 'keyPrefix', 128);
  }

  async get(scope: string, id: string): Promise<D1RegistrationCeremonyStoredRecord | null> {
    const key = this.normalizeKey(scope, id);
    const row = await this.database
      .prepare(
        `SELECT version, record_json, expires_at_ms
           FROM ${TABLE_NAME}
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND record_scope = ?5
            AND record_id = ?6`,
      )
      .bind(...this.bindKey(key))
      .first<StoredRow>();
    if (!row) return null;
    const parsed = parseStoredRow(row);
    if (parsed.expiresAtMs > Date.now()) return parsed;
    await this.deleteVersion(key, parsed.version);
    return null;
  }

  async putExact(mutation: D1RegistrationCeremonyRecordMutation): Promise<void> {
    const key = this.normalizeKey(mutation.scope, mutation.id);
    const prepared = prepareValue(mutation.value, mutation.expiresAtMs);
    const inserted = await this.insert(key, prepared);
    if (inserted) return;
    const current = await this.get(mutation.scope, mutation.id);
    if (!current) {
      const retryInserted = await this.insert(key, prepared);
      if (retryInserted) return;
      throw conflict('Registration ceremony record was concurrently created');
    }
    if (recordsMatch(current, prepared)) return;
    throw conflict('Registration ceremony record conflicts with the stored value');
  }

  async reserveExclusive(mutation: D1RegistrationCeremonyRecordMutation): Promise<boolean> {
    const key = this.normalizeKey(mutation.scope, mutation.id);
    const prepared = prepareValue(mutation.value, mutation.expiresAtMs);
    if (await this.insert(key, prepared)) return true;
    await this.get(mutation.scope, mutation.id);
    return await this.insert(key, prepared);
  }

  async updateExpected(input: {
    readonly scope: string;
    readonly id: string;
    readonly expected: Record<string, unknown>;
    readonly next: Record<string, unknown>;
    readonly expiresAtMs: number;
  }): Promise<void> {
    const key = this.normalizeKey(input.scope, input.id);
    const current = await this.get(input.scope, input.id);
    if (!current || stableJson(current.value) !== stableJson(input.expected)) {
      throw conflict('Registration ceremony record changed before update');
    }
    const next = prepareValue(input.next, input.expiresAtMs);
    const result = await this.database
      .prepare(
        `UPDATE ${TABLE_NAME}
            SET version = version + 1,
                record_json = ?7,
                expires_at_ms = ?8,
                updated_at_ms = ?9
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND record_scope = ?5
            AND record_id = ?6
            AND version = ?10`,
      )
      .bind(...this.bindKey(key), next.recordJson, next.expiresAtMs, Date.now(), current.version)
      .run();
    if (changes(result) !== 1) {
      throw conflict('Registration ceremony record changed during update');
    }
  }

  async claimEcdsaRegistrationBranch(input: {
    readonly scope: string;
    readonly id: string;
    readonly expectedKind: 'evm_family_ecdsa_prepared' | 'evm_family_ecdsa_pending_activation';
    readonly binding:
      | {
          readonly kind: 'strict_registration';
          readonly strictRegistrationBindingJson: string;
        }
      | { readonly kind: 'pending_activation' };
    readonly patch: Record<string, unknown>;
  }): Promise<D1RegistrationCeremonyAtomicBranchClaim | null> {
    const key = this.normalizeKey(input.scope, input.id);
    const strictRegistrationBindingJson =
      input.binding.kind === 'strict_registration'
        ? normalizeKeyPart(
            input.binding.strictRegistrationBindingJson,
            'strictRegistrationBindingJson',
            16_384,
          )
        : '';
    const patchJson = stableJson(input.patch);
    const nowMs = Date.now();
    const row = await this.database
      .prepare(
        `WITH target(branch_index) AS (
           SELECT CAST(branch.key AS INTEGER)
             FROM ${TABLE_NAME} AS ceremony,
                  json_each(ceremony.record_json, '$.signerState.branches') AS branch
            WHERE ceremony.namespace = ?1
              AND ceremony.org_id = ?2
              AND ceremony.project_id = ?3
              AND ceremony.env_id = ?4
              AND ceremony.record_scope = ?5
              AND ceremony.record_id = ?6
              AND ceremony.expires_at_ms > ?11
              AND json_extract(branch.value, '$.kind') = ?7
              AND (
                ?8 = 'pending_activation'
                OR json_extract(branch.value, '$.strictRegistrationBindingJson') = ?9
              )
            LIMIT 1
         )
         UPDATE ${TABLE_NAME}
            SET version = version + 1,
                record_json = json_set(
                  record_json,
                  '$.signerState.branches[' || (SELECT branch_index FROM target) || ']',
                  json_patch(
                    json_extract(
                      record_json,
                      '$.signerState.branches[' || (SELECT branch_index FROM target) || ']'
                    ),
                    json(?10)
                  )
                ),
                updated_at_ms = ?11
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND record_scope = ?5
            AND record_id = ?6
            AND EXISTS (SELECT 1 FROM target)
        RETURNING version, record_json, expires_at_ms`,
      )
      .bind(
        ...this.bindKey(key),
        input.expectedKind,
        input.binding.kind,
        strictRegistrationBindingJson,
        patchJson,
        nowMs,
      )
      .first<StoredRow>();
    if (!row) return null;
    const parsed = parseStoredRow(row);
    return {
      value: parsed.value,
      version: parsed.version,
      expiresAtMs: parsed.expiresAtMs,
    };
  }

  async updateExpectedVersion(input: {
    readonly scope: string;
    readonly id: string;
    readonly expectedVersion: number;
    readonly next: Record<string, unknown>;
    readonly expiresAtMs: number;
  }): Promise<number> {
    const key = this.normalizeKey(input.scope, input.id);
    if (!Number.isSafeInteger(input.expectedVersion) || input.expectedVersion < 1) {
      throw new Error('Registration ceremony expected version is invalid');
    }
    const next = prepareValue(input.next, input.expiresAtMs);
    const result = await this.database
      .prepare(
        `UPDATE ${TABLE_NAME}
            SET version = version + 1,
                record_json = ?7,
                expires_at_ms = ?8,
                updated_at_ms = ?9
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND record_scope = ?5
            AND record_id = ?6
            AND version = ?10`,
      )
      .bind(
        ...this.bindKey(key),
        next.recordJson,
        next.expiresAtMs,
        Date.now(),
        input.expectedVersion,
      )
      .run();
    if (changes(result) !== 1) {
      throw conflict('Registration ceremony record changed during versioned update');
    }
    return input.expectedVersion + 1;
  }

  async take(scope: string, id: string): Promise<Record<string, unknown> | null> {
    const key = this.normalizeKey(scope, id);
    const current = await this.get(scope, id);
    if (!current) return null;
    return (await this.deleteVersion(key, current.version)) ? current.value : null;
  }

  async delete(scope: string, id: string): Promise<boolean> {
    const key = this.normalizeKey(scope, id);
    const current = await this.get(scope, id);
    if (!current) return false;
    return await this.deleteVersion(key, current.version);
  }

  /**
   * The statements `putManyExact` would run, for callers that need these records
   * to land in someone else's batch rather than their own.
   *
   * Returns nothing when every record is already stored exactly as given, which
   * is the same "already done" outcome `putManyExact` treats as success.
   */
  async buildPutManyExactStatements(
    mutations: readonly D1RegistrationCeremonyRecordMutation[],
  ): Promise<readonly D1PreparedStatementLike[]> {
    const prepared = await this.prepareExactMutations(mutations);
    const statements: D1PreparedStatementLike[] = [];
    for (const mutation of prepared) {
      statements.push(this.prepareInsert(mutation.key, mutation.value));
      statements.push(this.database.prepare(CAS_GUARD_SQL));
    }
    return statements;
  }

  private async prepareExactMutations(
    mutations: readonly D1RegistrationCeremonyRecordMutation[],
  ): Promise<readonly PreparedBatchMutation[]> {
    const prepared: PreparedBatchMutation[] = [];
    for (const mutation of mutations) {
      const key = this.normalizeKey(mutation.scope, mutation.id);
      const value = prepareValue(mutation.value, mutation.expiresAtMs);
      const current = await this.get(mutation.scope, mutation.id);
      if (current && recordsMatch(current, value)) continue;
      if (current) {
        throw conflict('Registration ceremony atomic batch conflicts with a stored value');
      }
      prepared.push({ key, value });
    }
    if (prepared.length === 0) return [];
    if (prepared.length !== mutations.length) {
      throw conflict('Registration ceremony atomic batch is only partially stored');
    }
    return prepared;
  }

  async putManyExact(mutations: readonly D1RegistrationCeremonyRecordMutation[]): Promise<void> {
    if (mutations.length < 2) {
      throw new Error('Registration ceremony atomic batch requires at least two records');
    }
    const statements = await this.buildPutManyExactStatements(mutations);
    if (statements.length === 0) return;
    try {
      assertBatchSucceeded(await this.database.batch<D1ResultLike>(statements), statements.length);
    } catch (error: unknown) {
      const allStored = await this.allRecordsMatch(mutations);
      if (allStored) return;
      throw conflict(error instanceof Error ? error.message : 'Registration ceremony batch failed');
    }
  }

  private async allRecordsMatch(
    mutations: readonly D1RegistrationCeremonyRecordMutation[],
  ): Promise<boolean> {
    for (const mutation of mutations) {
      const current = await this.get(mutation.scope, mutation.id);
      if (!current || !recordsMatch(current, prepareValue(mutation.value, mutation.expiresAtMs))) {
        return false;
      }
    }
    return true;
  }

  private async insert(key: StorageKey, value: PreparedValue): Promise<boolean> {
    return changes(await this.prepareInsert(key, value).run()) === 1;
  }

  private prepareInsert(key: StorageKey, value: PreparedValue): D1PreparedStatementLike {
    return this.database
      .prepare(
        `INSERT OR IGNORE INTO ${TABLE_NAME}
          (namespace, org_id, project_id, env_id, record_scope, record_id,
           version, record_json, expires_at_ms, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8, ?9)`,
      )
      .bind(...this.bindKey(key), value.recordJson, value.expiresAtMs, Date.now());
  }

  private async deleteVersion(key: StorageKey, version: number): Promise<boolean> {
    return changes(await this.prepareDelete(key, version).run()) === 1;
  }

  private prepareDelete(key: StorageKey, version: number): D1PreparedStatementLike {
    return this.database
      .prepare(
        `DELETE FROM ${TABLE_NAME}
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND record_scope = ?5
            AND record_id = ?6
            AND version = ?7`,
      )
      .bind(...this.bindKey(key), version);
  }

  private bindKey(key: StorageKey): readonly string[] {
    return [
      this.tenantScope.namespace,
      this.tenantScope.orgId,
      this.tenantScope.projectId,
      this.tenantScope.envId,
      key.scope,
      key.id,
    ];
  }

  private normalizeKey(scope: string, id: string): StorageKey {
    return {
      scope: normalizeKeyPart(scope, 'scope', 128),
      id: `${this.keyPrefix}${normalizeKeyPart(id, 'id', 512)}`,
    };
  }
}

type StorageKey = { readonly scope: string; readonly id: string };
type PreparedValue = {
  readonly value: Record<string, unknown>;
  readonly recordJson: string;
  readonly expiresAtMs: number;
};
type PreparedBatchMutation = { readonly key: StorageKey; readonly value: PreparedValue };

function prepareValue(value: Record<string, unknown>, expiresAtMs: number): PreparedValue {
  if (!isPlainObject(value)) throw new Error('Registration ceremony record must be an object');
  const normalizedExpiresAtMs = Math.floor(Number(expiresAtMs));
  if (!Number.isSafeInteger(normalizedExpiresAtMs) || normalizedExpiresAtMs <= Date.now()) {
    throw new Error('Registration ceremony record expiry must be in the future');
  }
  return { value, recordJson: stableJson(value), expiresAtMs: normalizedExpiresAtMs };
}

function parseStoredRow(row: StoredRow): D1RegistrationCeremonyStoredRecord {
  const version = Number(row.version);
  const expiresAtMs = Number(row.expires_at_ms);
  if (!Number.isSafeInteger(version) || version < 1 || !Number.isSafeInteger(expiresAtMs)) {
    throw new Error('Stored registration ceremony D1 envelope is invalid');
  }
  if (typeof row.record_json !== 'string') {
    throw new Error('Stored registration ceremony D1 JSON is invalid');
  }
  let value: unknown;
  try {
    value = JSON.parse(row.record_json);
  } catch {
    throw new Error('Stored registration ceremony D1 JSON is malformed');
  }
  if (!isPlainObject(value)) throw new Error('Stored registration ceremony D1 record is invalid');
  return { value, version, expiresAtMs };
}

function recordsMatch(current: D1RegistrationCeremonyStoredRecord, next: PreparedValue): boolean {
  return current.expiresAtMs === next.expiresAtMs && stableJson(current.value) === next.recordJson;
}

function stableJson(value: Record<string, unknown>): string {
  return alphabetizeStringify(value);
}

function changes(result: D1ResultLike<unknown>): number {
  if (!result.success) throw new Error('Registration ceremony D1 mutation failed');
  const value = result.meta?.changes;
  return typeof value === 'number' && Number.isSafeInteger(value) ? value : 0;
}

function assertBatchSucceeded(results: readonly D1ResultLike[], expectedCount: number): void {
  if (results.length !== expectedCount || results.some((result) => !result.success)) {
    throw new Error('Registration ceremony D1 batch returned an invalid result');
  }
}

function normalizeTenantScope(
  scope: D1RegistrationCeremonyRecordScope,
): D1RegistrationCeremonyRecordScope {
  return {
    namespace: normalizeKeyPart(scope.namespace, 'namespace', 256),
    orgId: normalizeKeyPart(scope.orgId, 'orgId', 256),
    projectId: normalizeKeyPart(scope.projectId, 'projectId', 256),
    envId: normalizeKeyPart(scope.envId, 'envId', 256),
  };
}

function normalizeKeyPart(value: unknown, field: string, maxLength: number): string {
  const normalized = toOptionalTrimmedString(value);
  if (!normalized || normalized.length > maxLength || containsAsciiControlCharacter(normalized)) {
    throw new Error(`Registration ceremony D1 ${field} is invalid`);
  }
  return normalized;
}

function containsAsciiControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function conflict(message: string): D1RegistrationCeremonyRecordConflictError {
  return new D1RegistrationCeremonyRecordConflictError(message);
}
