import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../../../storage/tenantRoute';
import { isD1DatabaseLike } from '../../../../storage/d1Sql';
import { containsControlCharacter } from '../../durableObjects/versionedJsonRecordStore';
import type {
  VersionedJsonObject,
  VersionedJsonRecordPutResult,
  VersionedJsonRecordReadResult,
} from '../../../framework/versionedJsonRecordStore';

const TABLE_NAME = 'router_ab_yao_versioned_json_records';
const CAS_GUARD_TABLE_NAME = 'router_ab_yao_versioned_json_cas_guard';
const CAS_GUARD_SQL = `INSERT INTO ${CAS_GUARD_TABLE_NAME} (guard_id)
SELECT 1
 WHERE changes() = 0`;

export type CloudflareD1VersionedJsonRecordScopeV1 = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

export type CloudflareD1VersionedJsonRecordStoreOptions<T> = {
  readonly database: D1DatabaseLike;
  readonly scope: CloudflareD1VersionedJsonRecordScopeV1;
  readonly encode: (value: T) => VersionedJsonObject;
  readonly parse: (raw: unknown) => T | null;
  readonly keyPrefix?: string;
};

export type CloudflareD1VersionedJsonRecordMutationV1<T> = {
  readonly key: string;
  readonly value: T;
  readonly expectedVersion: string | null;
};

export type CloudflareD1VersionedJsonRecordReadManyEntryV1<T> = {
  readonly key: string;
  readonly result: VersionedJsonRecordReadResult<T>;
};

export type CloudflareD1VersionedJsonRecordBatchPutResultV1 =
  | {
      readonly kind: 'stored';
      readonly versions: readonly {
        readonly key: string;
        readonly version: string;
      }[];
    }
  | { readonly kind: 'version_mismatch'; readonly key: string };

export type CloudflareD1VersionedJsonRecordAtomicPatchV1 = {
  readonly key: string;
  readonly expectedVersion: string;
  readonly exactStringPredicates: readonly {
    readonly jsonPath: string;
    readonly value: string;
  }[];
  readonly unexpired: {
    readonly jsonPath: string;
    readonly nowMs: number;
  };
  readonly patch: VersionedJsonObject;
};

type StoredRecord = {
  readonly version?: unknown;
  readonly record_json?: unknown;
};

export class CloudflareD1VersionedJsonRecordStoreError extends Error {
  readonly code: 'invalid_record' | 'invalid_response' | 'request_failed';

  constructor(code: 'invalid_record' | 'invalid_response' | 'request_failed', message: string) {
    super(message);
    this.name = 'CloudflareD1VersionedJsonRecordStoreError';
    this.code = code;
  }
}

export class CloudflareD1VersionedJsonRecordStore<T> {
  private readonly database: D1DatabaseLike;
  private readonly scope: CloudflareD1VersionedJsonRecordScopeV1;
  private readonly encode: (value: T) => VersionedJsonObject;
  private readonly parse: (raw: unknown) => T | null;
  private readonly keyPrefix: string;

  constructor(options: CloudflareD1VersionedJsonRecordStoreOptions<T>) {
    if (!isD1DatabaseLike(options.database)) {
      throw new Error('Cloudflare D1 versioned JSON database is required');
    }
    this.database = options.database;
    this.scope = normalizeScope(options.scope);
    if (typeof options.encode !== 'function' || typeof options.parse !== 'function') {
      throw new Error('Cloudflare D1 versioned JSON encoder and parser are required');
    }
    this.encode = options.encode;
    this.parse = options.parse;
    this.keyPrefix = normalizeKeyPrefix(options.keyPrefix);
  }

  async read(key: string): Promise<VersionedJsonRecordReadResult<T>> {
    const [entry] = await this.readMany([key]);
    if (!entry) throw new Error('Cloudflare D1 versioned JSON read returned no entry');
    return entry.result;
  }

  /**
   * Reads a set of records from one D1 batch snapshot. Callers that compose
   * shared and ceremony state must use this method so they never merge rows
   * from different database versions.
   */
  /**
   * Reads every record whose key starts with `keyStartsWith`, inside this
   * scope.
   *
   * A prefix scan rather than a key batch because the caller does not know the
   * keys: enumerating a wallet's envelopes means finding rows it has never
   * seen. The prefix is matched literally — `LIKE` wildcards in it are escaped
   * — so a caller cannot widen its own scan into another wallet's rows by
   * passing `%`.
   *
   * Rows that fail to parse are skipped rather than failing the scan. A single
   * unreadable row must not make a wallet's whole envelope set unlistable,
   * which would turn one corrupt record into a wallet nobody can manage.
   */
  async listByKeyPrefix(
    keyStartsWith: string,
    options: { readonly limit?: number } = {},
  ): Promise<readonly CloudflareD1VersionedJsonRecordReadManyEntryV1<T>[]> {
    const prefix = `${this.keyPrefix}${normalizeRecordKey(keyStartsWith)}`;
    const limit = Math.min(Math.max(options.limit ?? 100, 1), 1000);
    const rows = await this.database
      .prepare(
        `SELECT record_key, version, record_json
           FROM ${TABLE_NAME}
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND record_key LIKE ?5 ESCAPE '\\'
          ORDER BY record_key
          LIMIT ?6`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        `${escapeLikePattern(prefix)}%`,
        limit,
      )
      .all<StoredRecord & { record_key: string }>();

    const entries: CloudflareD1VersionedJsonRecordReadManyEntryV1<T>[] = [];
    for (const row of rows.results ?? []) {
      const value = parseJson(String(row.record_json));
      const parsed = value === null ? null : this.parse(value);
      if (!parsed) continue;
      entries.push({
        key: String(row.record_key).slice(this.keyPrefix.length),
        result: { kind: 'present', value: parsed, version: String(row.version) },
      });
    }
    return entries;
  }

  async readMany(
    keys: readonly string[],
  ): Promise<readonly CloudflareD1VersionedJsonRecordReadManyEntryV1<T>[]> {
    const preparedKeys = prepareReadKeys(keys, this.keyPrefix);
    const statements = preparedKeys.map(({ storageKey }) =>
      this.database
        .prepare(
          `SELECT version, record_json
           FROM ${TABLE_NAME}
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND record_key = ?5`,
        )
        .bind(
          this.scope.namespace,
          this.scope.orgId,
          this.scope.projectId,
          this.scope.envId,
          storageKey,
        ),
    );
    let results: readonly D1ResultLike<StoredRecord>[];
    try {
      results = await this.database.batch<D1ResultLike<StoredRecord>>(statements);
    } catch (error: unknown) {
      throw requestFailure(error);
    }
    try {
      assertBatchSucceeded(results, preparedKeys.length);
    } catch (error: unknown) {
      throw error instanceof CloudflareD1VersionedJsonRecordStoreError
        ? error
        : invalidResponseFailure(
            error instanceof Error ? error.message : 'Cloudflare D1 batch response is invalid',
          );
    }
    return preparedKeys.map(({ key }, index) => ({
      key,
      result: this.parseReadResult(results[index]),
    }));
  }

  private parseReadResult(
    result: D1ResultLike<StoredRecord> | undefined,
  ): VersionedJsonRecordReadResult<T> {
    const row = firstResult(result);
    if (row === null) return { kind: 'missing' };
    const version = parseVersion(row.version);
    if (version === null || typeof row.record_json !== 'string') {
      throw invalidRecordFailure('Stored D1 versioned JSON record envelope is invalid');
    }
    const value = parseJson(row.record_json);
    const parsed = value === null ? null : this.parse(value);
    if (parsed === null) throw invalidRecordFailure('Stored D1 versioned JSON record is invalid');
    return { kind: 'present', value: parsed, version: String(version) };
  }

  async put(
    key: string,
    value: T,
    expectedVersion: string | null,
  ): Promise<VersionedJsonRecordPutResult> {
    const storageKey = this.storageKey(key);
    const encoded = this.encode(value);
    if (!isJsonObject(encoded)) {
      throw new Error('Cloudflare D1 versioned JSON encoder returned a non-object value');
    }
    const recordJson = JSON.stringify(encoded);
    if (expectedVersion === null) return await this.insert(storageKey, recordJson);
    const parsedExpectedVersion = parseVersion(expectedVersion);
    if (parsedExpectedVersion === null) {
      throw new Error('Cloudflare D1 versioned JSON expectedVersion must be null or non-empty');
    }
    return await this.update(storageKey, recordJson, parsedExpectedVersion);
  }

  /**
   * Applies multiple records in one D1 transaction. The guard statement turns
   * every zero-row CAS into a constraint failure, which makes D1 roll back the
   * whole batch instead of committing a partial update.
   */
  async putMany(
    mutations: readonly CloudflareD1VersionedJsonRecordMutationV1<T>[],
  ): Promise<CloudflareD1VersionedJsonRecordBatchPutResultV1> {
    return await this.putManyWithAdditionalStatements(mutations, []);
  }

  /**
   * Applies versioned-record mutations and caller-owned D1 statements in the
   * same transaction. The additional statements are used only where a domain
   * commit spans this JSON store and a normalized table (for example, a
   * recovery envelope plus its WebAuthn authenticator and binding).
   */
  async putManyWithAdditionalStatements(
    mutations: readonly CloudflareD1VersionedJsonRecordMutationV1<T>[],
    additionalStatements: readonly D1PreparedStatementLike[],
  ): Promise<CloudflareD1VersionedJsonRecordBatchPutResultV1> {
    const prepared = this.prepareBatchMutations(mutations);
    const statements: D1PreparedStatementLike[] = [];
    for (const mutation of prepared) {
      statements.push(this.prepareMutationStatement(mutation));
      statements.push(this.database.prepare(CAS_GUARD_SQL));
    }
    statements.push(...additionalStatements);
    try {
      const results = await this.database.batch<D1ResultLike>(statements);
      assertBatchSucceeded(results, statements.length);
      return {
        kind: 'stored',
        versions: prepared.map((mutation) => ({
          key: mutation.key,
          version: String((mutation.expectedVersion ?? 0) + 1),
        })),
      };
    } catch (error: unknown) {
      const conflictKey = await this.findBatchConflict(prepared);
      if (conflictKey !== null) return { kind: 'version_mismatch', key: conflictKey };
      throw requestFailure(error);
    }
  }

  /**
   * The same mutation + CAS-guard statements `putManyWithAdditionalStatements`
   * would run, returned instead of executed, so a caller whose transaction is
   * owned elsewhere can fold them into that batch.
   *
   * Auth-method revocation needs exactly this: the method, its sessions, and
   * its sealed envelope have to commit together, and the authority store owns
   * that batch.
   */
  prepareMutationStatements(
    mutations: readonly CloudflareD1VersionedJsonRecordMutationV1<T>[],
  ): readonly D1PreparedStatementLike[] {
    const statements: D1PreparedStatementLike[] = [];
    for (const mutation of this.prepareBatchMutations(mutations)) {
      statements.push(this.prepareMutationStatement(mutation));
      statements.push(this.database.prepare(CAS_GUARD_SQL));
    }
    return statements;
  }

  async patchAtomically(
    input: CloudflareD1VersionedJsonRecordAtomicPatchV1,
  ): Promise<VersionedJsonRecordPutResult & { readonly value?: T }> {
    const storageKey = this.storageKey(input.key);
    const expectedVersion = parseVersion(input.expectedVersion);
    if (expectedVersion === null) {
      throw new Error('Cloudflare D1 atomic JSON patch expectedVersion is invalid');
    }
    if (
      !Number.isSafeInteger(input.unexpired.nowMs) ||
      input.unexpired.nowMs <= 0 ||
      !isJsonPath(input.unexpired.jsonPath)
    ) {
      throw new Error('Cloudflare D1 atomic JSON patch expiry predicate is invalid');
    }
    for (const predicate of input.exactStringPredicates) {
      if (!isJsonPath(predicate.jsonPath) || typeof predicate.value !== 'string') {
        throw new Error('Cloudflare D1 atomic JSON patch exact predicate is invalid');
      }
    }
    if (!isJsonObject(input.patch)) {
      throw new Error('Cloudflare D1 atomic JSON patch value is invalid');
    }
    const exactSql = input.exactStringPredicates
      .map((_, index) => `AND json_extract(record_json, ?${9 + index * 2}) = ?${10 + index * 2}`)
      .join('\n');
    const expiryPathIndex = 9 + input.exactStringPredicates.length * 2;
    const nowIndex = expiryPathIndex + 1;
    const bindings: unknown[] = [
      this.scope.namespace,
      this.scope.orgId,
      this.scope.projectId,
      this.scope.envId,
      storageKey,
      JSON.stringify(input.patch),
      Date.now(),
      expectedVersion,
      ...input.exactStringPredicates.flatMap((predicate) => [predicate.jsonPath, predicate.value]),
      input.unexpired.jsonPath,
      input.unexpired.nowMs,
    ];
    let row: StoredRecord | null;
    try {
      row = await this.database
        .prepare(
          `UPDATE ${TABLE_NAME}
              SET version = version + 1,
                  record_json = json_patch(record_json, json(?6)),
                  updated_at_ms = ?7
            WHERE namespace = ?1
              AND org_id = ?2
              AND project_id = ?3
              AND env_id = ?4
              AND record_key = ?5
              AND version = ?8
              ${exactSql}
              AND json_extract(record_json, ?${expiryPathIndex}) > ?${nowIndex}
          RETURNING version, record_json`,
        )
        .bind(...bindings)
        .first<StoredRecord>();
    } catch (error: unknown) {
      throw requestFailure(error);
    }
    if (row === null) return { kind: 'version_mismatch' };
    const parsed = this.parseReadResult({ success: true, results: [row] });
    if (parsed.kind !== 'present') {
      throw invalidResponseFailure('Cloudflare D1 atomic JSON patch omitted its stored value');
    }
    return { kind: 'stored', version: parsed.version, value: parsed.value };
  }

  private prepareBatchMutations(
    mutations: readonly CloudflareD1VersionedJsonRecordMutationV1<T>[],
  ): readonly PreparedMutation[] {
    if (mutations.length === 0) {
      throw new Error('Cloudflare D1 versioned JSON batch requires at least one mutation');
    }
    const seenKeys = new Set<string>();
    return mutations.map((mutation) => {
      const key = normalizeRecordKey(mutation.key);
      const storageKey = this.storageKey(key);
      if (seenKeys.has(storageKey)) {
        throw new Error('Cloudflare D1 versioned JSON batch contains duplicate keys');
      }
      seenKeys.add(storageKey);
      const encoded = this.encode(mutation.value);
      if (!isJsonObject(encoded)) {
        throw new Error('Cloudflare D1 versioned JSON encoder returned a non-object value');
      }
      const expectedVersion =
        mutation.expectedVersion === null ? null : parseVersion(mutation.expectedVersion);
      if (mutation.expectedVersion !== null && expectedVersion === null) {
        throw new Error('Cloudflare D1 versioned JSON expectedVersion must be null or non-empty');
      }
      return {
        key,
        storageKey,
        recordJson: JSON.stringify(encoded),
        expectedVersion,
      };
    });
  }

  private prepareMutationStatement(mutation: PreparedMutation): D1PreparedStatementLike {
    if (mutation.expectedVersion === null) {
      return this.database
        .prepare(
          `INSERT OR IGNORE INTO ${TABLE_NAME}
            (namespace, org_id, project_id, env_id, record_key, version, record_json)
           VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)`,
        )
        .bind(
          this.scope.namespace,
          this.scope.orgId,
          this.scope.projectId,
          this.scope.envId,
          mutation.storageKey,
          mutation.recordJson,
        );
    }
    return this.database
      .prepare(
        `UPDATE ${TABLE_NAME}
            SET version = version + 1,
                record_json = ?6,
                updated_at_ms = ?7
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND record_key = ?5
            AND version = ?8`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        mutation.storageKey,
        mutation.recordJson,
        Date.now(),
        mutation.expectedVersion,
      );
  }

  private async findBatchConflict(prepared: readonly PreparedMutation[]): Promise<string | null> {
    for (const mutation of prepared) {
      const current = await this.read(mutation.key);
      if (!matchesExpectedVersion(current, mutation.expectedVersion)) return mutation.key;
    }
    return null;
  }

  private async insert(
    storageKey: string,
    recordJson: string,
  ): Promise<VersionedJsonRecordPutResult> {
    let result: D1ResultLike<unknown>;
    try {
      result = await this.database
        .prepare(
          `INSERT OR IGNORE INTO ${TABLE_NAME}
            (namespace, org_id, project_id, env_id, record_key, version, record_json)
           VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)`,
        )
        .bind(
          this.scope.namespace,
          this.scope.orgId,
          this.scope.projectId,
          this.scope.envId,
          storageKey,
          recordJson,
        )
        .run();
    } catch (error: unknown) {
      throw requestFailure(error);
    }
    return changes(result) === 1 ? { kind: 'stored', version: '1' } : { kind: 'version_mismatch' };
  }

  private async update(
    storageKey: string,
    recordJson: string,
    expectedVersion: number,
  ): Promise<VersionedJsonRecordPutResult> {
    let result: D1ResultLike<unknown>;
    try {
      result = await this.database
        .prepare(
          `UPDATE ${TABLE_NAME}
              SET version = version + 1,
                  record_json = ?6,
                  updated_at_ms = ?7
            WHERE namespace = ?1
              AND org_id = ?2
              AND project_id = ?3
              AND env_id = ?4
              AND record_key = ?5
              AND version = ?8`,
        )
        .bind(
          this.scope.namespace,
          this.scope.orgId,
          this.scope.projectId,
          this.scope.envId,
          storageKey,
          recordJson,
          Date.now(),
          expectedVersion,
        )
        .run();
    } catch (error: unknown) {
      throw requestFailure(error);
    }
    return changes(result) === 1
      ? { kind: 'stored', version: String(expectedVersion + 1) }
      : { kind: 'version_mismatch' };
  }

  private storageKey(key: string): string {
    return `${this.keyPrefix}${normalizeRecordKey(key)}`;
  }
}

export function createCloudflareD1VersionedJsonRecordStore<T>(
  options: CloudflareD1VersionedJsonRecordStoreOptions<T>,
): CloudflareD1VersionedJsonRecordStore<T> {
  return new CloudflareD1VersionedJsonRecordStore(options);
}

function normalizeScope(
  scope: CloudflareD1VersionedJsonRecordScopeV1,
): CloudflareD1VersionedJsonRecordScopeV1 {
  return {
    namespace: normalizeScopePart(scope.namespace, 'namespace'),
    orgId: normalizeScopePart(scope.orgId, 'orgId'),
    projectId: normalizeScopePart(scope.projectId, 'projectId'),
    envId: normalizeScopePart(scope.envId, 'envId'),
  };
}

function normalizeScopePart(value: unknown, field: string): string {
  const normalized = toOptionalTrimmedString(value);
  if (!normalized || normalized.length > 256 || containsControlCharacter(normalized)) {
    throw new Error(`Cloudflare D1 versioned JSON ${field} is invalid`);
  }
  return normalized;
}

function normalizeKeyPrefix(value: unknown): string {
  const prefix = toOptionalTrimmedString(value);
  if (!prefix) return 'router-ab-yao:';
  if (prefix.length > 128 || containsControlCharacter(prefix)) {
    throw new Error('Cloudflare D1 versioned JSON keyPrefix is invalid');
  }
  return prefix.endsWith(':') ? prefix : `${prefix}:`;
}

function normalizeRecordKey(value: unknown): string {
  const key = toOptionalTrimmedString(value);
  if (!key) throw new Error('Cloudflare D1 versioned JSON record key is required');
  if (key.length > 512 || containsControlCharacter(key)) {
    throw new Error('Cloudflare D1 versioned JSON record key is invalid');
  }
  return key;
}

function isJsonPath(value: unknown): value is string {
  return typeof value === 'string' && /^\$\.[A-Za-z][A-Za-z0-9.]*$/u.test(value);
}

function parseVersion(value: unknown): number | null {
  const text = typeof value === 'number' ? String(value) : toOptionalTrimmedString(value);
  if (!text || !/^\d+$/u.test(text)) return null;
  const version = Number(text);
  return Number.isSafeInteger(version) && version > 0 ? version : null;
}

function parseJson(value: string): unknown | null {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

type PreparedReadKey = {
  readonly key: string;
  readonly storageKey: string;
};

function prepareReadKeys(keys: readonly string[], keyPrefix: string): readonly PreparedReadKey[] {
  if (keys.length === 0) {
    throw new Error('Cloudflare D1 versioned JSON read batch requires at least one key');
  }
  const seen = new Set<string>();
  return keys.map((rawKey) => {
    const key = normalizeRecordKey(rawKey);
    const storageKey = `${keyPrefix}${key}`;
    if (seen.has(storageKey)) {
      throw new Error('Cloudflare D1 versioned JSON read batch contains duplicate keys');
    }
    seen.add(storageKey);
    return { key, storageKey };
  });
}

function firstResult<T>(result: D1ResultLike<T> | undefined): T | null {
  if (!result) {
    throw invalidResponseFailure('Cloudflare D1 versioned JSON batch response is invalid');
  }
  if (!result.success || !Array.isArray(result.results)) {
    throw invalidResponseFailure('Cloudflare D1 versioned JSON read response is invalid');
  }
  return result.results[0] ?? null;
}

function changes(result: D1ResultLike<unknown>): number {
  if (!result.success) throw requestFailure('Cloudflare D1 versioned JSON write failed');
  const value = result.meta?.changes;
  return typeof value === 'number' && Number.isSafeInteger(value) ? value : 0;
}

function assertBatchSucceeded(
  results: readonly D1ResultLike[],
  expectedStatementCount: number,
): void {
  if (results.length !== expectedStatementCount) {
    throw invalidResponseFailure('Cloudflare D1 versioned JSON batch returned incomplete results');
  }
  for (const result of results) {
    if (!result.success) throw invalidResponseFailure('Cloudflare D1 versioned JSON batch failed');
  }
}

function matchesExpectedVersion(
  current: VersionedJsonRecordReadResult<unknown>,
  expectedVersion: number | null,
): boolean {
  if (expectedVersion === null) return current.kind === 'missing';
  return current.kind === 'present' && Number(current.version) === expectedVersion;
}

type PreparedMutation = {
  readonly key: string;
  readonly storageKey: string;
  readonly recordJson: string;
  readonly expectedVersion: number | null;
};

function isJsonObject(value: unknown): value is VersionedJsonObject {
  return isPlainObject(value) && Object.values(value).every(isJsonValue);
}

function isJsonValue(value: unknown): boolean {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isJsonValue);
  return isJsonObject(value);
}

function requestFailure(error: unknown): CloudflareD1VersionedJsonRecordStoreError {
  return new CloudflareD1VersionedJsonRecordStoreError(
    'request_failed',
    error instanceof Error ? error.message : 'Cloudflare D1 versioned JSON request failed',
  );
}

function invalidRecordFailure(message: string): CloudflareD1VersionedJsonRecordStoreError {
  return new CloudflareD1VersionedJsonRecordStoreError('invalid_record', message);
}

function invalidResponseFailure(message: string): CloudflareD1VersionedJsonRecordStoreError {
  return new CloudflareD1VersionedJsonRecordStoreError('invalid_response', message);
}

/** Escapes `LIKE` metacharacters so a prefix matches literally. */
function escapeLikePattern(value: string): string {
  return value.replace(/[\\%_]/g, (match) => `\\${match}`);
}
