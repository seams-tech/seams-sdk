import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { expect, test } from '@playwright/test';
import { createD1ConsoleBillingPrepaidReservationService } from '../../packages/sdk-server-ts/src/console/billingPrepaidReservations/d1';
import {
  createD1ConsoleRuntimeSnapshotService,
  runD1ConsoleRuntimeSnapshotOutboxDispatch,
  type D1ConsoleRuntimeSnapshotOutboxDispatchResult,
} from '../../packages/sdk-server-ts/src/console/runtimeSnapshots/d1';
import type { ConsoleRuntimeSnapshotOutboxEvent } from '../../packages/sdk-server-ts/src/console/runtimeSnapshots/types';
import { createD1ConsoleSponsoredCallService } from '../../packages/sdk-server-ts/src/console/sponsoredCalls/d1';
import { D1SigningRootSecretStore } from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/SigningRootSecretStore';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../packages/sdk-server-ts/src/storage/tenantRoute';

type SqliteJsonRow = Record<string, unknown>;
type ErrorWithCode = { readonly code?: unknown };

class SqliteCliD1Database implements D1DatabaseLike {
  constructor(readonly databasePath: string) {}

  prepare(query: string): D1PreparedStatementLike {
    return new SqliteCliD1PreparedStatement(this.databasePath, query, []);
  }

  async batch<T = unknown>(
    statements: readonly D1PreparedStatementLike[],
  ): Promise<readonly T[]> {
    const sqlStatements = statements.map(sqlFromD1PreparedStatement);
    runSqlite(this.databasePath, `BEGIN IMMEDIATE; ${sqlStatements.join(' ')} COMMIT;`);
    return sqlStatements.map(buildSuccessfulD1BatchResult) as readonly T[];
  }

  async exec(query: string): Promise<unknown> {
    runSqlite(this.databasePath, query);
    return null;
  }
}

class SqliteCliD1PreparedStatement implements D1PreparedStatementLike {
  constructor(
    private readonly databasePath: string,
    private readonly query: string,
    private readonly values: readonly unknown[],
  ) {}

  bind(...values: readonly unknown[]): D1PreparedStatementLike {
    return new SqliteCliD1PreparedStatement(this.databasePath, this.query, values);
  }

  async first<T = unknown>(columnName?: string): Promise<T | null> {
    const result = await this.all<SqliteJsonRow>();
    const row = result.results?.[0] || null;
    if (!row) return null;
    if (!columnName) return row as T;
    const value = row[columnName];
    return value === undefined ? null : (value as T);
  }

  async all<T = unknown>(): Promise<D1ResultLike<T>> {
    const results = runSqliteJson(this.databasePath, this.toSql());
    return {
      success: true,
      results: results as readonly T[],
      meta: {
        rows_read: results.length,
        rows_written: 0,
      },
    };
  }

  async run<T = unknown>(): Promise<D1ResultLike<T>> {
    const sql = `${this.toSql()} SELECT changes() AS changes, last_insert_rowid() AS last_row_id;`;
    const results = runSqliteJson(this.databasePath, sql);
    const metaRow = results.at(-1) || {};
    return {
      success: true,
      results: [] as readonly T[],
      meta: {
        changes: toInteger(metaRow.changes),
        last_row_id: toInteger(metaRow.last_row_id),
        rows_written: toInteger(metaRow.changes),
      },
    };
  }

  toSql(): string {
    return interpolateSql(this.query, this.values);
  }
}

class RuntimeSnapshotOutboxRaceHarness {
  readonly dispatchedEventIds: string[] = [];
  competitorResult: D1ConsoleRuntimeSnapshotOutboxDispatchResult | null = null;

  constructor(
    private readonly database: D1DatabaseLike,
    private readonly namespace: string,
    private readonly orgId: string,
    private readonly nowMs: number,
  ) {}

  now(): Date {
    return new Date(this.nowMs);
  }

  async dispatch(event: ConsoleRuntimeSnapshotOutboxEvent): Promise<void> {
    this.dispatchedEventIds.push(event.eventId);
    this.competitorResult = await runD1ConsoleRuntimeSnapshotOutboxDispatch({
      database: this.database,
      namespace: this.namespace,
      orgIds: [this.orgId],
      limit: 1,
      ensureSchema: false,
      now: this.now.bind(this),
      workerId: 'snapshot-race-worker-b',
      claimTtlMs: 60_000,
      dispatch: this.competitorDispatch.bind(this),
    });
  }

  async competitorDispatch(event: ConsoleRuntimeSnapshotOutboxEvent): Promise<void> {
    this.dispatchedEventIds.push(`competitor:${event.eventId}`);
  }
}

function sqlFromD1PreparedStatement(statement: D1PreparedStatementLike): string {
  if (!(statement instanceof SqliteCliD1PreparedStatement)) {
    throw new Error('SQLite D1 test batch only accepts SQLite-backed statements');
  }
  return statement.toSql();
}

function buildSuccessfulD1BatchResult(): D1ResultLike {
  return {
    success: true,
    results: [],
    meta: {
      changes: 0,
      rows_written: 0,
    },
  };
}

function createTemporaryD1Database(): { readonly database: D1DatabaseLike; readonly tempDir: string } {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'seams-d1-adapter-test-'));
  return {
    database: new SqliteCliD1Database(path.join(tempDir, 'test.sqlite')),
    tempDir,
  };
}

function cleanupTemporaryD1Database(tempDir: string): void {
  rmSync(tempDir, { recursive: true, force: true });
}

function runSqlite(databasePath: string, sql: string): void {
  const result = spawnSync('sqlite3', [databasePath, sql], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status === 0) return;
  throw new Error(formatSqliteError(result.stderr, sql));
}

function runSqliteJson(databasePath: string, sql: string): readonly SqliteJsonRow[] {
  const result = spawnSync('sqlite3', ['-json', databasePath, sql], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(formatSqliteError(result.stderr, sql));
  }
  const stdout = result.stdout.trim();
  if (!stdout) return [];
  const parsed: unknown = JSON.parse(stdout);
  if (!Array.isArray(parsed)) {
    throw new Error(`sqlite3 JSON output was not an array: ${stdout}`);
  }
  return parsed.filter(isSqliteJsonRow);
}

function formatSqliteError(stderr: string, sql: string): string {
  return `sqlite3 failed: ${stderr.trim() || 'unknown error'}\nSQL: ${sql}`;
}

function isSqliteJsonRow(input: unknown): input is SqliteJsonRow {
  return Boolean(input && typeof input === 'object' && !Array.isArray(input));
}

function interpolateSql(query: string, values: readonly unknown[]): string {
  const segments = splitSqlByPlaceholders(query);
  if (segments.length - 1 !== values.length) {
    throw new Error(
      `SQL placeholder count ${segments.length - 1} did not match bound value count ${values.length}`,
    );
  }
  let sql = segments[0] || '';
  for (let i = 0; i < values.length; i += 1) {
    sql += `${sqlLiteral(values[i])}${segments[i + 1] || ''}`;
  }
  return ensureSqlStatementTerminator(sql);
}

function splitSqlByPlaceholders(query: string): readonly string[] {
  const segments: string[] = [];
  let current = '';
  let inSingleQuote = false;
  for (let i = 0; i < query.length; i += 1) {
    const char = query[i] || '';
    const next = query[i + 1] || '';
    if (char === "'" && inSingleQuote && next === "'") {
      current += "''";
      i += 1;
      continue;
    }
    if (char === "'") {
      inSingleQuote = !inSingleQuote;
      current += char;
      continue;
    }
    if (char === '?' && !inSingleQuote) {
      segments.push(current);
      current = '';
      continue;
    }
    current += char;
  }
  segments.push(current);
  return segments;
}

function ensureSqlStatementTerminator(sql: string): string {
  const trimmed = sql.trim();
  return trimmed.endsWith(';') ? trimmed : `${trimmed};`;
}

function sqlLiteral(value: unknown): string {
  if (value === null || value === undefined) return 'NULL';
  if (typeof value === 'boolean') return value ? '1' : '0';
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Uint8Array) return `X'${Buffer.from(value).toString('hex')}'`;
  if (value instanceof Date) return quoteSqlString(value.toISOString());
  return quoteSqlString(String(value));
}

function quoteSqlString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function toInteger(value: unknown): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : 0;
}

function errorCode(error: unknown): string {
  const maybeCode = isErrorWithCode(error) ? error.code : null;
  return String(maybeCode || '');
}

function isErrorWithCode(input: unknown): input is ErrorWithCode {
  return Boolean(input && typeof input === 'object' && 'code' in input);
}

test.describe('D1 adapter contracts', () => {
  test('billing reservations are trigger-atomic and idempotent', async () => {
    const temp = createTemporaryD1Database();
    try {
      const service = await createD1ConsoleBillingPrepaidReservationService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
        defaultReservationTtlMs: 60_000,
      });
      const ctx = {
        orgId: 'org-d1-billing',
        actorUserId: 'user-d1-billing',
        roles: ['admin'],
      };

      const first = await service.reserve(ctx, {
        sourceEventId: 'reservation-source-1',
        environmentId: 'env-production',
        policyId: 'policy-sponsored-gas',
        postedBalanceMinor: 500,
        estimatedSpendMinor: 300,
      });
      expect(first.summary.reservedMinor).toBe(300);
      expect(first.summary.activeReservationCount).toBe(1);

      const duplicate = await service.reserve(ctx, {
        sourceEventId: 'reservation-source-1',
        environmentId: 'env-production',
        policyId: 'policy-sponsored-gas',
        postedBalanceMinor: 500,
        estimatedSpendMinor: 450,
      });
      expect(duplicate.reservation.id).toBe(first.reservation.id);
      expect(duplicate.summary.reservedMinor).toBe(300);
      expect(duplicate.summary.activeReservationCount).toBe(1);

      let insufficientError: unknown = null;
      try {
        await service.reserve(ctx, {
          sourceEventId: 'reservation-source-2',
          environmentId: 'env-production',
          policyId: 'policy-sponsored-gas',
          postedBalanceMinor: 500,
          estimatedSpendMinor: 250,
        });
      } catch (error: unknown) {
        insufficientError = error;
      }
      expect(errorCode(insufficientError)).toBe('prepaid_balance_insufficient');
      expect(await service.getReservationBySourceEventId(ctx, 'reservation-source-2')).toBeNull();

      const summaryAfterFailure = await service.getSummary(ctx);
      expect(summaryAfterFailure.reservedMinor).toBe(300);
      expect(summaryAfterFailure.activeReservationCount).toBe(1);

      const settled = await service.settle(ctx, {
        sourceEventId: 'reservation-source-1',
        settledSpendMinor: 175,
        txOrExecutionRef: '0xsettled',
        pricingVersion: 'static:v1',
      });
      expect(settled?.reservation.status).toBe('SETTLED');
      expect(settled?.reservation.settledMinor).toBe(175);
      expect(settled?.reservation.releasedMinor).toBe(125);
      expect(settled?.summary.reservedMinor).toBe(0);
      expect(settled?.summary.activeReservationCount).toBe(0);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('sponsored call idempotency returns the original record', async () => {
    const temp = createTemporaryD1Database();
    try {
      const service = await createD1ConsoleSponsoredCallService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      });
      const ctx = {
        orgId: 'org-d1-sponsored',
        actorUserId: 'user-d1-sponsored',
        roles: ['admin'],
      };
      const request = {
        environmentId: 'env-production',
        apiKeyId: 'api-key-1',
        apiKeyKind: 'secret_key' as const,
        route: 'sponsored_evm_call_v1',
        policyId: 'policy-sponsored-gas',
        chainFamily: 'evm' as const,
        intentKind: 'evm_call' as const,
        executorKind: 'evm_eoa' as const,
        accountRef: '0x1111111111111111111111111111111111111111',
        targetRef: '0x2222222222222222222222222222222222222222',
        sponsorRef: '0x3333333333333333333333333333333333333333',
        receiptStatus: 'success' as const,
        feeUnit: 'wei' as const,
        feeAmount: '1000000000000000',
        detailsJson: '{"kind":"contract-test"}',
        estimatedSpendMinor: 100,
        settledSpendMinor: 75,
        pricingVersion: 'static:v1',
        pricingSource: 'contract-test',
        billingLedgerEntryId: 'ledger-entry-1',
        prepaidReservationId: 'reservation-1',
        charged: true,
        chargedReason: 'sponsored_gas',
        settledAt: '2026-06-27T00:00:01.000Z',
        idempotencyKey: 'sponsored-idempotency-1',
      };

      const first = await service.createRecord(ctx, request);
      const duplicate = await service.createRecord(ctx, {
        ...request,
        id: 'different-record-id',
        feeAmount: '9999999999999999',
      });
      const page = await service.listRecords(ctx, { limit: 10, lookbackDays: 1 });

      expect(duplicate.id).toBe(first.id);
      expect(duplicate.feeAmount).toBe(first.feeAmount);
      expect(page.items).toHaveLength(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('signer sealed shares are scoped by tenant, project, and environment', async () => {
    const temp = createTemporaryD1Database();
    try {
      const sharedOptions = {
        database: temp.database,
        namespace: 'd1-contracts',
        orgId: 'org-d1-signer',
        projectId: 'project-d1-signer',
        envelopeVersion: 'd1-secret-share-v1',
        lastAuditEventId: 'audit-event-1',
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      };
      const productionStore = new D1SigningRootSecretStore({
        ...sharedOptions,
        envId: 'env-production',
      });
      const developmentStore = new D1SigningRootSecretStore({
        ...sharedOptions,
        envId: 'env-development',
      });

      await productionStore.putSealedSigningRootSecretShare({
        signingRootId: 'signing-root-1',
        signingRootVersion: 'version-1',
        shareId: 1,
        sealedShare: new Uint8Array([1, 2, 3, 4]),
        storageId: 'r2://shares/signing-root-1/share-1',
        kekId: 'kek-production-1',
      });

      const productionShares = await productionStore.listSealedSigningRootSecretShares({
        signingRootId: 'signing-root-1',
        signingRootVersion: 'version-1',
      });
      const developmentShares = await developmentStore.listSealedSigningRootSecretShares({
        signingRootId: 'signing-root-1',
        signingRootVersion: 'version-1',
      });

      expect(productionShares).toHaveLength(1);
      expect(productionShares[0]?.kekId).toBe('kek-production-1');
      expect(Array.from(productionShares[0]?.sealedShare || [])).toEqual([1, 2, 3, 4]);
      expect(developmentShares).toHaveLength(0);

      let missingKekError: unknown = null;
      try {
        await productionStore.putSealedSigningRootSecretShare({
          signingRootId: 'signing-root-1',
          signingRootVersion: 'version-1',
          shareId: 2,
          sealedShare: new Uint8Array([5, 6, 7, 8]),
        });
      } catch (error: unknown) {
        missingKekError = error;
      }
      expect(String(missingKekError)).toContain(
        'kekId is required for D1 signing-root secret shares',
      );
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('runtime snapshot outbox claim lease prevents duplicate dispatch', async () => {
    const temp = createTemporaryD1Database();
    try {
      const namespace = 'd1-contracts';
      const orgId = 'org-d1-runtime-snapshot';
      const nowMs = Date.parse('2026-06-27T00:00:00.000Z');
      const harness = new RuntimeSnapshotOutboxRaceHarness(
        temp.database,
        namespace,
        orgId,
        nowMs,
      );
      const service = await createD1ConsoleRuntimeSnapshotService({
        database: temp.database,
        namespace,
        ensureSchema: true,
        now: harness.now.bind(harness),
        retentionTtlMs: 1000 * 60 * 60,
      });
      const ctx = {
        orgId,
        actorUserId: 'user-d1-runtime-snapshot',
        roles: ['admin'],
      };

      await service.publishSnapshot(ctx, {
        snapshotId: 'snapshot-race-1',
        projectId: 'project-runtime',
        environmentId: 'env-production',
        payload: {
          policy: { id: 'policy-runtime' },
          gasSponsorship: { enabled: true },
          metadata: { source: 'd1-contract-test' },
        },
      });

      const primaryResult = await runD1ConsoleRuntimeSnapshotOutboxDispatch({
        database: temp.database,
        namespace,
        orgIds: [orgId],
        limit: 1,
        ensureSchema: false,
        now: harness.now.bind(harness),
        workerId: 'snapshot-race-worker-a',
        claimTtlMs: 60_000,
        dispatch: harness.dispatch.bind(harness),
      });
      const afterDispatchResult = await runD1ConsoleRuntimeSnapshotOutboxDispatch({
        database: temp.database,
        namespace,
        orgIds: [orgId],
        limit: 1,
        ensureSchema: false,
        now: harness.now.bind(harness),
        workerId: 'snapshot-race-worker-c',
        claimTtlMs: 60_000,
        dispatch: harness.competitorDispatch.bind(harness),
      });

      expect(primaryResult.dispatchedCount).toBe(1);
      expect(primaryResult.failureCount).toBe(0);
      expect(harness.competitorResult?.dispatchedCount).toBe(0);
      expect(harness.competitorResult?.failureCount).toBe(0);
      expect(afterDispatchResult.dispatchedCount).toBe(0);
      expect(harness.dispatchedEventIds).toHaveLength(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });
});
