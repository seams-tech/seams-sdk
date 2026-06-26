import { secureRandomBase36 } from '@shared/utils/secureRandomId';
import { normalizeLogger, type Logger, type NormalizedLogger } from '../../core/logger';
import type { D1DatabaseLike, D1ResultLike } from '../../storage/tenantRoute';
import {
  computeConsoleRuntimeSnapshotChecksum,
  type ConsoleRuntimeSnapshotContext,
  type ConsoleRuntimeSnapshotService,
} from './service';
import type {
  ConsoleRuntimeSnapshot,
  ConsoleRuntimeSnapshotOutboxDispatchResult,
  ConsoleRuntimeSnapshotOutboxEvent,
  ConsoleRuntimeSnapshotPayload,
  GetLatestConsoleRuntimeSnapshotRequest,
  ListConsoleRuntimeSnapshotsRequest,
  PublishConsoleRuntimeSnapshotRequest,
} from './types';

type D1Row = Record<string, unknown>;

const DEFAULT_RETENTION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const DEFAULT_RETENTION_PRUNE_INTERVAL_MS = 1000 * 60 * 5;
const DEFAULT_RETENTION_BATCH_SIZE = 1_000;
const DEFAULT_OUTBOX_CLAIM_TTL_MS = 1000 * 60 * 5;
const DEFAULT_OUTBOX_RETRY_BACKOFF_MS = 1000 * 60;
const DEFAULT_OUTBOX_MAX_ATTEMPTS = 5;
const MAX_LIST_LIMIT = 100;
const MAX_OUTBOX_DISPATCH_LIMIT = 500;
const MAX_PUBLISH_ATTEMPTS = 5;

export const CONSOLE_RUNTIME_SNAPSHOT_D1_RUNTIME = Symbol('consoleRuntimeSnapshotD1Runtime');

export interface ConsoleRuntimeSnapshotD1Runtime {
  database: D1DatabaseLike;
  namespace: string;
  now: () => Date;
}

export type ConsoleRuntimeSnapshotD1Service = ConsoleRuntimeSnapshotService & {
  [CONSOLE_RUNTIME_SNAPSHOT_D1_RUNTIME]: ConsoleRuntimeSnapshotD1Runtime;
};

export interface D1ConsoleRuntimeSnapshotSchemaOptions {
  database: D1DatabaseLike;
}

export interface D1ConsoleRuntimeSnapshotServiceOptions {
  database: D1DatabaseLike;
  namespace?: string;
  ensureSchema?: boolean;
  now?: () => Date;
  logger?: Logger | null;
  retentionTtlMs?: number;
  retentionPruneIntervalMs?: number;
  retentionBatchSize?: number;
}

export interface D1ConsoleRuntimeSnapshotOutboxDispatchOptions {
  database: D1DatabaseLike;
  namespace?: string;
  orgIds: string[];
  limit?: number;
  ensureSchema?: boolean;
  now?: () => Date;
  logger?: Logger | null;
  dispatch?: (event: ConsoleRuntimeSnapshotOutboxEvent) => Promise<void> | void;
  workerId?: string;
  claimTtlMs?: number;
  retryBackoffMs?: number;
  maxAttempts?: number;
}

export type D1ConsoleRuntimeSnapshotOutboxDispatchResult =
  ConsoleRuntimeSnapshotOutboxDispatchResult;

export interface D1ConsoleRuntimeSnapshotRetentionCleanupOptions
  extends D1ConsoleRuntimeSnapshotSchemaOptions {
  namespace?: string;
  orgId: string;
  ensureSchema?: boolean;
  now?: () => Date;
  ttlMs?: number;
  batchSize?: number;
}

export interface D1ConsoleRuntimeSnapshotRetentionCleanupResult {
  cutoffMs: number;
  deletedOutbox: number;
  deletedSnapshots: number;
}

interface D1ConsoleRuntimeSnapshotServiceState {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
  readonly logger: NormalizedLogger;
  readonly retentionTtlMs: number;
  readonly retentionPruneIntervalMs: number;
  readonly retentionBatchSize: number;
  readonly nextRetentionRunAtByOrg: Map<string, number>;
}

interface D1ClaimedOutboxEvent {
  readonly event: ConsoleRuntimeSnapshotOutboxEvent;
  readonly attemptCount: number;
}

interface D1OutboxDispatchState {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgIds: readonly string[];
  readonly limit: number;
  readonly now: () => Date;
  readonly logger: NormalizedLogger;
  readonly dispatch: (event: ConsoleRuntimeSnapshotOutboxEvent) => Promise<void> | void;
  readonly workerId: string;
  readonly claimTtlMs: number;
  readonly retryBackoffMs: number;
  readonly maxAttempts: number;
}

export const CONSOLE_RUNTIME_SNAPSHOT_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS console_runtime_snapshots (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL DEFAULT '',
      environment_id TEXT NOT NULL,
      snapshot_id TEXT NOT NULL,
      version INTEGER NOT NULL,
      effective_at_ms INTEGER NOT NULL,
      checksum TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      created_by TEXT NOT NULL,
      PRIMARY KEY (namespace, org_id, snapshot_id),
      UNIQUE (namespace, org_id, project_id, environment_id, version),
      CHECK (version >= 1),
      CHECK (length(payload_json) > 0)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS console_runtime_snapshots_scope_version_idx
      ON console_runtime_snapshots (
        namespace,
        org_id,
        project_id,
        environment_id,
        version DESC,
        created_at_ms DESC
      )
  `,
  `
    CREATE INDEX IF NOT EXISTS console_runtime_snapshots_env_version_idx
      ON console_runtime_snapshots (
        namespace,
        org_id,
        environment_id,
        version DESC,
        created_at_ms DESC
      )
  `,
  `
    CREATE TABLE IF NOT EXISTS console_runtime_snapshot_outbox (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL DEFAULT '',
      environment_id TEXT NOT NULL,
      event_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      snapshot_id TEXT NOT NULL,
      snapshot_version INTEGER NOT NULL,
      payload_json TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'PENDING',
      attempt_count INTEGER NOT NULL DEFAULT 0,
      available_at_ms INTEGER NOT NULL,
      claimed_by TEXT,
      claim_expires_at_ms INTEGER,
      last_error TEXT,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      dispatched_at_ms INTEGER,
      PRIMARY KEY (namespace, org_id, event_id),
      UNIQUE (namespace, org_id, snapshot_id, snapshot_version, event_type),
      CHECK (event_type IN ('RUNTIME_SNAPSHOT_PUBLISHED_V1')),
      CHECK (status IN ('PENDING', 'DISPATCHED', 'DEAD_LETTER')),
      CHECK (snapshot_version >= 1),
      CHECK (attempt_count >= 0),
      CHECK (length(payload_json) > 0)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS console_runtime_snapshot_outbox_visible_idx
      ON console_runtime_snapshot_outbox (
        namespace,
        org_id,
        status,
        available_at_ms ASC,
        created_at_ms ASC,
        event_id ASC
      )
  `,
  `
    CREATE INDEX IF NOT EXISTS console_runtime_snapshot_outbox_claim_idx
      ON console_runtime_snapshot_outbox (
        namespace,
        org_id,
        claimed_by,
        claim_expires_at_ms
      )
  `,
] as const);

export async function ensureConsoleRuntimeSnapshotsD1Schema(
  options: D1ConsoleRuntimeSnapshotSchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_RUNTIME_SNAPSHOT_D1_SCHEMA_SQL) {
    await options.database.exec(statement);
  }
}

export function getConsoleRuntimeSnapshotD1Runtime(
  service: ConsoleRuntimeSnapshotService | null | undefined,
): ConsoleRuntimeSnapshotD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (
    (service as Partial<ConsoleRuntimeSnapshotD1Service>)[
      CONSOLE_RUNTIME_SNAPSHOT_D1_RUNTIME
    ] || null
  );
}

function defaultNow(): Date {
  return new Date();
}

function nowMs(now: Date): number {
  return now.getTime();
}

function toIso(ms: number): string {
  return new Date(ms).toISOString();
}

function toNumber(value: unknown, fallback = 0): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizeNamespace(namespace: string | undefined): string {
  const normalized = String(namespace || 'default').trim();
  return normalized || 'default';
}

function normalizeProjectId(projectId: string | undefined | null): string {
  const normalized = String(projectId || '').trim();
  return normalized;
}

function toNullableProjectId(projectId: unknown): string | null {
  const normalized = String(projectId || '').trim();
  return normalized || null;
}

function normalizeRequiredString(raw: unknown, field: string): string {
  const normalized = String(raw || '').trim();
  if (!normalized) {
    throw new Error(`Missing ${field} for D1 console runtime snapshots`);
  }
  return normalized;
}

function normalizePositiveInteger(raw: unknown, fallback: number, max?: number): number {
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  const value = Math.floor(parsed);
  return max ? Math.min(value, max) : value;
}

function normalizeOrgIds(orgIds: readonly string[]): string[] {
  return Array.from(
    new Set(orgIds.map((orgId) => String(orgId || '').trim()).filter(Boolean)),
  );
}

function runChanges(result: D1ResultLike): number {
  const changes = Number(result.meta?.changes);
  return Number.isFinite(changes) ? Math.max(0, Math.trunc(changes)) : 0;
}

function parseJsonObject(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return raw as Record<string, unknown>;
  }
  if (typeof raw === 'string') {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      return {};
    }
  }
  return {};
}

function cloneObject(input: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(input || {})) as Record<string, unknown>;
}

function clonePayload(input: ConsoleRuntimeSnapshotPayload): ConsoleRuntimeSnapshotPayload {
  return {
    policy: cloneObject(input.policy),
    gasSponsorship: cloneObject(input.gasSponsorship),
    ...(input.metadata ? { metadata: cloneObject(input.metadata) } : {}),
  };
}

function parsePayload(raw: unknown): ConsoleRuntimeSnapshotPayload {
  const row = parseJsonObject(raw);
  const metadataRaw = row.metadata;
  return {
    policy: parseJsonObject(row.policy),
    gasSponsorship: parseJsonObject(row.gasSponsorship),
    ...(metadataRaw && typeof metadataRaw === 'object' && !Array.isArray(metadataRaw)
      ? { metadata: parseJsonObject(metadataRaw) }
      : {}),
  };
}

function parseSnapshotRow(row: D1Row): ConsoleRuntimeSnapshot {
  const effectiveAtMs = toNumber(row.effective_at_ms, Date.now());
  const createdAtMs = toNumber(row.created_at_ms, Date.now());
  return {
    orgId: String(row.org_id || ''),
    projectId: toNullableProjectId(row.project_id),
    environmentId: String(row.environment_id || ''),
    snapshotId: String(row.snapshot_id || ''),
    version: Math.max(1, Math.floor(toNumber(row.version, 1))),
    effectiveAt: toIso(effectiveAtMs),
    checksum: String(row.checksum || ''),
    payload: clonePayload(parsePayload(row.payload_json)),
    createdAt: toIso(createdAtMs),
    createdBy: String(row.created_by || ''),
  };
}

function parseOutboxEventRow(row: D1Row): ConsoleRuntimeSnapshotOutboxEvent {
  const createdAtMs = toNumber(row.created_at_ms, Date.now());
  const dispatchedAtMs = row.dispatched_at_ms == null ? null : toNumber(row.dispatched_at_ms, 0);
  return {
    namespace: String(row.namespace || ''),
    orgId: String(row.org_id || ''),
    projectId: toNullableProjectId(row.project_id),
    environmentId: String(row.environment_id || ''),
    eventId: String(row.event_id || ''),
    eventType: 'RUNTIME_SNAPSHOT_PUBLISHED_V1',
    snapshotId: String(row.snapshot_id || ''),
    snapshotVersion: Math.max(1, Math.floor(toNumber(row.snapshot_version, 1))),
    payload: parseJsonObject(row.payload_json),
    createdAt: toIso(createdAtMs),
    dispatchedAt: dispatchedAtMs && dispatchedAtMs > 0 ? toIso(dispatchedAtMs) : null,
  };
}

function parseClaimedOutboxEventRow(row: D1Row): D1ClaimedOutboxEvent {
  return {
    event: parseOutboxEventRow(row),
    attemptCount: Math.max(0, Math.floor(toNumber(row.attempt_count, 0))),
  };
}

function makeSnapshotId(now: Date): string {
  return `runtime_snapshot_${now.getTime().toString(36)}_${secureRandomBase36(8, 'console IDs')}`;
}

function makeOutboxEventId(now: Date): string {
  return `runtime_snapshot_event_${now.getTime().toString(36)}_${secureRandomBase36(8, 'console IDs')}`;
}

function makeWorkerId(now: Date): string {
  return `runtime_snapshot_outbox_${now.getTime().toString(36)}_${secureRandomBase36(8, 'console IDs')}`;
}

function makeClaimToken(workerId: string, now: Date): string {
  return `${workerId}:${now.getTime().toString(36)}:${secureRandomBase36(8, 'console IDs')}`;
}

function readEffectiveAtMs(input: string | undefined, fallback: Date): number {
  if (!input) return nowMs(fallback);
  const asDate = new Date(input);
  if (!Number.isFinite(asDate.getTime())) return nowMs(fallback);
  return asDate.getTime();
}

function isD1ConstraintError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes('UNIQUE constraint failed') || message.includes('constraint failed');
}

function buildOutboxPayload(snapshot: ConsoleRuntimeSnapshot): Record<string, unknown> {
  return {
    eventType: 'runtime_snapshot.published.v1',
    snapshot: {
      orgId: snapshot.orgId,
      projectId: snapshot.projectId,
      environmentId: snapshot.environmentId,
      snapshotId: snapshot.snapshotId,
      version: snapshot.version,
      effectiveAt: snapshot.effectiveAt,
      checksum: snapshot.checksum,
      createdAt: snapshot.createdAt,
      createdBy: snapshot.createdBy,
    },
  };
}

async function queryOne(
  database: D1DatabaseLike,
  text: string,
  values: readonly unknown[],
): Promise<D1Row | null> {
  return await database.prepare(text).bind(...values).first<D1Row>();
}

async function queryAll(
  database: D1DatabaseLike,
  text: string,
  values: readonly unknown[],
): Promise<readonly D1Row[]> {
  const result = await database.prepare(text).bind(...values).all<D1Row>();
  return result.results || [];
}

async function readNextSnapshotVersion(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  projectId: string;
  environmentId: string;
}): Promise<number> {
  const row = await queryOne(
    input.database,
    `SELECT COALESCE(MAX(version), 0) + 1 AS next_version
       FROM console_runtime_snapshots
      WHERE namespace = ?
        AND org_id = ?
        AND project_id = ?
        AND environment_id = ?`,
    [input.namespace, input.orgId, input.projectId, input.environmentId],
  );
  return Math.max(1, Math.floor(toNumber(row?.next_version, 1)));
}

async function loadSnapshotById(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  snapshotId: string;
}): Promise<ConsoleRuntimeSnapshot | null> {
  const row = await queryOne(
    input.database,
    `SELECT *
       FROM console_runtime_snapshots
      WHERE namespace = ?
        AND org_id = ?
        AND snapshot_id = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.snapshotId],
  );
  return row ? parseSnapshotRow(row) : null;
}

async function listD1RuntimeSnapshots(
  state: D1ConsoleRuntimeSnapshotServiceState,
  ctx: ConsoleRuntimeSnapshotContext,
  request: ListConsoleRuntimeSnapshotsRequest,
): Promise<ConsoleRuntimeSnapshot[]> {
  const projectId = normalizeProjectId(request.projectId);
  const environmentId = normalizeRequiredString(request.environmentId, 'environmentId');
  const limit = normalizePositiveInteger(request.limit, 20, MAX_LIST_LIMIT);
  const values: unknown[] = [state.namespace, ctx.orgId, environmentId];
  let sql = `SELECT *
       FROM console_runtime_snapshots
      WHERE namespace = ?
        AND org_id = ?
        AND environment_id = ?`;
  if (projectId) {
    values.push(projectId);
    sql += `
        AND project_id = ?`;
  }
  values.push(limit);
  sql += `
      ORDER BY version DESC, created_at_ms DESC
      LIMIT ?`;
  const rows = await queryAll(state.database, sql, values);
  return rows.map(parseSnapshotRow);
}

async function getLatestD1RuntimeSnapshot(
  state: D1ConsoleRuntimeSnapshotServiceState,
  ctx: ConsoleRuntimeSnapshotContext,
  request: GetLatestConsoleRuntimeSnapshotRequest,
): Promise<ConsoleRuntimeSnapshot | null> {
  const rows = await listD1RuntimeSnapshots(state, ctx, {
    environmentId: request.environmentId,
    ...(request.projectId ? { projectId: request.projectId } : {}),
    limit: 1,
  });
  return rows[0] || null;
}

async function insertD1RuntimeSnapshotOnce(input: {
  state: D1ConsoleRuntimeSnapshotServiceState;
  ctx: ConsoleRuntimeSnapshotContext;
  request: PublishConsoleRuntimeSnapshotRequest;
  now: Date;
  snapshotId: string;
  projectId: string;
  environmentId: string;
  payload: ConsoleRuntimeSnapshotPayload;
}): Promise<ConsoleRuntimeSnapshot> {
  const createdAtMs = nowMs(input.now);
  const effectiveAtMs = readEffectiveAtMs(input.request.effectiveAt, input.now);
  const effectiveAt = toIso(effectiveAtMs);
  const version = await readNextSnapshotVersion({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    projectId: input.projectId,
    environmentId: input.environmentId,
  });
  const checksum = computeConsoleRuntimeSnapshotChecksum({
    orgId: input.ctx.orgId,
    projectId: toNullableProjectId(input.projectId),
    environmentId: input.environmentId,
    snapshotId: input.snapshotId,
    version,
    effectiveAt,
    payload: input.payload,
  });
  const snapshot: ConsoleRuntimeSnapshot = {
    orgId: input.ctx.orgId,
    projectId: toNullableProjectId(input.projectId),
    environmentId: input.environmentId,
    snapshotId: input.snapshotId,
    version,
    effectiveAt,
    checksum,
    payload: clonePayload(input.payload),
    createdAt: toIso(createdAtMs),
    createdBy: input.ctx.actorUserId,
  };
  const outboxPayload = buildOutboxPayload(snapshot);
  await input.state.database.batch([
    input.state.database
      .prepare(
        `INSERT INTO console_runtime_snapshots
          (
            namespace,
            org_id,
            project_id,
            environment_id,
            snapshot_id,
            version,
            effective_at_ms,
            checksum,
            payload_json,
            created_at_ms,
            created_by
          )
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        input.state.namespace,
        input.ctx.orgId,
        input.projectId,
        input.environmentId,
        input.snapshotId,
        version,
        effectiveAtMs,
        checksum,
        JSON.stringify(input.payload),
        createdAtMs,
        input.ctx.actorUserId,
      ),
    input.state.database
      .prepare(
        `INSERT INTO console_runtime_snapshot_outbox
          (
            namespace,
            org_id,
            project_id,
            environment_id,
            event_id,
            event_type,
            snapshot_id,
            snapshot_version,
            payload_json,
            status,
            attempt_count,
            available_at_ms,
            claimed_by,
            claim_expires_at_ms,
            last_error,
            created_at_ms,
            updated_at_ms,
            dispatched_at_ms
          )
         VALUES (?, ?, ?, ?, ?, 'RUNTIME_SNAPSHOT_PUBLISHED_V1', ?, ?, ?, 'PENDING', 0, ?, NULL, NULL, NULL, ?, ?, NULL)`,
      )
      .bind(
        input.state.namespace,
        input.ctx.orgId,
        input.projectId,
        input.environmentId,
        makeOutboxEventId(input.now),
        input.snapshotId,
        version,
        JSON.stringify(outboxPayload),
        createdAtMs,
        createdAtMs,
        createdAtMs,
      ),
  ]);
  const inserted = await loadSnapshotById({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    snapshotId: input.snapshotId,
  });
  if (!inserted) {
    throw new Error('Failed to insert D1 runtime snapshot');
  }
  return inserted;
}

async function maybeRunD1RuntimeSnapshotRetentionForTenant(input: {
  state: D1ConsoleRuntimeSnapshotServiceState;
  orgId: string;
  nowValueMs: number;
}): Promise<D1ConsoleRuntimeSnapshotRetentionCleanupResult | null> {
  if (input.state.retentionTtlMs <= 0) return null;
  const nextRunAt = Number(input.state.nextRetentionRunAtByOrg.get(input.orgId) || 0);
  if (input.nowValueMs < nextRunAt) return null;
  const result = await pruneD1ConsoleRuntimeSnapshotRetentionForTenant({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.orgId,
    cutoffMs: Math.max(0, input.nowValueMs - input.state.retentionTtlMs),
    batchSize: input.state.retentionBatchSize,
  });
  input.state.nextRetentionRunAtByOrg.set(
    input.orgId,
    input.nowValueMs + input.state.retentionPruneIntervalMs,
  );
  return result;
}

async function publishD1RuntimeSnapshot(
  state: D1ConsoleRuntimeSnapshotServiceState,
  ctx: ConsoleRuntimeSnapshotContext,
  request: PublishConsoleRuntimeSnapshotRequest,
): Promise<ConsoleRuntimeSnapshot> {
  const currentNow = state.now();
  const projectId = normalizeProjectId(request.projectId);
  const environmentId = normalizeRequiredString(request.environmentId, 'environmentId');
  const snapshotId = String(request.snapshotId || makeSnapshotId(currentNow)).trim();
  const payload = clonePayload(request.payload);
  let lastError: unknown = null;
  for (let attempt = 0; attempt < MAX_PUBLISH_ATTEMPTS; attempt += 1) {
    try {
      const inserted = await insertD1RuntimeSnapshotOnce({
        state,
        ctx,
        request,
        now: currentNow,
        snapshotId,
        projectId,
        environmentId,
        payload,
      });
      try {
        await maybeRunD1RuntimeSnapshotRetentionForTenant({
          state,
          orgId: ctx.orgId,
          nowValueMs: nowMs(currentNow),
        });
      } catch (error: unknown) {
        state.logger.warn('[console-runtime-snapshots][d1] retention cleanup failed', {
          namespace: state.namespace,
          orgId: ctx.orgId,
          message: error instanceof Error ? error.message : String(error),
        });
      }
      return inserted;
    } catch (error: unknown) {
      lastError = error;
      if (!isD1ConstraintError(error)) throw error;
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

async function pruneD1ConsoleRuntimeSnapshotRetentionForTenant(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  cutoffMs: number;
  batchSize: number;
}): Promise<D1ConsoleRuntimeSnapshotRetentionCleanupResult> {
  const batchSize = normalizePositiveInteger(input.batchSize, DEFAULT_RETENTION_BATCH_SIZE);
  const deleteOutbox = await input.database
    .prepare(
      `DELETE FROM console_runtime_snapshot_outbox
        WHERE namespace = ?
          AND org_id = ?
          AND event_id IN (
            SELECT event_id
              FROM console_runtime_snapshot_outbox
             WHERE namespace = ?
               AND org_id = ?
               AND created_at_ms < ?
             ORDER BY created_at_ms ASC, event_id ASC
             LIMIT ?
          )`,
    )
    .bind(input.namespace, input.orgId, input.namespace, input.orgId, input.cutoffMs, batchSize)
    .run();
  const deleteSnapshots = await input.database
    .prepare(
      `DELETE FROM console_runtime_snapshots
        WHERE namespace = ?
          AND org_id = ?
          AND snapshot_id IN (
            SELECT snapshot.snapshot_id
              FROM console_runtime_snapshots snapshot
             WHERE snapshot.namespace = ?
               AND snapshot.org_id = ?
               AND snapshot.created_at_ms < ?
               AND EXISTS (
                 SELECT 1
                   FROM console_runtime_snapshots newer
                  WHERE newer.namespace = snapshot.namespace
                    AND newer.org_id = snapshot.org_id
                    AND newer.project_id = snapshot.project_id
                    AND newer.environment_id = snapshot.environment_id
                    AND newer.version > snapshot.version
               )
             ORDER BY snapshot.created_at_ms ASC, snapshot.snapshot_id ASC
             LIMIT ?
          )`,
    )
    .bind(input.namespace, input.orgId, input.namespace, input.orgId, input.cutoffMs, batchSize)
    .run();
  return {
    cutoffMs: input.cutoffMs,
    deletedOutbox: runChanges(deleteOutbox),
    deletedSnapshots: runChanges(deleteSnapshots),
  };
}

async function claimD1OutboxEventsForOrg(input: {
  state: D1OutboxDispatchState;
  orgId: string;
  remaining: number;
  claimToken: string;
  nowValueMs: number;
}): Promise<D1ClaimedOutboxEvent[]> {
  if (input.remaining <= 0) return [];
  const claimExpiresAtMs = input.nowValueMs + input.state.claimTtlMs;
  const rows = await queryAll(
    input.state.database,
    `SELECT event_id
       FROM console_runtime_snapshot_outbox
      WHERE namespace = ?
        AND org_id = ?
        AND status = 'PENDING'
        AND available_at_ms <= ?
        AND (claimed_by IS NULL OR claim_expires_at_ms <= ?)
      ORDER BY created_at_ms ASC, event_id ASC
      LIMIT ?`,
    [input.state.namespace, input.orgId, input.nowValueMs, input.nowValueMs, input.remaining],
  );
  const claimed: D1ClaimedOutboxEvent[] = [];
  for (const row of rows) {
    const eventId = String(row.event_id || '').trim();
    if (!eventId) continue;
    const update = await input.state.database
      .prepare(
        `UPDATE console_runtime_snapshot_outbox
            SET claimed_by = ?,
                claim_expires_at_ms = ?,
                attempt_count = attempt_count + 1,
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND event_id = ?
            AND status = 'PENDING'
            AND available_at_ms <= ?
            AND (claimed_by IS NULL OR claim_expires_at_ms <= ?)`,
      )
      .bind(
        input.claimToken,
        claimExpiresAtMs,
        input.nowValueMs,
        input.state.namespace,
        input.orgId,
        eventId,
        input.nowValueMs,
        input.nowValueMs,
      )
      .run();
    if (runChanges(update) !== 1) continue;
    const claimedRow = await queryOne(
      input.state.database,
      `SELECT *
         FROM console_runtime_snapshot_outbox
        WHERE namespace = ?
          AND org_id = ?
          AND event_id = ?
          AND claimed_by = ?
          AND claim_expires_at_ms = ?
        LIMIT 1`,
      [input.state.namespace, input.orgId, eventId, input.claimToken, claimExpiresAtMs],
    );
    if (claimedRow) {
      claimed.push(parseClaimedOutboxEventRow(claimedRow));
    }
  }
  return claimed;
}

async function markD1OutboxDispatched(input: {
  state: D1OutboxDispatchState;
  event: ConsoleRuntimeSnapshotOutboxEvent;
  claimToken: string;
  nowValueMs: number;
}): Promise<boolean> {
  const update = await input.state.database
    .prepare(
      `UPDATE console_runtime_snapshot_outbox
          SET status = 'DISPATCHED',
              dispatched_at_ms = ?,
              claimed_by = NULL,
              claim_expires_at_ms = NULL,
              last_error = NULL,
              updated_at_ms = ?
        WHERE namespace = ?
          AND org_id = ?
          AND event_id = ?
          AND claimed_by = ?
          AND status = 'PENDING'`,
    )
    .bind(
      input.nowValueMs,
      input.nowValueMs,
      input.state.namespace,
      input.event.orgId,
      input.event.eventId,
      input.claimToken,
    )
    .run();
  return runChanges(update) === 1;
}

async function markD1OutboxDispatchFailure(input: {
  state: D1OutboxDispatchState;
  claimed: D1ClaimedOutboxEvent;
  claimToken: string;
  nowValueMs: number;
  message: string;
}): Promise<void> {
  const nextStatus = input.claimed.attemptCount >= input.state.maxAttempts ? 'DEAD_LETTER' : 'PENDING';
  const availableAtMs =
    nextStatus === 'PENDING' ? input.nowValueMs + input.state.retryBackoffMs : input.nowValueMs;
  await input.state.database
    .prepare(
      `UPDATE console_runtime_snapshot_outbox
          SET status = ?,
              available_at_ms = ?,
              claimed_by = NULL,
              claim_expires_at_ms = NULL,
              last_error = ?,
              updated_at_ms = ?
        WHERE namespace = ?
          AND org_id = ?
          AND event_id = ?
          AND claimed_by = ?
          AND status = 'PENDING'`,
    )
    .bind(
      nextStatus,
      availableAtMs,
      input.message,
      input.nowValueMs,
      input.state.namespace,
      input.claimed.event.orgId,
      input.claimed.event.eventId,
      input.claimToken,
    )
    .run();
}

async function dispatchD1ClaimedOutboxEvents(input: {
  state: D1OutboxDispatchState;
  claimed: readonly D1ClaimedOutboxEvent[];
  claimToken: string;
  failures: ConsoleRuntimeSnapshotOutboxDispatchResult['failures'];
}): Promise<number> {
  let dispatched = 0;
  for (const claimed of input.claimed) {
    try {
      await input.state.dispatch(claimed.event);
      const marked = await markD1OutboxDispatched({
        state: input.state,
        event: claimed.event,
        claimToken: input.claimToken,
        nowValueMs: nowMs(input.state.now()),
      });
      if (marked) dispatched += 1;
    } catch (error: unknown) {
      const code = 'dispatch_failed';
      const message = error instanceof Error ? error.message : String(error);
      input.failures.push({
        orgId: claimed.event.orgId,
        eventId: claimed.event.eventId,
        code,
        message,
      });
      await markD1OutboxDispatchFailure({
        state: input.state,
        claimed,
        claimToken: input.claimToken,
        nowValueMs: nowMs(input.state.now()),
        message,
      });
      input.state.logger.error('[console-runtime-snapshots][d1-outbox] dispatch failed', {
        namespace: input.state.namespace,
        orgId: claimed.event.orgId,
        eventId: claimed.event.eventId,
        code,
        message,
      });
    }
  }
  return dispatched;
}

async function dispatchD1OutboxForOrg(input: {
  state: D1OutboxDispatchState;
  orgId: string;
  remaining: number;
  failures: ConsoleRuntimeSnapshotOutboxDispatchResult['failures'];
}): Promise<number> {
  const now = input.state.now();
  const claimToken = makeClaimToken(input.state.workerId, now);
  const claimed = await claimD1OutboxEventsForOrg({
    state: input.state,
    orgId: input.orgId,
    remaining: input.remaining,
    claimToken,
    nowValueMs: nowMs(now),
  });
  return await dispatchD1ClaimedOutboxEvents({
    state: input.state,
    claimed,
    claimToken,
    failures: input.failures,
  });
}

function createD1OutboxDispatchState(
  options: D1ConsoleRuntimeSnapshotOutboxDispatchOptions,
): D1OutboxDispatchState {
  const orgIds = normalizeOrgIds(options.orgIds);
  if (orgIds.length === 0) {
    throw new Error('Runtime snapshot D1 outbox dispatch requires at least one orgId');
  }
  if (typeof options.dispatch !== 'function') {
    throw new Error('Runtime snapshot D1 outbox dispatch requires a dispatch callback');
  }
  const now = options.now || defaultNow;
  return {
    database: options.database,
    namespace: normalizeNamespace(options.namespace),
    orgIds,
    limit: normalizePositiveInteger(options.limit, 100, MAX_OUTBOX_DISPATCH_LIMIT),
    now,
    logger: normalizeLogger(options.logger),
    dispatch: options.dispatch,
    workerId: String(options.workerId || makeWorkerId(now())).trim(),
    claimTtlMs: normalizePositiveInteger(options.claimTtlMs, DEFAULT_OUTBOX_CLAIM_TTL_MS),
    retryBackoffMs: normalizePositiveInteger(
      options.retryBackoffMs,
      DEFAULT_OUTBOX_RETRY_BACKOFF_MS,
    ),
    maxAttempts: normalizePositiveInteger(options.maxAttempts, DEFAULT_OUTBOX_MAX_ATTEMPTS),
  };
}

export async function runD1ConsoleRuntimeSnapshotRetentionCleanup(
  options: D1ConsoleRuntimeSnapshotRetentionCleanupOptions,
): Promise<D1ConsoleRuntimeSnapshotRetentionCleanupResult> {
  if (options.ensureSchema) {
    await ensureConsoleRuntimeSnapshotsD1Schema({ database: options.database });
  }
  const now = options.now || defaultNow;
  const ttlMs = normalizePositiveInteger(options.ttlMs, DEFAULT_RETENTION_TTL_MS);
  const batchSize = normalizePositiveInteger(options.batchSize, DEFAULT_RETENTION_BATCH_SIZE);
  return await pruneD1ConsoleRuntimeSnapshotRetentionForTenant({
    database: options.database,
    namespace: normalizeNamespace(options.namespace),
    orgId: normalizeRequiredString(options.orgId, 'orgId'),
    cutoffMs: Math.max(0, nowMs(now()) - ttlMs),
    batchSize,
  });
}

export async function runD1ConsoleRuntimeSnapshotOutboxDispatch(
  options: D1ConsoleRuntimeSnapshotOutboxDispatchOptions,
): Promise<D1ConsoleRuntimeSnapshotOutboxDispatchResult> {
  if (options.ensureSchema) {
    await ensureConsoleRuntimeSnapshotsD1Schema({ database: options.database });
  }
  const state = createD1OutboxDispatchState(options);
  const failures: ConsoleRuntimeSnapshotOutboxDispatchResult['failures'] = [];
  let dispatchedCount = 0;
  for (const orgId of state.orgIds) {
    if (dispatchedCount >= state.limit) break;
    const remaining = state.limit - dispatchedCount;
    dispatchedCount += await dispatchD1OutboxForOrg({
      state,
      orgId,
      remaining,
      failures,
    });
  }
  return {
    namespace: state.namespace,
    orgCount: state.orgIds.length,
    dispatchedCount,
    failureCount: failures.length,
    failures,
  };
}

class D1ConsoleRuntimeSnapshotServiceImpl implements ConsoleRuntimeSnapshotD1Service {
  readonly [CONSOLE_RUNTIME_SNAPSHOT_D1_RUNTIME]: ConsoleRuntimeSnapshotD1Runtime;

  private readonly state: D1ConsoleRuntimeSnapshotServiceState;

  constructor(state: D1ConsoleRuntimeSnapshotServiceState) {
    this.state = state;
    this[CONSOLE_RUNTIME_SNAPSHOT_D1_RUNTIME] = {
      database: state.database,
      namespace: state.namespace,
      now: state.now,
    };
  }

  async listSnapshots(
    ctx: ConsoleRuntimeSnapshotContext,
    request: ListConsoleRuntimeSnapshotsRequest,
  ): Promise<ConsoleRuntimeSnapshot[]> {
    return await listD1RuntimeSnapshots(this.state, ctx, request);
  }

  async getLatestSnapshot(
    ctx: ConsoleRuntimeSnapshotContext,
    request: GetLatestConsoleRuntimeSnapshotRequest,
  ): Promise<ConsoleRuntimeSnapshot | null> {
    return await getLatestD1RuntimeSnapshot(this.state, ctx, request);
  }

  async publishSnapshot(
    ctx: ConsoleRuntimeSnapshotContext,
    request: PublishConsoleRuntimeSnapshotRequest,
  ): Promise<ConsoleRuntimeSnapshot> {
    return await publishD1RuntimeSnapshot(this.state, ctx, request);
  }
}

export async function createD1ConsoleRuntimeSnapshotService(
  options: D1ConsoleRuntimeSnapshotServiceOptions,
): Promise<ConsoleRuntimeSnapshotService> {
  if (options.ensureSchema) {
    await ensureConsoleRuntimeSnapshotsD1Schema({ database: options.database });
  }
  const state: D1ConsoleRuntimeSnapshotServiceState = {
    database: options.database,
    namespace: normalizeNamespace(options.namespace),
    now: options.now || defaultNow,
    logger: normalizeLogger(options.logger),
    retentionTtlMs: normalizePositiveInteger(options.retentionTtlMs, DEFAULT_RETENTION_TTL_MS),
    retentionPruneIntervalMs: normalizePositiveInteger(
      options.retentionPruneIntervalMs,
      DEFAULT_RETENTION_PRUNE_INTERVAL_MS,
    ),
    retentionBatchSize: normalizePositiveInteger(
      options.retentionBatchSize,
      DEFAULT_RETENTION_BATCH_SIZE,
    ),
    nextRetentionRunAtByOrg: new Map<string, number>(),
  };
  return new D1ConsoleRuntimeSnapshotServiceImpl(state);
}
