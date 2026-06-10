export interface PostgresConsoleRuntimeSnapshotRetentionCleanupResult {
  cutoffMs: number;
  deletedOutbox: number;
  deletedSnapshots: number;
}

export interface ConsoleRuntimeSnapshotRetentionQueryable {
  query: (
    text: string,
    values?: unknown[],
  ) => Promise<{ rowCount?: number | null | undefined }>;
}

export async function pruneConsoleRuntimeSnapshotRetentionForTenant(
  q: ConsoleRuntimeSnapshotRetentionQueryable,
  input: {
    namespace: string;
    orgId: string;
    cutoffMs: number;
    batchSize: number;
  },
): Promise<PostgresConsoleRuntimeSnapshotRetentionCleanupResult> {
  const deleteOutbox = await q.query(
    `WITH stale AS (
       SELECT ctid
         FROM console_runtime_snapshot_outbox
        WHERE namespace = $1
          AND org_id = $2
          AND created_at_ms < $3
        ORDER BY created_at_ms ASC, event_id ASC
        LIMIT $4
     )
     DELETE FROM console_runtime_snapshot_outbox target
      USING stale
      WHERE target.ctid = stale.ctid`,
    [input.namespace, input.orgId, input.cutoffMs, input.batchSize],
  );

  const deleteSnapshots = await q.query(
    `WITH stale AS (
       SELECT snapshot.ctid
         FROM console_runtime_snapshots snapshot
        WHERE snapshot.namespace = $1
          AND snapshot.org_id = $2
          AND snapshot.created_at_ms < $3
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
        LIMIT $4
     )
     DELETE FROM console_runtime_snapshots target
      USING stale
      WHERE target.ctid = stale.ctid`,
    [input.namespace, input.orgId, input.cutoffMs, input.batchSize],
  );

  return {
    cutoffMs: input.cutoffMs,
    deletedOutbox: Number(deleteOutbox.rowCount || 0),
    deletedSnapshots: Number(deleteSnapshots.rowCount || 0),
  };
}

export async function maybeRunConsoleRuntimeSnapshotRetentionForTenant(
  q: ConsoleRuntimeSnapshotRetentionQueryable,
  input: {
    namespace: string;
    orgId: string;
    nowValueMs: number;
    ttlMs: number;
    pruneIntervalMs: number;
    batchSize: number;
    nextRunAtByOrg: Map<string, number>;
  },
): Promise<PostgresConsoleRuntimeSnapshotRetentionCleanupResult | null> {
  if (input.ttlMs <= 0) return null;
  const nextRunAt = Number(input.nextRunAtByOrg.get(input.orgId) || 0);
  if (input.nowValueMs < nextRunAt) return null;
  const result = await pruneConsoleRuntimeSnapshotRetentionForTenant(q, {
    namespace: input.namespace,
    orgId: input.orgId,
    cutoffMs: Math.max(0, input.nowValueMs - input.ttlMs),
    batchSize: input.batchSize,
  });
  input.nextRunAtByOrg.set(input.orgId, input.nowValueMs + input.pruneIntervalMs);
  return result;
}
