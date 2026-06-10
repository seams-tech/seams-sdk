export interface PostgresConsoleObservabilityRetentionCleanupResult {
  cutoffMs: number;
  deletedEvents: number;
  deletedDedup: number;
  deletedIngestWindows: number;
  deletedRequestRollups: number;
}

export interface ConsoleObservabilityRetentionQueryable {
  query: (
    text: string,
    values?: unknown[],
  ) => Promise<{ rowCount?: number | null | undefined }>;
}

export async function pruneConsoleObservabilityRetentionForTenant(
  q: ConsoleObservabilityRetentionQueryable,
  input: {
    namespace: string;
    orgId: string;
    cutoffMs: number;
    batchSize: number;
  },
): Promise<PostgresConsoleObservabilityRetentionCleanupResult> {
  const deleteEvents = await q.query(
    `WITH stale AS (
       SELECT namespace, org_id, created_at_ms, event_id
         FROM console_observability_events
        WHERE namespace = $1
          AND org_id = $2
          AND created_at_ms < $3
        ORDER BY created_at_ms ASC, event_id ASC
        LIMIT $4
     )
     DELETE FROM console_observability_events target
      USING stale
      WHERE target.namespace = stale.namespace
        AND target.org_id = stale.org_id
        AND target.created_at_ms = stale.created_at_ms
        AND target.event_id = stale.event_id`,
    [input.namespace, input.orgId, input.cutoffMs, input.batchSize],
  );

  const deleteDedup = await q.query(
    `WITH stale AS (
       SELECT ctid
         FROM console_observability_event_dedup
        WHERE namespace = $1
          AND org_id = $2
          AND created_at_ms < $3
        LIMIT $4
     )
     DELETE FROM console_observability_event_dedup target
      USING stale
      WHERE target.ctid = stale.ctid`,
    [input.namespace, input.orgId, input.cutoffMs, input.batchSize],
  );

  const deleteIngestWindows = await q.query(
    `DELETE FROM console_observability_ingest_windows
      WHERE namespace = $1
        AND org_id = $2
        AND window_start_ms < $3`,
    [input.namespace, input.orgId, input.cutoffMs],
  );

  const deleteRequestRollups = await q.query(
    `DELETE FROM console_observability_request_rollups_minute
      WHERE namespace = $1
        AND org_id = $2
        AND window_start_ms < $3`,
    [input.namespace, input.orgId, input.cutoffMs],
  );

  return {
    cutoffMs: input.cutoffMs,
    deletedEvents: Number(deleteEvents.rowCount || 0),
    deletedDedup: Number(deleteDedup.rowCount || 0),
    deletedIngestWindows: Number(deleteIngestWindows.rowCount || 0),
    deletedRequestRollups: Number(deleteRequestRollups.rowCount || 0),
  };
}

export async function maybeRunConsoleObservabilityRetentionForTenant(
  q: ConsoleObservabilityRetentionQueryable,
  input: {
    namespace: string;
    orgId: string;
    nowValueMs: number;
    ttlMs: number;
    pruneIntervalMs: number;
    batchSize: number;
    nextRunAtByOrg: Map<string, number>;
  },
): Promise<void> {
  if (input.ttlMs <= 0) return;
  const nextRunAt = Number(input.nextRunAtByOrg.get(input.orgId) || 0);
  if (input.nowValueMs < nextRunAt) return;
  await pruneConsoleObservabilityRetentionForTenant(q, {
    namespace: input.namespace,
    orgId: input.orgId,
    cutoffMs: Math.max(0, input.nowValueMs - input.ttlMs),
    batchSize: input.batchSize,
  });
  input.nextRunAtByOrg.set(input.orgId, input.nowValueMs + input.pruneIntervalMs);
}
