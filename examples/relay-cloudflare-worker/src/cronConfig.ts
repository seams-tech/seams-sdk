import type { CloudflareCronOptions } from '@seams/sdk-server/router/cloudflare';
import type { ConsoleObservabilityIngestionService } from '@seams/sdk-server/router/express';
import type { WorkerCronFeatureFlags } from './cronFlags';

export interface WorkerCronConfigEnv {
  BILLING_POSTGRES_URL?: string;
  BILLING_NAMESPACE?: string;
  BILLING_FINALIZATION_PERIOD_MONTH_UTC?: string;
  BILLING_FINALIZATION_ORG_IDS?: string;
  BILLING_FINALIZATION_CRONS?: string;
  RUNTIME_SNAPSHOT_OUTBOX_POSTGRES_URL?: string;
  RUNTIME_SNAPSHOT_OUTBOX_NAMESPACE?: string;
  RUNTIME_SNAPSHOT_OUTBOX_ORG_IDS?: string;
  RUNTIME_SNAPSHOT_OUTBOX_LIMIT?: string;
  RUNTIME_SNAPSHOT_OUTBOX_CRONS?: string;
  WEBHOOK_RETRY_POSTGRES_URL?: string;
  WEBHOOK_RETRY_NAMESPACE?: string;
  WEBHOOK_RETRY_ORG_IDS?: string;
  WEBHOOK_RETRY_LIMIT?: string;
  WEBHOOK_RETRY_CRONS?: string;
  WEBHOOK_RETRY_MAX_ATTEMPTS?: string;
  WEBHOOK_RETRY_INITIAL_BACKOFF_MS?: string;
  WEBHOOK_RETRY_MAX_BACKOFF_MS?: string;
}

interface RuntimeSnapshotOutboxEventShape {
  payload: Record<string, unknown>;
}

interface RuntimeSnapshotOutboxSink {
  applyOutboxEvent(event: RuntimeSnapshotOutboxEventShape): void;
}

function parseCsv(input: string | undefined): string[] {
  return String(input || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function parseOptionalPositiveInt(input: string | undefined): number | undefined {
  const n = Number(input || 0);
  if (!Number.isFinite(n) || n <= 0) return undefined;
  return n;
}

export function createWorkerCronOptions(
  env: WorkerCronConfigEnv,
  cronFlags: WorkerCronFeatureFlags,
  runtimeSnapshotOutboxSink: RuntimeSnapshotOutboxSink,
  observabilityIngestion?: ConsoleObservabilityIngestionService | null,
): CloudflareCronOptions {
  return {
    enabled: cronFlags.cronEnabled,
    billingMonthlyFinalization: cronFlags.billingFinalizationEnabled
      ? {
          enabled: true,
          postgresUrl: env.BILLING_POSTGRES_URL,
          namespace: env.BILLING_NAMESPACE,
          periodMonthUtc: env.BILLING_FINALIZATION_PERIOD_MONTH_UTC,
          orgIds: parseCsv(env.BILLING_FINALIZATION_ORG_IDS),
          cronExpressions: parseCsv(env.BILLING_FINALIZATION_CRONS),
        }
      : undefined,
    runtimeSnapshotOutbox: cronFlags.runtimeSnapshotOutboxEnabled
      ? {
          enabled: true,
          postgresUrl: env.RUNTIME_SNAPSHOT_OUTBOX_POSTGRES_URL || env.BILLING_POSTGRES_URL,
          namespace: env.RUNTIME_SNAPSHOT_OUTBOX_NAMESPACE || env.BILLING_NAMESPACE,
          orgIds: parseCsv(env.RUNTIME_SNAPSHOT_OUTBOX_ORG_IDS),
          cronExpressions: parseCsv(env.RUNTIME_SNAPSHOT_OUTBOX_CRONS),
          limit: parseOptionalPositiveInt(env.RUNTIME_SNAPSHOT_OUTBOX_LIMIT),
          dispatch: async (event) => {
            runtimeSnapshotOutboxSink.applyOutboxEvent({
              payload: event.payload as Record<string, unknown>,
            });
          },
        }
      : undefined,
    webhookRetryDispatch: cronFlags.webhookRetryEnabled
      ? {
          enabled: true,
          postgresUrl: env.WEBHOOK_RETRY_POSTGRES_URL || env.BILLING_POSTGRES_URL,
          namespace: env.WEBHOOK_RETRY_NAMESPACE || env.BILLING_NAMESPACE,
          orgIds: parseCsv(env.WEBHOOK_RETRY_ORG_IDS),
          cronExpressions: parseCsv(env.WEBHOOK_RETRY_CRONS),
          limit: parseOptionalPositiveInt(env.WEBHOOK_RETRY_LIMIT),
          maxAttempts: parseOptionalPositiveInt(env.WEBHOOK_RETRY_MAX_ATTEMPTS),
          initialBackoffMs: parseOptionalPositiveInt(env.WEBHOOK_RETRY_INITIAL_BACKOFF_MS),
          maxBackoffMs: parseOptionalPositiveInt(env.WEBHOOK_RETRY_MAX_BACKOFF_MS),
          observabilityIngestion: observabilityIngestion || null,
        }
      : undefined,
  };
}
