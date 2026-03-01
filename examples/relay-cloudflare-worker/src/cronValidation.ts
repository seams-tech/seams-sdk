import type { WorkerCronConfigEnv } from './cronConfig';
import type { WorkerCronFeatureFlags } from './cronFlags';

export type WorkerCronJobName =
  | 'billingMonthlyFinalization'
  | 'runtimeSnapshotOutbox'
  | 'webhookRetryDispatch';

export type WorkerCronConfigIssueCode = 'missing_postgres_url' | 'missing_org_ids';

export interface WorkerCronConfigIssue {
  job: WorkerCronJobName;
  code: WorkerCronConfigIssueCode;
  message: string;
  envKeys: string[];
}

function parseCsv(input: string | undefined): string[] {
  return String(input || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function hasValue(input: string | undefined): boolean {
  return String(input || '').trim().length > 0;
}

export function collectWorkerCronConfigIssues(
  env: WorkerCronConfigEnv,
  cronFlags: WorkerCronFeatureFlags,
): WorkerCronConfigIssue[] {
  const issues: WorkerCronConfigIssue[] = [];

  if (cronFlags.billingFinalizationEnabled) {
    if (!hasValue(env.BILLING_POSTGRES_URL)) {
      issues.push({
        job: 'billingMonthlyFinalization',
        code: 'missing_postgres_url',
        message: 'BILLING_FINALIZATION_ENABLED=1 requires BILLING_POSTGRES_URL',
        envKeys: ['BILLING_FINALIZATION_ENABLED', 'BILLING_POSTGRES_URL'],
      });
    }
    if (parseCsv(env.BILLING_FINALIZATION_ORG_IDS).length === 0) {
      issues.push({
        job: 'billingMonthlyFinalization',
        code: 'missing_org_ids',
        message: 'BILLING_FINALIZATION_ENABLED=1 requires BILLING_FINALIZATION_ORG_IDS',
        envKeys: ['BILLING_FINALIZATION_ENABLED', 'BILLING_FINALIZATION_ORG_IDS'],
      });
    }
  }

  if (cronFlags.runtimeSnapshotOutboxEnabled) {
    const runtimeOutboxPostgresUrl =
      env.RUNTIME_SNAPSHOT_OUTBOX_POSTGRES_URL || env.BILLING_POSTGRES_URL;
    if (!hasValue(runtimeOutboxPostgresUrl)) {
      issues.push({
        job: 'runtimeSnapshotOutbox',
        code: 'missing_postgres_url',
        message:
          'RUNTIME_SNAPSHOT_OUTBOX_ENABLED=1 requires RUNTIME_SNAPSHOT_OUTBOX_POSTGRES_URL (or BILLING_POSTGRES_URL fallback)',
        envKeys: [
          'RUNTIME_SNAPSHOT_OUTBOX_ENABLED',
          'RUNTIME_SNAPSHOT_OUTBOX_POSTGRES_URL',
          'BILLING_POSTGRES_URL',
        ],
      });
    }
    if (parseCsv(env.RUNTIME_SNAPSHOT_OUTBOX_ORG_IDS).length === 0) {
      issues.push({
        job: 'runtimeSnapshotOutbox',
        code: 'missing_org_ids',
        message: 'RUNTIME_SNAPSHOT_OUTBOX_ENABLED=1 requires RUNTIME_SNAPSHOT_OUTBOX_ORG_IDS',
        envKeys: ['RUNTIME_SNAPSHOT_OUTBOX_ENABLED', 'RUNTIME_SNAPSHOT_OUTBOX_ORG_IDS'],
      });
    }
  }

  if (cronFlags.webhookRetryEnabled) {
    const webhookRetryPostgresUrl = env.WEBHOOK_RETRY_POSTGRES_URL || env.BILLING_POSTGRES_URL;
    if (!hasValue(webhookRetryPostgresUrl)) {
      issues.push({
        job: 'webhookRetryDispatch',
        code: 'missing_postgres_url',
        message:
          'WEBHOOK_RETRY_ENABLED=1 requires WEBHOOK_RETRY_POSTGRES_URL (or BILLING_POSTGRES_URL fallback)',
        envKeys: [
          'WEBHOOK_RETRY_ENABLED',
          'WEBHOOK_RETRY_POSTGRES_URL',
          'BILLING_POSTGRES_URL',
        ],
      });
    }
    if (parseCsv(env.WEBHOOK_RETRY_ORG_IDS).length === 0) {
      issues.push({
        job: 'webhookRetryDispatch',
        code: 'missing_org_ids',
        message: 'WEBHOOK_RETRY_ENABLED=1 requires WEBHOOK_RETRY_ORG_IDS',
        envKeys: ['WEBHOOK_RETRY_ENABLED', 'WEBHOOK_RETRY_ORG_IDS'],
      });
    }
  }

  return issues;
}
