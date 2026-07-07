import type {
  RouterApiCloudflareSignerWorkerEnv,
  SeamsD1SignerTenantStorageWorkerEnv,
} from '@seams/sdk-server/internal/router/cloudflare/cloudflare.types';
import type { D1DatabaseLike } from '@seams/sdk-server/internal/storage/tenantRoute';

export interface RouterApiCloudflareConsoleWorkerEnv {
  BILLING_FINALIZATION_ENABLED?: string;
  BILLING_NAMESPACE?: string;
  BILLING_FINALIZATION_PERIOD_MONTH_UTC?: string;
  BILLING_FINALIZATION_ORG_IDS?: string;
  RUNTIME_SNAPSHOT_OUTBOX_ENABLED?: string;
  RUNTIME_SNAPSHOT_OUTBOX_NAMESPACE?: string;
  RUNTIME_SNAPSHOT_OUTBOX_ORG_IDS?: string;
  RUNTIME_SNAPSHOT_OUTBOX_LIMIT?: string;
  WEBHOOK_RETRY_ENABLED?: string;
  WEBHOOK_RETRY_NAMESPACE?: string;
  WEBHOOK_RETRY_ORG_IDS?: string;
  WEBHOOK_RETRY_LIMIT?: string;
  WEBHOOK_RETRY_MAX_ATTEMPTS?: string;
  WEBHOOK_RETRY_INITIAL_BACKOFF_MS?: string;
  WEBHOOK_RETRY_MAX_BACKOFF_MS?: string;
}

export type SeamsCloudflareComposedWorkerEnv =
  RouterApiCloudflareSignerWorkerEnv & RouterApiCloudflareConsoleWorkerEnv;

export interface SeamsD1ConsoleTenantStorageWorkerEnv {
  CONSOLE_DB: D1DatabaseLike;
}

export type SeamsD1ComposedTenantStorageWorkerEnv =
  SeamsD1SignerTenantStorageWorkerEnv & SeamsD1ConsoleTenantStorageWorkerEnv;
