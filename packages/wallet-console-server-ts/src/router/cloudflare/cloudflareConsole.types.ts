import type {
  RouterApiCloudflareSignerWorkerEnv,
  SeamsD1SignerTenantStorageWorkerEnv,
} from '@seams/wallet-server/cloud-host';
import type { D1DatabaseLike } from '@seams/wallet-server/cloud-host';

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
  CONSOLE_EMAIL_RUNTIME_PROFILE?: string;
  CONSOLE_EMAIL_PROVIDER?: string;
  CONSOLE_EMAIL_INVITATION_SECRET_KEY_ID?: string;
  CONSOLE_EMAIL_INVITATION_SECRET_KEY_B64U?: string;
  CONSOLE_WEBHOOK_SECRET_KEY_ID?: string;
  CONSOLE_WEBHOOK_SECRET_KEY_B64U?: string;
  CONSOLE_EMAIL_FROM?: string;
  CONSOLE_EMAIL_REPLY_TO?: string;
  CONSOLE_EMAIL_CRON_EXPRESSIONS?: string;
  CONSOLE_DOCS_BASE_URL?: string;
  RESEND_API_KEY?: string;
}

export type SeamsCloudflareComposedWorkerEnv = RouterApiCloudflareSignerWorkerEnv &
  RouterApiCloudflareConsoleWorkerEnv;

export interface SeamsD1ConsoleTenantStorageWorkerEnv {
  CONSOLE_DB: D1DatabaseLike;
}

export type SeamsD1ComposedTenantStorageWorkerEnv = SeamsD1SignerTenantStorageWorkerEnv &
  SeamsD1ConsoleTenantStorageWorkerEnv;
