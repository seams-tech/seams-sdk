// Minimal Worker runtime types (avoid adding @cloudflare/workers-types dependency here)
export type CfEnv = object;

/**
 * Convenience env shape matching the `examples/relay-cloudflare-worker` configuration.
 * This is optional — you can define your own `Env` type with different binding names.
 */
export interface RelayCloudflareWorkerEnv {
  RELAYER_ACCOUNT_ID: string;
  RELAYER_PRIVATE_KEY: string;
  // Optional overrides (SDK provides defaults when omitted)
  NEAR_RPC_URL?: string;
  NETWORK_ID?: string;
  ACCOUNT_INITIAL_BALANCE?: string;
  CREATE_ACCOUNT_AND_REGISTER_GAS?: string;
  SESSION_COOKIE_NAME?: string;
  EXPECTED_ORIGIN?: string;
  EXPECTED_WALLET_ORIGIN?: string;
  RECOVER_EMAIL_RECIPIENT?: string;
  // Optional console billing monthly finalization
  BILLING_FINALIZATION_ENABLED?: string;
  BILLING_POSTGRES_URL?: string;
  BILLING_NAMESPACE?: string;
  BILLING_FINALIZATION_PERIOD_MONTH_UTC?: string;
  BILLING_FINALIZATION_ORG_IDS?: string;
  // Optional runtime snapshot outbox dispatch
  RUNTIME_SNAPSHOT_OUTBOX_ENABLED?: string;
  RUNTIME_SNAPSHOT_OUTBOX_POSTGRES_URL?: string;
  RUNTIME_SNAPSHOT_OUTBOX_NAMESPACE?: string;
  RUNTIME_SNAPSHOT_OUTBOX_ORG_IDS?: string;
  RUNTIME_SNAPSHOT_OUTBOX_LIMIT?: string;
  // Optional webhook retry dispatch
  WEBHOOK_RETRY_ENABLED?: string;
  WEBHOOK_RETRY_POSTGRES_URL?: string;
  WEBHOOK_RETRY_NAMESPACE?: string;
  WEBHOOK_RETRY_ORG_IDS?: string;
  WEBHOOK_RETRY_LIMIT?: string;
  WEBHOOK_RETRY_MAX_ATTEMPTS?: string;
  WEBHOOK_RETRY_INITIAL_BACKOFF_MS?: string;
  WEBHOOK_RETRY_MAX_BACKOFF_MS?: string;

  // Optional: Threshold signing (2-party FROST).
  // The SDK enables `/threshold-ed25519/*` endpoints when `thresholdEd25519KeyStore` is configured.
}

export interface CfExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

export interface CfScheduledEvent {
  scheduledTime?: number;
  cron?: string;
}

export interface CfEmailMessage {
  from: string;
  to: string;
  // Cloudflare uses `Headers`, but keep this flexible for userland tests.
  headers: Headers | Iterable<[string, string]> | Record<string, string>;
  raw: ReadableStream | ArrayBuffer | string;
  rawSize?: number;
  setReject(reason: string): void;
}

export type FetchHandler = (
  request: Request,
  env?: CfEnv,
  ctx?: CfExecutionContext,
) => Promise<Response>;
export type ScheduledHandler = (
  event: CfScheduledEvent,
  env?: CfEnv,
  ctx?: CfExecutionContext,
) => Promise<void>;
export type EmailHandler = (
  message: CfEmailMessage,
  env?: CfEnv,
  ctx?: CfExecutionContext,
) => Promise<void>;
