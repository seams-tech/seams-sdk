import type { CloudflareDurableObjectNamespaceLike } from '../../core/types';
import type { D1DatabaseLike } from '../../storage/tenantRoute';

// Minimal Worker runtime types (avoid adding @cloudflare/workers-types dependency here)
export type CfEnv = object;

export interface RouterApiCloudflareSignerWorkerEnv {
  RELAYER_ACCOUNT_ID: string;
  RELAYER_PRIVATE_KEY: string;
  RELAYER_PUBLIC_KEY?: string;
  NEAR_RPC_URL?: string;
  NETWORK_ID?: string;
  ACCOUNT_INITIAL_BALANCE?: string;
  CREATE_ACCOUNT_AND_REGISTER_GAS?: string;
  SESSION_COOKIE_NAME?: string;
  EXPECTED_ORIGIN?: string;
  EXPECTED_WALLET_ORIGIN?: string;
  RECOVER_EMAIL_RECIPIENT?: string;
}

export interface SeamsD1SignerTenantStorageWorkerEnv {
  SIGNER_DB: D1DatabaseLike;
  THRESHOLD_STORE: CloudflareDurableObjectNamespaceLike;
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
