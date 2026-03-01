export type ConsoleBackendKind = 'postgres' | 'memory';

export interface RelayServerConsoleConfig {
  thresholdPostgresUrl: string;
  signerMigrationPostgresUrl: string;
  consolePostgresUrl: string;
  consoleMigrationPostgresUrl: string;
  consoleBillingBackend: ConsoleBackendKind;
  consoleBillingEnsureSchema: boolean;
  consoleBillingNamespace: string;
  consoleWebhooksBackend: ConsoleBackendKind;
  consoleWebhooksEnsureSchema: boolean;
  consoleWebhooksNamespace: string;
  consoleBillingStripeWebhookSecret: string;
}

function normalizeString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function parseConsoleBackendKind(
  value: unknown,
  fallback: ConsoleBackendKind,
  envKey: string,
): ConsoleBackendKind {
  const raw = normalizeString(value).toLowerCase() || fallback;
  if (raw !== 'postgres' && raw !== 'memory') {
    throw new Error(`Invalid ${envKey}="${raw}". Expected "postgres" or "memory".`);
  }
  return raw;
}

function parseBooleanEnv(value: unknown, fallback: boolean, envKey: string): boolean {
  const raw = normalizeString(value).toLowerCase();
  if (!raw) return fallback;
  if (raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on') return true;
  if (raw === '0' || raw === 'false' || raw === 'no' || raw === 'off') return false;
  throw new Error(
    `Invalid ${envKey}="${raw}". Expected one of: 1,true,yes,on,0,false,no,off.`,
  );
}

export function resolveRelayServerConsoleConfig(env: Record<string, unknown>): RelayServerConsoleConfig {
  const thresholdPostgresUrl = normalizeString(env.POSTGRES_URL);
  const signerMigrationPostgresUrl =
    normalizeString(env.POSTGRES_MIGRATION_URL) || thresholdPostgresUrl;
  const explicitConsolePostgresUrl = normalizeString(env.CONSOLE_POSTGRES_URL);
  const consolePostgresUrl = explicitConsolePostgresUrl || thresholdPostgresUrl;
  const consoleMigrationPostgresUrl =
    normalizeString(env.CONSOLE_POSTGRES_MIGRATION_URL) || consolePostgresUrl;
  const consoleDefaultBackend: ConsoleBackendKind = consolePostgresUrl ? 'postgres' : 'memory';

  return {
    thresholdPostgresUrl,
    signerMigrationPostgresUrl,
    consolePostgresUrl,
    consoleMigrationPostgresUrl,
    consoleBillingBackend: parseConsoleBackendKind(
      env.CONSOLE_BILLING_BACKEND,
      consoleDefaultBackend,
      'CONSOLE_BILLING_BACKEND',
    ),
    consoleBillingEnsureSchema: parseBooleanEnv(
      env.CONSOLE_BILLING_ENSURE_SCHEMA,
      true,
      'CONSOLE_BILLING_ENSURE_SCHEMA',
    ),
    consoleBillingNamespace: normalizeString(env.CONSOLE_BILLING_NAMESPACE) || 'relay-console',
    consoleWebhooksBackend: parseConsoleBackendKind(
      env.CONSOLE_WEBHOOKS_BACKEND,
      consoleDefaultBackend,
      'CONSOLE_WEBHOOKS_BACKEND',
    ),
    consoleWebhooksEnsureSchema: parseBooleanEnv(
      env.CONSOLE_WEBHOOKS_ENSURE_SCHEMA,
      true,
      'CONSOLE_WEBHOOKS_ENSURE_SCHEMA',
    ),
    consoleWebhooksNamespace: normalizeString(env.CONSOLE_WEBHOOKS_NAMESPACE) || 'relay-console',
    consoleBillingStripeWebhookSecret: normalizeString(env.CONSOLE_BILLING_STRIPE_WEBHOOK_SECRET),
  };
}

export function toOptionalSecret(secret: string): string | undefined {
  return normalizeString(secret) || undefined;
}
