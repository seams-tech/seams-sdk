#!/usr/bin/env node
import dotenv from 'dotenv';
import {
  ensureConsoleBillingPostgresSchema,
  ensureConsoleObservabilityPostgresSchema,
  ensureConsoleWebhooksPostgresSchema,
} from '@seams/sdk-server/router/express';

dotenv.config({ path: '.env' });

const postgresUrl = String(
  process.env.CONSOLE_POSTGRES_MIGRATION_URL || process.env.CONSOLE_POSTGRES_URL || '',
).trim();
if (!postgresUrl) {
  throw new Error(
    'Missing console Postgres URL. Set CONSOLE_POSTGRES_MIGRATION_URL (preferred) or CONSOLE_POSTGRES_URL.',
  );
}

const namespace = String(process.env.CONSOLE_NAMESPACE || 'relay-console').trim();

await ensureConsoleBillingPostgresSchema({
  postgresUrl,
  namespace,
  logger: console,
});
await ensureConsoleWebhooksPostgresSchema({
  postgresUrl,
  namespace,
  logger: console,
});
await ensureConsoleObservabilityPostgresSchema({
  postgresUrl,
  logger: console,
});

console.log(
  '[postgres-migrate-console] console billing + webhooks + observability schemas ready',
);
