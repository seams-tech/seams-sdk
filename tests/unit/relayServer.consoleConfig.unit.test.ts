import { expect, test } from '@playwright/test';
import { resolveRelayServerConsoleConfig, toOptionalSecret } from '../../examples/relay-server/src/consoleConfig';

test.describe('relay-server console config resolution', () => {
  test('uses CONSOLE_POSTGRES_URL when provided', async () => {
    const cfg = resolveRelayServerConsoleConfig({
      POSTGRES_URL: 'postgres://threshold/db',
      CONSOLE_POSTGRES_URL: 'postgres://console/db',
    });

    expect(cfg.thresholdPostgresUrl).toBe('postgres://threshold/db');
    expect(cfg.signerMigrationPostgresUrl).toBe('postgres://threshold/db');
    expect(cfg.consolePostgresUrl).toBe('postgres://console/db');
    expect(cfg.consoleMigrationPostgresUrl).toBe('postgres://console/db');
    expect(cfg.consoleBillingBackend).toBe('postgres');
    expect(cfg.consoleWebhooksBackend).toBe('postgres');
    expect(cfg.consoleObservabilityBackend).toBe('postgres');
    expect(cfg.consoleBillingEnsureSchema).toBe(true);
    expect(cfg.consoleWebhooksEnsureSchema).toBe(true);
    expect(cfg.consoleObservabilityEnsureSchema).toBe(true);
  });

  test('does not fall back to POSTGRES_URL for console url when CONSOLE_POSTGRES_URL is unset', async () => {
    const cfg = resolveRelayServerConsoleConfig({
      POSTGRES_URL: 'postgres://shared/db',
    });

    expect(cfg.thresholdPostgresUrl).toBe('postgres://shared/db');
    expect(cfg.signerMigrationPostgresUrl).toBe('postgres://shared/db');
    expect(cfg.consolePostgresUrl).toBe('');
    expect(cfg.consoleMigrationPostgresUrl).toBe('');
    expect(cfg.consoleBillingBackend).toBe('memory');
    expect(cfg.consoleWebhooksBackend).toBe('memory');
    expect(cfg.consoleObservabilityBackend).toBe('memory');
    expect(cfg.consoleBillingEnsureSchema).toBe(true);
    expect(cfg.consoleWebhooksEnsureSchema).toBe(true);
    expect(cfg.consoleObservabilityEnsureSchema).toBe(true);
  });

  test('supports explicit migration URLs for signer and console', async () => {
    const cfg = resolveRelayServerConsoleConfig({
      POSTGRES_URL: 'postgres://runtime/signer',
      CONSOLE_POSTGRES_URL: 'postgres://runtime/console',
      POSTGRES_MIGRATION_URL: 'postgres://migrator/signer',
      CONSOLE_POSTGRES_MIGRATION_URL: 'postgres://migrator/console',
    });

    expect(cfg.thresholdPostgresUrl).toBe('postgres://runtime/signer');
    expect(cfg.signerMigrationPostgresUrl).toBe('postgres://migrator/signer');
    expect(cfg.consolePostgresUrl).toBe('postgres://runtime/console');
    expect(cfg.consoleMigrationPostgresUrl).toBe('postgres://migrator/console');
  });

  test('defaults console backends to memory when no postgres url exists', async () => {
    const cfg = resolveRelayServerConsoleConfig({});

    expect(cfg.thresholdPostgresUrl).toBe('');
    expect(cfg.signerMigrationPostgresUrl).toBe('');
    expect(cfg.consolePostgresUrl).toBe('');
    expect(cfg.consoleMigrationPostgresUrl).toBe('');
    expect(cfg.consoleBillingBackend).toBe('memory');
    expect(cfg.consoleWebhooksBackend).toBe('memory');
    expect(cfg.consoleObservabilityBackend).toBe('memory');
    expect(cfg.consoleBillingEnsureSchema).toBe(true);
    expect(cfg.consoleWebhooksEnsureSchema).toBe(true);
    expect(cfg.consoleObservabilityEnsureSchema).toBe(true);
  });

  test('parses ensure schema flags and rejects invalid boolean values', async () => {
    const cfg = resolveRelayServerConsoleConfig({
      CONSOLE_BILLING_ENSURE_SCHEMA: '0',
      CONSOLE_WEBHOOKS_ENSURE_SCHEMA: 'false',
      CONSOLE_OBSERVABILITY_ENSURE_SCHEMA: 'off',
    });
    expect(cfg.consoleBillingEnsureSchema).toBe(false);
    expect(cfg.consoleWebhooksEnsureSchema).toBe(false);
    expect(cfg.consoleObservabilityEnsureSchema).toBe(false);

    expect(() =>
      resolveRelayServerConsoleConfig({
        CONSOLE_BILLING_ENSURE_SCHEMA: 'maybe',
      }),
    ).toThrow(
      'Invalid CONSOLE_BILLING_ENSURE_SCHEMA="maybe". Expected one of: 1,true,yes,on,0,false,no,off.',
    );

    expect(() =>
      resolveRelayServerConsoleConfig({
        CONSOLE_WEBHOOKS_ENSURE_SCHEMA: 'nope',
      }),
    ).toThrow(
      'Invalid CONSOLE_WEBHOOKS_ENSURE_SCHEMA="nope". Expected one of: 1,true,yes,on,0,false,no,off.',
    );

    expect(() =>
      resolveRelayServerConsoleConfig({
        CONSOLE_OBSERVABILITY_ENSURE_SCHEMA: 'invalid',
      }),
    ).toThrow(
      'Invalid CONSOLE_OBSERVABILITY_ENSURE_SCHEMA="invalid". Expected one of: 1,true,yes,on,0,false,no,off.',
    );
  });

  test('rejects invalid backend enum values', async () => {
    expect(() =>
      resolveRelayServerConsoleConfig({
        CONSOLE_BILLING_BACKEND: 'sqlite',
      }),
    ).toThrow('Invalid CONSOLE_BILLING_BACKEND="sqlite". Expected "postgres" or "memory".');

    expect(() =>
      resolveRelayServerConsoleConfig({
        CONSOLE_WEBHOOKS_BACKEND: 'redis',
      }),
    ).toThrow('Invalid CONSOLE_WEBHOOKS_BACKEND="redis". Expected "postgres" or "memory".');

    expect(() =>
      resolveRelayServerConsoleConfig({
        CONSOLE_OBSERVABILITY_BACKEND: 'redis',
      }),
    ).toThrow('Invalid CONSOLE_OBSERVABILITY_BACKEND="redis". Expected "postgres" or "memory".');
  });

  test('parses observability guardrail limits and rejects invalid values', async () => {
    const cfg = resolveRelayServerConsoleConfig({
      CONSOLE_OBSERVABILITY_QUERY_MAX_WINDOW_MS: '600000',
      CONSOLE_OBSERVABILITY_INGEST_MAX_BATCH_SIZE: '250',
      CONSOLE_OBSERVABILITY_INGEST_MAX_EVENTS_PER_MINUTE: '12000',
      CONSOLE_OBSERVABILITY_RETENTION_TTL_MS: '86400000',
      CONSOLE_OBSERVABILITY_RETENTION_PRUNE_INTERVAL_MS: '90000',
      CONSOLE_OBSERVABILITY_RETENTION_BATCH_SIZE: '500',
      CONSOLE_RUNTIME_SNAPSHOT_RETENTION_TTL_MS: '604800000',
      CONSOLE_RUNTIME_SNAPSHOT_RETENTION_PRUNE_INTERVAL_MS: '120000',
      CONSOLE_RUNTIME_SNAPSHOT_RETENTION_BATCH_SIZE: '250',
    });

    expect(cfg.consoleObservabilityQueryMaxWindowMs).toBe(600000);
    expect(cfg.consoleObservabilityIngestMaxBatchSize).toBe(250);
    expect(cfg.consoleObservabilityIngestMaxEventsPerMinute).toBe(12000);
    expect(cfg.consoleObservabilityRetentionTtlMs).toBe(86400000);
    expect(cfg.consoleObservabilityRetentionPruneIntervalMs).toBe(90000);
    expect(cfg.consoleObservabilityRetentionBatchSize).toBe(500);
    expect(cfg.consoleRuntimeSnapshotRetentionTtlMs).toBe(604800000);
    expect(cfg.consoleRuntimeSnapshotRetentionPruneIntervalMs).toBe(120000);
    expect(cfg.consoleRuntimeSnapshotRetentionBatchSize).toBe(250);

    expect(() =>
      resolveRelayServerConsoleConfig({
        CONSOLE_OBSERVABILITY_QUERY_MAX_WINDOW_MS: '0',
      }),
    ).toThrow(
      'Invalid CONSOLE_OBSERVABILITY_QUERY_MAX_WINDOW_MS="0". Expected a positive integer.',
    );
    expect(() =>
      resolveRelayServerConsoleConfig({
        CONSOLE_OBSERVABILITY_INGEST_MAX_BATCH_SIZE: 'abc',
      }),
    ).toThrow(
      'Invalid CONSOLE_OBSERVABILITY_INGEST_MAX_BATCH_SIZE="abc". Expected a positive integer.',
    );
    expect(() =>
      resolveRelayServerConsoleConfig({
        CONSOLE_RUNTIME_SNAPSHOT_RETENTION_TTL_MS: '0',
      }),
    ).toThrow(
      'Invalid CONSOLE_RUNTIME_SNAPSHOT_RETENTION_TTL_MS="0". Expected a positive integer.',
    );
  });

  test('normalizes billing webhook secret to optional value', async () => {
    expect(toOptionalSecret('')).toBeUndefined();
    expect(toOptionalSecret('   ')).toBeUndefined();
    expect(toOptionalSecret('secret_123')).toBe('secret_123');
    expect(toOptionalSecret('  secret_123  ')).toBe('secret_123');
  });
});
