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
    expect(cfg.consoleBillingEnsureSchema).toBe(true);
    expect(cfg.consoleWebhooksEnsureSchema).toBe(true);
  });

  test('falls back to POSTGRES_URL for console url when CONSOLE_POSTGRES_URL is unset', async () => {
    const cfg = resolveRelayServerConsoleConfig({
      POSTGRES_URL: 'postgres://shared/db',
    });

    expect(cfg.thresholdPostgresUrl).toBe('postgres://shared/db');
    expect(cfg.signerMigrationPostgresUrl).toBe('postgres://shared/db');
    expect(cfg.consolePostgresUrl).toBe('postgres://shared/db');
    expect(cfg.consoleMigrationPostgresUrl).toBe('postgres://shared/db');
    expect(cfg.consoleBillingBackend).toBe('postgres');
    expect(cfg.consoleWebhooksBackend).toBe('postgres');
    expect(cfg.consoleBillingEnsureSchema).toBe(true);
    expect(cfg.consoleWebhooksEnsureSchema).toBe(true);
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
    expect(cfg.consoleBillingEnsureSchema).toBe(true);
    expect(cfg.consoleWebhooksEnsureSchema).toBe(true);
  });

  test('parses ensure schema flags and rejects invalid boolean values', async () => {
    const cfg = resolveRelayServerConsoleConfig({
      CONSOLE_BILLING_ENSURE_SCHEMA: '0',
      CONSOLE_WEBHOOKS_ENSURE_SCHEMA: 'false',
    });
    expect(cfg.consoleBillingEnsureSchema).toBe(false);
    expect(cfg.consoleWebhooksEnsureSchema).toBe(false);

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
  });

  test('normalizes billing webhook secret to optional value', async () => {
    expect(toOptionalSecret('')).toBeUndefined();
    expect(toOptionalSecret('   ')).toBeUndefined();
    expect(toOptionalSecret('secret_123')).toBe('secret_123');
    expect(toOptionalSecret('  secret_123  ')).toBe('secret_123');
  });
});
