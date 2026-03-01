import { expect, test } from '@playwright/test';
import { resolveRelayServerConsoleConfig, toOptionalSecret } from '../../examples/relay-server/src/consoleConfig';

test.describe('relay-server console config resolution', () => {
  test('uses CONSOLE_POSTGRES_URL when provided', async () => {
    const cfg = resolveRelayServerConsoleConfig({
      POSTGRES_URL: 'postgres://threshold/db',
      CONSOLE_POSTGRES_URL: 'postgres://console/db',
    });

    expect(cfg.thresholdPostgresUrl).toBe('postgres://threshold/db');
    expect(cfg.consolePostgresUrl).toBe('postgres://console/db');
    expect(cfg.consoleBillingBackend).toBe('postgres');
    expect(cfg.consoleWebhooksBackend).toBe('postgres');
  });

  test('falls back to POSTGRES_URL for console url when CONSOLE_POSTGRES_URL is unset', async () => {
    const cfg = resolveRelayServerConsoleConfig({
      POSTGRES_URL: 'postgres://shared/db',
    });

    expect(cfg.thresholdPostgresUrl).toBe('postgres://shared/db');
    expect(cfg.consolePostgresUrl).toBe('postgres://shared/db');
    expect(cfg.consoleBillingBackend).toBe('postgres');
    expect(cfg.consoleWebhooksBackend).toBe('postgres');
  });

  test('defaults console backends to memory when no postgres url exists', async () => {
    const cfg = resolveRelayServerConsoleConfig({});

    expect(cfg.thresholdPostgresUrl).toBe('');
    expect(cfg.consolePostgresUrl).toBe('');
    expect(cfg.consoleBillingBackend).toBe('memory');
    expect(cfg.consoleWebhooksBackend).toBe('memory');
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
