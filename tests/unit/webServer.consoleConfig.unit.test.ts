import { expect, test } from '@playwright/test';
import { resolveWebServerConsoleConfig, toOptionalSecret } from '../../apps/web-server/src/consoleConfig';

test.describe('web-server console config resolution', () => {
  test('ignores legacy Postgres console env because the Node runner is memory-only', async () => {
    const cfg = resolveWebServerConsoleConfig({
      POSTGRES_URL: 'postgres://threshold/db',
      CONSOLE_POSTGRES_URL: 'postgres://console/db',
      CONSOLE_POSTGRES_MIGRATION_URL: 'postgres://migrator/console',
      CONSOLE_NAMESPACE: 'tenant-console',
      CONSOLE_ENSURE_SCHEMA: '0',
    });

    expect(cfg).toEqual({ consoleBillingStripeWebhookSecret: '' });
  });

  test('does not fall back to POSTGRES_URL for console storage', async () => {
    const cfg = resolveWebServerConsoleConfig({
      POSTGRES_URL: 'postgres://shared/db',
    });

    expect(cfg).toEqual({ consoleBillingStripeWebhookSecret: '' });
  });

  test('normalizes billing webhook secret to optional value', async () => {
    expect(toOptionalSecret('')).toBeUndefined();
    expect(toOptionalSecret('   ')).toBeUndefined();
    expect(toOptionalSecret('secret_123')).toBe('secret_123');
    expect(toOptionalSecret('  secret_123  ')).toBe('secret_123');
  });
});
