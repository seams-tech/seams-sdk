import { expect, test } from '@playwright/test';
import {
  createWorkerCronObservabilityIngestion,
  resolveWorkerCronObservabilityConfig,
} from '../../examples/relay-cloudflare-worker/src/observability';

test.describe('relay cloudflare worker observability config', () => {
  test('resolves webhook retry postgres config ahead of billing defaults', async () => {
    const resolved = resolveWorkerCronObservabilityConfig({
      BILLING_POSTGRES_URL: 'postgres://billing/db',
      BILLING_NAMESPACE: 'billing-ns',
      WEBHOOK_RETRY_POSTGRES_URL: 'postgres://webhooks/db',
      WEBHOOK_RETRY_NAMESPACE: 'webhooks-ns',
    });

    expect(resolved).toEqual({
      postgresUrl: 'postgres://webhooks/db',
      namespace: 'webhooks-ns',
    });
  });

  test('falls back to billing postgres config and returns null without a url', async () => {
    const fallback = resolveWorkerCronObservabilityConfig({
      BILLING_POSTGRES_URL: 'postgres://billing/db',
      BILLING_NAMESPACE: 'billing-ns',
    });
    expect(fallback).toEqual({
      postgresUrl: 'postgres://billing/db',
      namespace: 'billing-ns',
    });

    await expect(
      createWorkerCronObservabilityIngestion({
        BILLING_POSTGRES_URL: '',
        WEBHOOK_RETRY_POSTGRES_URL: '',
      }),
    ).resolves.toBeNull();
  });
});
