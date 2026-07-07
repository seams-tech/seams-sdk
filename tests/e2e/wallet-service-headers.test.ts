import { test, expect } from '@playwright/test';

test('app-origin wallet-service path does not emit SDK plugin headers', async ({ request }) => {
  const res = await request.get('/wallet-service');

  const headers = res.headers();
  expect(headers['permissions-policy']).toBeUndefined();
  expect(headers['content-security-policy']).toBeUndefined();
  expect(headers['cross-origin-opener-policy']).toBeUndefined();
  expect(headers['cross-origin-embedder-policy']).toBeUndefined();
  expect(headers['cross-origin-resource-policy']).toBeUndefined();
});
