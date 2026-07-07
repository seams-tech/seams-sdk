import { test, expect } from '@playwright/test';

test('wallet-service default route does not emit legacy strict CSP', async ({
  page,
  baseURL,
}) => {
  const url = new URL('/wallet-service/', baseURL!).toString();
  const resp = await page.goto(url, { waitUntil: 'domcontentloaded' });
  expect(resp).toBeTruthy();
  expect(resp!.headers()['content-security-policy']).toBeUndefined();

  const hasWalletServiceDocument = await page.evaluate(() => document.body !== null);
  expect(hasWalletServiceDocument).toBe(true);
});
