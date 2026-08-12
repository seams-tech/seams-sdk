import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: ['docs/**/*.browser.smoke.test.ts'],
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  reporter: 'line',
  use: {
    ...devices['Desktop Chrome'],
    baseURL: process.env.DOCS_BASE_URL ?? 'http://127.0.0.1:5222',
    ignoreHTTPSErrors: true,
  },
  webServer: {
    command: 'pnpm -C ../apps/docs preview --host 127.0.0.1',
    url: 'http://127.0.0.1:5222',
    reuseExistingServer: true,
    timeout: 30_000,
  },
});
