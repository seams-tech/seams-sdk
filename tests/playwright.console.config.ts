import { defineConfig, devices } from '@playwright/test';

const APP_URL = process.env.SEAMS_INTENDED_APP_URL || 'http://localhost:4001';
const WEB_SERVER_READY_PORT =
  process.env.SEAMS_INTENDED_WEB_SERVER_READY_PORT || String(37_000 + (process.pid % 10_000));
process.env.SEAMS_INTENDED_WEB_SERVER_READY_PORT = WEB_SERVER_READY_PORT;
const WEB_SERVER_READY_URL =
  process.env.SEAMS_INTENDED_WEB_SERVER_READY_URL ||
  `http://127.0.0.1:${WEB_SERVER_READY_PORT}/readyz`;

export default defineConfig({
  tsconfig: './tsconfig.playwright.json',
  testDir: '.',
  testMatch: ['**/e2e/console/**/*.operating.test.ts'],
  fullyParallel: false,
  workers: 1,
  retries: 0,
  globalTimeout: 1_800_000,
  timeout: 180_000,
  expect: {
    timeout: 15_000,
  },
  reporter: 'line',
  use: {
    baseURL: APP_URL,
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: 'node ./scripts/start-intended-services.mjs',
    url: WEB_SERVER_READY_URL,
    reuseExistingServer: false,
    gracefulShutdown: { signal: 'SIGTERM', timeout: 30_000 },
    timeout: 1_800_000,
  },
});
