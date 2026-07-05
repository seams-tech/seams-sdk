import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, devices } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
dotenv.config({ path: path.join(repoRoot, '.env.intended.local'), override: true });

const APP_URL = process.env.SEAMS_INTENDED_APP_URL || 'https://localhost';

export default defineConfig({
  tsconfig: './tsconfig.playwright.json',
  testDir: '.',
  testMatch: ['**/e2e/intended-behaviours/**/*.contract.test.ts'],
  fullyParallel: false,
  workers: 1,
  retries: 0,
  globalTimeout: 600_000,
  timeout: 420_000,
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
});
