import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, devices } from '@playwright/test';
import {
  readEnvFile,
  resolveGoogleClientId,
  resolveGoogleIdToken,
} from './scripts/intended-google-oidc-env.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const intendedEnvFilePath = path.join(repoRoot, '.env.local');
const intendedFileEnv: Record<string, string | undefined> = readEnvFile(intendedEnvFilePath);
dotenv.config({ path: intendedEnvFilePath, override: false });

const intendedGoogleClientId = resolveGoogleClientId({
  processEnv: process.env,
  fileEnv: intendedFileEnv,
});
const intendedGoogleIdToken = resolveGoogleIdToken({
  processToken: process.env.SEAMS_INTENDED_GOOGLE_ID_TOKEN,
  fileToken: intendedFileEnv.SEAMS_INTENDED_GOOGLE_ID_TOKEN,
  clientId: intendedGoogleClientId,
});
if (intendedGoogleIdToken) {
  process.env.SEAMS_INTENDED_GOOGLE_ID_TOKEN = intendedGoogleIdToken;
}

const APP_URL = process.env.SEAMS_INTENDED_APP_URL || 'http://localhost:4001';

export default defineConfig({
  tsconfig: './tsconfig.playwright.json',
  testDir: '.',
  testMatch: [
    '**/e2e/intended-behaviours/**/*.contract.test.ts',
    '**/e2e/linked-device.operating-path.test.ts',
  ],
  fullyParallel: false,
  workers: 1,
  retries: 0,
  globalTimeout: 1_800_000,
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
