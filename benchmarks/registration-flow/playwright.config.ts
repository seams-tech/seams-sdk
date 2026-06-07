import * as playwrightNs from '@playwright/test';
import baseConfig from '../../tests/playwright.config';

const defineConfig =
  (playwrightNs as any).defineConfig || (playwrightNs as any).default?.defineConfig;
if (typeof defineConfig !== 'function') {
  throw new Error('Registration benchmark Playwright config failed to load defineConfig');
}

export default defineConfig({
  ...baseConfig,
  tsconfig: '../../tests/tsconfig.playwright.json',
  testDir: './src',
  testMatch: ['scenario-harness.ts'],
  reporter: 'line',
});
