import * as playwrightNs from '@playwright/test';

const defineConfig =
  (playwrightNs as any).defineConfig || (playwrightNs as any).default?.defineConfig;
if (typeof defineConfig !== 'function') {
  throw new Error('Playwright source config failed to load defineConfig from @playwright/test');
}

export default defineConfig({
  tsconfig: './tsconfig.playwright.json',
  build: { external: ['wasm/**/pkg/**'] },
  testDir: '.',
  testMatch: ['**/unit/*.guard.unit.test.ts'],
  fullyParallel: false,
  retries: 0,
  workers: 1,
  timeout: 30_000,
  reporter: 'html',
});
