import { defineConfig } from '@playwright/test';

// Minimal stand-alone config used by unit/collectionGuard.unit.test.ts. It mirrors
// how playwright.unit.config.ts wires the guard reporter, over a two-file fixture
// suite (one healthy file, one that fails to link) so the regression test can run
// in ~seconds without touching the real unit suite.
export default defineConfig({
  testDir: '.',
  testMatch: ['**/*.spec.ts'],
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['line'], ['../../failOnCollectionErrors.ts']],
});
