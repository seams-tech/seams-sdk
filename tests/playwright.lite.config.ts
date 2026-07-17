import * as playwrightNs from '@playwright/test';
import base from './playwright.config';

const defineConfig =
  (playwrightNs as any).defineConfig || (playwrightNs as any).default?.defineConfig;
if (typeof defineConfig !== 'function') {
  throw new Error('Playwright lite config failed to load defineConfig from @playwright/test');
}

export default defineConfig({
  ...base,
});
