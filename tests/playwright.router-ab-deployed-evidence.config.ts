import baseConfig from './playwright.config';

export default {
  ...baseConfig,
  webServer: undefined,
  testMatch: ['**/router-ab-deployed-browser-evidence.test.ts'],
  timeout: 120_000,
  workers: 1,
};
