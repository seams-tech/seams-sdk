import baseConfig from './playwright.config';

export default {
  ...baseConfig,
  webServer: undefined,
  testMatch: ['**/unit/router.relayRouteSurface.unit.test.ts'],
};
