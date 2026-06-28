import baseConfig from './playwright.config';

export default {
  ...baseConfig,
  webServer: undefined,
  testMatch: ['**/unit/router.routerApiRouteSurface.unit.test.ts'],
};
