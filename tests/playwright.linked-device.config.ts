import baseConfig from './playwright.intended.config';

export default {
  ...baseConfig,
  testMatch: ['**/e2e/linked-device.operating-path.test.ts'],
  webServer: undefined,
  use: {
    ...baseConfig.use,
    trace: 'off',
    video: 'off',
  },
};
