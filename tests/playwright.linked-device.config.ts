import baseConfig from './playwright.intended.config';

export default {
  ...baseConfig,
  globalTimeout: 1_200_000,
  timeout: 540_000,
  testMatch: ['**/e2e/linked-device.operating-path.test.ts'],
  webServer: undefined,
  use: {
    ...baseConfig.use,
    trace: 'off',
    video: 'off',
  },
};
