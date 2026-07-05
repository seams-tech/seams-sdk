import baseConfig from './playwright.config';

export default {
  ...baseConfig,
  webServer: undefined,
  testMatch: [
    '**/unit/**/*.guard.unit.test.ts',
    '**/unit/**/*.behavior.guard.unit.test.ts',
    '**/unit/**/*.domain.guard.unit.test.ts',
    '**/unit/**/*.script.unit.test.ts',
    '**/unit/**/*.source.script.unit.test.ts',
  ],
};
