import baseConfig from './playwright.intended.config';

export default {
  ...baseConfig,
  testMatch: ['**/e2e/intended-behaviours/**/*.benchmark.test.ts'],
};
