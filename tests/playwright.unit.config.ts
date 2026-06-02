import baseConfig from './playwright.config';

export default {
  ...baseConfig,
  testMatch: ['**/unit/**/*.test.ts'],
  testIgnore: [
    '**/unit/**/*.guard.unit.test.ts',
    '**/unit/**/*.behavior.guard.unit.test.ts',
    '**/unit/**/*.domain.guard.unit.test.ts',
    '**/unit/**/*.guards.test.ts',
    '**/unit/**/*.guardrails.unit.test.ts',
    '**/unit/**/*.script.unit.test.ts',
    '**/unit/**/*.source.script.unit.test.ts',
    '**/unit/**/*.integration.test.ts',
  ],
};
