import baseConfig from './playwright.config';
import testSlice from './yaos-local-test-slice.json' with { type: 'json' };

function toPlaywrightTestMatch(testFile: string): string {
  return `**/${testFile}`;
}

export default {
  ...baseConfig,
  testMatch: testSlice.test_files.map(toPlaywrightTestMatch),
  testIgnore: [],
  timeout: 180_000,
  webServer: undefined,
};
