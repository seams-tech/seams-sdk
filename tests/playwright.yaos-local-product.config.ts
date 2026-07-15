import baseConfig from './playwright.intended.ci.config';
import testSlice from './yaos-local-product-test-slice.json' with { type: 'json' };

function toPlaywrightTestMatch(testFile: string): string {
  return `**/${testFile}`;
}

export default {
  ...baseConfig,
  testMatch: testSlice.test_files.map(toPlaywrightTestMatch),
};
