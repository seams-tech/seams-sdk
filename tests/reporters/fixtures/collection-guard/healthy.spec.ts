import { expect, test } from '@playwright/test';
import { presentExport } from './moduleUnderTest';

test('loads and passes', () => {
  expect(presentExport).toBe('present');
});
