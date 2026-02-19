import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect } from '@playwright/test';
import { findStableExperimentalExportBoundaryViolations } from '../../sdk/scripts/lib/stable-experimental-export-boundaries.mjs';

test.describe('stable/experimental export boundary guard', () => {
  test('keeps root stable boundaries and forbids experimental entrypoints', async () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const result = findStableExperimentalExportBoundaryViolations(repoRoot);
    expect(result.error, result.error || undefined).toBeNull();
    for (const check of result.checks) {
      expect(check.violations, check.description).toEqual([]);
    }
  });
});
