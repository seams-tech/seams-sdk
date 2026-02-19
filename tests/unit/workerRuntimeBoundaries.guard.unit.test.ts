import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect } from '@playwright/test';
import { findWorkerRuntimeBoundaryViolations } from '../../sdk/scripts/lib/worker-runtime-boundaries.mjs';

test.describe('worker/runtime boundary guard', () => {
  test('keeps worker/runtime boundary guarantees intact', async () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const result = findWorkerRuntimeBoundaryViolations(repoRoot);
    expect(result.error, result.error || undefined).toBeNull();
    for (const check of result.checks) {
      expect(check.violations, check.description).toEqual([]);
    }
  });
});
