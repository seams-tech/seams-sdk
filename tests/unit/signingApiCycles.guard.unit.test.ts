import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect } from '@playwright/test';
import { findSigningApiCrossLayerCycles } from '../../sdk/scripts/lib/signing-api-cycles.mjs';

test.describe('signing api cycle guard', () => {
  test('has no api/lower-layer import cycles', async () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const result = findSigningApiCrossLayerCycles(repoRoot);
    expect(result.error, result.error || undefined).toBeNull();
    expect(result.cycles).toEqual([]);
  });
});

