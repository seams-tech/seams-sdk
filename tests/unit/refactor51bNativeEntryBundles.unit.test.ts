import { expect, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

test('native-facing package entry bundles avoid browser implementation modules', () => {
  const output = execFileSync(
    'node',
    ['sdk/scripts/checks/assert-native-package-entry-bundles.mjs'],
    {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );

  expect(output).toContain('native-facing entries avoid browser bundles');
});
