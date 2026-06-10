import { expect, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

test('runtime package entry bundle avoids browser implementation modules', () => {
  const output = execFileSync(
    'node',
    ['packages/sdk-web/scripts/checks/assert-runtime-entry-bundles.mjs'],
    {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );

  expect(output).toContain('runtime entry avoids browser bundles');
});
