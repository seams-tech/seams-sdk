import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listFiles(relativeDir: string): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  if (!fs.existsSync(absoluteDir)) return [];
  return fs.readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) return listFiles(relativePath);
    return entry.isFile() ? [relativePath] : [];
  });
}

test.describe('PasskeyAuthMenu public entrypoint guards', () => {
  test('keeps the SSR-safe public entrypoint out of compat-named paths', () => {
    const checkedFiles = [
      'packages/sdk-web/package.json',
      'packages/sdk-web/rolldown.config.ts',
      ...listFiles('packages/sdk-web/src/react').filter((file) => /\.(ts|tsx)$/.test(file)),
      ...listFiles('tests').filter((file) => /\.(ts|tsx)$/.test(file)),
    ].filter((file) => file !== 'tests/unit/passkeyAuthMenuPublicEntry.guard.unit.test.ts');

    const offenders = checkedFiles.filter((file) =>
      readRepoFile(file).includes('passkeyAuthMenuCompat'),
    );

    expect(offenders).toEqual([]);
  });
});
