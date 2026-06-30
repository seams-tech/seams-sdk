import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listSourceFiles(relativeDir: string): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  return fs.readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) return listSourceFiles(relativePath);
    return /\.(ts|tsx)$/.test(entry.name) ? [relativePath] : [];
  });
}

test.describe('IndexedDB consolidation source guards', () => {
  test('signing session persistence uses canonical wallet DB constants', () => {
    const sharedSealSource = readRepoSource('packages/shared-ts/src/utils/signingSessionSeal.ts');
    expect(sharedSealSource).not.toMatch(/SIGNING_SESSION_SEAL_DB_NAME/);
    expect(sharedSealSource).not.toMatch(/SIGNING_SESSION_SEAL_DB_VERSION/);
    expect(sharedSealSource).not.toMatch(/SIGNING_SESSION_SEAL_STORE_NAME/);
    expect(sharedSealSource).not.toMatch(/SIGNING_SESSION_RESTORE_LEASE_STORE_NAME/);

    const repositorySource = readRepoSource(
      'packages/sdk-web/src/core/indexedDB/seamsWalletDB/signingSessionSeals.ts',
    );
    expect(repositorySource).not.toMatch(/SIGNING_SESSION_SEAL_DB_NAME/);
    expect(repositorySource).not.toMatch(/SIGNING_SESSION_SEAL_DB_VERSION/);
  });

  test('raw IndexedDB APIs stay behind persistence boundaries', () => {
    const rawIndexedDbPattern =
      /\bIDB(?:Database|Transaction|ObjectStore|Request|OpenDBRequest|Factory|Index|KeyRange)\b|indexedDB\.open\(/;
    const allowedRuntimePrefixes = ['packages/sdk-web/src/core/indexedDB/'];
    const sourceFiles = [
      ...listSourceFiles('packages/sdk-web/src'),
      ...listSourceFiles('packages/shared-ts/src'),
    ];
    const offenders = sourceFiles.filter((relativePath) => {
      if (allowedRuntimePrefixes.some((prefix) => relativePath.startsWith(prefix))) return false;
      return rawIndexedDbPattern.test(readRepoSource(relativePath));
    });

    expect(offenders).toEqual([]);
  });

  test('runtime code uses the unified manager instead of reaching through to clientDB', () => {
    const directClientDbPattern =
      /\b(?:IndexedDBManager|deps\.indexedDB|args\.indexedDB|args\.deps\.indexedDB|ctx\.indexedDB)\.clientDB\b/;
    const sourceFiles = listSourceFiles('packages/sdk-web/src').filter(
      (relativePath) => relativePath !== 'packages/sdk-web/src/core/indexedDB/unifiedIndexedDBManager.ts',
    );
    const offenders = sourceFiles.filter((relativePath) =>
      directClientDbPattern.test(readRepoSource(relativePath)),
    );

    expect(offenders).toEqual([]);
  });
});
