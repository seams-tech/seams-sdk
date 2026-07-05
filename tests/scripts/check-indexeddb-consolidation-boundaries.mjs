#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');

const rawIndexedDbPattern =
  /\bIDB(?:Database|Transaction|ObjectStore|Request|OpenDBRequest|Factory|Index|KeyRange)\b|indexedDB\.open\(/;
const allowedRuntimePrefixes = ['packages/sdk-web/src/core/indexedDB/'];
const directClientDbPattern =
  /\b(?:IndexedDBManager|deps\.indexedDB|args\.indexedDB|args\.deps\.indexedDB|ctx\.indexedDB)\.clientDB\b/;

function absolutePath(relativePath) {
  return path.join(repoRoot, relativePath);
}

function readRepoSource(relativePath) {
  return fs.readFileSync(absolutePath(relativePath), 'utf8');
}

function listTypeScriptFiles(relativeDir) {
  const absoluteDir = absolutePath(relativeDir);
  if (!fs.existsSync(absoluteDir)) return [];

  return fs.readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name).split(path.sep).join('/');
    if (entry.isDirectory()) return listTypeScriptFiles(relativePath);
    return /\.(ts|tsx)$/.test(entry.name) ? [relativePath] : [];
  });
}

function collectCanonicalWalletDbConstantViolations() {
  const violations = [];
  const sharedSealSource = readRepoSource('packages/shared-ts/src/utils/signingSessionSeal.ts');

  for (const forbidden of [
    'SIGNING_SESSION_SEAL_DB_NAME',
    'SIGNING_SESSION_SEAL_DB_VERSION',
    'SIGNING_SESSION_SEAL_STORE_NAME',
    'SIGNING_SESSION_RESTORE_LEASE_STORE_NAME',
  ]) {
    if (sharedSealSource.includes(forbidden)) {
      violations.push(`packages/shared-ts/src/utils/signingSessionSeal.ts: contains ${forbidden}`);
    }
  }

  const repositorySource = readRepoSource(
    'packages/sdk-web/src/core/indexedDB/seamsWalletDB/signingSessionSeals.ts',
  );
  for (const forbidden of ['SIGNING_SESSION_SEAL_DB_NAME', 'SIGNING_SESSION_SEAL_DB_VERSION']) {
    if (repositorySource.includes(forbidden)) {
      violations.push(
        `packages/sdk-web/src/core/indexedDB/seamsWalletDB/signingSessionSeals.ts: contains ${forbidden}`,
      );
    }
  }

  return violations;
}

function collectRawIndexedDbViolations() {
  const sourceFiles = [
    ...listTypeScriptFiles('packages/sdk-web/src'),
    ...listTypeScriptFiles('packages/shared-ts/src'),
  ];

  return sourceFiles.filter((relativePath) => {
    if (allowedRuntimePrefixes.some((prefix) => relativePath.startsWith(prefix))) return false;
    return rawIndexedDbPattern.test(readRepoSource(relativePath));
  });
}

function collectDirectClientDbViolations() {
  return listTypeScriptFiles('packages/sdk-web/src')
    .filter(
      (relativePath) => relativePath !== 'packages/sdk-web/src/core/indexedDB/unifiedIndexedDBManager.ts',
    )
    .filter((relativePath) => directClientDbPattern.test(readRepoSource(relativePath)));
}

function main() {
  const violations = [
    ...collectCanonicalWalletDbConstantViolations(),
    ...collectRawIndexedDbViolations().map(
      (relativePath) => `${relativePath}: raw IndexedDB API outside persistence boundary`,
    ),
    ...collectDirectClientDbViolations().map(
      (relativePath) => `${relativePath}: reaches through UnifiedIndexedDBManager.clientDB`,
    ),
  ];

  if (violations.length > 0) {
    console.error('[check-indexeddb-consolidation-boundaries] failed');
    for (const violation of violations) {
      console.error(`- ${violation}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log('[check-indexeddb-consolidation-boundaries] passed');
}

main();
