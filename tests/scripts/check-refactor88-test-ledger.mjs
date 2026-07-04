#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');
const docPath = path.join(repoRoot, 'docs/refactor-88-intended-behaviour-e2e.md');

const scopeRoots = [
  'tests/unit',
  'tests/e2e',
  'tests/relayer',
  'tests/lit-components',
  'tests/wallet-iframe',
];

const args = new Set(process.argv.slice(2));
const listMissing = args.has('--list-missing');
const requireComplete = args.has('--require-complete');

function toRepoPath(absolutePath) {
  return path.relative(repoRoot, absolutePath).split(path.sep).join('/');
}

function listFiles(directory) {
  const entries = fs.readdirSync(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const absolutePath = path.join(directory, entry.name);

    if (entry.isDirectory()) {
      files.push(...listFiles(absolutePath));
      continue;
    }

    if (entry.isFile()) {
      files.push(toRepoPath(absolutePath));
    }
  }

  return files;
}

function collectScopeFiles() {
  return new Set(
    scopeRoots.flatMap((root) => listFiles(path.join(repoRoot, root))).sort(),
  );
}

function pathInScope(candidate) {
  return scopeRoots.some((root) => candidate === root || candidate.startsWith(`${root}/`));
}

function collectLedgerPaths() {
  const source = fs.readFileSync(docPath, 'utf8');
  const lines = source.split(/\r?\n/);
  const ledgerPaths = new Set();
  let inLedgerTable = false;

  for (const line of lines) {
    if (line.startsWith('| Target | Classification | Reason |')) {
      inLedgerTable = true;
      continue;
    }

    if (inLedgerTable && line.startsWith('### Phase 6:')) {
      break;
    }

    if (!inLedgerTable || !line.startsWith('| `')) {
      continue;
    }

    for (const match of line.matchAll(/`([^`]+)`/g)) {
      if (pathInScope(match[1])) {
        ledgerPaths.add(match[1]);
      }
    }
  }

  return ledgerPaths;
}

const scopeFiles = collectScopeFiles();
const ledgerPaths = collectLedgerPaths();
const existingLedgerPaths = [...ledgerPaths].filter((ledgerPath) => scopeFiles.has(ledgerPath)).sort();
const deletedLedgerPaths = [...ledgerPaths].filter((ledgerPath) => !scopeFiles.has(ledgerPath)).sort();
const missingLedgerPaths = [...scopeFiles].filter((scopeFile) => !ledgerPaths.has(scopeFile)).sort();

console.log(
  `[refactor88-test-ledger] scope=${scopeFiles.size} ledger_existing=${existingLedgerPaths.length} ledger_deleted=${deletedLedgerPaths.length} missing=${missingLedgerPaths.length}`,
);

if (listMissing) {
  for (const missingPath of missingLedgerPaths) {
    console.log(missingPath);
  }
}

if (requireComplete && missingLedgerPaths.length > 0) {
  process.exitCode = 1;
}
