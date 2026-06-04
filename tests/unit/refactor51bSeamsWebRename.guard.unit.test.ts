import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

type RenameAllowListEntry = {
  file?: string;
  prefix?: string;
  owner: string;
  reason: string;
};

function renameAllowList(entries: readonly RenameAllowListEntry[]): readonly RenameAllowListEntry[] {
  const seen = new Set<string>();
  for (const entry of entries) {
    const key = entry.file ? `file:${entry.file}` : `prefix:${entry.prefix}`;
    if (!entry.file && !entry.prefix) {
      throw new Error('Rename allow-list entry requires file or prefix');
    }
    if (seen.has(key)) {
      throw new Error(`Duplicate rename allow-list entry: ${key}`);
    }
    seen.add(key);
    if (!entry.owner.trim() || !entry.reason.trim()) {
      throw new Error(`Incomplete rename allow-list entry: ${key}`);
    }
  }
  return entries;
}

function entryMatchesFile(entry: RenameAllowListEntry, file: string): boolean {
  if (entry.file) return entry.file === file;
  return Boolean(entry.prefix && file.startsWith(entry.prefix));
}

function isAllowed(file: string, entries: readonly RenameAllowListEntry[]): boolean {
  return entries.some((entry) => entryMatchesFile(entry, file));
}

function listFiles(relativeDir: string, predicate: (fileName: string) => boolean): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  if (!fs.existsSync(absoluteDir)) return [];
  const entries = fs.readdirSync(absoluteDir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listFiles(relativePath, predicate));
      continue;
    }
    if (entry.isFile() && predicate(entry.name)) {
      files.push(relativePath);
    }
  }
  return files;
}

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

const sourceRoots = [
  'client/src',
  'sdk',
  'tests/unit',
  'tests/e2e',
  'tests/helpers',
  'docs',
];

const legacyFacadePatterns = [
  /\bSeamsPasskey\b/,
  /\bPasskeyManagerContext\b/,
  /\bSeamsPasskeyProvider\b/,
  /\bSeamsPasskeyIframe\b/,
];

const historicalRefactorDocs = [
  'docs/refactor-25-device-num-to-signer-slot.md',
  'docs/refactor-36.md',
  'docs/refactor-36a-reduce-near-account-id-usage.md',
  'docs/refactor-37.md',
  'docs/refactor-39.md',
  'docs/refactor-43-cleanup.md',
  'docs/refactor-44-bundle-size-optimization.md',
  'docs/refactor-45-consolidate-indexeddb-tables.md',
  'docs/refactor-46d-bugs.md',
  'docs/refactor-50-cross-platform-inventory.md',
  'docs/refactor-51-cross-platform-2.md',
  'docs/refactor-51b-cross-platform-3.md',
  'docs/refactor-51b-inventory.md',
] as const;

const allowedLegacyFacadeReferences = renameAllowList([
  {
    file: 'tests/unit/refactor51bSeamsWebRename.guard.unit.test.ts',
    owner: 'legacy-name guard fixture',
    reason: 'guard fixture contains the banned legacy public symbols it rejects',
  },
  ...historicalRefactorDocs.map((file) => ({
    file,
    owner: 'historical SeamsWeb rename docs',
    reason: 'explicit historical refactor record predates or documents the hard facade rename',
  })),
]);

test.describe('refactor 51b SeamsWeb rename guard', () => {
  test('keeps legacy browser facade names confined to historical docs and this guard', () => {
    const violations: string[] = [];
    for (const root of sourceRoots) {
      for (const file of listFiles(root, (fileName) => /\.(?:ts|tsx|md|json|sh)$/.test(fileName))) {
        if (file.startsWith('sdk/dist/')) continue;
        const source = readRepoFile(file);
        if (!legacyFacadePatterns.some((pattern) => pattern.test(source))) continue;
        if (isAllowed(file, allowedLegacyFacadeReferences)) continue;
        violations.push(file);
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });
});
