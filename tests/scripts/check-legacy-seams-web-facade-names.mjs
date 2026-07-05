import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const sourceRoots = Object.freeze([
  'packages/sdk-web/src',
  'sdk',
  'tests/unit',
  'tests/e2e',
  'tests/helpers',
  'tests/scripts',
  'docs',
]);

const legacyFacadePatterns = Object.freeze([
  /\bSeamsPasskey\b/,
  /\bPasskeyManagerContext\b/,
  /\bSeamsPasskeyProvider\b/,
  /\bSeamsPasskeyIframe\b/,
]);

const historicalRefactorDocs = Object.freeze([
  'docs/refactor-25-device-num-to-signer-slot.md',
  'docs/refactor-36.md',
  'docs/refactor-36-narrow-lifecycle-types.md',
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
]);

const allowedLegacyFacadeReferences = renameAllowList([
  {
    file: 'tests/scripts/check-legacy-seams-web-facade-names.mjs',
    owner: 'legacy-name source check',
    reason: 'source check contains the banned legacy public symbols it rejects',
  },
  ...historicalRefactorDocs.map((file) => ({
    file,
    owner: 'historical SeamsWeb rename docs',
    reason: 'explicit historical refactor record predates or documents the hard facade rename',
  })),
]);

function renameAllowList(entries) {
  const seen = new Set();
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

function entryMatchesFile(entry, file) {
  if (entry.file) return entry.file === file;
  return Boolean(entry.prefix && file.startsWith(entry.prefix));
}

function isAllowed(file, entries) {
  return entries.some((entry) => entryMatchesFile(entry, file));
}

function listFiles(relativeDir, predicate) {
  const absoluteDir = path.join(repoRoot, relativeDir);
  if (!fs.existsSync(absoluteDir)) return [];
  const entries = fs.readdirSync(absoluteDir, { withFileTypes: true });
  const files = [];
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

function readRepoFile(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function findLegacyFacadeViolations() {
  const violations = [];
  for (const root of sourceRoots) {
    for (const file of listFiles(root, (fileName) => /\.(?:ts|tsx|md|json|sh|mjs)$/.test(fileName))) {
      if (file.startsWith('packages/sdk-web/dist/')) continue;
      const source = readRepoFile(file);
      if (!legacyFacadePatterns.some((pattern) => pattern.test(source))) continue;
      if (isAllowed(file, allowedLegacyFacadeReferences)) continue;
      violations.push(file);
    }
  }
  return violations;
}

const violations = findLegacyFacadeViolations();
if (violations.length > 0) {
  console.error('[check-legacy-seams-web-facade-names] legacy facade references found:');
  for (const violation of violations) console.error(`- ${violation}`);
  process.exitCode = 1;
} else {
  console.log('[check-legacy-seams-web-facade-names] passed');
}
