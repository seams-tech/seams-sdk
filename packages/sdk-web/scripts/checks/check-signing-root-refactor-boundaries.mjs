#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../../../..');

const scanRoots = ['server', 'client', 'examples', 'tests', 'docs', 'crates/threshold-prf', 'wasm/threshold_prf'];
const includedExtensions = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.mjs',
  '.cjs',
  '.md',
  '.toml',
  '.json',
]);
const ignoredDirNames = new Set([
  '.git',
  'node_modules',
  'dist',
  'target',
  'pkg',
  'pkg-server',
  'test-results',
  'playwright-report',
]);

const forbiddenPatterns = [
  {
    pattern: /\bTenantRoot\b|\btenantRoot\b|tenant-root|\bTENANT_ROOT\b|\bProjectRoot\b|\bprojectRoot\b|project-root|\bproject_root\b|\bPROJECT_ROOT\b/,
    message: 'legacy tenant-root/project-root naming is not allowed; use signing-root names',
  },
  {
    pattern: /\bTHRESHOLD_[A-Z0-9_]*MASTER_SECRET\b/,
    message: 'threshold master-secret env vars are not allowed; use signing-root secret shares',
  },
  {
    pattern: /signingRootId\s*:\s*(?:input\.)?context\.orgId\b/,
    message:
      'signingRootId must not be sourced from HSS context.orgId; carry signing-root scope explicitly',
  },
  {
    pattern: /resolveSigningRootSharePair\s*\([^)]*projectId\s*:/s,
    message: 'signing-root resolver input must use signingRootId, not projectId',
  },
];

function* walkFiles(rootDir) {
  const entries = fs.readdirSync(rootDir, { withFileTypes: true });
  for (const entry of entries) {
    if (ignoredDirNames.has(entry.name)) continue;
    const fullPath = path.join(rootDir, entry.name);
    if (entry.isDirectory()) {
      yield* walkFiles(fullPath);
      continue;
    }
    if (!entry.isFile()) continue;
    if (!includedExtensions.has(path.extname(entry.name))) continue;
    yield fullPath;
  }
}

function lineNumberForOffset(text, offset) {
  let line = 1;
  for (let i = 0; i < offset; i += 1) {
    if (text.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

function main() {
  const violations = [];
  for (const root of scanRoots) {
    const rootDir = path.join(repoRoot, root);
    if (!fs.existsSync(rootDir)) continue;
    for (const filePath of walkFiles(rootDir)) {
      const text = fs.readFileSync(filePath, 'utf8');
      for (const rule of forbiddenPatterns) {
        rule.pattern.lastIndex = 0;
        const match = rule.pattern.exec(text);
        if (!match) continue;
        violations.push({
          file: path.relative(repoRoot, filePath),
          line: lineNumberForOffset(text, match.index),
          message: rule.message,
          match: match[0],
        });
      }
    }
  }

  if (!violations.length) {
    console.log('[check-signing-root-refactor-boundaries] OK');
    return;
  }

  console.error('[check-signing-root-refactor-boundaries] failed');
  for (const violation of violations) {
    console.error(
      `  - ${violation.file}:${violation.line}: ${violation.message} (${JSON.stringify(
        violation.match,
      )})`,
    );
  }
  process.exit(1);
}

main();
