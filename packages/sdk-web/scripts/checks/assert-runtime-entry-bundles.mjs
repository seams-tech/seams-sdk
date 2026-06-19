#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sdkRoot = path.resolve(path.join(__dirname, '../..'));
const distEsmRoot = path.join(sdkRoot, 'dist', 'esm');

const entryFiles = ['runtime.js'];
const expectedRuntimeValueExports = ['createSigningRuntime', 'createSigningRuntimeStatePorts'];
const forbiddenResolvedPathPatterns = [
  /(^|\/)react(\/|$)/,
  /(^|\/)web\/SeamsWeb(\/|$)/,
  /(^|\/)core\/WalletIframe(\/|$)/,
  /(^|\/)core\/platform\/browser(\/|$)/,
  /(^|\/)core\/indexedDB(\/|$)/,
];
const forbiddenSourcePatterns = [
  /\bwindow\b/,
  /\bdocument\b/,
  /\bnavigator\b/,
  /\bIndexedDBManager\b/,
  /\bUnifiedIndexedDBManager\b/,
  /\bWalletIframe\b/,
  /\bSeamsWeb\b/,
];

function fail(message) {
  console.error(`\n[assert-runtime-entry-bundles] ${message}`);
  process.exit(1);
}

function read(file) {
  return fs.readFileSync(file, 'utf8');
}

function normalizeDistPath(absPath) {
  return path.relative(distEsmRoot, absPath).split(path.sep).join('/');
}

function resolveRelativeImport(fromFile, specifier) {
  if (!specifier.startsWith('.')) return null;
  const base = path.resolve(path.dirname(fromFile), specifier);
  const candidates = [base, `${base}.js`, path.join(base, 'index.js')];
  return candidates.find((candidate) => fs.existsSync(candidate) && fs.statSync(candidate).isFile());
}

function importSpecifiers(source) {
  const specifiers = [];
  const patterns = [
    /\bimport\s+(?:[^'"]*?\s+from\s+)?['"]([^'"]+)['"]/g,
    /\bexport\s+(?:[^'"]*?\s+from\s+)['"]([^'"]+)['"]/g,
  ];
  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(source))) {
      specifiers.push(match[1]);
    }
  }
  return specifiers;
}

async function assertPublicRuntimeValueExports() {
  let runtimeModule;
  try {
    runtimeModule = await import('@seams/sdk/runtime');
  } catch (error) {
    fail(`Failed to import @seams/sdk/runtime from the built package: ${error.message}`);
  }

  const missing = expectedRuntimeValueExports.filter(
    (exportName) => typeof runtimeModule[exportName] !== 'function',
  );
  if (missing.length > 0) {
    fail(`Missing @seams/sdk/runtime value export(s): ${missing.join(', ')}`);
  }
}

if (!fs.existsSync(distEsmRoot)) {
  fail(`Missing directory: ${distEsmRoot}. Run pnpm -C sdk build first.`);
}

const missingEntries = entryFiles.filter((entry) => !fs.existsSync(path.join(distEsmRoot, entry)));
if (missingEntries.length > 0) {
  fail(`Missing runtime package entry output(s): ${missingEntries.join(', ')}`);
}

await assertPublicRuntimeValueExports();

const offenders = [];

for (const entry of entryFiles) {
  const entryAbs = path.join(distEsmRoot, entry);
  const queue = [entryAbs];
  const seen = new Set();

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current || seen.has(current)) continue;
    seen.add(current);

    const rel = normalizeDistPath(current);
    for (const pattern of forbiddenResolvedPathPatterns) {
      if (pattern.test(rel)) {
        offenders.push(`${entry} imports forbidden built module ${rel}`);
      }
    }

    const source = read(current);
    for (const pattern of forbiddenSourcePatterns) {
      if (pattern.test(source)) {
        offenders.push(`${entry} graph contains forbidden browser source in ${rel}: ${pattern}`);
      }
    }

    for (const specifier of importSpecifiers(source)) {
      const resolved = resolveRelativeImport(current, specifier);
      if (resolved && resolved.startsWith(distEsmRoot)) {
        queue.push(resolved);
      }
    }
  }
}

if (offenders.length > 0) {
  console.error('[assert-runtime-entry-bundles] Runtime entry bundle violations:');
  for (const offender of offenders.slice(0, 80)) {
    console.error(`  - ${offender}`);
  }
  if (offenders.length > 80) console.error(`  ...and ${offenders.length - 80} more`);
  process.exit(1);
}

console.log(
  '[assert-runtime-entry-bundles] OK: runtime entry avoids browser bundles and exposes public runtime values',
);
