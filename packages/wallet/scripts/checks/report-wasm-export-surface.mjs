#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sdkRoot = path.resolve(path.join(__dirname, '../..'));
/**
 * `sdkRoot` is `packages/wallet`, so the repo root is two levels up, not one.
 * It read as one for as long as this script existed and still found the wasm
 * packages, because `packages/wasm` is a symlink to `../wasm` — so the only
 * visible symptom was that no source root resolved and every export looked
 * unused.
 */
const repoRoot = path.resolve(path.join(sdkRoot, '../..'));

const help = process.argv.includes('--help') || process.argv.includes('-h');
const jsonOutput = process.argv.includes('--json');
const assertMode = process.argv.includes('--assert');

if (help) {
  console.log(
    `
[report-wasm-export-surface] Audit generated WASM wrapper export usage.

Scans:
  - wasm/*/pkg/*.js generated wasm-bindgen wrappers
  - runtime, build, and test imports across the repo

Reports:
  - exports used by runtime code
  - exports used only by build scripts
  - exports used only by tests/benchmarks
  - exports with no observed import usage
  - imports naming something the generated wrapper does not export

Options:
  --assert    Exit non-zero on imports the wrapper does not export
  --json      Print machine-readable JSON
  -h,--help   Show help
`.trim(),
  );
  process.exit(0);
}

/**
 * Where hand-written source lives. These were the pre-monorepo directory names
 * until 2026-08-07; none of them existed any more, so the scan matched no files
 * and the report called every export unused — which is why nobody read it.
 */
const SOURCE_ROOTS = ['packages', 'apps', 'tests', 'benchmarks', 'examples', 'clients', 'tools'];
const GENERATED_SKIP_SEGMENTS = ['/dist/', '/node_modules/', '/wasm/', '/target/'];

function toPosix(value) {
  return value.split(path.sep).join('/');
}

function walkFiles(rootAbs, include) {
  const out = [];
  if (!fs.existsSync(rootAbs)) return out;
  const stack = [rootAbs];
  while (stack.length > 0) {
    const next = stack.pop();
    if (!next) continue;
    const stat = fs.statSync(next);
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(next)) {
        stack.push(path.join(next, entry));
      }
      continue;
    }
    if (include(next)) out.push(next);
  }
  return out.sort((a, b) => a.localeCompare(b));
}

function categoryForFile(relPath) {
  if (relPath.startsWith('tests/') || relPath.startsWith('benchmarks/')) return 'test';
  if (relPath.startsWith('packages/wallet/scripts/') || relPath.endsWith('rolldown.config.ts')) return 'build';
  return 'runtime';
}

function parseGeneratedExports(source) {
  const names = new Set();
  const functionPattern = /^\s*export function (\w+)\s*\(/gm;
  const classPattern = /^\s*export class (\w+)\s*/gm;
  let match;
  while ((match = functionPattern.exec(source))) names.add(match[1]);
  while ((match = classPattern.exec(source))) names.add(match[1]);
  if (/^\s*export default /m.test(source)) names.add('default');
  return [...names].sort();
}

/**
 * Type-only exports — `InitInput`, `InitOutput`, `SyncInitInput` — exist solely
 * in the generated `.d.ts`. They are legitimate imports, so a check that read
 * only the `.js` would report every one of them as drift.
 */
function parseGeneratedTypeExports(dtsPath) {
  if (!fs.existsSync(dtsPath)) return [];
  const source = fs.readFileSync(dtsPath, 'utf8');
  const names = new Set();
  const pattern =
    /^\s*export\s+(?:declare\s+)?(?:type|interface|class|function|const|enum)\s+(\w+)/gm;
  let match;
  while ((match = pattern.exec(source))) names.add(match[1]);
  if (/^\s*export\s+default\s/m.test(source)) names.add('default');
  return [...names];
}

function parseImportClause(clause) {
  const trimmed = clause.trim();
  const result = {
    named: [],
    /**
     * Named imports written `type X`. They are excluded from usage
     * categorisation — a type import is not a runtime reference — but they are
     * still checked against the wrapper's exports, because a wasm-bindgen class
     * that no longer exists is exactly as broken whether it was imported for
     * its type or its constructor.
     */
    namedTypes: [],
    defaultAlias: null,
    namespaceAlias: null,
    isTypeOnly: false,
  };
  if (!trimmed) return result;
  let rest = trimmed;
  if (rest.startsWith('type ')) {
    result.isTypeOnly = true;
    rest = rest.slice('type '.length).trim();
  }
  const namedStart = rest.indexOf('{');
  if (namedStart >= 0) {
    const namedEnd = rest.lastIndexOf('}');
    const namedInner = rest.slice(namedStart + 1, namedEnd);
    for (const rawPart of namedInner.split(',')) {
      const part = rawPart.trim();
      if (!part) continue;
      const isType = result.isTypeOnly || part.startsWith('type ');
      const [imported] = (isType ? part.replace(/^type\s+/, '') : part).split(/\s+as\s+/);
      const cleanImported = imported.trim();
      if (!cleanImported) continue;
      if (isType) result.namedTypes.push(cleanImported);
      else result.named.push(cleanImported);
    }
    rest = rest.slice(0, namedStart).replace(/,\s*$/, '').trim();
  }
  if (result.isTypeOnly) return result;
  if (rest.startsWith('* as ')) {
    result.namespaceAlias = rest.slice('* as '.length).trim();
    return result;
  }
  if (rest) {
    result.defaultAlias = rest.replace(/,$/, '').trim() || null;
  }
  return result;
}

function parseFileImports(source, packageSuffixes) {
  const imports = [];
  const importPattern = /\bimport\s+([\s\S]*?)\s+from\s+['"]([^'"]+)['"]/gm;
  let match;
  while ((match = importPattern.exec(source))) {
    const clause = match[1];
    const specifier = match[2];
    const matchedSuffix = packageSuffixes.find((suffix) => specifier.endsWith(suffix));
    if (!matchedSuffix) continue;
    const parsed = parseImportClause(clause);
    imports.push({
      packageSuffix: matchedSuffix,
      named: parsed.named,
      namedTypes: parsed.namedTypes,
      defaultAlias: parsed.defaultAlias,
      namespaceAlias: parsed.namespaceAlias,
    });
  }
  return imports;
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function addRef(refs, exportName, entry) {
  const bucket = refs.get(exportName);
  if (!bucket) return;
  bucket.push(entry);
}

const packageFiles = walkFiles(path.join(repoRoot, 'wasm'), (absPath) => {
  const relPath = toPosix(path.relative(repoRoot, absPath));
  return /\/pkg\/[^/]+\.js$/.test(relPath) && !relPath.endsWith('_bg.js');
}).map((absPath) => ({
  absPath,
  relPath: toPosix(path.relative(repoRoot, absPath)),
  packageName: path.basename(path.dirname(path.dirname(absPath))),
}));

const packageSuffixes = packageFiles.map((pkg) => pkg.relPath);
const sourceFiles = SOURCE_ROOTS.flatMap((root) =>
  walkFiles(path.join(repoRoot, root), (absPath) => {
    const relPath = toPosix(path.relative(repoRoot, absPath));
    if (!/\.(cjs|cts|js|jsx|mjs|mts|ts|tsx)$/.test(relPath)) return false;
    if (GENERATED_SKIP_SEGMENTS.some((segment) => relPath.includes(segment))) return false;
    return true;
  }),
);

const sourceRecords = sourceFiles.map((absPath) => {
  const relPath = toPosix(path.relative(repoRoot, absPath));
  const source = fs.readFileSync(absPath, 'utf8');
  return {
    absPath,
    relPath,
    category: categoryForFile(relPath),
    source,
    imports: parseFileImports(source, packageSuffixes),
  };
});

const report = [];

for (const pkg of packageFiles) {
  const source = fs.readFileSync(pkg.absPath, 'utf8');
  const exportNames = parseGeneratedExports(source);
  const refs = new Map(exportNames.map((name) => [name, []]));
  const unknownImports = [];
  // Usage categorisation stays over the runtime exports; the type exports only
  // widen what counts as a resolvable import.
  const importableNames = new Set([
    ...exportNames,
    ...parseGeneratedTypeExports(pkg.absPath.replace(/\.js$/, '.d.ts')),
  ]);

  for (const file of sourceRecords) {
    const imports = file.imports.filter((entry) => entry.packageSuffix === pkg.relPath);
    if (imports.length === 0) continue;
    for (const entry of imports) {
      // An import naming something the wrapper does not export. This is the
      // drift catch: `pkg/` is a gitignored build artifact, so a stale one lets
      // `tsc` validate source against generated typings for code that is gone.
      for (const named of [...entry.named, ...entry.namedTypes]) {
        if (!importableNames.has(named)) {
          unknownImports.push({ file: file.relPath, exportName: named });
        }
      }
      for (const named of entry.named) {
        addRef(refs, named, { category: file.category, file: file.relPath, via: 'named' });
      }
      if (entry.defaultAlias) {
        addRef(refs, 'default', { category: file.category, file: file.relPath, via: 'default' });
      }
      if (entry.namespaceAlias) {
        for (const exportName of exportNames) {
          if (exportName === 'default') continue;
          const usagePatterns = [
            new RegExp(`\\b${escapeRegex(entry.namespaceAlias)}\\.${escapeRegex(exportName)}\\b`, 'g'),
            new RegExp(`\\.${escapeRegex(exportName)}\\b`, 'g'),
            new RegExp(`\\[['"]${escapeRegex(exportName)}['"]\\]`, 'g'),
          ];
          if (usagePatterns.some((pattern) => pattern.test(file.source))) {
            addRef(refs, exportName, {
              category: file.category,
              file: file.relPath,
              via: `namespace:${entry.namespaceAlias}`,
            });
          }
        }
      }
    }
  }

  const exportRows = exportNames.map((name) => {
    const matches = refs.get(name) || [];
    const runtime = matches.filter((entry) => entry.category === 'runtime');
    const build = matches.filter((entry) => entry.category === 'build');
    const test = matches.filter((entry) => entry.category === 'test');
    let status = 'unused';
    if (runtime.length > 0) status = 'runtime';
    else if (build.length > 0) status = 'build_only';
    else if (test.length > 0) status = 'test_only';
    return {
      exportName: name,
      status,
      references: matches,
    };
  });

  report.push({
    packageName: pkg.packageName,
    packagePath: pkg.relPath,
    exports: exportRows,
    unknownImports,
    counts: {
      total: exportRows.length,
      runtime: exportRows.filter((row) => row.status === 'runtime').length,
      buildOnly: exportRows.filter((row) => row.status === 'build_only').length,
      testOnly: exportRows.filter((row) => row.status === 'test_only').length,
      unused: exportRows.filter((row) => row.status === 'unused').length,
    },
  });
}

const allUnknownImports = report.flatMap((pkg) =>
  pkg.unknownImports.map((entry) => ({ packageName: pkg.packageName, ...entry })),
);

if (jsonOutput) {
  console.log(JSON.stringify({ packages: report, unknownImports: allUnknownImports }, null, 2));
  process.exit(assertMode && allUnknownImports.length > 0 ? 1 : 0);
}

if (assertMode) {
  if (allUnknownImports.length === 0) {
    console.log(
      `[report-wasm-export-surface] OK: every wasm wrapper import resolves to an export (${report.length} packages)`,
    );
    process.exit(0);
  }
  console.error(
    '[report-wasm-export-surface] FAIL: imports name exports the generated wrapper does not have.',
  );
  console.error(
    '  A stale pkg/ is the usual cause — it is a gitignored build artifact, so tsc may be',
  );
  console.error('  checking your source against typings for code that no longer exists.');
  console.error('  Rebuild the package, then re-run. If it still fails, the import is wrong.');
  for (const entry of allUnknownImports) {
    console.error(`    - ${entry.file} imports ${entry.exportName} from ${entry.packageName}`);
  }
  process.exit(1);
}

console.log('[report-wasm-export-surface] Generated WASM wrapper export audit');

for (const pkg of report) {
  console.log(`\n${pkg.packageName} (${pkg.packagePath})`);
  console.log(
    `  exports: ${pkg.counts.total}, runtime: ${pkg.counts.runtime}, build-only: ${pkg.counts.buildOnly}, test-only: ${pkg.counts.testOnly}, unused: ${pkg.counts.unused}`,
  );
  const groups = [
    ['runtime', 'runtime-used'],
    ['build_only', 'build-only'],
    ['test_only', 'test-only'],
    ['unused', 'unused'],
  ];
  for (const [status, label] of groups) {
    const rows = pkg.exports.filter((row) => row.status === status);
    if (rows.length === 0) continue;
    console.log(`  ${label}:`);
    for (const row of rows) {
      if (row.references.length === 0) {
        console.log(`    - ${row.exportName}`);
        continue;
      }
      const refsByFile = row.references.map((ref) => `${ref.file} (${ref.via})`);
      console.log(`    - ${row.exportName}: ${refsByFile.join(', ')}`);
    }
  }
}
