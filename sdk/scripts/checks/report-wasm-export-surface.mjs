#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sdkRoot = path.resolve(path.join(__dirname, '../..'));
const repoRoot = path.resolve(path.join(sdkRoot, '..'));

const help = process.argv.includes('--help') || process.argv.includes('-h');
const jsonOutput = process.argv.includes('--json');

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

Options:
  --json      Print machine-readable JSON
  -h,--help   Show help
`.trim(),
  );
  process.exit(0);
}

const SOURCE_ROOTS = ['client', 'server', 'shared', 'tests', 'benchmarks', 'sdk', 'examples'];
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
  if (relPath.startsWith('sdk/scripts/') || relPath.endsWith('rolldown.config.ts')) return 'build';
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

function parseImportClause(clause) {
  const trimmed = clause.trim();
  const result = {
    named: [],
    defaultAlias: null,
    namespaceAlias: null,
    isTypeOnly: false,
  };
  if (!trimmed) return result;
  if (trimmed.startsWith('type ')) {
    result.isTypeOnly = true;
    return result;
  }
  let rest = trimmed;
  const namedStart = rest.indexOf('{');
  if (namedStart >= 0) {
    const namedEnd = rest.lastIndexOf('}');
    const namedInner = rest.slice(namedStart + 1, namedEnd);
    for (const rawPart of namedInner.split(',')) {
      const part = rawPart.trim();
      if (!part || part.startsWith('type ')) continue;
      const [imported] = part.split(/\s+as\s+/);
      const cleanImported = imported.trim();
      if (cleanImported) result.named.push(cleanImported);
    }
    rest = rest.slice(0, namedStart).replace(/,\s*$/, '').trim();
  }
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
    if (parsed.isTypeOnly) continue;
    imports.push({
      packageSuffix: matchedSuffix,
      named: parsed.named,
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

  for (const file of sourceRecords) {
    const imports = file.imports.filter((entry) => entry.packageSuffix === pkg.relPath);
    if (imports.length === 0) continue;
    for (const entry of imports) {
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
    counts: {
      total: exportRows.length,
      runtime: exportRows.filter((row) => row.status === 'runtime').length,
      buildOnly: exportRows.filter((row) => row.status === 'build_only').length,
      testOnly: exportRows.filter((row) => row.status === 'test_only').length,
      unused: exportRows.filter((row) => row.status === 'unused').length,
    },
  });
}

if (jsonOutput) {
  console.log(JSON.stringify({ packages: report }, null, 2));
  process.exit(0);
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
