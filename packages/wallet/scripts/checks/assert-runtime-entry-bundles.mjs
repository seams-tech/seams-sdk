#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sdkRoot = path.resolve(path.join(__dirname, '../..'));
const distEsmRoot = path.join(sdkRoot, 'dist', 'esm');

const entryFiles = ['runtime.js'];
const walletIframeHostEntryFiles = [
  'sdk/wallet-iframe-host-runtime.js',
  'sdk/wallet-iframe-host-near.js',
  'sdk/wallet-iframe-host-ecdsa.js',
  'sdk/wallet-iframe-host-full.js',
];
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
const forbiddenWalletIframeHostPathPatterns = [
  /(^|\/)react(?:\/|[-.]|$)/i,
  /(^|\/)react-dom(?:\/|[-.]|$)/i,
  /(^|\/)lucide-react(?:\/|[-.]|$)/i,
  /(?:^|\/)packages\/sdk-web\/src\/react(?:\/|$)/i,
];
const forbiddenWalletIframeHostSourcePatterns = [
  /(?:^|\r?\n)\s*\/\/#region\s+(?:(?:\.\.\/|[^/\r\n]+[\\/]))*src[\\/]react(?:[\\/]|$)/i,
  /(?:^|\r?\n)\s*\/\/#region\s+(?:(?:\.\.\/|[^/\r\n]+[\\/]))*node_modules[\\/](?:react|react-dom|lucide-react)(?:[\\/]|$)/i,
  /(?:^|[^\w$])(?:var|let|const)\s+React(?:DOM)?\s*=/,
];
const inlinedReactSymbolPattern = /Symbol\.for\(\s*['"]react\.(?:element|fragment)['"]\s*\)/;
const inlinedReactRuntimePattern =
  /\b(?:ReactCurrentDispatcher|ReactCurrentOwner|ReactSharedInternals|__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED|createRoot|hydrateRoot|jsxDEV|jsxs|createElement)\b/;
const forbiddenWalletIframeHostSourcePredicates = [
  {
    label: 'inlined React runtime markers',
    test: (source) =>
      inlinedReactSymbolPattern.test(source) && inlinedReactRuntimePattern.test(source),
  },
];

function fail(message) {
  console.error(`\n[assert-runtime-entry-bundles] ${message}`);
  process.exit(1);
}

function read(file) {
  return fs.readFileSync(file, 'utf8');
}

function normalizeDistPath(absPath, root = distEsmRoot) {
  return path.relative(root, absPath).split(path.sep).join('/');
}

function resolveRelativeImport(fromFile, specifier) {
  if (!specifier.startsWith('.')) return null;
  const base = path.resolve(path.dirname(fromFile), specifier);
  const candidates = [base, `${base}.js`, path.join(base, 'index.js')];
  return candidates.find(
    (candidate) => fs.existsSync(candidate) && fs.statSync(candidate).isFile(),
  );
}

function importSpecifiers(source, { includeDynamicImports = false } = {}) {
  const specifiers = [];
  const patterns = [
    /\bimport\s+(?:[^'"]*?\s+from\s+)?['"]([^'"]+)['"]/g,
    /\bexport\s+(?:[^'"]*?\s+from\s+)['"]([^'"]+)['"]/g,
    /\b(?:require|module\.require)\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];
  if (includeDynamicImports) {
    patterns.push(/\bimport\s*\(\s*(?:\/\*[\s\S]*?\*\/\s*)?['"]([^'"]+)['"]\s*\)/g);
  }
  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(source))) {
      specifiers.push(match[1]);
    }
  }
  return specifiers;
}

function collectEntryGraphOffenders(
  entries,
  rules,
  root = distEsmRoot,
  { includeDynamicImports = false } = {},
) {
  const offenders = [];
  const sourceCache = new Map();
  const specifierCache = new Map();
  const resolutionCache = new Map();

  function readCached(file) {
    const cached = sourceCache.get(file);
    if (cached !== undefined) return cached;
    const source = read(file);
    sourceCache.set(file, source);
    return source;
  }

  function importSpecifiersCached(file, source) {
    const cached = specifierCache.get(file);
    if (cached) return cached;
    const specifiers = importSpecifiers(source, { includeDynamicImports });
    specifierCache.set(file, specifiers);
    return specifiers;
  }

  function resolveRelativeImportCached(fromFile, specifier) {
    const cacheKey = `${fromFile}\0${specifier}`;
    if (resolutionCache.has(cacheKey)) return resolutionCache.get(cacheKey);
    const resolved = resolveRelativeImport(fromFile, specifier);
    resolutionCache.set(cacheKey, resolved);
    return resolved;
  }

  for (const entry of entries) {
    const entryAbs = path.join(root, entry);
    const queue = [entryAbs];
    const seen = new Set();
    const queued = new Set([entryAbs]);
    let queueIndex = 0;

    while (queueIndex < queue.length) {
      const current = queue[queueIndex++];
      if (!current || seen.has(current)) continue;
      seen.add(current);

      const rel = normalizeDistPath(current, root);
      for (const pattern of rules.forbiddenPathPatterns) {
        if (pattern.test(rel)) {
          offenders.push(`${entry} imports forbidden built module ${rel}`);
        }
      }

      const source = readCached(current);
      for (const pattern of rules.forbiddenSourcePatterns) {
        if (pattern.test(source)) {
          offenders.push(`${entry} graph contains forbidden source in ${rel}: ${pattern}`);
        }
      }
      for (const predicate of rules.forbiddenSourcePredicates ?? []) {
        if (predicate.test(source)) {
          offenders.push(`${entry} graph contains forbidden source in ${rel}: ${predicate.label}`);
        }
      }

      const specifiers = importSpecifiersCached(current, source);
      for (const specifier of specifiers) {
        for (const pattern of rules.forbiddenSpecifierPatterns) {
          if (pattern.test(specifier)) {
            offenders.push(`${entry} graph imports forbidden package ${specifier} from ${rel}`);
          }
        }

        const resolved = resolveRelativeImportCached(current, specifier);
        if (
          resolved &&
          (resolved === root || resolved.startsWith(`${root}${path.sep}`)) &&
          !queued.has(resolved)
        ) {
          queued.add(resolved);
          queue.push(resolved);
        }
      }
    }
  }
  return offenders;
}

export function collectWalletIframeHostGraphOffenders(
  entries = walletIframeHostEntryFiles,
  root = distEsmRoot,
) {
  return collectEntryGraphOffenders(
    entries,
    {
      forbiddenPathPatterns: forbiddenWalletIframeHostPathPatterns,
      forbiddenSourcePatterns: forbiddenWalletIframeHostSourcePatterns,
      forbiddenSourcePredicates: forbiddenWalletIframeHostSourcePredicates,
      forbiddenSpecifierPatterns: [
        /^(?:react|react-dom|lucide-react)(?:\/|$)/i,
        /(?:^|\/)src\/react(?:\/|$)/i,
      ],
    },
    root,
    { includeDynamicImports: true },
  );
}

export function collectRuntimeEntryGraphOffenders(entries = entryFiles, root = distEsmRoot) {
  return collectEntryGraphOffenders(
    entries,
    {
      forbiddenPathPatterns: forbiddenResolvedPathPatterns,
      forbiddenSourcePatterns,
      forbiddenSpecifierPatterns: [],
    },
    root,
  );
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

async function main() {
  if (!fs.existsSync(distEsmRoot)) {
    fail(`Missing directory: ${distEsmRoot}. Run pnpm build:sdk first.`);
  }

  const missingEntries = entryFiles.filter(
    (entry) => !fs.existsSync(path.join(distEsmRoot, entry)),
  );
  if (missingEntries.length > 0) {
    fail(`Missing runtime package entry output(s): ${missingEntries.join(', ')}`);
  }

  const missingWalletIframeHostEntries = walletIframeHostEntryFiles.filter(
    (entry) => !fs.existsSync(path.join(distEsmRoot, entry)),
  );
  if (missingWalletIframeHostEntries.length > 0) {
    fail(
      `Missing wallet iframe host entry output(s): ${missingWalletIframeHostEntries.join(', ')}`,
    );
  }

  await assertPublicRuntimeValueExports();

  const runtimeOffenders = collectRuntimeEntryGraphOffenders();
  const walletIframeHostOffenders = collectWalletIframeHostGraphOffenders();
  const offenders = [...runtimeOffenders, ...walletIframeHostOffenders];

  if (offenders.length > 0) {
    console.error('[assert-runtime-entry-bundles] Runtime entry bundle violations:');
    for (const offender of offenders.slice(0, 80)) {
      console.error(`  - ${offender}`);
    }
    if (offenders.length > 80) console.error(`  ...and ${offenders.length - 80} more`);
    process.exit(1);
  }

  console.log(
    '[assert-runtime-entry-bundles] OK: runtime entry avoids browser bundles and exposes public runtime values; wallet iframe host graphs are React-free',
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  await main();
}
