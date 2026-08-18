#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const SDK_ROOT = path.resolve(SCRIPT_DIR, '../..');
const REPO_ROOT = path.resolve(SDK_ROOT, '../..');
const PACKAGE_JSON_PATH = path.join(SDK_ROOT, 'package.json');

const SCAN_ENTRIES = [
  'apps',
  'examples',
  'packages/sdk-web/README.md',
  'docs/saas/self-hosted-migration.md',
];

const INCLUDED_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.md',
  '.mdx',
  '.json',
]);

const IGNORED_DIRS = new Set([
  '.git',
  '.next',
  'dist',
  'node_modules',
  'playwright-report',
  'test-results',
]);

const FORBIDDEN_APP_PATTERNS = [
  {
    pattern: /@seams\/sdk\/plugins\/(?:vite|next|headers)\b/,
    message: 'app-facing surfaces must not import or recommend Seams SDK plugins for wallet hosting',
  },
  {
    pattern:
      /\bseams(?:Wallet|ServeSdk|WalletService|WasmMime|BuildHeaders|Next|App|Headers|Dev)\s*\(/,
    message: 'app-facing surfaces must not call legacy plugin helpers for wallet hosting',
  },
  {
    pattern: /\bVite Plugin Integration\b/,
    message: 'app-facing docs must describe hosted wallet integration directly',
  },
  {
    pattern: /\bUse the Vite plugins\b/i,
    message: 'app-facing docs must not recommend Vite plugins for wallet hosting',
  },
  {
    pattern: /\bserve wallet assets in dev\b/i,
    message: 'app-facing docs must not tell app origins to serve wallet assets',
  },
];

const PLUGIN_README_PATH = path.join(SDK_ROOT, 'src/plugins/README.md');
const FORBIDDEN_PACKAGE_EXPORTS = ['./plugins/headers', './plugins/next', './plugins/vite'];
const SOURCE_GUARD_RULES = [
  {
    file: 'packages/sdk-web/src/plugins/vite.ts',
    pattern: /\bWALLET_SHIM_SOURCE\b|\bWALLET_SURFACE_CSS\b/,
    message: 'wallet shim and CSS sources must live in src/static/wallet-assets',
  },
  {
    file: 'packages/sdk-web/src/plugins/vite.ts',
    pattern:
      /configuredBase\s*\+\s*['"]\/wallet-shims\.js['"]|configuredBase\s*\+\s*['"]\/wallet-service\.css['"]/,
    message: 'Vite helper must serve built wallet static files instead of virtual shim/CSS routes',
  },
];
const PLUGIN_README_REQUIRED_PATTERNS = [
  {
    pattern: /App integrations should not use these helpers for wallet runtime delivery\./,
    message: 'plugin README must lead with hosted-wallet guidance',
  },
  {
    pattern:
      /App origins should return 404 for `\/sdk\/\*` and `\/wallet-service`\./,
    message: 'plugin README must state that app origins do not serve wallet routes',
  },
  {
    pattern: /no hosted `\/export-viewer` page is part of the runtime contract\./,
    message: 'plugin README must document the srcdoc-only export viewer contract',
  },
  {
    pattern: /Seams wallet hosting publishes that tree from the wallet origin/,
    message: 'plugin README must point runtime delivery at the wallet origin',
  },
];

const PLUGIN_README_FORBIDDEN_PATTERNS = [
  {
    pattern: /\bimport\b[\s\S]{0,180}\bfrom\s+['"]@seams\/sdk\/plugins\/(?:vite|next|headers)['"]/,
    message: 'plugin README must not include app import examples for plugin helpers',
  },
  {
    pattern: /plugins\s*:\s*\[[^\]]*\bseams(?:Wallet|ServeSdk|WalletService|WasmMime|Next|App|Headers|Dev)\s*\(/,
    message: 'plugin README must not include app Vite/Next examples using plugin helpers',
  },
];

function isIncludedFile(filePath) {
  return INCLUDED_EXTENSIONS.has(path.extname(filePath));
}

function* walkFiles(rootPath) {
  if (!fs.existsSync(rootPath)) return;

  const stat = fs.statSync(rootPath);
  if (stat.isFile()) {
    if (isIncludedFile(rootPath)) yield rootPath;
    return;
  }

  if (!stat.isDirectory()) return;

  const entries = fs.readdirSync(rootPath, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory() && IGNORED_DIRS.has(entry.name)) continue;
    const entryPath = path.join(rootPath, entry.name);
    if (entry.isDirectory()) {
      yield* walkFiles(entryPath);
      continue;
    }
    if (!entry.isFile()) continue;
    if (isIncludedFile(entryPath)) yield entryPath;
  }
}

function lineNumberForOffset(text, offset) {
  let line = 1;
  for (let i = 0; i < offset; i += 1) {
    if (text.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

function addViolation(violations, filePath, text, match, message) {
  violations.push({
    file: path.relative(REPO_ROOT, filePath),
    line: lineNumberForOffset(text, match.index),
    message,
    match: match[0],
  });
}

function addTextViolation(violations, filePath, text, offset, match, message) {
  violations.push({
    file: path.relative(REPO_ROOT, filePath),
    line: lineNumberForOffset(text, offset),
    message,
    match,
  });
}

function collectAppSurfaceViolations(violations) {
  for (const entry of SCAN_ENTRIES) {
    const entryPath = path.join(REPO_ROOT, entry);
    for (const filePath of walkFiles(entryPath)) {
      if (filePath === PLUGIN_README_PATH) continue;
      const text = fs.readFileSync(filePath, 'utf8');
      for (const rule of FORBIDDEN_APP_PATTERNS) {
        rule.pattern.lastIndex = 0;
        const match = rule.pattern.exec(text);
        if (match) addViolation(violations, filePath, text, match, rule.message);
      }
    }
  }
}

function collectPackageExportViolations(violations) {
  const text = fs.readFileSync(PACKAGE_JSON_PATH, 'utf8');
  const packageJson = JSON.parse(text);
  const packageExports = packageJson.exports || {};
  for (const exportPath of FORBIDDEN_PACKAGE_EXPORTS) {
    if (!Object.prototype.hasOwnProperty.call(packageExports, exportPath)) continue;
    const offset = Math.max(0, text.indexOf(`"${exportPath}"`));
    addTextViolation(
      violations,
      PACKAGE_JSON_PATH,
      text,
      offset,
      exportPath,
      'plugin helpers must not be public package exports',
    );
  }
}

function collectSourceGuardViolations(violations) {
  for (const rule of SOURCE_GUARD_RULES) {
    const filePath = path.join(REPO_ROOT, rule.file);
    const text = fs.readFileSync(filePath, 'utf8');
    rule.pattern.lastIndex = 0;
    const match = rule.pattern.exec(text);
    if (match) addViolation(violations, filePath, text, match, rule.message);
  }
}

function collectPluginReadmeViolations(violations) {
  const text = fs.readFileSync(PLUGIN_README_PATH, 'utf8');
  for (const rule of PLUGIN_README_REQUIRED_PATTERNS) {
    rule.pattern.lastIndex = 0;
    if (rule.pattern.test(text)) continue;
    violations.push({
      file: path.relative(REPO_ROOT, PLUGIN_README_PATH),
      line: 1,
      message: rule.message,
      match: 'missing required hosted-wallet guidance',
    });
  }

  for (const rule of PLUGIN_README_FORBIDDEN_PATTERNS) {
    rule.pattern.lastIndex = 0;
    const match = rule.pattern.exec(text);
    if (match) addViolation(violations, PLUGIN_README_PATH, text, match, rule.message);
  }
}

function reportViolations(violations) {
  if (!violations.length) {
    console.log('[assert-hosted-wallet-docs] OK');
    return;
  }

  console.error('[assert-hosted-wallet-docs] failed');
  for (const violation of violations) {
    console.error(
      `  - ${violation.file}:${violation.line}: ${violation.message} (${JSON.stringify(
        violation.match,
      )})`,
    );
  }
  process.exit(1);
}

function main() {
  const violations = [];
  collectAppSurfaceViolations(violations);
  collectPackageExportViolations(violations);
  collectSourceGuardViolations(violations);
  collectPluginReadmeViolations(violations);
  reportViolations(violations);
}

main();
