#!/usr/bin/env node

import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../..');

const SOURCE_DIRS = ['client/src', 'tests', 'examples'];

const ALLOWED_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);

const IGNORED_DIR_NAMES = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  'coverage',
  'playwright-report',
  'test-results',
]);

const PATTERNS = [
  {
    code: 'family_union_arc',
    description: 'Family union/type contains legacy arc discriminator',
    regex: /\|\s*['"]arc['"]/g,
  },
  {
    code: 'family_compare_arc',
    description: 'Family comparison uses legacy arc discriminator',
    regex: /(?:===|==|!==|!=)\s*['"]arc['"]/g,
  },
  {
    code: 'family_switch_arc',
    description: 'Switch branch uses legacy arc discriminator',
    regex: /\bcase\s+['"]arc['"]\s*:/g,
  },
  {
    code: 'family_resolver_arc',
    description: 'resolvePrimaryExplorerUrl called with legacy arc family',
    regex: /\bresolvePrimaryExplorerUrl\s*\([^)\n]*,\s*['"]arc['"]\s*\)/g,
  },
  {
    code: 'seams_chain_family_arc',
    description: 'SeamsChainFamily declaration includes arc',
    regex: /\bSeamsChainFamily\b[^\n;]*['"]arc['"]/g,
  },
];

/**
 * @typedef {{
 *   file: string;
 *   line: number;
 *   code: string;
 *   description: string;
 *   snippet: string;
 * }} Violation
 */

/** @type {Violation[]} */
const violations = [];

for (const sourceDir of SOURCE_DIRS) {
  const absoluteDir = path.resolve(repoRoot, sourceDir);
  walkFiles(absoluteDir, (filePath) => {
    if (!ALLOWED_EXTENSIONS.has(path.extname(filePath))) return;
    scanFile(filePath);
  });
}

if (violations.length > 0) {
  console.error('[chain-family-naming] Found legacy `arc` family usage:');
  for (const violation of violations) {
    const relativePath = path.relative(repoRoot, violation.file);
    console.error(
      `- ${relativePath}:${violation.line} [${violation.code}] ${violation.description}\n` +
        `  ${violation.snippet}`,
    );
  }
  process.exit(1);
}

console.log('[chain-family-naming] OK: no legacy `arc` family discriminators found');

/**
 * @param {string} startPath
 * @param {(filePath: string) => void} onFile
 */
function walkFiles(startPath, onFile) {
  let entries;
  try {
    entries = readdirSync(startPath, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (IGNORED_DIR_NAMES.has(entry.name)) continue;
    const absolutePath = path.join(startPath, entry.name);
    if (entry.isDirectory()) {
      walkFiles(absolutePath, onFile);
      continue;
    }
    if (entry.isFile()) {
      onFile(absolutePath);
    }
  }
}

/**
 * @param {string} filePath
 */
function scanFile(filePath) {
  let content;
  try {
    if (!statSync(filePath).isFile()) return;
    content = readFileSync(filePath, 'utf8');
  } catch {
    return;
  }

  const lines = content.split('\n');
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex];
    for (const pattern of PATTERNS) {
      pattern.regex.lastIndex = 0;
      if (!pattern.regex.test(line)) continue;
      violations.push({
        file: filePath,
        line: lineIndex + 1,
        code: pattern.code,
        description: pattern.description,
        snippet: line.trim(),
      });
    }
  }
}
