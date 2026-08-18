#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const consoleCoreRoots = ['packages/console-server-ts/src', 'packages/console-shared-ts/src'];

// The R105 Phase 0-2 allowlist burned down to empty: console packages import
// no Wallet package at all. Keep it empty; new entries are forbidden.
const temporaryAllowedWalletImports = buildAllowedImportSet([]);

function buildAllowedImportSet(entries) {
  const allowed = new Set();
  for (const [file, specifier] of entries) {
    const key = allowedImportKey(file, specifier);
    assert.ok(!allowed.has(key), `duplicate console-core wallet-import allowlist entry: ${key}`);
    allowed.add(key);
  }
  return allowed;
}

function allowedImportKey(file, specifier) {
  return `${file}\0${specifier}`;
}

const importSpecifierPatterns = [
  /\bimport\s+(?:type\s+)?(?:[^'"]*?\s+from\s+)?['"]([^'"]+)['"]/g,
  /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  /\bexport\s+(?:type\s+)?(?:\*|\{[^}]*\})\s+from\s+['"]([^'"]+)['"]/g,
];

function absolutePath(relativePath) {
  return path.join(repoRoot, relativePath);
}

function isProductionTypeScriptFile(relativePath) {
  return /\.tsx?$/.test(relativePath) && !relativePath.endsWith('.typecheck.ts');
}

function listTypeScriptFiles(relativePath) {
  const absolute = absolutePath(relativePath);
  if (!fs.existsSync(absolute)) return [];
  const stat = fs.statSync(absolute);
  if (stat.isFile()) return isProductionTypeScriptFile(relativePath) ? [relativePath] : [];

  const files = [];
  const entries = fs.readdirSync(absolute, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === 'dist' || entry.name === 'node_modules') continue;
    const childPath = path.join(relativePath, entry.name).split(path.sep).join('/');
    if (entry.isDirectory()) {
      files.push(...listTypeScriptFiles(childPath));
      continue;
    }
    if (entry.isFile() && isProductionTypeScriptFile(childPath)) files.push(childPath);
  }
  return files;
}

function readRepoFile(relativePath) {
  return fs.readFileSync(absolutePath(relativePath), 'utf8');
}

function extractImportSpecifiers(source) {
  const specifiers = [];
  for (const pattern of importSpecifierPatterns) {
    pattern.lastIndex = 0;
    let match = pattern.exec(source);
    while (match) {
      if (match[1]) specifiers.push(match[1]);
      match = pattern.exec(source);
    }
  }
  return specifiers;
}

function isWalletPackageImport(specifier) {
  if (specifier === '@seams/sdk' || specifier.startsWith('@seams/sdk/')) return true;
  if (specifier === '@seams/sdk-server' || specifier.startsWith('@seams/sdk-server/')) return true;
  if (specifier === '@seams/wallet' || specifier.startsWith('@seams/wallet/')) return true;
  if (specifier === '@seams/wallet-server' || specifier.startsWith('@seams/wallet-server/'))
    return true;
  if (
    specifier === '@seams-internal/wallet-console-shared' ||
    specifier.startsWith('@seams-internal/wallet-console-shared/')
  )
    return true;
  if (
    specifier === '@seams-internal/wallet-console-server' ||
    specifier.startsWith('@seams-internal/wallet-console-server/')
  )
    return true;
  return /(?:^|\/)(?:sdk-web|sdk-server-ts|wallet-server|wallet-console-shared-ts|wallet-console-server-ts)\/(?:src|dist)(?:\/|$)/.test(
    specifier,
  );
}

function collectConsoleCoreFiles() {
  const files = [];
  for (const root of consoleCoreRoots) files.push(...listTypeScriptFiles(root));
  return files;
}

function checkConsoleCoreWalletImportsStayOnAllowlist() {
  const offenders = [];
  for (const file of collectConsoleCoreFiles()) {
    const specifiers = extractImportSpecifiers(readRepoFile(file));
    for (const specifier of specifiers) {
      if (!isWalletPackageImport(specifier)) continue;
      if (temporaryAllowedWalletImports.has(allowedImportKey(file, specifier))) continue;
      offenders.push(`${file} imports ${specifier}`);
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `console packages may not add Wallet package imports beyond the temporary R105 allowlist:\n${offenders.join('\n')}`,
  );
}

function checkTemporaryAllowlistIsNotStale() {
  const staleEntries = [];
  for (const key of temporaryAllowedWalletImports) {
    const [file, specifier] = key.split('\0');
    if (!fs.existsSync(absolutePath(file))) {
      staleEntries.push(`${file} no longer exists`);
      continue;
    }
    const specifiers = extractImportSpecifiers(readRepoFile(file));
    if (!specifiers.includes(specifier)) {
      staleEntries.push(`${file} no longer imports ${specifier}`);
    }
  }
  assert.deepEqual(
    staleEntries,
    [],
    `delete stale entries from the temporary R105 wallet-import allowlist:\n${staleEntries.join('\n')}`,
  );
}

checkConsoleCoreWalletImportsStayOnAllowlist();
checkTemporaryAllowlistIsNotStale();

console.log('[check-console-core-wallet-import-boundaries] passed');
