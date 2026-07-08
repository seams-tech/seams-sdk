#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const signerCoreRoots = [
  'packages/sdk-server-ts/src/core',
  'packages/sdk-server-ts/src/threshold',
  'packages/sdk-server-ts/src/wasm',
  'packages/sdk-server-ts/src/storage',
  'packages/sdk-server-ts/src/delegateAction',
  'packages/sdk-server-ts/src/email-recovery',
];

const signerRouterFiles = [
  'packages/sdk-server-ts/src/router/routerApi.ts',
  'packages/sdk-server-ts/src/router/commonRouterUtils.ts',
  'packages/sdk-server-ts/src/router/bootstrapGrantBroker.ts',
  'packages/sdk-server-ts/src/router/routerApiKeyAuth.ts',
  'packages/sdk-server-ts/src/router/routerApiCredentialAuth.ts',
  'packages/sdk-server-ts/src/router/routerApiBootstrapGrant.ts',
  'packages/sdk-server-ts/src/router/walletRegistrationRoutes.ts',
  'packages/sdk-server-ts/src/router/routeDefinitions.ts',
  'packages/sdk-server-ts/src/router/routeAuthPolicy.ts',
  'packages/sdk-server-ts/src/router/cloudflare/createCloudflareRouter.ts',
  'packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts',
  'packages/sdk-server-ts/src/router/cloudflare/cloudflare.types.ts',
];

const signerPackageConfigFiles = [
  'packages/sdk-server-ts/tsconfig.json',
  'packages/sdk-server-ts/tsconfig.build.json',
  'packages/sdk-server-ts/rolldown.config.ts',
];

const allowedSignerRouterImports = buildAllowedImportSet([]);

const importSpecifierPatterns = [
  /\bimport\s+(?:type\s+)?(?:[^'"]*?\s+from\s+)?['"]([^'"]+)['"]/g,
  /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
];

function buildAllowedImportSet(entries) {
  const allowed = new Set();
  for (const [file, specifier] of entries) {
    const key = allowedImportKey(file, specifier);
    assert.ok(!allowed.has(key), `duplicate signer-console allowlist entry: ${key}`);
    allowed.add(key);
  }
  return allowed;
}

function allowedImportKey(file, specifier) {
  return `${file}\0${specifier}`;
}

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

function isConsoleOrSponsorshipImport(specifier) {
  if (specifier === '@seams-internal/console-shared') return true;
  if (specifier.startsWith('@seams-internal/console-shared/')) return true;
  if (specifier.startsWith('@shared/console/')) return true;
  return /(?:^|\/)(?:console|sponsorship)(?:\/|$)/.test(specifier);
}

function collectForbiddenImports(files, allowedImports) {
  const offenders = [];
  for (const file of files) {
    const source = readRepoFile(file);
    const specifiers = extractImportSpecifiers(source);
    for (const specifier of specifiers) {
      if (!isConsoleOrSponsorshipImport(specifier)) continue;
      if (allowedImports.has(allowedImportKey(file, specifier))) continue;
      offenders.push(`${file} imports ${specifier}`);
    }
  }
  return offenders;
}

function collectSignerCoreFiles() {
  const files = [];
  for (const root of signerCoreRoots) files.push(...listTypeScriptFiles(root));
  return files;
}

function checkSignerCoreHasNoConsoleOrSponsorshipImports() {
  const offenders = collectForbiddenImports(collectSignerCoreFiles(), new Set());
  assert.deepEqual(
    offenders,
    [],
    `signer core roots must not import console or sponsorship modules:\n${offenders.join('\n')}`,
  );
}

function checkSignerRouterImportsStayOnAllowlist() {
  const missingFiles = [];
  for (const file of signerRouterFiles) {
    if (!fs.existsSync(absolutePath(file))) missingFiles.push(file);
  }
  assert.deepEqual(
    missingFiles,
    [],
    `signer-router guard file list contains missing files:\n${missingFiles.join('\n')}`,
  );

  const offenders = collectForbiddenImports(signerRouterFiles, allowedSignerRouterImports);
  assert.deepEqual(
    offenders,
    [],
    `signer-router files may only keep inventoried console/sponsorship imports:\n${offenders.join('\n')}`,
  );
}

function checkSignerPackageConfigHasNoConsoleSharedCoupling() {
  const offenders = [];
  for (const file of signerPackageConfigFiles) {
    const source = readRepoFile(file);
    if (source.includes('@seams-internal/console-shared')) {
      offenders.push(`${file} references @seams-internal/console-shared`);
    }
    if (source.includes('console-shared-ts')) {
      offenders.push(`${file} references console-shared-ts`);
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `signer package config must not include console-shared coupling:\n${offenders.join('\n')}`,
  );
}

checkSignerCoreHasNoConsoleOrSponsorshipImports();
checkSignerRouterImportsStayOnAllowlist();
checkSignerPackageConfigHasNoConsoleSharedCoupling();

console.log('[check-signer-console-module-boundaries] passed');
