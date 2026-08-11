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
  'packages/sdk-server-ts/src/router/framework/routerApi.ts',
  'packages/sdk-server-ts/src/router/auth/commonRouterUtils.ts',
  'packages/sdk-server-ts/src/router/auth/routerApiKeyAuth.ts',
  'packages/sdk-server-ts/src/router/auth/routerApiCredentialAuth.ts',
  'packages/sdk-server-ts/src/router/domains/walletRegistration/walletRegistrationRoutes.ts',
  'packages/sdk-server-ts/src/router/framework/routeDefinitions.ts',
  'packages/sdk-server-ts/src/router/framework/routeAuthPolicy.ts',
  'packages/sdk-server-ts/src/router/cloudflare/runtime/createCloudflareRouter.ts',
  'packages/sdk-server-ts/src/router/transport/fetch/routes/thresholdEcdsa.ts',
  'packages/sdk-server-ts/src/router/cloudflare/runtime/cloudflare.types.ts',
];

const signerPackageConfigFiles = [
  'packages/sdk-server-ts/tsconfig.json',
  'packages/sdk-server-ts/tsconfig.build.json',
  'packages/sdk-server-ts/rolldown.config.ts',
];

const publicSdkSourceRoots = [
  'packages/sdk-web/src',
  'packages/sdk-server-ts/src',
  'packages/shared-ts/src',
];

const publicSdkArtifactRoots = ['packages/sdk-web/dist', 'packages/sdk-server-ts/dist'];

const forbiddenPublicConceptPatterns = [
  {
    label: 'private console package',
    pattern: /@seams-internal\/console-|packages\/console-(?:server|shared)-ts/,
  },
  {
    label: 'console route or server contract',
    pattern:
      /\/console(?:\/|['"`])|\bConsole(?:Auth|Principal|Route|Router|Tenant|Organization|Billing|TeamRbac)\b/,
  },
  {
    label: 'dashboard implementation',
    pattern: /\bdashboard\b/i,
  },
  {
    label: 'billing implementation',
    pattern: /\bbilling(?:_[a-z]|[A-Z]|\b)/,
  },
  {
    label: 'refund implementation',
    pattern: /\brefund(?:_[a-z]|[A-Z]|\b)/,
  },
  {
    label: 'organization membership implementation',
    pattern:
      /\b(?:organization_memberships?|OrganizationMembership|admin_permissions?|AdminPermission|owner_set_version|OwnerSetVersion|team_members?|TeamMember)\b/,
  },
  {
    label: 'local checkout path',
    pattern: /(?:\/Users\/|[A-Za-z]:\\Users\\|\.claude\/worktrees\/)/,
  },
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

function isBoundaryTextFile(relativePath) {
  return /\.(?:cjs|d\.ts|js|json|map|md|mjs|ts|tsx)$/.test(relativePath);
}

function listBoundaryTextFiles(relativePath) {
  const absolute = absolutePath(relativePath);
  if (!fs.existsSync(absolute)) return [];
  const stat = fs.statSync(absolute);
  if (stat.isFile()) return isBoundaryTextFile(relativePath) ? [relativePath] : [];

  const files = [];
  const entries = fs.readdirSync(absolute, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === 'node_modules') continue;
    const childPath = path.join(relativePath, entry.name).split(path.sep).join('/');
    if (entry.isDirectory()) {
      files.push(...listBoundaryTextFiles(childPath));
      continue;
    }
    if (entry.isFile() && isBoundaryTextFile(childPath)) files.push(childPath);
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

function collectForbiddenPublicConcepts(roots) {
  const offenders = [];
  for (const root of roots) {
    for (const file of listBoundaryTextFiles(root)) {
      if (file.endsWith('.typecheck.ts')) continue;
      const source = readRepoFile(file);
      for (const forbidden of forbiddenPublicConceptPatterns) {
        forbidden.pattern.lastIndex = 0;
        if (forbidden.pattern.test(source)) {
          offenders.push(`${file}: ${forbidden.label}`);
        }
      }
    }
  }
  return offenders;
}

function checkPublicSdkContainsNoPrivateProductImplementation() {
  const sourceOffenders = collectForbiddenPublicConcepts(publicSdkSourceRoots);
  assert.deepEqual(
    sourceOffenders,
    [],
    `public SDK source contains private product concepts:\n${sourceOffenders.join('\n')}`,
  );

  const artifactOffenders = collectForbiddenPublicConcepts(publicSdkArtifactRoots);
  assert.deepEqual(
    artifactOffenders,
    [],
    `public SDK package artifacts contain private product concepts:\n${artifactOffenders.join('\n')}`,
  );
}

checkSignerCoreHasNoConsoleOrSponsorshipImports();
checkSignerRouterImportsStayOnAllowlist();
checkSignerPackageConfigHasNoConsoleSharedCoupling();
checkPublicSdkContainsNoPrivateProductImplementation();

console.log('[check-signer-console-module-boundaries] passed');
