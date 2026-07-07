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
  'packages/sdk-server-ts/src/router/routerApiSponsoredEvmCall.ts',
  'packages/sdk-server-ts/src/router/routerApiWallets.ts',
  'packages/sdk-server-ts/src/router/routerApiSignedDelegate.ts',
  'packages/sdk-server-ts/src/router/sponsorshipExecution.ts',
  'packages/sdk-server-ts/src/router/sponsorshipBillingEvents.ts',
  'packages/sdk-server-ts/src/router/sponsorshipRuntime.ts',
  'packages/sdk-server-ts/src/router/sponsorshipSpendCapObservability.ts',
  'packages/sdk-server-ts/src/router/walletRegistrationRoutes.ts',
  'packages/sdk-server-ts/src/router/routeDefinitions.ts',
  'packages/sdk-server-ts/src/router/routeAuthPolicy.ts',
  'packages/sdk-server-ts/src/router/cloudflare/createCloudflareRouter.ts',
  'packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts',
  'packages/sdk-server-ts/src/router/cloudflare/cloudflare.types.ts',
  'packages/sdk-server-ts/src/router/cloudflare/d1LocalDevWorker.ts',
  'packages/sdk-server-ts/src/router/cloudflare/d1RouterApiStagingWorker.ts',
  'packages/sdk-server-ts/src/router/cloudflare/d1StagingSession.ts',
];

const allowedSignerRouterImports = buildAllowedImportSet([
  ['packages/sdk-server-ts/src/router/routerApi.ts', '../console/apiKeys'],
  ['packages/sdk-server-ts/src/router/routerApi.ts', '../console/billing'],
  ['packages/sdk-server-ts/src/router/routerApi.ts', '../console/billingPrepaidReservations'],
  ['packages/sdk-server-ts/src/router/routerApi.ts', '../console/bootstrapTokens'],
  ['packages/sdk-server-ts/src/router/routerApi.ts', '../console/observability'],
  ['packages/sdk-server-ts/src/router/routerApi.ts', '../console/orgProjectEnv'],
  ['packages/sdk-server-ts/src/router/routerApi.ts', '../console/runtimeSnapshots'],
  ['packages/sdk-server-ts/src/router/routerApi.ts', '../console/sponsoredCalls'],
  ['packages/sdk-server-ts/src/router/routerApi.ts', '../console/sponsorshipSpendCaps'],
  ['packages/sdk-server-ts/src/router/routerApi.ts', '../console/wallets'],
  ['packages/sdk-server-ts/src/router/routerApi.ts', '../console/webhooks'],
  ['packages/sdk-server-ts/src/router/routerApi.ts', '../sponsorship/evmExecutorTypes'],
  ['packages/sdk-server-ts/src/router/routerApi.ts', '../sponsorship/spendCaps'],
  ['packages/sdk-server-ts/src/router/routerApi.ts', '@shared/console/apiKeyScopes'],
  ['packages/sdk-server-ts/src/router/commonRouterUtils.ts', '../console/orgProjectEnv'],
  ['packages/sdk-server-ts/src/router/bootstrapGrantBroker.ts', '../console/apiKeys'],
  ['packages/sdk-server-ts/src/router/bootstrapGrantBroker.ts', '../console/bootstrapTokens'],
  ['packages/sdk-server-ts/src/router/bootstrapGrantBroker.ts', '../console/orgProjectEnv'],
  ['packages/sdk-server-ts/src/router/routerApiKeyAuth.ts', '../console/apiKeys'],
  ['packages/sdk-server-ts/src/router/routerApiKeyAuth.ts', '../console/apiKeys/ipAllowlist'],
  ['packages/sdk-server-ts/src/router/routerApiKeyAuth.ts', '../console/billing'],
  ['packages/sdk-server-ts/src/router/routerApiKeyAuth.ts', '../console/orgProjectEnv'],
  ['packages/sdk-server-ts/src/router/routerApiKeyAuth.ts', '../console/wallets'],
  ['packages/sdk-server-ts/src/router/routerApiCredentialAuth.ts', '../console/apiKeys/types'],
  ['packages/sdk-server-ts/src/router/routerApiCredentialAuth.ts', '../console/bootstrapTokens/secret'],
  ['packages/sdk-server-ts/src/router/routerApiCredentialAuth.ts', '../console/bootstrapTokens/service'],
  ['packages/sdk-server-ts/src/router/routerApiBootstrapGrant.ts', '../console/apiKeys'],
  ['packages/sdk-server-ts/src/router/routerApiSponsoredEvmCall.ts', '../console/billing'],
  ['packages/sdk-server-ts/src/router/routerApiSponsoredEvmCall.ts', '../console/billingPrepaidReservations'],
  ['packages/sdk-server-ts/src/router/routerApiSponsoredEvmCall.ts', '../console/observability'],
  ['packages/sdk-server-ts/src/router/routerApiSponsoredEvmCall.ts', '../console/runtimeSnapshots'],
  ['packages/sdk-server-ts/src/router/routerApiSponsoredEvmCall.ts', '../console/sponsoredCalls'],
  ['packages/sdk-server-ts/src/router/routerApiSponsoredEvmCall.ts', '../console/sponsorshipSpendCaps'],
  ['packages/sdk-server-ts/src/router/routerApiSponsoredEvmCall.ts', '../console/webhooks'],
  ['packages/sdk-server-ts/src/router/routerApiSponsoredEvmCall.ts', '../sponsorship/evm'],
  ['packages/sdk-server-ts/src/router/routerApiSponsoredEvmCall.ts', '../sponsorship/evmExecutorTypes'],
  ['packages/sdk-server-ts/src/router/routerApiSponsoredEvmCall.ts', '../sponsorship/evmRoutes'],
  ['packages/sdk-server-ts/src/router/routerApiSponsoredEvmCall.ts', '../sponsorship/executionAdapter'],
  ['packages/sdk-server-ts/src/router/routerApiSponsoredEvmCall.ts', '../sponsorship/prepaidBalance'],
  ['packages/sdk-server-ts/src/router/routerApiSponsoredEvmCall.ts', '../sponsorship/spendCaps'],
  ['packages/sdk-server-ts/src/router/routerApiWallets.ts', '../console/wallets/errors'],
  ['packages/sdk-server-ts/src/router/routerApiWallets.ts', '../console/wallets/requests'],
  ['packages/sdk-server-ts/src/router/routerApiWallets.ts', '../console/wallets/service'],
  ['packages/sdk-server-ts/src/router/routerApiWallets.ts', '../console/wallets/types'],
  ['packages/sdk-server-ts/src/router/routerApiSignedDelegate.ts', '../console/billing'],
  ['packages/sdk-server-ts/src/router/routerApiSignedDelegate.ts', '../console/billingPrepaidReservations'],
  ['packages/sdk-server-ts/src/router/routerApiSignedDelegate.ts', '../console/observability'],
  ['packages/sdk-server-ts/src/router/routerApiSignedDelegate.ts', '../console/runtimeSnapshots'],
  ['packages/sdk-server-ts/src/router/routerApiSignedDelegate.ts', '../console/sponsoredCalls'],
  ['packages/sdk-server-ts/src/router/routerApiSignedDelegate.ts', '../console/sponsorshipSpendCaps'],
  ['packages/sdk-server-ts/src/router/routerApiSignedDelegate.ts', '../console/webhooks'],
  ['packages/sdk-server-ts/src/router/routerApiSignedDelegate.ts', '../sponsorship/executionAdapter'],
  ['packages/sdk-server-ts/src/router/routerApiSignedDelegate.ts', '../sponsorship/near'],
  ['packages/sdk-server-ts/src/router/routerApiSignedDelegate.ts', '../sponsorship/nearExecutionAdapter'],
  ['packages/sdk-server-ts/src/router/routerApiSignedDelegate.ts', '../sponsorship/prepaidBalance'],
  ['packages/sdk-server-ts/src/router/routerApiSignedDelegate.ts', '../sponsorship/spendCaps'],
  ['packages/sdk-server-ts/src/router/routerApiSignedDelegate.ts', '@shared/console/gasSponsorshipSpendCapTargets'],
  ['packages/sdk-server-ts/src/router/sponsorshipExecution.ts', '../console/billing/d1'],
  ['packages/sdk-server-ts/src/router/sponsorshipExecution.ts', '../console/billing/service'],
  ['packages/sdk-server-ts/src/router/sponsorshipExecution.ts', '../console/billingPrepaidReservations/d1'],
  ['packages/sdk-server-ts/src/router/sponsorshipExecution.ts', '../console/billingPrepaidReservations/errors'],
  ['packages/sdk-server-ts/src/router/sponsorshipExecution.ts', '../console/billingPrepaidReservations/service'],
  ['packages/sdk-server-ts/src/router/sponsorshipExecution.ts', '../console/billingPrepaidReservations/types'],
  ['packages/sdk-server-ts/src/router/sponsorshipExecution.ts', '../console/sponsoredCalls/d1'],
  ['packages/sdk-server-ts/src/router/sponsorshipExecution.ts', '../console/sponsoredCalls/service'],
  ['packages/sdk-server-ts/src/router/sponsorshipExecution.ts', '../console/sponsoredCalls/types'],
  ['packages/sdk-server-ts/src/router/sponsorshipExecution.ts', '../sponsorship/prepaidBalance'],
  ['packages/sdk-server-ts/src/router/sponsorshipExecution.ts', '../sponsorship/spendCaps'],
  ['packages/sdk-server-ts/src/router/sponsorshipBillingEvents.ts', '../console/billing/readiness'],
  ['packages/sdk-server-ts/src/router/sponsorshipBillingEvents.ts', '../console/billing/service'],
  ['packages/sdk-server-ts/src/router/sponsorshipBillingEvents.ts', '../console/billing/types'],
  ['packages/sdk-server-ts/src/router/sponsorshipBillingEvents.ts', '../console/observability/adapters'],
  ['packages/sdk-server-ts/src/router/sponsorshipBillingEvents.ts', '../console/observability/ingestionService'],
  ['packages/sdk-server-ts/src/router/sponsorshipBillingEvents.ts', '../console/webhooks/service'],
  ['packages/sdk-server-ts/src/router/sponsorshipRuntime.ts', '../console/runtimeSnapshots'],
  ['packages/sdk-server-ts/src/router/sponsorshipRuntime.ts', '../console/sponsoredCalls'],
  ['packages/sdk-server-ts/src/router/sponsorshipSpendCapObservability.ts', '../console/sponsoredCalls'],
  ['packages/sdk-server-ts/src/router/sponsorshipSpendCapObservability.ts', '../sponsorship/spendCaps'],
  ['packages/sdk-server-ts/src/router/walletRegistrationRoutes.ts', '../console/bootstrapTokens'],
  ['packages/sdk-server-ts/src/router/walletRegistrationRoutes.ts', '../console/orgProjectEnv'],
  ['packages/sdk-server-ts/src/router/routeDefinitions.ts', '../sponsorship/evmRoutes'],
  ['packages/sdk-server-ts/src/router/routeAuthPolicy.ts', '@shared/console/apiKeyScopes'],
  ['packages/sdk-server-ts/src/router/cloudflare/d1LocalDevWorker.ts', '../../sponsorship/evmWorkerExecutionAdapter'],
  ['packages/sdk-server-ts/src/router/cloudflare/d1RouterApiStagingWorker.ts', '../../sponsorship/evmWorkerExecutionAdapter'],
  ['packages/sdk-server-ts/src/router/cloudflare/d1StagingSession.ts', '../../console/teamRbac/service'],
]);

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

checkSignerCoreHasNoConsoleOrSponsorshipImports();
checkSignerRouterImportsStayOnAllowlist();

console.log('[check-signer-console-module-boundaries] passed');
