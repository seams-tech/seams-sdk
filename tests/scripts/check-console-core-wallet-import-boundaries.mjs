#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const consoleCoreRoots = ['packages/console-server-ts/src', 'packages/console-shared-ts/src'];

const cloudHost = '@seams/sdk-server/cloud-host';

// Temporary R105 Phase 0 allowlist. Every entry is an inventoried pre-split
// import that Phases 1-2 either replace with a Console-owned module or move to
// wallet-console-server-ts. Entries may only be deleted, never added; a stale
// entry (file gone or import gone) fails this guard until it is removed.
const temporaryAllowedWalletImports = buildAllowedImportSet([
  ['packages/console-server-ts/src/router/cloudflare/d1SignerWasm.ts', '@seams/sdk-server/wasm/signer'],
  ...[
  'packages/console-server-ts/src/account/d1.ts',
  'packages/console-server-ts/src/apiKeys/d1.ts',
  'packages/console-server-ts/src/apiKeys/ipAllowlist.ts',
  'packages/console-server-ts/src/apiKeys/originMessage.ts',
  'packages/console-server-ts/src/apiKeys/service.ts',
  'packages/console-server-ts/src/approvals/d1.ts',
  'packages/console-server-ts/src/approvals/service.ts',
  'packages/console-server-ts/src/audit/d1.ts',
  'packages/console-server-ts/src/audit/service.ts',
  'packages/console-server-ts/src/auditExports/service.ts',
  'packages/console-server-ts/src/billing/d1.ts',
  'packages/console-server-ts/src/billing/providers.ts',
  'packages/console-server-ts/src/billing/service.ts',
  'packages/console-server-ts/src/billingPrepaidReservations/d1.ts',
  'packages/console-server-ts/src/billingPrepaidReservations/service.ts',
  'packages/console-server-ts/src/email/d1.ts',
  'packages/console-server-ts/src/email/otp/amazonSesEmailOtpProvider.ts',
  'packages/console-server-ts/src/email/otp/emailOtpDeliveryAdapter.ts',
  'packages/console-server-ts/src/email/otp/emailOtpProviders.ts',
  'packages/console-server-ts/src/email/otp/resendEmailOtpProvider.ts',
  'packages/console-server-ts/src/email/secrets.ts',
  'packages/console-server-ts/src/keyExports/d1.ts',
  'packages/console-server-ts/src/keyExports/service.ts',
  'packages/console-server-ts/src/observability/adapters.ts',
  'packages/console-server-ts/src/observability/d1.ts',
  'packages/console-server-ts/src/onboarding/service.ts',
  'packages/console-server-ts/src/onboarding/welcomeEmail.ts',
  'packages/console-server-ts/src/orgProjectEnv/d1.ts',
  'packages/console-server-ts/src/orgProjectEnv/service.ts',
  'packages/console-server-ts/src/policies/d1.ts',
  'packages/console-server-ts/src/policies/rules.ts',
  'packages/console-server-ts/src/policies/service.ts',
  'packages/console-server-ts/src/router/cloudflare-adaptor.ts',
  'packages/console-server-ts/src/router/cloudflare/cloudflareConsole.types.ts',
  'packages/console-server-ts/src/router/cloudflare/createCloudflareConsoleRouter.ts',
  'packages/console-server-ts/src/router/cloudflare/cron.ts',
  'packages/console-server-ts/src/router/cloudflare/d1ConsoleServices.ts',
  'packages/console-server-ts/src/router/cloudflare/d1ConsoleStagingWorker.ts',
  'packages/console-server-ts/src/router/cloudflare/d1LocalDevWorker.ts',
  'packages/console-server-ts/src/router/cloudflare/d1RouterApiStagingWorker.ts',
  'packages/console-server-ts/src/router/cloudflare/d1StagingSession.ts',
  'packages/console-server-ts/src/router/cloudflare/tenantStorageRoute.ts',
  'packages/console-server-ts/src/router/console.ts',
  'packages/console-server-ts/src/router/consoleAppSessionAuth.ts',
  'packages/console-server-ts/src/router/consoleObservabilityHooks.ts',
  'packages/console-server-ts/src/router/consoleSessionContext.ts',
  'packages/console-server-ts/src/router/express-adaptor.ts',
  'packages/console-server-ts/src/router/express/createConsoleRouter.ts',
  'packages/console-server-ts/src/router/opsCockpitSummary.ts',
  'packages/console-server-ts/src/router/routeExtensions.ts',
  'packages/console-server-ts/src/router/routerApiKeyAuth.ts',
  'packages/console-server-ts/src/router/routerApiSignedDelegate.ts',
  'packages/console-server-ts/src/router/routerApiSponsoredEvmCall.ts',
  'packages/console-server-ts/src/router/routerApiWallets.ts',
  'packages/console-server-ts/src/router/sponsorshipBillingEvents.ts',
  'packages/console-server-ts/src/router/sponsorshipExecution.ts',
  'packages/console-server-ts/src/router/sponsorshipRuntime.ts',
  'packages/console-server-ts/src/router/sponsorshipSpendCapObservability.ts',
  'packages/console-server-ts/src/router/stripePostProcessing.ts',
  'packages/console-server-ts/src/runtimeSnapshots/d1.ts',
  'packages/console-server-ts/src/runtimeSnapshots/service.ts',
  'packages/console-server-ts/src/sponsoredCalls/d1.ts',
  'packages/console-server-ts/src/sponsoredCalls/service.ts',
  'packages/console-server-ts/src/sponsorship/evmRelay.ts',
  'packages/console-server-ts/src/sponsorship/evmWorkerSignerWasm.ts',
  'packages/console-server-ts/src/sponsorship/near.ts',
  'packages/console-server-ts/src/sponsorship/nearExecutionAdapter.ts',
  'packages/console-server-ts/src/sponsorshipPricing/d1.ts',
  'packages/console-server-ts/src/sponsorshipSpendCaps/d1.ts',
  'packages/console-server-ts/src/sponsorshipSpendCaps/service.ts',
  'packages/console-server-ts/src/teamRbac/d1.ts',
  'packages/console-server-ts/src/teamRbac/secret.ts',
  'packages/console-server-ts/src/teamRbac/service.ts',
  'packages/console-server-ts/src/wallets/d1.ts',
  'packages/console-server-ts/src/wallets/normalization.ts',
  'packages/console-server-ts/src/webhooks/d1.ts',
  'packages/console-server-ts/src/webhooks/observability.ts',
  'packages/console-server-ts/src/webhooks/pagination.ts',
  'packages/console-server-ts/src/webhooks/shared.ts',
  ].map((file) => [file, cloudHost]),
]);

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
  return /(?:^|\/)(?:sdk-web|sdk-server-ts|wallet-server)\/(?:src|dist)(?:\/|$)/.test(specifier);
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
