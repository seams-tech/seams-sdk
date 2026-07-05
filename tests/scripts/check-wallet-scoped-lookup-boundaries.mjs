#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const cloudflareRouterDir = path.join(repoRoot, 'packages/sdk-server-ts/src/router/cloudflare');

function readRepoFile(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listProductionCoreFiles(dir = path.join(repoRoot, 'packages/sdk-web/src/core')) {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listProductionCoreFiles(entryPath));
      continue;
    }
    if (entry.isFile() && /\.(ts|tsx)$/.test(entry.name) && !entry.name.endsWith('.d.ts')) {
      files.push(path.relative(repoRoot, entryPath));
    }
  }
  return files.sort();
}

function listProductionCloudflareD1Files() {
  return fs
    .readdirSync(cloudflareRouterDir, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .filter((name) => /^d1.*\.ts$/.test(name) && !name.endsWith('.typecheck.ts'))
    .map((name) => path.relative(repoRoot, path.join(cloudflareRouterDir, name)))
    .sort();
}

function listProductionServerTypeScriptFiles(relativeDir) {
  const absoluteDir = path.join(repoRoot, relativeDir);
  const files = [];
  for (const entry of fs.readdirSync(absoluteDir, { withFileTypes: true })) {
    const entryPath = path.join(absoluteDir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listProductionServerTypeScriptFiles(path.relative(repoRoot, entryPath)));
      continue;
    }
    if (entry.isFile() && /\.ts$/.test(entry.name) && !entry.name.endsWith('.typecheck.ts')) {
      files.push(path.relative(repoRoot, entryPath));
    }
  }
  return files.sort();
}

function listWalletPersistenceParserGuardFiles() {
  const files = new Set();
  for (const relativePath of listProductionServerTypeScriptFiles('packages/sdk-server-ts/src/core')) {
    files.add(relativePath);
  }
  for (const relativePath of listProductionCloudflareD1Files()) {
    files.add(relativePath);
  }
  return [...files].sort();
}

function assertNoViolations(label, violations) {
  assert.deepEqual(violations, [], `${label}\n${violations.join('\n')}`);
}

function collectD1NearAccountPredicateViolations() {
  const violations = [];
  for (const relativePath of listProductionCloudflareD1Files()) {
    const source = readRepoFile(relativePath);
    if (source.includes('isValidAccountId')) {
      violations.push(`${relativePath} validates D1 wallet identity as a NEAR account`);
    }
    if (/subject:\s*`near:\$\{/.test(source)) {
      violations.push(`${relativePath} links D1 wallet identity through a near:* subject`);
    }
  }
  return violations;
}

function collectCoreWalletNearAccountPredicateViolations() {
  const violations = [];
  const checkedFiles = ['packages/sdk-server-ts/src/core/AuthService.ts'];
  for (const relativePath of checkedFiles) {
    const source = readRepoFile(relativePath);
    const matches = source.matchAll(
      /isValidAccountId\((walletId|userId|linkedWalletId|enrollment\.walletId)\)/g,
    );
    for (const match of matches) {
      violations.push(`${relativePath} validates ${match[1]} as a NEAR account`);
    }
  }
  return violations;
}

function collectNearPublicKeyRootPasskeyFieldViolations() {
  const violations = [];
  const checkedFiles = [
    'packages/sdk-server-ts/src/core/NearPublicKeyStore.ts',
    'packages/sdk-server-ts/src/router/cloudflare/d1WebAuthnRecords.ts',
  ];
  for (const relativePath of checkedFiles) {
    const source = readRepoFile(relativePath);
    const recordType = source.match(/export type NearPublicKeyRecord = \{[\s\S]*?\n\};/);
    if (!recordType) {
      violations.push(`${relativePath} is missing NearPublicKeyRecord`);
      continue;
    }
    if (/\brpId\?:\s*string;/.test(recordType[0])) {
      violations.push(`${relativePath} stores passkey rpId at NearPublicKeyRecord root`);
    }
    if (/\bcredentialIdB64u\?:\s*string;/.test(recordType[0])) {
      violations.push(`${relativePath} stores passkey credentialIdB64u at NearPublicKeyRecord root`);
    }
    if (!recordType[0].includes('authBinding?: NearPublicKeyAuthBinding')) {
      violations.push(`${relativePath} lacks branch-specific NearPublicKey authBinding`);
    }
  }

  const relayListSource = readRepoFile(
    'packages/sdk-server-ts/src/router/cloudflare/d1NearPublicKeyStore.ts',
  );
  if (/\brecord\.(rpId|credentialIdB64u)\b/.test(relayListSource)) {
    violations.push('Cloudflare D1 NEAR public-key list response flattens passkey fields');
  }

  return violations;
}

function collectWalletPersistenceBrandCastViolations() {
  const violations = [];
  for (const relativePath of listWalletPersistenceParserGuardFiles()) {
    const source = readRepoFile(relativePath);
    if (/\bas\s+WalletId\b/.test(source)) {
      violations.push(`${relativePath} brands a raw string with as WalletId`);
    }
  }
  return violations;
}

function checkProductionWalletPathsAvoidNearProjectionHelpers() {
  const forbiddenGlobal = [
    'buildNearAccountRefs(walletId)',
    'buildNearProfileId(walletId)',
    'ensureEmailOtpNearAccountMapping',
    'hostedWalletIdAsNearAccountId',
    'toAccountId(persistArgs.walletId)',
  ];

  const violations = [];
  for (const relativePath of listProductionCoreFiles()) {
    const source = readRepoFile(relativePath);
    for (const token of forbiddenGlobal) {
      if (source.includes(token)) violations.push(`${relativePath} contains ${token}`);
    }
    if (/walletId\s*:\s*toAccountId\s*\([^)]*walletId[^)]*\)/.test(source)) {
      violations.push(`${relativePath} assigns a NEAR-projected value to walletId`);
    }
  }

  assertNoViolations('production wallet paths must avoid NEAR projection helpers', violations);
}

function checkEcdsaWalletScopedFilesRejectNearAccountProjection() {
  const ecdsaWalletScopedFiles = [
    'packages/sdk-web/src/core/signingEngine/threshold/ecdsa/activation.ts',
    'packages/sdk-web/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts',
    'packages/sdk-web/src/core/signingEngine/threshold/ecdsa/commitQueue.ts',
    'packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget.ts',
  ];
  const forbiddenPatterns = [
    /toAccountId\s*\([^)]*walletId[^)]*\)/,
    /walletId\s*:\s*AccountId(?:\s*\|\s*string)?[;,]/,
  ];
  const violations = [];

  for (const relativePath of ecdsaWalletScopedFiles) {
    const source = readRepoFile(relativePath);
    for (const pattern of forbiddenPatterns) {
      if (pattern.test(source)) violations.push(`${relativePath} matches ${pattern}`);
    }
  }

  const reauthSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts',
  );
  const reauthStart = reauthSource.indexOf(
    'export function buildReauthAnchorIdentityFromAvailableLane',
  );
  const reauthEnd = reauthSource.indexOf('\nfunction emptyEd25519Lane', reauthStart);
  assert.ok(reauthStart >= 0, 'missing buildReauthAnchorIdentityFromAvailableLane');
  assert.ok(reauthEnd > reauthStart, 'missing buildReauthAnchorIdentityFromAvailableLane body end');
  const reauthBody = reauthSource.slice(reauthStart, reauthEnd);
  if (/toAccountId\s*\([^)]*walletId[^)]*\)/.test(reauthBody)) {
    violations.push('availableSigningLanes.ts projects walletId through toAccountId in reauth body');
  }

  assertNoViolations('ECDSA wallet-scoped files must reject NEAR account projection', violations);
}

function checkEcdsaBootstrapPersistenceAvoidsNearCompatibilityMappingApis() {
  const source = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence.ts',
  );
  const violations = [];
  for (const token of ['upsertChainAccount', 'setLastProfileStateForProfile', 'near:testnet']) {
    if (source.includes(token)) violations.push(`ecdsaBootstrapPersistence.ts contains ${token}`);
  }
  assertNoViolations('ECDSA bootstrap persistence must avoid NEAR compatibility mapping APIs', violations);
}

function checkCoreNearAccountAuthenticatorLookupHasExplicitApiOnly() {
  const lifecycle = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/flows/registration/accountLifecycle.ts',
  );
  const publicApi = readRepoFile('packages/sdk-web/src/core/signingEngine/flows/registration/public.ts');
  const violations = [];
  if (lifecycle.includes('export async function getAuthenticatorsByUser')) {
    violations.push('accountLifecycle exports getAuthenticatorsByUser');
  }
  if (publicApi.includes('export function getAuthenticatorsByUser')) {
    violations.push('registration public API exports getAuthenticatorsByUser');
  }
  assertNoViolations('core NEAR-account authenticator lookup must have explicit near-prefixed API only', violations);
}

checkProductionWalletPathsAvoidNearProjectionHelpers();
checkEcdsaWalletScopedFilesRejectNearAccountProjection();
checkEcdsaBootstrapPersistenceAvoidsNearCompatibilityMappingApis();
checkCoreNearAccountAuthenticatorLookupHasExplicitApiOnly();
assertNoViolations(
  'D1 auth and recovery boundaries must avoid NEAR account predicates for wallet ids',
  [
    ...collectD1NearAccountPredicateViolations(),
    ...collectCoreWalletNearAccountPredicateViolations(),
    ...collectNearPublicKeyRootPasskeyFieldViolations(),
  ],
);
assertNoViolations(
  'wallet persistence parsers must use wallet id parsers before branding domain state',
  collectWalletPersistenceBrandCastViolations(),
);

console.log('[check-wallet-scoped-lookup-boundaries] passed');
