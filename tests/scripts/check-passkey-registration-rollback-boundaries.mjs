#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');
const registrationPath = 'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts';
const seamsWebPath = 'packages/sdk-web/src/SeamsWeb/SeamsWeb.ts';
const productionContinuationScanPaths = [
  'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
  'packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts',
  'packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts',
  'packages/sdk-server-ts/src/core/types.ts',
  'packages/sdk-server-ts/src/router/commonRouterUtils.ts',
];

function absolutePath(relativePath) {
  return path.join(repoRoot, relativePath);
}

function readRepoSource(relativePath) {
  return fs.readFileSync(absolutePath(relativePath), 'utf8');
}

function requireContains(source, needle, label, violations) {
  if (!source.includes(needle)) {
    violations.push(`${label}: missing ${needle}`);
  }
}

function requireAbsent(source, needle, label, violations) {
  if (source.includes(needle)) {
    violations.push(`${label}: contains ${needle}`);
  }
}

function requireOrdered(source, first, second, label, violations) {
  const firstIndex = source.indexOf(first);
  const secondIndex = source.indexOf(second);
  if (firstIndex === -1 || secondIndex === -1 || firstIndex >= secondIndex) {
    violations.push(`${label}: expected ${first} before ${second}`);
  }
}

function sourceBlock(source, startNeedle, endNeedle, label, violations) {
  const startIndex = source.indexOf(startNeedle);
  if (startIndex === -1) {
    violations.push(`${label}: missing ${startNeedle}`);
    return '';
  }

  if (!endNeedle) {
    return source.slice(startIndex);
  }

  const endIndex = source.indexOf(endNeedle, startIndex);
  if (endIndex <= startIndex) {
    violations.push(`${label}: missing ${endNeedle} after ${startNeedle}`);
    return '';
  }

  return source.slice(startIndex, endIndex);
}

function collectRollbackStateViolations() {
  const violations = [];
  const registrationSource = readRepoSource(registrationPath);
  const rollbackBlock = sourceBlock(
    registrationSource,
    'async function performRegistrationRollback',
    '',
    registrationPath,
    violations,
  );

  requireContains(rollbackBlock, 'registrationState.databaseStored', registrationPath, violations);
  requireContains(
    rollbackBlock,
    'registrationState.accountCreated || registrationState.contractRegistered',
    registrationPath,
    violations,
  );
  requireContains(rollbackBlock, 'databaseRollbackSkippedReason', registrationPath, violations);
  requireContains(rollbackBlock, 'on_chain_account_created', registrationPath, violations);
  requireContains(rollbackBlock, 'rollbackUserRegistration', registrationPath, violations);
  requireOrdered(
    rollbackBlock,
    'on_chain_account_created',
    'await registrationAccounts.rollbackUserRegistration',
    registrationPath,
    violations,
  );

  return violations;
}

function collectPasskeyRegistrationHelperViolations() {
  const violations = [];
  const seamsWebSource = readRepoSource(seamsWebPath);
  const functionBlock = sourceBlock(
    seamsWebSource,
    'private async registerPasskeyDomain',
    'private createPasskeyRegistrationActivationSurfaceDomain',
    seamsWebPath,
    violations,
  );

  requireContains(functionBlock, 'return await this.registerWalletDomain({', seamsWebPath, violations);
  requireContains(
    functionBlock,
    'buildNearWalletRegistrationSignerSetSelection',
    seamsWebPath,
    violations,
  );
  requireAbsent(functionBlock, "mode: 'ed25519_only'", seamsWebPath, violations);
  requireAbsent(
    seamsWebSource,
    'async function provisionThresholdEcdsaAfterRegistration',
    seamsWebPath,
    violations,
  );
  requireAbsent(seamsWebSource, "kind: 'registration_continuation'", seamsWebPath, violations);

  return violations;
}

function collectContinuationAuthViolations() {
  const violations = [];

  for (const relativePath of productionContinuationScanPaths) {
    const source = readRepoSource(relativePath);
    requireAbsent(source, 'registrationContinuation', relativePath, violations);
    requireAbsent(source, 'registration_continuation', relativePath, violations);
  }

  return violations;
}

function main() {
  const violations = [
    ...collectRollbackStateViolations(),
    ...collectPasskeyRegistrationHelperViolations(),
    ...collectContinuationAuthViolations(),
  ];

  if (violations.length > 0) {
    console.error('[check-passkey-registration-rollback-boundaries] failed');
    for (const violation of violations) {
      console.error(`- ${violation}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log('[check-passkey-registration-rollback-boundaries] passed');
}

main();
