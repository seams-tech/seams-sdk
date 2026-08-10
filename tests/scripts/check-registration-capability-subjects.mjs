#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SDK_WEB_SRC = 'packages/sdk-web/src';
const ECDSA_HANDLE_MODULE =
  'packages/sdk-web/src/core/signingEngine/session/identity/ecdsaDerivationSigningMaterialHandle.ts';

function absolutePath(relativePath) {
  return path.join(repoRoot, relativePath);
}

function readRepoSource(relativePath) {
  return fs.readFileSync(absolutePath(relativePath), 'utf8');
}

function assertContains(source, marker, label) {
  assert.ok(source.includes(marker), `${label}: missing ${marker}`);
}

function assertNotContains(source, marker, label) {
  assert.ok(!source.includes(marker), `${label}: unexpectedly contained ${marker}`);
}

function listTypeScriptFiles(relativePath) {
  const absoluteRoot = absolutePath(relativePath);
  const stat = fs.statSync(absoluteRoot);
  if (stat.isFile()) return /\.(ts|tsx)$/.test(relativePath) ? [relativePath] : [];

  const files = [];
  for (const entry of fs.readdirSync(absoluteRoot, { withFileTypes: true })) {
    if (entry.name === 'dist' || entry.name === 'node_modules') continue;
    const childPath = path.join(relativePath, entry.name).split(path.sep).join('/');
    if (entry.isDirectory()) files.push(...listTypeScriptFiles(childPath));
    if (entry.isFile() && /\.(ts|tsx)$/.test(entry.name)) files.push(childPath);
  }
  return files;
}

function checkRoleLocalEcdsaMaterialHandlesAreIdentityLocal() {
  const offenders = [];
  for (const relativePath of listTypeScriptFiles(SDK_WEB_SRC)) {
    if (relativePath === ECDSA_HANDLE_MODULE) continue;
    if (readRepoSource(relativePath).includes('router-ab-ecdsa-role-local:')) {
      offenders.push(relativePath);
    }
  }

  assert.deepEqual(offenders, [], `role-local ECDSA handle offenders\n${offenders.join('\n')}`);
  assertContains(
    readRepoSource(ECDSA_HANDLE_MODULE),
    'EcdsaRoleLocalMaterialBinding',
    ECDSA_HANDLE_MODULE,
  );
}

function checkWalletScopedUnlockAvoidsCollapsedNearBindingError() {
  const walletAuth = readRepoSource('packages/sdk-web/src/SeamsWeb/operations/auth/walletAuth.ts');
  assertNotContains(
    walletAuth,
    'wallet-scoped auth requires a resolved NEAR account binding',
    'walletAuth',
  );
  assertContains(walletAuth, 'WalletUnlockSubject', 'walletAuth');
}

function checkRegistrationTimingUsesSpanCoverage() {
  const registration = readRepoSource(
    'packages/sdk-web/src/SeamsWeb/operations/registration/registrationTiming.ts',
  );
  assertNotContains(registration, 'registration_timing_summary_v1', 'registration timing schema');
  assertContains(registration, 'registration_timing_summary_v2', 'registration timing schema');
  assertContains(registration, 'startOffsetMs', 'registration timing spans');
  assertContains(registration, 'endOffsetMs', 'registration timing spans');
  assertContains(registration, 'registrationTimingSpanUnionMs', 'registration span union');
  assertContains(registration, 'spanCoverageRatio', 'registration span coverage');
  assertContains(registration, 'emailOtpYaoTotalMs', 'Yao timing span');
  for (const timing of [
    'ecdsaRegistrationTotalMs',
    'ecdsaRegistrationClientCreateMs',
    'ecdsaRegistrationGatewayRespondMs',
    'ecdsaRegistrationClientProofVerifyMs',
    'ecdsaRegistrationGatewayActivateMs',
    'ecdsaRegistrationClientActivationFinalizeMs',
  ]) {
    assertContains(registration, timing, 'ECDSA timing span');
  }
  assertContains(registration, 'JSON.stringify(summary)', 'registration');
}

function main() {
  checkRoleLocalEcdsaMaterialHandlesAreIdentityLocal();
  checkWalletScopedUnlockAvoidsCollapsedNearBindingError();
  checkRegistrationTimingUsesSpanCoverage();
  console.log('[registration-capability-subjects] ok');
}

main();
