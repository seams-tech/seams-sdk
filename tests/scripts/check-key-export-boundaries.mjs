#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');
const accountMenuPath = 'packages/sdk-web/src/react/components/AccountMenuButton/index.tsx';
const exportKeysSectionPath =
  'packages/sdk-web/src/react/components/AccountMenuButton/ExportKeysSection.tsx';
const reactStylesPath = 'packages/sdk-web/src/react/styles.css';
const keyExportFlowPath =
  'packages/sdk-web/src/core/signingEngine/flows/recovery/keyExportFlow.ts';
const ed25519YaoExportFlowPath =
  'packages/sdk-web/src/core/signingEngine/flows/recovery/ed25519YaoExportFlow.ts';
const ed25519YaoClientPath =
  'packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoClient.ts';
const passkeyConfirmWorkerPath =
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts';

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

function collectCanonicalExportApiViolations() {
  const violations = [];
  const accountMenu = readRepoSource(accountMenuPath);

  requireContains(accountMenu, '.keys.exportKeypairWithUI(', accountMenuPath, violations);
  requireContains(accountMenu, "kind: 'ecdsa'", accountMenuPath, violations);
  requireContains(accountMenu, "kind: 'ed25519'", accountMenuPath, violations);
  requireAbsent(accountMenu, "kind: 'near'", accountMenuPath, violations);

  return violations;
}

function collectEd25519YaoExportViolations() {
  const violations = [];
  const keyExportFlow = readRepoSource(keyExportFlowPath);
  const ed25519YaoExportFlow = readRepoSource(ed25519YaoExportFlowPath);
  const ed25519YaoClient = readRepoSource(ed25519YaoClientPath);
  const passkeyConfirmWorker = readRepoSource(passkeyConfirmWorkerPath);
  const exportKeysSection = readRepoSource(exportKeysSectionPath);

  requireContains(keyExportFlow, "kind: 'ed25519'", keyExportFlowPath, violations);
  requireContains(keyExportFlow, 'nearAccount: NearAccountRef', keyExportFlowPath, violations);
  requireContains(keyExportFlow, 'chainTarget?: never', keyExportFlowPath, violations);
  requireContains(exportKeysSection, "chain: 'near'", exportKeysSectionPath, violations);
  requireContains(exportKeysSection, 'Ed25519 signing key', exportKeysSectionPath, violations);
  requireContains(
    ed25519YaoClient,
    'redactCredentialExtensionOutputs<WebAuthnAuthenticationCredential>',
    ed25519YaoClientPath,
    violations,
  );
  requireContains(
    ed25519YaoClient,
    'buildRouterAbEd25519YaoExportAdmissionBodyV1',
    ed25519YaoClientPath,
    violations,
  );
  requireAbsent(
    ed25519YaoClient,
    'webauthn_authentication: args.webauthnAuthentication',
    ed25519YaoClientPath,
    violations,
  );
  requireAbsent(ed25519YaoClient, 'seedB64u', ed25519YaoClientPath, violations);
  requireAbsent(passkeyConfirmWorker, 'seedB64u', passkeyConfirmWorkerPath, violations);
  requireAbsent(ed25519YaoExportFlow, 'ed25519-hss', ed25519YaoExportFlowPath, violations);
  requireAbsent(ed25519YaoExportFlow, "kind: 'near'", ed25519YaoExportFlowPath, violations);

  return violations;
}

function collectEmailOtpRestrictionViolations() {
  const violations = [];
  const accountMenu = readRepoSource(accountMenuPath);
  const exportKeysSection = readRepoSource(exportKeysSectionPath);

  requireAbsent(accountMenu, "loginState.authMethod === 'email_otp'", accountMenuPath, violations);
  requireContains(accountMenu, 'setExportRestrictionMessage(', accountMenuPath, violations);
  requireAbsent(
    accountMenu,
    'Key export requires a passkey-authenticated account.',
    accountMenuPath,
    violations,
  );
  requireContains(
    exportKeysSection,
    'restrictionMessage',
    exportKeysSectionPath,
    violations,
  );
  requireContains(exportKeysSection, 'disabled={isBusy}', exportKeysSectionPath, violations);

  return violations;
}

function collectPortalHostViolations() {
  const violations = [];
  const accountMenu = readRepoSource(accountMenuPath);

  requireContains(accountMenu, '{canPortal &&', accountMenuPath, violations);
  requireContains(accountMenu, '          portalHost!,', accountMenuPath, violations);
  requireAbsent(
    accountMenu,
    'document.body so global modal CSS applies consistently',
    accountMenuPath,
    violations,
  );
  requireAbsent(
    accountMenu,
    "(typeof document !== 'undefined' ? document.body : portalHost)!",
    accountMenuPath,
    violations,
  );

  return violations;
}

function collectReactStylesViolations() {
  const violations = [];
  const reactStyles = readRepoSource(reactStylesPath);

  requireContains(
    reactStyles,
    "@import './components/AccountMenuButton/ExportKeysSection.css';",
    reactStylesPath,
    violations,
  );

  return violations;
}

function main() {
  const violations = [
    ...collectCanonicalExportApiViolations(),
    ...collectEd25519YaoExportViolations(),
    ...collectEmailOtpRestrictionViolations(),
    ...collectPortalHostViolations(),
    ...collectReactStylesViolations(),
  ];

  if (violations.length > 0) {
    console.error('[check-key-export-boundaries] failed');
    for (const violation of violations) {
      console.error(`- ${violation}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log('[check-key-export-boundaries] passed');
}

main();
