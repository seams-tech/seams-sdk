#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');
const accountMenuPath = 'packages/sdk-web/src/react/components/AccountMenuButton/index.tsx';
const exportModalPath =
  'packages/sdk-web/src/react/components/AccountMenuButton/ExportKeyTypeModal.tsx';
const reactStylesPath = 'packages/sdk-web/src/react/styles.css';

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
  requireContains(accountMenu, "chain: 'near'", accountMenuPath, violations);

  return violations;
}

function collectEmailOtpRestrictionViolations() {
  const violations = [];
  const accountMenu = readRepoSource(accountMenuPath);
  const modal = readRepoSource(exportModalPath);

  requireAbsent(accountMenu, "loginState.authMethod === 'email_otp'", accountMenuPath, violations);
  requireContains(accountMenu, 'setExportRestrictionMessage(', accountMenuPath, violations);
  requireAbsent(
    accountMenu,
    'Key export requires a passkey-authenticated account.',
    accountMenuPath,
    violations,
  );
  requireContains(accountMenu, 'if (exportRestrictionMessage) return;', accountMenuPath, violations);
  requireContains(modal, 'restrictionMessage', exportModalPath, violations);
  requireContains(modal, 'disabled={isBusy || isRestricted}', exportModalPath, violations);

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
    "@import './components/AccountMenuButton/ExportKeyTypeModal.css';",
    reactStylesPath,
    violations,
  );

  return violations;
}

function main() {
  const violations = [
    ...collectCanonicalExportApiViolations(),
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
