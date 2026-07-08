#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');
const registrationButtonRoot =
  'packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/passkey-registration-btn';
const forbiddenImport =
  /(?:IframeTxConfirmer|TxTree|tx-confirmer|tx-confirm|export-key|export-private-key|ExportKey|viewer-modal|viewer-drawer|Drawer|Modal|\/react\b|@\/react\b|SeamsAuthMenu)/;

function absolutePath(relativePath) {
  return path.join(repoRoot, relativePath);
}

function listTypeScriptFiles(relativeRoot) {
  const absoluteRoot = absolutePath(relativeRoot);
  return fs.readdirSync(absoluteRoot).flatMap((entryName) => {
    const relativePath = path.join(relativeRoot, entryName).split(path.sep).join('/');
    const entry = fs.statSync(absolutePath(relativePath));
    if (entry.isDirectory()) return listTypeScriptFiles(relativePath);
    return /\.(ts|tsx)$/.test(entryName) ? [relativePath] : [];
  });
}

function readSource(relativePath) {
  return fs.readFileSync(absolutePath(relativePath), 'utf8');
}

function importSpecifiers(source) {
  const specifiers = [];
  const importPattern =
    /import\s+(?:type\s+)?(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]|import\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  for (const match of source.matchAll(importPattern)) {
    const specifier = match[1] || match[2];
    if (specifier) specifiers.push(specifier);
  }
  return specifiers;
}

function collectViolations() {
  const violations = [];
  for (const relativePath of listTypeScriptFiles(registrationButtonRoot)) {
    for (const specifier of importSpecifiers(readSource(relativePath))) {
      if (forbiddenImport.test(specifier)) {
        violations.push(`${relativePath}: forbidden registration-button import ${specifier}`);
      }
    }
  }
  return violations;
}

function main() {
  const violations = collectViolations();
  if (violations.length > 0) {
    console.error(
      `[passkey-registration-button-boundaries] failed with ${violations.length} violation(s):`,
    );
    for (const violation of violations) {
      console.error(`- ${violation}`);
    }
    process.exit(1);
  }
  console.log('[passkey-registration-button-boundaries] ok');
}

main();
