#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const clientSrcRoot = path.join(repoRoot, 'packages/sdk-web/src');

function readRepoFile(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listTypeScriptFiles(dir) {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listTypeScriptFiles(fullPath));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith('.ts')) files.push(fullPath);
  }
  return files;
}

function findCallObjects(source, callName) {
  const objects = [];
  let searchFrom = 0;
  const needle = `${callName}({`;

  while (true) {
    const callStart = source.indexOf(needle, searchFrom);
    if (callStart < 0) break;

    let depth = 0;
    let end = -1;
    for (let i = callStart + callName.length + 1; i < source.length; i += 1) {
      const char = source[i];
      if (char === '{') depth += 1;
      if (char === '}') {
        depth -= 1;
        if (depth === 0) {
          end = i + 1;
          break;
        }
      }
    }

    if (end < 0) break;
    objects.push(source.slice(callStart, end));
    searchFrom = end;
  }

  return objects;
}

function checkProductionSignerLifecycleWritesCarryRequiredDomainFields() {
  const offenders = [];

  for (const absolutePath of listTypeScriptFiles(clientSrcRoot)) {
    const relativePath = path.relative(repoRoot, absolutePath);
    const source = readRepoFile(relativePath);
    for (const callName of ['activateAccountSigner', 'stageAccountSigner']) {
      for (const callObject of findCallObjects(source, callName)) {
        if (
          !callObject.includes('signerKind:') ||
          !callObject.includes('signerAuthMethod:') ||
          !callObject.includes('signerSource:')
        ) {
          offenders.push(`${relativePath}:${callName}`);
        }
      }
    }
  }

  assert.deepEqual(
    offenders,
    [],
    `production signer lifecycle writes must set signerKind, signerAuthMethod, and signerSource\n${offenders.join(
      '\n',
    )}`,
  );
}

function checkProductionSignerAndWalletDomainCodeUsesSharedConstants() {
  const guardedFiles = [
    'packages/sdk-web/src/core/types/seams.ts',
    'packages/sdk-web/src/core/indexedDB/accountSignerLifecycle.ts',
    'packages/sdk-web/src/core/indexedDB/passkeyClientDB.types.ts',
    'packages/sdk-web/src/core/indexedDB/unifiedIndexedDBManager.ts',
    'packages/sdk-web/src/core/accountData/near/accountProjection.ts',
    'packages/sdk-web/src/SeamsWeb/operations/devices/linkDevice.ts',
    'packages/sdk-web/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts',
    'packages/sdk-web/src/core/signingEngine/flows/registration/accountLifecycle.ts',
  ];
  const forbiddenPatterns = [
    /export\s+type\s+WalletAuthMethod\s*=\s*['"]passkey['"]/,
    /export\s+type\s+SigningSessionRetention\s*=\s*['"]session['"]/,
    /export\s+type\s+SignerKind\s*=\s*['"]threshold-ed25519['"]/,
    /export\s+type\s+SignerAuthMethod\s*=\s*['"]passkey['"]\s*\|/,
    /export\s+type\s+SignerSource\s*=\s*['"]passkey_registration['"]/,
    /method:\s*['"]passkey['"];/,
    /method:\s*['"]email_otp['"];/,
    /primaryAuthMethod\s*===\s*['"]passkey['"]/,
    /primaryAuthMethod\s*===\s*['"]email_otp['"]/,
    /signerKind:\s*['"]threshold-(?:ed25519|ecdsa)['"]/,
    /signerAuthMethod:\s*['"](?:passkey|email_otp)['"]/,
    /signerSource:\s*['"](?:passkey_registration|email_otp_registration|self_hosted_import)['"]/,
    /new Set\(\[['"]threshold-ed25519['"],\s*['"]threshold-ecdsa['"]\]\)/,
  ];

  const offenders = [];
  for (const relativePath of guardedFiles) {
    const source = readRepoFile(relativePath);
    if (!source.includes('@shared/utils')) {
      offenders.push(`missing shared signer domain import: ${relativePath}`);
    }
    for (const pattern of forbiddenPatterns) {
      if (pattern.test(source)) offenders.push(`hard-coded signer domain literal: ${relativePath}`);
    }
  }

  assert.deepEqual(
    offenders,
    [],
    `production signer and wallet domain code must use shared signer domain constants\n${offenders.join(
      '\n',
    )}`,
  );
}

checkProductionSignerLifecycleWritesCarryRequiredDomainFields();
checkProductionSignerAndWalletDomainCodeUsesSharedConstants();

console.log('[check-account-signer-lifecycle-boundaries] passed');
