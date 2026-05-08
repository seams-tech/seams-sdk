import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const clientSrcRoot = path.join(repoRoot, 'client/src');

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listTsFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) return listTsFiles(fullPath);
    if (!entry.isFile() || !entry.name.endsWith('.ts')) return [];
    return [fullPath];
  });
}

function findCallObjects(source: string, callName: string): string[] {
  const objects: string[] = [];
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

test.describe('account signer lifecycle domain guard', () => {
  test('production signer lifecycle writes always set signerKind, signerAuthMethod, and signerSource', () => {
    const offenders: string[] = [];

    for (const absolutePath of listTsFiles(clientSrcRoot)) {
      const relativePath = path.relative(repoRoot, absolutePath);
      if (relativePath.endsWith('client/src/core/indexedDB/passkeyClientDB/manager.ts')) {
        continue;
      }

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

    expect(offenders).toEqual([]);
  });

  test('production signer lifecycle code uses shared signer domain constants', () => {
    const guardedFiles = [
      'client/src/core/indexedDB/accountSignerLifecycle.ts',
      'client/src/core/indexedDB/passkeyClientDB.types.ts',
      'client/src/core/indexedDB/unifiedIndexedDBManager.ts',
      'client/src/core/accountData/near/accountProjection.ts',
      'client/src/core/SeamsPasskey/near/linkDevicePreparedEcdsa.ts',
      'client/src/core/SeamsPasskey/evm/linkDeviceThresholdEcdsa.ts',
      'client/src/core/signingEngine/SigningEngine.ts',
      'client/src/core/signingEngine/flows/registration/accountLifecycle.ts',
    ];
    const forbidden = [
      /export\s+type\s+SignerKind\s*=\s*['"]threshold-ed25519['"]/,
      /export\s+type\s+SignerAuthMethod\s*=\s*['"]passkey['"]\s*\|/,
      /export\s+type\s+SignerSource\s*=\s*['"]passkey_registration['"]/,
      /signerKind:\s*['"]threshold-(?:ed25519|ecdsa)['"]/,
      /signerAuthMethod:\s*['"](?:passkey|email_otp)['"]/,
      /signerSource:\s*['"](?:passkey_registration|email_otp_registration|self_hosted_import)['"]/,
      /new Set\(\[['"]threshold-ed25519['"],\s*['"]threshold-ecdsa['"]\]\)/,
    ];

    const offenders: string[] = [];
    for (const relativePath of guardedFiles) {
      const source = readRepoFile(relativePath);
      if (!source.includes('@shared/utils')) {
        offenders.push(`missing shared signer domain import: ${relativePath}`);
      }
      for (const pattern of forbidden) {
        if (pattern.test(source)) {
          offenders.push(`hard-coded signer domain literal: ${relativePath}`);
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });
});
