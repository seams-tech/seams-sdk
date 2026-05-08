import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test.describe('signer domain guard', () => {
  test('wallet auth and signer metadata domains are imported from shared domain constants', () => {
    const guardedFiles = [
      'client/src/core/types/seams.ts',
      'client/src/core/signingEngine/walletAuth/walletAuthModeResolver.ts',
      'client/src/core/indexedDB/passkeyClientDB.types.ts',
      'client/src/core/indexedDB/accountSignerLifecycle.ts',
    ];
    const forbidden = [
      /export type WalletAuthMethod\s*=\s*['"]passkey['"]/,
      /export type SigningSessionRetention\s*=\s*['"]session['"]/,
      /export type SignerKind\s*=\s*['"]threshold-ed25519['"]/,
      /export type SignerAuthMethod\s*=\s*['"]passkey['"]/,
      /export type SignerSource\s*=\s*['"]passkey_registration['"]/,
      /method:\s*['"]passkey['"];/,
      /method:\s*['"]email_otp['"];/,
      /primaryAuthMethod\s*===\s*['"]passkey['"]/,
      /primaryAuthMethod\s*===\s*['"]email_otp['"]/,
    ];

    const violations: string[] = [];
    for (const relativePath of guardedFiles) {
      const source = readRepoFile(relativePath);
      if (!source.includes('@shared/utils')) {
        violations.push(`missing shared domain import: ${relativePath}`);
      }
      for (const pattern of forbidden) {
        if (pattern.test(source)) {
          violations.push(`local wallet/signer domain literal: ${relativePath}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });
});
