import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listProductionCoreFiles(dir = path.join(repoRoot, 'client/src/core')): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
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

test.describe('wallet-scoped lookup guards', () => {
  test('production wallet paths do not resolve wallet ids through NEAR projection helpers', () => {
    const allowedToAccountIdWalletFiles = new Set([
      'client/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts',
      'client/src/core/signingEngine/session/public.ts',
      'client/src/core/signingEngine/session/availability/availableSigningLanes.ts',
      'client/src/core/signingEngine/session/availability/readiness.ts',
      'client/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts',
      'client/src/core/signingEngine/session/emailOtp/persistedSnapshot.ts',
      'client/src/core/signingEngine/session/emailOtp/sealedRestoreOrchestrator.ts',
      'client/src/core/signingEngine/session/passkey/ecdsaRecovery.ts',
      'client/src/core/signingEngine/session/persistence/records.ts',
    ]);
    const forbiddenGlobal = [
      'buildNearAccountRefs(walletId)',
      'buildNearProfileId(walletId)',
      'ensureEmailOtpNearAccountMapping',
      'hostedWalletIdAsNearAccountId',
      'toAccountId(persistArgs.walletId)',
    ];

    const violations: string[] = [];
    for (const relativePath of listProductionCoreFiles()) {
      const source = readRepoFile(relativePath);
      for (const token of forbiddenGlobal) {
        if (source.includes(token)) {
          violations.push(`${relativePath} contains ${token}`);
        }
      }
      if (
        source.includes('toAccountId(args.walletId)') &&
        !allowedToAccountIdWalletFiles.has(relativePath)
      ) {
        violations.push(`${relativePath} contains toAccountId(args.walletId)`);
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('ECDSA bootstrap persistence writes wallet signers without NEAR compatibility mapping APIs', () => {
    const source = readRepoFile(
      'client/src/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence.ts',
    );

    expect(source).not.toContain('upsertChainAccount');
    expect(source).not.toContain('setLastProfileStateForProfile');
    expect(source).not.toContain('near:testnet');
  });

  test('core NEAR-account authenticator lookup has an explicit near-prefixed API only', () => {
    const lifecycle = readRepoFile(
      'client/src/core/signingEngine/flows/registration/accountLifecycle.ts',
    );
    const publicApi = readRepoFile('client/src/core/signingEngine/flows/registration/public.ts');

    expect(lifecycle).not.toContain('export async function getAuthenticatorsByUser');
    expect(publicApi).not.toContain('export function getAuthenticatorsByUser');
  });
});
