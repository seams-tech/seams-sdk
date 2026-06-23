import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listProductionCoreFiles(dir = path.join(repoRoot, 'packages/sdk-web/src/core')): string[] {
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
      if (/walletId\s*:\s*toAccountId\s*\([^)]*walletId[^)]*\)/.test(source)) {
        violations.push(`${relativePath} assigns a NEAR-projected value to walletId`);
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('ECDSA wallet-scoped files reject NEAR account projections for wallet identity', () => {
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
    const violations: string[] = [];

    for (const relativePath of ecdsaWalletScopedFiles) {
      const source = readRepoFile(relativePath);
      for (const pattern of forbiddenPatterns) {
        if (pattern.test(source)) {
          violations.push(`${relativePath} matches ${pattern}`);
        }
      }
    }

    const reauthSource = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts',
    );
    const reauthStart = reauthSource.indexOf(
      'export function buildReauthAnchorIdentityFromAvailableLane',
    );
    const reauthEnd = reauthSource.indexOf('\nfunction emptyEd25519Lane', reauthStart);
    const reauthBody = reauthSource.slice(reauthStart, reauthEnd);

    expect(reauthStart).toBeGreaterThanOrEqual(0);
    expect(reauthEnd).toBeGreaterThan(reauthStart);
    expect(reauthBody).not.toMatch(/toAccountId\s*\([^)]*walletId[^)]*\)/);
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('ECDSA bootstrap persistence writes wallet signers without NEAR compatibility mapping APIs', () => {
    const source = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence.ts',
    );

    expect(source).not.toContain('upsertChainAccount');
    expect(source).not.toContain('setLastProfileStateForProfile');
    expect(source).not.toContain('near:testnet');
  });

  test('core NEAR-account authenticator lookup has an explicit near-prefixed API only', () => {
    const lifecycle = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/registration/accountLifecycle.ts',
    );
    const publicApi = readRepoFile('packages/sdk-web/src/core/signingEngine/flows/registration/public.ts');

    expect(lifecycle).not.toContain('export async function getAuthenticatorsByUser');
    expect(publicApi).not.toContain('export function getAuthenticatorsByUser');
  });
});
