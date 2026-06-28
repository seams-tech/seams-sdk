import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { parseD1BoundaryWalletIdResult } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthBoundary';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const cloudflareRouterDir = path.join(repoRoot, 'packages/sdk-server-ts/src/router/cloudflare');

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

function listProductionCloudflareD1Files(): string[] {
  return fs
    .readdirSync(cloudflareRouterDir, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .filter((name) => /^d1.*\.ts$/.test(name) && !name.endsWith('.typecheck.ts'))
    .map((name) => path.relative(repoRoot, path.join(cloudflareRouterDir, name)))
    .sort();
}

function listProductionServerTypeScriptFiles(relativeDir: string): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  const entries = fs.readdirSync(absoluteDir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const entryPath = path.join(absoluteDir, entry.name);
    if (entry.isDirectory()) {
      files.push(
        ...listProductionServerTypeScriptFiles(path.relative(repoRoot, entryPath)),
      );
      continue;
    }
    if (entry.isFile() && /\.ts$/.test(entry.name) && !entry.name.endsWith('.typecheck.ts')) {
      files.push(path.relative(repoRoot, entryPath));
    }
  }
  return files.sort();
}

function listWalletPersistenceParserGuardFiles(): string[] {
  const files = new Set<string>();
  for (const relativePath of listProductionServerTypeScriptFiles('packages/sdk-server-ts/src/core')) {
    files.add(relativePath);
  }
  for (const relativePath of listProductionCloudflareD1Files()) {
    files.add(relativePath);
  }
  return [...files].sort();
}

function collectD1NearAccountPredicateViolations(): string[] {
  const violations: string[] = [];
  for (const relativePath of listProductionCloudflareD1Files()) {
    const source = readRepoFile(relativePath);
    if (source.includes('isValidAccountId')) {
      violations.push(`${relativePath} validates D1 wallet identity as a NEAR account`);
    }
    if (/subject:\s*`near:\$\{/.test(source)) {
      violations.push(`${relativePath} links D1 wallet identity through a near:* subject`);
    }
  }
  return violations;
}

function collectCoreWalletNearAccountPredicateViolations(): string[] {
  const violations: string[] = [];
  const checkedFiles = ['packages/sdk-server-ts/src/core/AuthService.ts'];
  for (const relativePath of checkedFiles) {
    const source = readRepoFile(relativePath);
    const matches = source.matchAll(
      /isValidAccountId\((walletId|userId|linkedWalletId|enrollment\.walletId)\)/g,
    );
    for (const match of matches) {
      violations.push(`${relativePath} validates ${match[1]} as a NEAR account`);
    }
  }
  return violations;
}

function collectNearPublicKeyRootPasskeyFieldViolations(): string[] {
  const violations: string[] = [];
  const checkedFiles = [
    'packages/sdk-server-ts/src/core/NearPublicKeyStore.ts',
    'packages/sdk-server-ts/src/router/cloudflare/d1WebAuthnRecords.ts',
  ];
  for (const relativePath of checkedFiles) {
    const source = readRepoFile(relativePath);
    const recordType = source.match(/export type NearPublicKeyRecord = \{[\s\S]*?\n\};/);
    if (!recordType) {
      violations.push(`${relativePath} is missing NearPublicKeyRecord`);
      continue;
    }
    if (/\brpId\?:\s*string;/.test(recordType[0])) {
      violations.push(`${relativePath} stores passkey rpId at NearPublicKeyRecord root`);
    }
    if (/\bcredentialIdB64u\?:\s*string;/.test(recordType[0])) {
      violations.push(
        `${relativePath} stores passkey credentialIdB64u at NearPublicKeyRecord root`,
      );
    }
    if (!recordType[0].includes('authBinding?: NearPublicKeyAuthBinding')) {
      violations.push(`${relativePath} lacks branch-specific NearPublicKey authBinding`);
    }
  }

  const relayListSource = readRepoFile(
    'packages/sdk-server-ts/src/router/cloudflare/d1NearPublicKeyStore.ts',
  );
  if (/\brecord\.(rpId|credentialIdB64u)\b/.test(relayListSource)) {
    violations.push('Cloudflare D1 NEAR public-key list response flattens passkey fields');
  }

  return violations;
}

function collectWalletPersistenceBrandCastViolations(): string[] {
  const violations: string[] = [];
  for (const relativePath of listWalletPersistenceParserGuardFiles()) {
    const source = readRepoFile(relativePath);
    if (/\bas\s+WalletId\b/.test(source)) {
      violations.push(`${relativePath} brands a raw string with as WalletId`);
    }
  }
  return violations;
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

  test('D1 auth and recovery boundaries parse wallet ids without NEAR account validation', () => {
    expect(parseD1BoundaryWalletIdResult('frost-vermillion-k7p9m2')).toEqual({
      ok: true,
      value: 'frost-vermillion-k7p9m2',
    });
    expect(parseD1BoundaryWalletIdResult('wallet:alice')).toEqual({
      ok: true,
      value: 'wallet:alice',
    });
    expect(parseD1BoundaryWalletIdResult('alice testnet')).toEqual({
      ok: false,
      code: 'invalid',
    });
    expect(collectD1NearAccountPredicateViolations()).toEqual([]);
    expect(collectCoreWalletNearAccountPredicateViolations()).toEqual([]);
    expect(collectNearPublicKeyRootPasskeyFieldViolations()).toEqual([]);
  });

  test('wallet persistence parsers use the wallet id parser before branding domain state', () => {
    expect(collectWalletPersistenceBrandCastViolations()).toEqual([]);
  });
});
