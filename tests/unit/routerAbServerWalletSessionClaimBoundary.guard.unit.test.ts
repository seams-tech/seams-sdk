import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function read(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listTsFiles(relativePath: string): string[] {
  const absolutePath = path.join(repoRoot, relativePath);
  const stat = fs.statSync(absolutePath);
  if (stat.isFile()) return /\.(ts|tsx)$/.test(relativePath) ? [relativePath] : [];
  return fs.readdirSync(absolutePath, { withFileTypes: true }).flatMap((entry) => {
    const childPath = path.join(relativePath, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'dist' || entry.name === 'node_modules') return [];
      return listTsFiles(childPath);
    }
    return /\.(ts|tsx)$/.test(entry.name) ? [childPath] : [];
  });
}

test.describe('Router A/B server Wallet Session claim boundary guards', () => {
  test('active signing-capable server code rejects legacy threshold-session claim kinds', () => {
    const guardedRoots = [
      'packages/sdk-server-ts/src/router',
      'packages/sdk-server-ts/src/core/ThresholdService',
      'packages/sdk-server-ts/src/threshold/session/signingSessionSeal',
      'packages/sdk-web/src/core/signingEngine/session',
      'packages/sdk-web/src/core/signingEngine/flows',
    ];
    const forbiddenMarkers = [
      'parseThresholdEd25519SessionClaims',
      'parseThresholdEcdsaSessionClaims',
      'LegacyThresholdSessionJwtKind',
      'THRESHOLD_ED25519_SESSION_AUTH_TOKEN_KIND',
      'THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND',
      'export async function signWalletSessionJwt',
      'export function signWalletSessionJwt',
      "walletSessionJwt ? 'jwt' : 'cookie'",
      "kind: 'threshold_ed25519_session_v1'",
      'kind: "threshold_ed25519_session_v1"',
      "kind: 'threshold_ecdsa_session_v2'",
      'kind: "threshold_ecdsa_session_v2"',
      "kind: 'browser_cookie'",
      'kind: "browser_cookie"',
    ];

    const offenders = guardedRoots
      .flatMap((root) => listTsFiles(root))
      .flatMap((relativePath) => {
        if (relativePath.endsWith('.typecheck.ts')) return [];
        const source = read(relativePath);
        return forbiddenMarkers
          .filter((marker) => source.includes(marker))
          .map((marker) => `${relativePath} contains ${marker}`);
      });

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('Router A/B server Wallet Session issuer uses exact claim builders', () => {
    const source = read('packages/sdk-server-ts/src/router/commonRouterUtils.ts');
    const forbiddenMarkers = [
      'extraClaims',
      'allowedSessionKinds',
      'WalletSessionJwtKind',
      'signWalletSessionJwt',
      'isEcdsaWalletSessionJwtKind',
    ];
    const offenders = forbiddenMarkers
      .filter((marker) => source.includes(marker))
      .map((marker) => `commonRouterUtils.ts contains ${marker}`);

    expect(offenders, offenders.join('\n')).toEqual([]);
    expect(source).toContain('function buildRouterAbEd25519WalletSessionClaims(');
    expect(source).toContain('): RouterAbEd25519WalletSessionClaims {');
    expect(source).toContain('const claims = buildRouterAbEd25519WalletSessionClaims({');
    expect(source).toContain('function buildRouterAbEcdsaHssWalletSessionClaims(');
    expect(source).toContain('const claims: RouterAbEcdsaHssWalletSessionClaims = {');
    expect(source).toContain('const claims = buildRouterAbEcdsaHssWalletSessionClaims({');
  });

  test('Router A/B ECDSA-HSS scope comparison uses canonical protocol bytes', () => {
    const guardedFiles = [
      'packages/shared-ts/src/utils/routerAbEcdsaHss.ts',
      'packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts',
      'packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/presignaturePool.ts',
    ];
    const forbiddenMarkers = [
      'JSON.stringify(left) === JSON.stringify(right)',
      'sameNormalSigningScope(',
      'sameEcdsaHssNormalSigningScope(',
    ];
    const offenders = guardedFiles.flatMap((relativePath) => {
      const source = read(relativePath);
      return forbiddenMarkers
        .filter((marker) => source.includes(marker))
        .map((marker) => `${relativePath} contains ${marker}`);
    });

    expect(offenders, offenders.join('\n')).toEqual([]);
    expect(read('packages/shared-ts/src/utils/routerAbEcdsaHss.ts')).toContain(
      'routerAbEcdsaHssNormalSigningScopeCanonicalBytesV1',
    );
    expect(read('packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts')).toContain(
      'sameRouterAbEcdsaHssNormalSigningScopeV1',
    );
    expect(
      read('packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/presignaturePool.ts'),
    ).toContain('routerAbEcdsaHssNormalSigningScopeCanonicalBytesV1');
  });

  test('Router A/B private service JSON calls use the shared internal-auth helper', () => {
    const guardedFiles = [
      'packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPresignBridge.ts',
      'packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts',
    ];
    const offenders = guardedFiles.flatMap((relativePath) => {
      const source = read(relativePath);
      const markers = [
        '[ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1]:',
        'body: JSON.stringify(request)',
        'body: JSON.stringify(input.body)',
      ];
      return markers
        .filter((marker) => source.includes(marker))
        .map((marker) => `${relativePath} contains ${marker}`);
    });

    expect(offenders, offenders.join('\n')).toEqual([]);
    for (const relativePath of guardedFiles) {
      expect(read(relativePath)).toContain('postRouterAbInternalServiceJson');
    }
  });
});
