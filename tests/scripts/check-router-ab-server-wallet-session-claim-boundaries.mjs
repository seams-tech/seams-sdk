#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listTsFiles(relativePath) {
  const absolutePath = path.join(repoRoot, relativePath);
  const stat = fs.statSync(absolutePath);
  if (stat.isFile()) return /\.(ts|tsx)$/.test(relativePath) ? [relativePath] : [];

  const files = [];
  for (const entry of fs.readdirSync(absolutePath, { withFileTypes: true })) {
    const childPath = path.join(relativePath, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'dist' || entry.name === 'node_modules') continue;
      files.push(...listTsFiles(childPath));
      continue;
    }
    if (/\.(ts|tsx)$/.test(entry.name)) files.push(childPath);
  }
  return files;
}

function assertNoOffenders(label, offenders) {
  assert.deepEqual(offenders, [], `${label}\n${offenders.join('\n')}`);
}

function collectForbiddenMarkerOffenders(paths, forbiddenMarkers) {
  const offenders = [];
  for (const relativePath of paths) {
    if (relativePath.endsWith('.typecheck.ts')) continue;
    const source = readRepoFile(relativePath);
    for (const marker of forbiddenMarkers) {
      if (source.includes(marker)) offenders.push(`${relativePath} contains ${marker}`);
    }
  }
  return offenders;
}

function checkActiveSigningCapableServerCodeRejectsLegacyClaimKinds() {
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

  const guardedFiles = [];
  for (const root of guardedRoots) guardedFiles.push(...listTsFiles(root));
  assertNoOffenders(
    'active signing-capable server code must reject legacy threshold-session claim kinds',
    collectForbiddenMarkerOffenders(guardedFiles, forbiddenMarkers),
  );
}

function checkRouterAbServerWalletSessionIssuerUsesExactClaimBuilders() {
  const source = readRepoFile('packages/sdk-server-ts/src/router/commonRouterUtils.ts');
  const forbiddenMarkers = [
    'extraClaims',
    'allowedSessionKinds',
    'WalletSessionJwtKind',
    'signWalletSessionJwt',
    'isEcdsaWalletSessionJwtKind',
  ];
  const offenders = [];
  for (const marker of forbiddenMarkers) {
    if (source.includes(marker)) offenders.push(`commonRouterUtils.ts contains ${marker}`);
  }

  assertNoOffenders('Router A/B server Wallet Session issuer must use exact claim builders', offenders);
  for (const marker of [
    'function buildRouterAbEd25519WalletSessionClaims(',
    '): RouterAbEd25519WalletSessionClaims {',
    'const claims = buildRouterAbEd25519WalletSessionClaims({',
    'function buildRouterAbEcdsaHssWalletSessionClaims(',
    'const claims: RouterAbEcdsaHssWalletSessionClaims = {',
    'const claims = buildRouterAbEcdsaHssWalletSessionClaims({',
  ]) {
    assert.ok(source.includes(marker), `commonRouterUtils.ts missing ${marker}`);
  }
}

function checkRouterAbEcdsaHssScopeComparisonUsesCanonicalProtocolBytes() {
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
  const offenders = collectForbiddenMarkerOffenders(guardedFiles, forbiddenMarkers);

  assertNoOffenders('Router A/B ECDSA-HSS scope comparison must use canonical bytes', offenders);
  assert.ok(
    readRepoFile('packages/shared-ts/src/utils/routerAbEcdsaHss.ts').includes(
      'routerAbEcdsaHssNormalSigningScopeCanonicalBytesV1',
    ),
    'routerAbEcdsaHss.ts missing canonical-byte helper',
  );
  assert.ok(
    readRepoFile('packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts').includes(
      'sameRouterAbEcdsaHssNormalSigningScopeV1',
    ),
    'routerAbPrivateSigningWorker.ts missing canonical scope comparison',
  );
  assert.ok(
    readRepoFile(
      'packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/presignaturePool.ts',
    ).includes('routerAbEcdsaHssNormalSigningScopeCanonicalBytesV1'),
    'presignaturePool.ts missing canonical-byte helper',
  );
}

function checkRouterAbPrivateServiceJsonCallsUseSharedInternalAuthHelper() {
  const guardedFiles = [
    'packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPresignBridge.ts',
    'packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts',
  ];
  const forbiddenMarkers = [
    '[ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1]:',
    'body: JSON.stringify(request)',
    'body: JSON.stringify(input.body)',
  ];
  const offenders = collectForbiddenMarkerOffenders(guardedFiles, forbiddenMarkers);

  assertNoOffenders(
    'Router A/B private service JSON calls must use shared internal-auth helper',
    offenders,
  );
  for (const relativePath of guardedFiles) {
    assert.ok(
      readRepoFile(relativePath).includes('postRouterAbInternalServiceJson'),
      `${relativePath} missing postRouterAbInternalServiceJson`,
    );
  }
}

checkActiveSigningCapableServerCodeRejectsLegacyClaimKinds();
checkRouterAbServerWalletSessionIssuerUsesExactClaimBuilders();
checkRouterAbEcdsaHssScopeComparisonUsesCanonicalProtocolBytes();
checkRouterAbPrivateServiceJsonCallsUseSharedInternalAuthHelper();

console.log('[check-router-ab-server-wallet-session-claim-boundaries] passed');
