#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function assertNoOffenders(label, offenders) {
  assert.deepEqual(offenders, [], `${label}\n${offenders.join('\n')}`);
}

function checkEcdsaDerivationScopeUsesCanonicalProtocolBytes() {
  const guardedFiles = [
    'packages/shared-ts/src/utils/routerAbEcdsaDerivation.ts',
    'packages/wallet-server/src/router/domains/signingOperations/routerAbPrivateSigningWorker.ts',
    'packages/wallet/src/core/signingEngine/routerAb/ecdsaDerivation/presignaturePool.ts',
  ];
  const forbiddenMarkers = [
    'JSON.stringify(left) === JSON.stringify(right)',
    'sameNormalSigningScope(',
    'sameEcdsaDerivationNormalSigningScope(',
  ];
  const offenders = [];
  for (const relativePath of guardedFiles) {
    const source = readRepoFile(relativePath);
    for (const marker of forbiddenMarkers) {
      if (source.includes(marker)) offenders.push(`${relativePath} contains ${marker}`);
    }
  }
  assertNoOffenders('Router A/B ECDSA derivation scope must use canonical bytes', offenders);
  assert.ok(
    readRepoFile('packages/shared-ts/src/utils/routerAbEcdsaDerivation.ts').includes(
      'routerAbEcdsaDerivationNormalSigningScopeCanonicalBytesV1',
    ),
    'routerAbEcdsaDerivation.ts missing canonical-byte helper',
  );
  assert.ok(
    readRepoFile(
      'packages/wallet-server/src/router/domains/signingOperations/routerAbPrivateSigningWorker.ts',
    ).includes('sameRouterAbEcdsaDerivationNormalSigningScopeV1'),
    'routerAbPrivateSigningWorker.ts missing canonical scope comparison',
  );
  assert.ok(
    readRepoFile(
      'packages/wallet/src/core/signingEngine/routerAb/ecdsaDerivation/presignaturePool.ts',
    ).includes('routerAbEcdsaDerivationNormalSigningScopeCanonicalBytesV1'),
    'presignaturePool.ts missing canonical-byte helper',
  );
}

function checkPrivateServiceCallsUseSharedInternalAuthHelper() {
  const guardedFiles = [
    'packages/wallet-server/src/core/ThresholdService/routerAb/ecdsaDerivationPresignBridge.ts',
    'packages/wallet-server/src/router/domains/signingOperations/routerAbPrivateSigningWorker.ts',
  ];
  const forbiddenMarkers = [
    '[ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1]:',
    'body: JSON.stringify(request)',
    'body: JSON.stringify(input.body)',
  ];
  const offenders = [];
  for (const relativePath of guardedFiles) {
    const source = readRepoFile(relativePath);
    for (const marker of forbiddenMarkers) {
      if (source.includes(marker)) offenders.push(`${relativePath} contains ${marker}`);
    }
  }
  assertNoOffenders('Router A/B private service calls must use shared internal auth', offenders);
  for (const relativePath of guardedFiles) {
    assert.ok(
      readRepoFile(relativePath).includes('postRouterAbInternalServiceJson'),
      `${relativePath} missing postRouterAbInternalServiceJson`,
    );
  }
}

checkEcdsaDerivationScopeUsesCanonicalProtocolBytes();
checkPrivateServiceCallsUseSharedInternalAuthHelper();

console.log('[check-router-ab-private-service-boundaries] passed');
