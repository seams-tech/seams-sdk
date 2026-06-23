import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sdkSrcRoot = path.join(repoRoot, 'packages/sdk-web/src');
const canonicalExactIdentityPath =
  'packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.ts';

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listTypeScriptFiles(dir: string): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const absolutePath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listTypeScriptFiles(absolutePath));
      continue;
    }
    if (entry.isFile() && absolutePath.endsWith('.ts') && !absolutePath.endsWith('.d.ts')) {
      files.push(path.relative(repoRoot, absolutePath).replaceAll(path.sep, '/'));
    }
  }
  return files.sort();
}

function productionSdkTypeScriptFiles(): string[] {
  return listTypeScriptFiles(sdkSrcRoot).filter((relativePath) => {
    return !relativePath.endsWith('.typecheck.ts');
  });
}

function authorityTypeScriptFiles(): string[] {
  return productionSdkTypeScriptFiles().filter((relativePath) => {
    return (
      relativePath.startsWith('packages/sdk-web/src/core/signingEngine/') ||
      relativePath.startsWith('packages/sdk-web/src/SeamsWeb/operations/')
    );
  });
}

function sourceRangeBetween(source: string, startNeedle: string, endNeedle: string): string {
  const start = source.indexOf(startNeedle);
  expect(start, `missing source range start: ${startNeedle}`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf(endNeedle, start + startNeedle.length);
  expect(end, `missing source range end: ${endNeedle}`).toBeGreaterThan(start);
  return source.slice(start, end);
}

function firstCandidateMarkerLines(relativePath: string): string[] {
  const source = readRepoSource(relativePath);
  return source
    .split('\n')
    .filter((line) => {
      return (
        line.includes('candidates[0]') ||
        line.includes('records[0]') ||
        line.includes('[0] || null') ||
        line.includes('.at(0)')
      );
    })
    .map((line) => `${relativePath}: ${line.trim()}`);
}

function timestampSelectorMarkerLines(relativePath: string): string[] {
  const source = readRepoSource(relativePath);
  return source
    .split('\n')
    .filter((line) => {
      return line.includes('selectNewest') || line.includes('newest_runtime_candidate');
    })
    .map((line) => `${relativePath}: ${line.trim()}`);
}

test('Refactor 79 keeps ExactSigningLaneIdentity as the only public exact authority type', () => {
  const duplicateTypeExports: string[] = [];
  const exactSigningLaneExports: string[] = [];

  for (const relativePath of productionSdkTypeScriptFiles()) {
    const source = readRepoSource(relativePath);
    if (/export\s+type\s+ExactEcdsaLaneIdentity\b/.test(source)) {
      duplicateTypeExports.push(`${relativePath}: ExactEcdsaLaneIdentity`);
    }
    if (/export\s+type\s+ExactEcdsaRuntimeLaneRef\b/.test(source)) {
      duplicateTypeExports.push(`${relativePath}: ExactEcdsaRuntimeLaneRef`);
    }
    if (/export\s+type\s+ExactSigningLaneIdentity\b/.test(source)) {
      exactSigningLaneExports.push(relativePath);
    }
  }

  expect(duplicateTypeExports, duplicateTypeExports.join('\n')).toEqual([]);
  expect(exactSigningLaneExports).toEqual([canonicalExactIdentityPath]);
});

test('Refactor 79 ECDSA exact identity carries wallet id, key handle, and full key identity', () => {
  const source = readRepoSource(canonicalExactIdentityPath);
  const ecdsaIdentity = sourceRangeBetween(
    source,
    'export type ExactEcdsaSigningLaneIdentity = {',
    'export type ExactSigningLaneIdentity =',
  );

  expect(ecdsaIdentity).toContain('walletId: WalletId;');
  expect(ecdsaIdentity).toContain('keyHandle: EvmFamilyEcdsaKeyHandle;');
  expect(ecdsaIdentity).toContain('key: EvmFamilyEcdsaKeyIdentity;');
  expect(ecdsaIdentity).not.toContain('walletId: AccountId;');
  expect(ecdsaIdentity).not.toContain('keyHandle?: never;');
});

test('Refactor 79 first-candidate selectors stay explicitly inventoried', () => {
  const markerLines = authorityTypeScriptFiles().flatMap(firstCandidateMarkerLines);

  expect(markerLines).toEqual([
    'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts: const record = records[0];',
    'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts: const primaryEcdsaWalletKey = ecdsaWalletKeys[0] || null;',
    'packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts: )[0] || null',
    'packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts: const record = records[0];',
    'packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection.ts: const candidate = candidates.at(0);',
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/companionSessions.ts: const record = records[0];',
    'packages/sdk-web/src/core/signingEngine/session/identity/selectLane.ts: const candidate = candidates.at(0);',
    'packages/sdk-web/src/core/signingEngine/session/persistence/records.ts: if (candidates.length === 1) return candidates[0]!;',
    'packages/sdk-web/src/core/signingEngine/session/public.ts: const record = records[0]!;',
  ]);
});

test('Refactor 79 timestamp authority selectors stay explicitly inventoried', () => {
  const markerLines = authorityTypeScriptFiles().flatMap(timestampSelectorMarkerLines);

  expect(markerLines).toEqual([
    'packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection.ts: function selectNewestExportLaneWhenUnambiguous<TLane extends ConcreteExportAvailableLane>(',
    'packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection.ts: return selectNewestExportLaneWhenUnambiguous(sourceCandidates);',
    'packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection.ts: const selectedLane = selectNewestExportLaneWhenUnambiguous(runtimeCandidates);',
    "packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection.ts: reason: 'newest_runtime_candidate',",
    'packages/sdk-web/src/core/signingEngine/session/identity/selectLane.ts: function selectNewestCandidateWhenUnambiguous<TCandidate extends ConcreteTransactionCandidate>(',
    'packages/sdk-web/src/core/signingEngine/session/identity/selectLane.ts: return selectNewestCandidateWhenUnambiguous(bestSourceCandidates);',
  ]);
});
