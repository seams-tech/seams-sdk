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

test('Refactor 79 planning lane base does not carry optional session identity', () => {
  const source = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/operationState/types.ts',
  );
  const basePlanningLane = sourceRangeBetween(
    source,
    'type BaseSigningSessionPlanningLane = {',
    'type BranchSigningSessionRuntimeState =',
  );
  const runtimeState = sourceRangeBetween(
    source,
    'type BranchSigningSessionRuntimeState =',
    'export type Ed25519SigningSessionPlanningLane =',
  );
  const resolvedIdentity = sourceRangeBetween(
    source,
    'type BaseResolvedSigningSessionIdentity =',
    'export type ResolvedEd25519SigningSessionIdentity =',
  );

  expect(basePlanningLane).not.toContain('thresholdSessionId?:');
  expect(basePlanningLane).not.toContain('backingMaterialSessionId?:');
  expect(basePlanningLane).not.toContain('activeSignerSlot?:');
  expect(source).not.toMatch(/backingMaterialSessionId\?:\s*BackingMaterialSessionId/);
  expect(source).not.toMatch(/activeSignerSlot\?:\s*number/);
  expect(runtimeState).toContain("runtimeState: 'no_runtime_material';");
  expect(runtimeState).toContain("runtimeState: 'backing_material';");
  expect(runtimeState).toContain("runtimeState: 'active_signer';");
  expect(runtimeState).toContain("runtimeState: 'backing_material_with_active_signer';");
  expect(resolvedIdentity).toContain('BranchSigningSessionRuntimeState');
});

test('Refactor 79 Email OTP ECDSA worker handles are wallet-key scoped', () => {
  const generatedSignerCore = readRepoSource(
    'packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts',
  );
  const secretSources = readRepoSource('packages/sdk-web/src/core/platform/secretSources.ts');

  expect(generatedSignerCore).not.toContain('EcdsaBootstrapEmailOtpWorkerSessionHandle');
  expect(generatedSignerCore).not.toContain('email_otp_worker_session');
  expect(secretSources).toContain('walletKeyId: WalletKeyId;');
  expect(secretSources).toContain('rpId?: never;');
});

test('Refactor 79 signer-core ECDSA export public facts exclude SDK lane key handles', () => {
  const generatedSignerCore = readRepoSource(
    'packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts',
  );
  const exportPublicFacts = sourceRangeBetween(
    generatedSignerCore,
    'export type EcdsaRoleLocalExportPublicFacts = {',
    'export type BuildEcdsaRoleLocalExportArtifactCommand =',
  );

  expect(exportPublicFacts).toContain('applicationBindingDigestB64u: string');
  expect(exportPublicFacts).not.toContain('keyHandle');
});

test('Refactor 79 ECDSA keygen and session envelopes expose walletKeyId rather than rpId', () => {
  const guardedFiles = [
    'packages/sdk-web/src/core/signingEngine/threshold/ecdsa/keygen.ts',
    'packages/sdk-web/src/core/signingEngine/threshold/ecdsa/activation.ts',
    'packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts',
    'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
    'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence.ts',
    'packages/sdk-web/src/core/signingEngine/session/persistence/records.ts',
    'packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts',
  ];
  const violations: string[] = [];

  for (const relativePath of guardedFiles) {
    const source = readRepoSource(relativePath);
    if (/rpId:\s*walletKeyId/.test(source)) {
      violations.push(`${relativePath}: rpId assigned from walletKeyId`);
    }
    if (/keygen\.rpId\b/.test(source)) {
      violations.push(`${relativePath}: keygen.rpId read`);
    }
    if (/authMetadata\.rpId\b/.test(source)) {
      violations.push(`${relativePath}: authMetadata.rpId read`);
    }
    if (/authMetadata:\s*\{\s*rpId\b/.test(source)) {
      violations.push(`${relativePath}: authMetadata writes rpId`);
    }
  }

  expect(violations, violations.join('\n')).toEqual([]);
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

test('Refactor 79 ECDSA-HSS context artifacts do not reintroduce product or auth scope fields', () => {
  const guardedArtifacts = [
    'crates/ecdsa-hss/src/shared/context.rs',
    'crates/ecdsa-hss/formal-verification/verus/src/shared/context.rs',
    'crates/ecdsa-hss/formal-verification/lean-boundary/rust-boundary/src/lib.rs',
    'crates/ecdsa-hss/formal-verification/lean-boundary/EcdsaHss/Types.lean',
    'crates/ecdsa-hss/formal-verification/lean-boundary/generated/visible-boundary-package/EcdsaHss/Types.lean',
    'crates/ecdsa-hss/formal-verification/lean-boundary/generated/visible-boundary-input/ecdsa_hss.llbc',
  ];
  const forbidden = [
    'rp_id',
    'wallet_id',
    'wallet_key_id',
    'ecdsa_threshold_key_id',
    'signing_root_id',
    'signing_root_version',
    'key_purpose',
    'key_version',
  ];
  const violations: string[] = [];

  for (const relativePath of guardedArtifacts) {
    const source = readRepoSource(relativePath);
    for (const token of forbidden) {
      if (source.includes(token)) {
        violations.push(`${relativePath} contains ${token}`);
      }
    }
  }

  expect(violations, violations.join('\n')).toEqual([]);
});
