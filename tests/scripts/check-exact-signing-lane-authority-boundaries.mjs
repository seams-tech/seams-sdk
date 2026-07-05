#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function test(_name, fn) {
    fn();
}

function expect(actual, message) {
    return {
        toEqual(expected) {
            assert.deepEqual(actual, expected, message);
        },
        toContain(expected) {
            assert.ok(
                actual.includes(expected),
                message ?? `expected value to contain ${String(expected)}`,
            );
        },
        toMatch(expected) {
            assert.match(actual, expected, message);
        },
        toBeGreaterThan(expected) {
            assert.ok(actual > expected, message ?? `expected ${String(actual)} > ${String(expected)}`);
        },
        toBeGreaterThanOrEqual(expected) {
            assert.ok(
                actual >= expected,
                message ?? `expected ${String(actual)} >= ${String(expected)}`,
            );
        },
        not: {
            toContain(expected) {
                assert.ok(
                    !actual.includes(expected),
                    message ?? `expected value not to contain ${String(expected)}`,
                );
            },
            toMatch(expected) {
                assert.ok(
                    !expected.test(actual),
                    message ?? `expected value not to match ${String(expected)}`,
                );
            },
        },
    };
}

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sdkSrcRoot = path.join(repoRoot, 'packages/sdk-web/src');
const canonicalExactIdentityPath = 'packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.ts';
function readRepoSource(relativePath) {
    return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}
function listTypeScriptFiles(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    const files = [];
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
function productionSdkTypeScriptFiles() {
    return listTypeScriptFiles(sdkSrcRoot).filter((relativePath) => {
        return !relativePath.endsWith('.typecheck.ts');
    });
}
function authorityTypeScriptFiles() {
    return productionSdkTypeScriptFiles().filter((relativePath) => {
        return (relativePath.startsWith('packages/sdk-web/src/core/signingEngine/') ||
            relativePath.startsWith('packages/sdk-web/src/SeamsWeb/operations/'));
    });
}
function exactAuthorityTypeScriptFiles() {
    return [
        'packages/sdk-web/src/SeamsWeb/SeamsWeb.ts',
        'packages/sdk-web/src/SeamsWeb/publicApi/types.ts',
        'packages/sdk-web/src/SeamsWeb/walletIframe/client/router.ts',
        'packages/sdk-web/src/SeamsWeb/walletIframe/host/handlers/export.ts',
        'packages/sdk-web/src/SeamsWeb/walletIframe/shared/messages.ts',
        'packages/sdk-web/src/core/signingEngine/assembly/ports/evmFamily.ts',
        'packages/sdk-web/src/core/signingEngine/assembly/ports/recovery.ts',
        'packages/sdk-web/src/core/signingEngine/session/identity/selectLane.ts',
        'packages/sdk-web/src/core/signingEngine/useCases/provisionEcdsaSession.ts',
        'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes.ts',
        'packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection.ts',
        'packages/sdk-web/src/core/signingEngine/flows/recovery/exportKeypairOperation.ts',
        'packages/sdk-web/src/core/signingEngine/flows/recovery/keyExportFlow.ts',
        'packages/sdk-web/src/core/signingEngine/session/sealedRecovery/exactRecordLookup.ts',
        'packages/sdk-web/src/core/signingEngine/session/sealedRecovery/restoreCoordinator.ts',
        'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
        'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/warmSessionServices.ts',
        'packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts',
        'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/capabilityReaderCore.ts',
        'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaCapabilityReadiness.ts',
        'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/statusReader.ts',
        'packages/sdk-web/src/core/signingEngine/session/operationState/warmSessionPolicyAdapter.ts',
        'packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts',
        'packages/sdk-web/src/core/signingEngine/session/SigningSessionCoordinator.ts',
    ];
}
function sourceRangeBetween(source, startNeedle, endNeedle) {
    const start = source.indexOf(startNeedle);
    expect(start, `missing source range start: ${startNeedle}`).toBeGreaterThanOrEqual(0);
    const end = source.indexOf(endNeedle, start + startNeedle.length);
    expect(end, `missing source range end: ${endNeedle}`).toBeGreaterThan(start);
    return source.slice(start, end);
}
function firstCandidateMarkerLines(relativePath) {
    const source = readRepoSource(relativePath);
    const lines = source.split('\n');
    return lines
        .filter((line, index) => {
        const surrounding = lines.slice(Math.max(0, index - 3), index + 4).join('\n');
        const hasTimestampSortedFirstCandidate = line.includes('[0]') && surrounding.includes('.sort(') && surrounding.includes('updatedAtMs');
        return (line.includes('candidates[0]') ||
            line.includes('records[0]') ||
            line.includes('[0] || null') ||
            line.includes('.at(0)') ||
            hasTimestampSortedFirstCandidate);
    })
        .map((line) => `${relativePath}: ${line.trim()}`);
}
function timestampSortedFirstCandidateMarkerLines(relativePath) {
    const source = readRepoSource(relativePath);
    const pattern = /\.sort\([\s\S]{0,500}updatedAtMs[\s\S]{0,500}\)\[0\]/;
    if (!pattern.test(source))
        return [];
    return [`${relativePath}: sort(updatedAtMs)[0] authority selector`];
}
function firstCandidateAuthorityMarkerLines(relativePath) {
    return [
        ...firstCandidateMarkerLines(relativePath),
        ...timestampSortedFirstCandidateMarkerLines(relativePath),
    ];
}
function timestampSelectorMarkerLines(relativePath) {
    const source = readRepoSource(relativePath);
    return source
        .split('\n')
        .filter((line) => {
        return line.includes('selectNewest') || line.includes('newest_runtime_candidate');
    })
        .map((line) => `${relativePath}: ${line.trim()}`);
}
function warmStatusAuthorityMarkerLines(relativePath) {
    const source = readRepoSource(relativePath);
    const forbidden = [
        /\bgetWarmSessionStatus\b/,
        /\bWarmSessionStatusResult\b/,
        /\bAvailableLaneStateAdvisory\b/,
        /\bcache_miss\b/,
        /\bstatus\s*={2,3}\s*['"]not_found['"]/,
        /\bcode\s*={2,3}\s*['"]not_found['"]/,
    ];
    const markers = [];
    for (const pattern of forbidden) {
        if (pattern.test(source)) {
            markers.push(`${relativePath}: ${pattern.source}`);
        }
    }
    return markers;
}
test('exact signing-lane authority keeps ExactSigningLaneIdentity as the only public exact authority type', () => {
    const duplicateTypeExports = [];
    const exactSigningLaneExports = [];
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
test('exact signing-lane authority selected and planning lanes carry exact identity authority', () => {
    const selectedLaneSource = readRepoSource('packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity.ts');
    const exactLaneSource = readRepoSource(canonicalExactIdentityPath);
    const planningLaneSource = readRepoSource('packages/sdk-web/src/core/signingEngine/session/operationState/types.ts');
    expect(selectedLaneSource).toContain('identity: ExactSigningLaneIdentity;');
    expect(selectedLaneSource).toContain('identity: ExactEd25519SigningLaneIdentity;');
    expect(selectedLaneSource).toContain('identity: ExactEcdsaSigningLaneIdentity;');
    expect(selectedLaneSource).toContain('const identity = exactEd25519SigningLaneIdentity({');
    expect(selectedLaneSource).toContain('const identity = exactEcdsaSigningLaneIdentity({');
    expect(planningLaneSource).toContain('identity: ExactEd25519SigningLaneIdentity;');
    expect(planningLaneSource).toContain('identity: ExactEcdsaSigningLaneIdentity;');
    expect(exactLaneSource).not.toContain('SelectedEd25519LaneIdentityFields');
    expect(exactLaneSource).not.toContain('SelectedEcdsaLaneIdentityFields');
    expect(exactLaneSource).not.toContain('nearAccountId: lane.nearAccountId');
    expect(exactLaneSource).not.toContain('chainTarget: lane.chainTarget');
});
test('exact signing-lane authority ECDSA exact identity carries wallet id, key handle, and full key identity', () => {
    const source = readRepoSource(canonicalExactIdentityPath);
    const ecdsaSigner = sourceRangeBetween(source, 'export type EvmFamilyEcdsaSignerBinding = {', 'export type ExactEd25519SigningLaneIdentity = {');
    const ecdsaIdentity = sourceRangeBetween(source, 'export type ExactEcdsaSigningLaneIdentity = {', 'export type ExactSigningLaneIdentity =');
    expect(ecdsaSigner).toContain("readonly kind: 'evm_family_ecdsa_signer';");
    expect(ecdsaSigner).toContain('readonly walletId: WalletId;');
    expect(ecdsaSigner).toContain('readonly keyHandle: EvmFamilyEcdsaKeyHandle;');
    expect(ecdsaSigner).toContain('readonly key: EvmFamilyEcdsaKeyIdentity;');
    expect(ecdsaIdentity).toContain('readonly signer: EvmFamilyEcdsaSignerBinding;');
    expect(ecdsaIdentity).not.toContain('walletId: WalletId;');
    expect(ecdsaIdentity).not.toContain('keyHandle: EvmFamilyEcdsaKeyHandle;');
    expect(ecdsaIdentity).not.toContain('key: EvmFamilyEcdsaKeyIdentity;');
    expect(ecdsaIdentity).not.toContain('walletId: AccountId;');
    expect(ecdsaIdentity).not.toContain('keyHandle?: never;');
});
test('exact signing-lane authority Ed25519 exact identity carries a NEAR-specific account brand', () => {
    const source = readRepoSource(canonicalExactIdentityPath);
    const capabilitySource = readRepoSource('packages/shared-ts/src/utils/walletCapabilityBindings.ts');
    const ed25519Identity = sourceRangeBetween(source, 'export type ExactEd25519SigningLaneIdentity = {', 'export type ExactEcdsaSigningLaneIdentity = {');
    const nearSigner = sourceRangeBetween(capabilitySource, 'export type NearEd25519SignerBinding = {', 'export type WalletCapabilityBindingParseError = {');
    expect(source).toContain('type NearAccountId,');
    expect(ed25519Identity).toContain('readonly signer: NearEd25519SignerBinding;');
    expect(ed25519Identity).not.toContain('nearAccountId: NearAccountId;');
    expect(nearSigner).toContain('readonly account: NearAccountBinding;');
    expect(nearSigner).toContain('readonly nearEd25519SigningKeyId: NearEd25519SigningKeyId;');
    expect(ed25519Identity).not.toContain('nearAccountId: AccountId;');
});
test('exact signing-lane authority planning lane base does not carry optional session identity', () => {
    const source = readRepoSource('packages/sdk-web/src/core/signingEngine/session/operationState/types.ts');
    const basePlanningLane = sourceRangeBetween(source, 'type BaseSigningSessionPlanningLane = {', 'type BranchSigningSessionRuntimeState =');
    const runtimeState = sourceRangeBetween(source, 'type BranchSigningSessionRuntimeState =', 'export type Ed25519SigningSessionPlanningLane =');
    const resolvedIdentity = sourceRangeBetween(source, 'type BaseResolvedSigningSessionIdentity =', 'export type ResolvedEd25519SigningSessionIdentity =');
    const summarySource = sourceRangeBetween(source, 'export function summarizeSigningLane(lane: SigningSessionPlanningLane): SigningLaneSummary {', 'function normalizeLaneIdentityField(value: unknown): string {');
    expect(basePlanningLane).not.toContain('thresholdSessionId?:');
    expect(basePlanningLane).not.toContain('backingMaterialSessionId?:');
    expect(basePlanningLane).not.toContain('activeSignerSlot?:');
    for (const staleSignerField of [
        'walletId:',
        'nearAccountId:',
        'nearEd25519SigningKeyId:',
        'chainTarget:',
        'keyHandle:',
        'key:',
    ]) {
        expect(basePlanningLane).not.toContain(staleSignerField);
        expect(runtimeState).not.toContain(staleSignerField);
    }
    expect(source).not.toMatch(/backingMaterialSessionId\?:\s*BackingMaterialSessionId/);
    expect(source).not.toMatch(/activeSignerSlot\?:\s*number/);
    expect(runtimeState).toContain("runtimeState: 'no_runtime_material';");
    expect(runtimeState).toContain("runtimeState: 'backing_material';");
    expect(runtimeState).toContain("runtimeState: 'active_signer';");
    expect(runtimeState).toContain("runtimeState: 'backing_material_with_active_signer';");
    expect(resolvedIdentity).toContain('BranchSigningSessionRuntimeState');
    expect(summarySource).toContain('const signer = lane.identity.signer;');
    expect(summarySource).not.toContain('lane.walletId');
    expect(summarySource).not.toContain('lane.nearAccountId');
    expect(summarySource).not.toContain('lane.nearEd25519SigningKeyId');
    expect(summarySource).not.toContain('lane.chainTarget');
    expect(summarySource).not.toContain('lane.keyHandle');
});
test('exact signing-lane authority Email OTP ECDSA worker handles are EVM-family signing-key scoped', () => {
    const generatedSignerCore = readRepoSource('packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts');
    const secretSources = readRepoSource('packages/sdk-web/src/core/platform/secretSources.ts');
    expect(generatedSignerCore).not.toContain('EcdsaBootstrapEmailOtpWorkerSessionHandle');
    expect(generatedSignerCore).not.toContain('email_otp_worker_session');
    expect(secretSources).toContain('evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;');
    expect(secretSources).toContain('rpId?: never;');
});
test('exact signing-lane authority signer-core ECDSA export public facts exclude SDK lane key handles', () => {
    const generatedSignerCore = readRepoSource('packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts');
    const exportPublicFacts = sourceRangeBetween(generatedSignerCore, 'export type EcdsaRoleLocalExportPublicFacts = {', 'export type BuildEcdsaRoleLocalExportArtifactCommand =');
    expect(exportPublicFacts).toContain('applicationBindingDigestB64u: string');
    expect(exportPublicFacts).not.toContain('keyHandle');
});
test('exact signing-lane authority ECDSA keygen and session envelopes expose walletKeyId rather than rpId', () => {
    const guardedFiles = [
        'packages/sdk-web/src/core/signingEngine/threshold/ecdsa/keygen.ts',
        'packages/sdk-web/src/core/signingEngine/threshold/ecdsa/activation.ts',
        'packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts',
        'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
        'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence.ts',
        'packages/sdk-web/src/core/signingEngine/session/persistence/records.ts',
        'packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts',
    ];
    const violations = [];
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
        if (/authMetadata\.walletKeyId\b/.test(source)) {
            violations.push(`${relativePath}: deleted authMetadata.walletKeyId read`);
        }
        if (/authMetadata:\s*\{\s*rpId\b/.test(source)) {
            violations.push(`${relativePath}: authMetadata writes rpId`);
        }
        if (/authMetadata:\s*\{\s*walletKeyId\b/.test(source)) {
            violations.push(`${relativePath}: authMetadata writes deleted walletKeyId`);
        }
    }
    expect(violations, violations.join('\n')).toEqual([]);
});
test('exact signing-lane authority ECDSA role-local public facts exclude auth fields', () => {
    const roleLocalSource = readRepoSource('packages/sdk-web/src/core/signingEngine/session/persistence/ecdsaRoleLocalRecords.ts');
    const parsePublicFactsSource = sourceRangeBetween(roleLocalSource, 'function parsePublicFacts(input: unknown): EcdsaRoleLocalPublicFacts {', 'export function buildEcdsaRoleLocalPublicFacts(input: unknown):');
    expect(parsePublicFactsSource).toContain('input.rpId !== undefined');
    expect(parsePublicFactsSource).toContain('auth fields are not publicFacts');
    const violations = [];
    for (const relativePath of productionSdkTypeScriptFiles()) {
        const source = readRepoSource(relativePath);
        if (/buildEcdsaRoleLocalPublicFacts\(\{[\s\S]{0,320}\brpId\b/.test(source)) {
            violations.push(`${relativePath}: ECDSA public facts include rpId`);
        }
    }
    expect(violations, violations.join('\n')).toEqual([]);
});
test('exact signing-lane authority exact authority paths reject first-candidate fallback selectors', () => {
    const markerLines = exactAuthorityTypeScriptFiles().flatMap(firstCandidateAuthorityMarkerLines);
    expect(markerLines).toEqual([]);
});
test('exact signing-lane authority export transport parses exact lane identities at public and iframe boundaries', () => {
    const messages = readRepoSource('packages/sdk-web/src/SeamsWeb/walletIframe/shared/messages.ts');
    const seamsWeb = readRepoSource('packages/sdk-web/src/SeamsWeb/SeamsWeb.ts');
    const router = readRepoSource('packages/sdk-web/src/SeamsWeb/walletIframe/client/router.ts');
    const hostExport = readRepoSource('packages/sdk-web/src/SeamsWeb/walletIframe/host/handlers/export.ts');
    const exportPayload = sourceRangeBetween(messages, 'export type PMExportKeypairUiPayload =', 'export interface PMExportThresholdEd25519SeedFromHssReportUiPayload');
    expect(exportPayload).toContain('laneIdentity: unknown;');
    expect(seamsWeb).toContain('parseExactEd25519SigningLaneIdentity(input.laneIdentity)');
    expect(seamsWeb).toContain('parseExactEcdsaSigningLaneIdentity(input.laneIdentity)');
    expect(router).toContain('parseExactEd25519SigningLaneIdentity(input.laneIdentity)');
    expect(router).toContain('parseExactEcdsaSigningLaneIdentity(input.laneIdentity)');
    expect(hostExport).toContain('parseExactEd25519SigningLaneIdentity(payload.laneIdentity)');
    expect(hostExport).toContain('parseExactEcdsaSigningLaneIdentity(payload.laneIdentity)');
});
test('exact signing-lane authority Ed25519 registration HSS scope keeps passkey rpId out of wallet key identity', () => {
    const serverTypes = readRepoSource('packages/sdk-server-ts/src/core/types.ts');
    const walletRegistrationPlanning = readRepoSource('packages/sdk-server-ts/src/core/authService/walletRegistrationPlanning.ts');
    const thresholdService = readRepoSource('packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts');
    const scopeType = sourceRangeBetween(serverTypes, 'export type ThresholdEd25519RegistrationAccountScope =', 'export interface ThresholdEd25519HssClientInputs');
    const registrationScopeBuilder = sourceRangeBetween(walletRegistrationPlanning, 'function thresholdEd25519RegistrationAccountScope(input:', 'function thresholdEd25519KnownAccountRegistrationScope(input:');
    const parser = sourceRangeBetween(thresholdService, 'function parseThresholdEd25519RegistrationAccountScope', 'function thresholdEd25519RegistrationAccountScopesEqual');
    const finalizeRequestType = sourceRangeBetween(serverTypes, 'export interface ThresholdEd25519HssFinalizeForRegistrationRequest', 'export type ThresholdEd25519HssFinalizeWithSessionResponse');
    expect(scopeType).toContain('nearEd25519SigningKeyId: NearEd25519SigningKeyId;');
    expect(scopeType).not.toContain('walletKeyId: string;');
    expect(scopeType).not.toContain('rpId: string;');
    expect(finalizeRequestType).toContain('wallet_key_id: NearEd25519SigningKeyId;');
    expect(finalizeRequestType).toContain('authority: WalletAuthAuthority;');
    expect(finalizeRequestType).not.toContain('authorityScope: ThresholdEd25519AuthorityScope;');
    expect(finalizeRequestType).not.toContain('rpId: string;');
    expect(registrationScopeBuilder).toContain('nearEd25519SigningKeyId: input.nearEd25519SigningKeyId');
    expect(registrationScopeBuilder).not.toContain('walletKeyId: nearEd25519SigningKeyId');
    expect(parser).toContain('registrationAccountScope.evmFamilySigningKeySlotId is not valid for Ed25519 HSS');
    expect(parser).toContain('parseNearEd25519SigningKeyIdField(');
    expect(thresholdService).toContain('parseWebAuthnRpIdField(');
    expect(thresholdService).toContain('registrationAccountScope.nearEd25519SigningKeyId does not match wallet_key_id');
    expect(thresholdService).not.toContain('registrationAccountScope.value.walletKeyId');
});
test('exact signing-lane authority timestamp authority selectors stay explicitly inventoried', () => {
    const markerLines = authorityTypeScriptFiles().flatMap(timestampSelectorMarkerLines);
    expect(markerLines).toEqual([]);
});
test('exact signing-lane authority transaction/export/restore authority paths do not read warm-status telemetry', () => {
    const guardedFiles = [
        'packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts',
        'packages/sdk-web/src/core/signingEngine/session/identity/selectLane.ts',
        'packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection.ts',
        'packages/sdk-web/src/core/signingEngine/flows/recovery/nearEd25519ExportFlow.ts',
        'packages/sdk-web/src/core/signingEngine/flows/recovery/exportKeypairOperation.ts',
        'packages/sdk-web/src/core/signingEngine/session/sealedRecovery/exactRecordLookup.ts',
        'packages/sdk-web/src/core/signingEngine/session/sealedRecovery/restoreCoordinator.ts',
    ];
    const markerLines = guardedFiles.flatMap(warmStatusAuthorityMarkerLines);
    expect(markerLines, markerLines.join('\n')).toEqual([]);
});
test('exact signing-lane authority wallet-scoped authority state uses WalletId, not AccountId', () => {
    const guardedFiles = [
        'packages/sdk-web/src/core/signingEngine/session/budget/budgetProjection.ts',
        'packages/sdk-web/src/core/signingEngine/session/operationState/postSignPolicy.ts',
        'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/transitions.ts',
        'packages/sdk-web/src/core/signingEngine/useCases/provisionEcdsaSession.ts',
        'packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts',
        'packages/sdk-web/src/core/signingEngine/session/passkey/ed25519Provisioner.ts',
    ];
    const violations = [];
    for (const relativePath of guardedFiles) {
        const source = readRepoSource(relativePath);
        if (/walletId:\s*AccountId\b/.test(source)) {
            violations.push(`${relativePath}: walletId typed as AccountId`);
        }
        if (/toAccountId\([^)\n]*(walletId|exactWalletId)[^)\n]*\)/.test(source)) {
            violations.push(`${relativePath}: walletId coerced through toAccountId`);
        }
    }
    expect(violations, violations.join('\n')).toEqual([]);
});
test('exact signing-lane authority ECDSA authority ranges read signer binding instead of flat lane projections', () => {
    const guardedRanges = [
        {
            file: 'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes.ts',
            start: 'export function requireResolvedEvmFamilyEcdsaSigningLane(args:',
            end: 'export function updateResolvedEvmFamilyEcdsaSigningLaneIdentity(args:',
        },
        {
            file: 'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes.ts',
            start: 'export function selectedEvmFamilyEcdsaLaneForMaterialIdentity(args:',
            end: 'export function requireEvmFamilyEcdsaAuthMethod(',
        },
        {
            file: 'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes.ts',
            start: 'function getSelectedEcdsaRecordLaneMismatchReason(args:',
            end: '  return null;\n}',
        },
        {
            file: 'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.ts',
            start: 'export function buildEcdsaMaterialStateForResolvedLane(args:',
            end: 'export function resolvedEcdsaMaterialInputFromOptionalRecord(args:',
        },
        {
            file: 'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.ts',
            start: 'export function materialIdentityMatchesResolvedLane(args:',
            end: '  );\n}',
        },
        {
            file: 'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaReadiness.ts',
            start: 'export async function ensureEvmFamilyThresholdEcdsaRecordReady(',
            end: '  return refreshedRecord;\n}',
        },
        {
            file: 'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signingFlowRuntime.ts',
            start: "if (args.senderSignatureAlgorithm !== 'secp256k1') return undefined;",
            end: 'const passkeyBootstrapDigest32B64u =',
        },
        {
            file: 'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
            start: 'const restoreMaterialLaneSigner = requireEvmFamilyEcdsaSigner(',
            end: 'const result = await args.deps.restorePersistedSessionForSigning({',
        },
    ];
    const forbiddenPatterns = [
        /\blane\.(walletId|keyHandle|chainTarget|key)\b/,
        /\bargs\.lane\.(walletId|keyHandle|chainTarget|key)\b/,
        /\btransactionLane\.(walletId|keyHandle|chainTarget|key)\b/,
        /\bresolvedLane\.(walletId|keyHandle|chainTarget|key)\b/,
    ];
    const violations = [];
    for (const range of guardedRanges) {
        const source = sourceRangeBetween(readRepoSource(range.file), range.start, range.end);
        for (const pattern of forbiddenPatterns) {
            if (pattern.test(source)) {
                violations.push(`${range.file}: ${range.start} contains ${pattern.source}`);
            }
        }
    }
    expect(violations, violations.join('\n')).toEqual([]);
});
test('exact signing-lane authority ECDSA-HSS context artifacts do not reintroduce product or auth scope fields', () => {
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
    const violations = [];
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
test('exact signing-lane authority Ed25519-HSS context artifacts do not reintroduce SDK identity fields', () => {
    const wholeFileArtifacts = [
        'crates/ed25519-hss/src/shared/context.rs',
        'crates/ed25519-hss/src/candidate.rs',
        'crates/ed25519-hss/src/artifact/prime_order_encoder.rs',
        'crates/ed25519-hss/formal-verification/verus/src/shared/reference.rs',
        'crates/ed25519-hss/formal-verification/lean-boundary/Ed25519Hss/Types.lean',
        'crates/ed25519-hss/formal-verification/lean-boundary/generated/visible-boundary-package/Ed25519Hss/Types.lean',
        'wasm/threshold_prf/pkg/threshold_prf.d.ts',
    ];
    const guardedRanges = [
        {
            path: 'packages/sdk-web/src/core/types/signer-worker.ts',
            start: 'export interface WasmDeriveThresholdEd25519HssClientInputsRequest',
            end: 'export interface WasmBuildThresholdEd25519SeedExportArtifactRequest',
        },
        {
            path: 'packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts',
            start: 'export type ThresholdEd25519HssCanonicalContext = {',
            end: 'export type ThresholdEcdsaHssStableKeyContext = {',
        },
        {
            path: 'packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts',
            start: 'export async function deriveThresholdEd25519HssClientInputsWasm',
            end: 'export async function buildThresholdEd25519SeedExportArtifactWasm',
        },
        {
            path: 'packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts',
            start: 'export async function deriveEd25519HssServerInputsFromSigningRootShares',
            end: 'function requireBase64UrlFixedBytes',
        },
    ];
    const forbidden = [
        'org_id',
        'account_id',
        'near_account_id',
        'key_purpose',
        'key_version',
        'derivation_version',
        'near_ed25519_signing_key_id',
        'signing_root_id',
        'signing_root_version',
        'orgId',
        'accountId',
        'nearAccountId',
        'keyPurpose',
        'keyVersion',
        'derivationVersion',
        'nearEd25519SigningKeyId',
        'signingRootId',
        'signingRootVersion',
    ];
    const violations = [];
    for (const relativePath of wholeFileArtifacts) {
        const source = readRepoSource(relativePath);
        for (const token of forbidden) {
            if (source.includes(token)) {
                violations.push(`${relativePath} contains ${token}`);
            }
        }
    }
    for (const range of guardedRanges) {
        const source = sourceRangeBetween(readRepoSource(range.path), range.start, range.end);
        for (const token of forbidden) {
            if (source.includes(token)) {
                violations.push(`${range.path} range ${range.start} contains ${token}`);
            }
        }
    }
    expect(violations, violations.join('\n')).toEqual([]);
});
test('exact signing-lane authority Ed25519 worker-material authority does not carry HSS keyVersion', () => {
    const guardedWholeFiles = [
        'crates/signer-core/src/commands/ed25519_worker_material.rs',
        'wasm/near_signer/src/threshold/worker_material.rs',
        'packages/sdk-web/src/core/signingEngine/threshold/ed25519/workerMaterialBinding.ts',
    ];
    const guardedRanges = [
        {
            path: 'packages/sdk-web/src/core/types/signer-worker.ts',
            start: 'export type ThresholdEd25519WorkerMaterialStoredResult = {',
            end: 'export type ThresholdEd25519HssClientOutputMaskTransport =',
        },
        {
            path: 'packages/sdk-web/src/core/types/signer-worker.ts',
            start: 'export type ThresholdEd25519WorkerMaterialBindingInputWithoutVerifier = {',
            end: 'export type ThresholdEd25519WorkerMaterialSealAuthorization =',
        },
    ];
    const forbidden = ['keyVersion', 'key_version', 'ed25519HssKeyVersion'];
    const violations = [];
    for (const relativePath of guardedWholeFiles) {
        const source = readRepoSource(relativePath);
        for (const token of forbidden) {
            if (source.includes(token)) {
                violations.push(`${relativePath} contains ${token}`);
            }
        }
    }
    for (const range of guardedRanges) {
        const source = sourceRangeBetween(readRepoSource(range.path), range.start, range.end);
        for (const token of forbidden) {
            if (source.includes(token)) {
                violations.push(`${range.path} range ${range.start} contains ${token}`);
            }
        }
    }
    expect(violations, violations.join('\n')).toEqual([]);
});
test('exact signing-lane authority Ed25519 finalize-derived HSS material does not echo keyVersion', () => {
    const relativePath = 'packages/sdk-server-ts/src/core/ThresholdService/ed25519HssWasm.ts';
    const source = readRepoSource(relativePath);
    const startNeedle = 'export async function deriveThresholdEd25519RegistrationMaterialFromHssFinalize';
    const start = source.indexOf(startNeedle);
    expect(start, `missing source range start: ${startNeedle}`).toBeGreaterThanOrEqual(0);
    const helperSource = source.slice(start);
    const forbidden = ['keyVersion', 'key_version', 'ed25519HssKeyVersion'];
    const violations = forbidden.filter((token) => helperSource.includes(token));
    expect(violations, violations.join('\n')).toEqual([]);
});
test('exact signing-lane authority wallet budget sessions do not synthesize NEAR signer identity', () => {
    const serviceSource = readRepoSource('packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts');
    const storeSource = readRepoSource('packages/sdk-server-ts/src/core/ThresholdService/stores/WalletSessionStore.ts');
    const ensureBudgetSource = sourceRangeBetween(serviceSource, 'private async ensureSigningGrantBudget(', 'private async resolveWalletOrCurveBudgetStore');
    const budgetRecordSource = sourceRangeBetween(storeSource, 'export type WalletSigningBudgetSessionRecord = {', 'export type WalletSessionRecord =');
    expect(ensureBudgetSource).toContain('this.walletBudgetSessionStore');
    expect(ensureBudgetSource).toContain("kind: 'wallet_signing_budget_session'");
    expect(ensureBudgetSource).not.toContain('nearAccountId: input.userId');
    expect(ensureBudgetSource).not.toContain('nearEd25519SigningKeyId: input.userId');
    expect(ensureBudgetSource).not.toContain('budgetScope');
    expect(budgetRecordSource).not.toContain('budgetScope:');
    expect(budgetRecordSource).not.toContain('binding:');
    expect(budgetRecordSource).not.toContain('nearAccountId');
    expect(budgetRecordSource).not.toContain('nearEd25519SigningKeyId');
    expect(budgetRecordSource).not.toContain('rpId: string;');
});
test('exact signing-lane authority ECDSA MPC sessions are native EVM-family signing-key records', () => {
    const serviceSource = readRepoSource('packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts');
    const sessionStoreSource = readRepoSource('packages/sdk-server-ts/src/core/ThresholdService/stores/SessionStore.ts');
    const ecdsaMpcType = sourceRangeBetween(sessionStoreSource, 'export type ThresholdEcdsaMpcSessionRecord = {', 'export type ThresholdMpcSessionRecord =');
    expect(ecdsaMpcType).toContain('walletId: string;');
    expect(ecdsaMpcType).toContain('evmFamilySigningKeySlotId: string;');
    expect(ecdsaMpcType).not.toContain('walletSessionUserId: string;');
    expect(ecdsaMpcType).not.toContain('userId: string;');
    expect(ecdsaMpcType).not.toContain('rpId: string;');
    expect(sessionStoreSource).not.toContain("export type ThresholdEcdsaMpcSessionRecord = Omit<");
    expect(serviceSource).not.toContain('toThresholdEcdsaMpcSessionRecord');
    expect(serviceSource).not.toContain('walletKeyId: record.rpId');
    expect(serviceSource).not.toContain('rpId: record.walletKeyId');
    expect(serviceSource).not.toContain('rpId: registrationAccountScope.value.walletKeyId');
});
test('exact signing-lane authority normalized server ECDSA records do not expose walletSessionUserId', () => {
    const normalizedServerRecordFiles = [
        'packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts',
        'packages/sdk-server-ts/src/core/ThresholdService/stores/SessionStore.ts',
        'packages/sdk-server-ts/src/core/ThresholdService/stores/WalletSessionStore.ts',
        'packages/sdk-server-ts/src/core/ThresholdService/stores/EcdsaSigningStore.ts',
        'packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPoolFillHandlers.ts',
    ];
    for (const relativePath of normalizedServerRecordFiles) {
        const source = readRepoSource(relativePath);
        expect(source, relativePath).not.toContain('walletSessionUserId');
    }
    const validationSource = readRepoSource('packages/sdk-server-ts/src/core/ThresholdService/validation.ts');
    const ecdsaValidationRanges = [
        sourceRangeBetween(validationSource, 'export function parseThresholdEcdsaMpcSessionRecord(', 'export type ParsedThresholdEd25519SigningSessionRecord ='),
        sourceRangeBetween(validationSource, 'export function parseEcdsaWalletSessionRecord(', 'export type ParsedWalletSigningBudgetSessionRecord ='),
        sourceRangeBetween(validationSource, 'export function parseRouterAbEcdsaHssPoolFillSessionRecord(', 'type EcdsaWalletSessionClaimsForKind<'),
    ];
    for (const source of ecdsaValidationRanges) {
        expect(source).not.toContain('walletSessionUserId');
        expect(source).not.toContain('toOptionalString(raw.userId)');
    }
    expect(validationSource).not.toContain('const walletKeyId = toOptionalString(raw.walletKeyId)');
});
test('exact signing-lane authority canonical NEAR Ed25519 signer binding rejects signer slot zero', () => {
    const source = readRepoSource('packages/shared-ts/src/utils/walletCapabilityBindings.ts');
    const parseSignerSlotSource = sourceRangeBetween(source, 'function parseSignerSlot(raw: unknown):', 'function missingObject(typeName: string):');
    expect(parseSignerSlotSource).toContain('signerSlot < 1');
    expect(parseSignerSlotSource).toContain('signerSlot must be an integer >= 1');
    expect(parseSignerSlotSource).not.toContain('signerSlot < 0');
    expect(parseSignerSlotSource).not.toContain('integer >= 0');
});
test('exact signing-lane authority Ed25519 session lane keys use full exact identity', () => {
    const recordsSource = readRepoSource('packages/sdk-web/src/core/signingEngine/session/persistence/records.ts');
    const keyTypeSource = sourceRangeBetween(recordsSource, 'export type ThresholdEd25519SessionRecordKey = {', '};');
    const serializerSource = sourceRangeBetween(recordsSource, 'export function serializeThresholdEd25519SessionLaneKey(args: {', 'function getThresholdEd25519SessionLaneKeyForRecord');
    const matcherSource = sourceRangeBetween(recordsSource, 'function thresholdEd25519RecordMatchesLane(', 'function rememberInMemoryThresholdEcdsaRecord');
    for (const field of [
        'walletId',
        'nearAccountId',
        'nearEd25519SigningKeyId',
        'authMethod',
        'signingGrantId',
        'thresholdSessionId',
        'signerSlot',
    ]) {
        expect(keyTypeSource).toContain(field);
        expect(serializerSource).toContain(field);
    }
    expect(keyTypeSource).toContain('walletId: WalletId;');
    expect(keyTypeSource).toContain('nearAccountId: StrictAccountId;');
    expect(keyTypeSource).toContain('nearEd25519SigningKeyId: NearEd25519SigningKeyId;');
    expect(keyTypeSource).toContain('signingGrantId: SigningGrantId;');
    expect(keyTypeSource).toContain('thresholdSessionId: ThresholdEd25519SessionId;');
    expect(keyTypeSource).toContain('signerSlot: SignerSlot;');
    expect(serializerSource).toContain('encodeLaneToken(walletId)');
    expect(serializerSource).toContain('encodeLaneToken(nearAccountId)');
    expect(serializerSource).toContain('encodeLaneToken(nearEd25519SigningKeyId)');
    expect(serializerSource).toContain('encodeLaneToken(authMethod)');
    expect(serializerSource).toContain('encodeLaneToken(signingGrantId)');
    expect(serializerSource).toContain('encodeLaneToken(thresholdSessionId)');
    expect(serializerSource).toContain('encodeLaneToken(String(signerSlot))');
    expect(matcherSource).toContain('record.walletId');
    expect(matcherSource).toContain('lane.walletId');
    expect(matcherSource).toContain('record.nearEd25519SigningKeyId');
    expect(matcherSource).toContain('lane.nearEd25519SigningKeyId');
    expect(matcherSource).toContain('record.signerSlot');
    expect(matcherSource).toContain('lane.signerSlot');
});
test('exact signing-lane authority Ed25519 grant clearing uses exact lane keys only', () => {
    const recordsSource = readRepoSource('packages/sdk-web/src/core/signingEngine/session/persistence/records.ts');
    const readinessSource = readRepoSource('packages/sdk-web/src/core/signingEngine/session/availability/readiness.ts');
    const clearSigningGrantSource = sourceRangeBetween(readinessSource, 'export async function clearSigningGrant(args: {', 'export async function syncSealedRefreshPolicyForLanes(args: {');
    expect(recordsSource).toContain('clearStoredThresholdEd25519SessionRecordForLaneKey');
    expect(recordsSource).toContain('thresholdEd25519SessionRecordKeyFromExactIdentity');
    expect(recordsSource).not.toContain('clearStoredThresholdEd25519SessionRecordForAccount');
    expect(readinessSource).not.toContain('ed25519NearAccountIdFromDiscoveredLane');
    expect(clearSigningGrantSource).toContain('ed25519LaneKeyFromDiscoveredLane');
    expect(clearSigningGrantSource).toContain('clearStoredThresholdEd25519SessionRecordForLaneKey');
    expect(clearSigningGrantSource).toContain('serializeThresholdEd25519SessionLaneKey');
    expect(clearSigningGrantSource).toContain('ecdsaExactIdentityFromDiscoveredLane');
    expect(clearSigningGrantSource).toContain('clearThresholdEcdsaSessionRecordForExactIdentity');
    expect(clearSigningGrantSource).not.toContain('nearAccountIdsToClear');
    expect(clearSigningGrantSource).not.toContain('clearStoredThresholdEd25519SessionRecordForAccount');
    expect(clearSigningGrantSource).not.toContain('clearThresholdEcdsaSessionRecordForWalletTarget');
});
test('exact signing-lane authority Ed25519 availability paths enumerate exact lane records', () => {
    const files = [
        'packages/sdk-web/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts',
        'packages/sdk-web/src/core/signingEngine/session/emailOtp/persistedSnapshot.ts',
    ];
    for (const file of files) {
        const source = readRepoSource(file);
        expect(source).toContain('listStoredThresholdEd25519SessionLaneRecordsForWallet');
        expect(source).not.toContain('listStoredThresholdEd25519SessionRecordsForWallet');
    }
});
test('exact signing-lane authority exact Ed25519 mutation paths reject unsafe identity casts', () => {
    const ranges = [
        {
            file: 'packages/sdk-web/src/core/signingEngine/session/persistence/records.ts',
            start: 'export type ThresholdEd25519SessionRecordKey = {',
            end: 'export function markThresholdEd25519EmailOtpSessionConsumedForWallet(args: {',
        },
        {
            file: 'packages/sdk-web/src/core/signingEngine/session/availability/readiness.ts',
            start: 'function ed25519LaneKeyFromDiscoveredLane(',
            end: 'export async function syncSealedRefreshPolicyForLanes(args: {',
        },
    ];
    const bannedCastPatterns = [
        /\bas\s+WalletId\b/,
        /\bas\s+AccountId\b/,
        /\bas\s+StrictAccountId\b/,
        /\bas\s+NearEd25519SigningKeyId\b/,
        /\bas\s+SigningGrantId\b/,
        /\bas\s+ThresholdEd25519SessionId\b/,
    ];
    for (const range of ranges) {
        const source = sourceRangeBetween(readRepoSource(range.file), range.start, range.end);
        for (const pattern of bannedCastPatterns) {
            expect(source).not.toMatch(pattern);
        }
    }
});
test('exact signing-lane authority selected wallet profile writes are wallet-id only', () => {
    const files = [
        'packages/sdk-web/src/core/signingEngine/flows/registration/accountLifecycle.ts',
        'packages/sdk-web/src/core/signingEngine/flows/registration/public.ts',
        'packages/sdk-web/src/core/signingEngine/flows/registration/services/registrationAccounts.ts',
        'packages/sdk-web/src/SeamsWeb/signingSurface/ports.ts',
        'packages/sdk-web/src/SeamsWeb/operations/auth/login.ts',
        'packages/sdk-web/src/core/runtime/createSigningRuntime.ts',
    ];
    const violations = [];
    for (const relativePath of files) {
        const source = readRepoSource(relativePath);
        for (const pattern of [
            'WalletId | AccountId',
            'AccountId | WalletId',
            'EcdsaWalletId | AccountId',
            'walletOrNearAccountId',
            'setLastUser(nearAccountId',
            'updateLastLogin(nearAccountId',
        ]) {
            if (source.includes(pattern)) {
                violations.push(`${relativePath} contains ${pattern}`);
            }
        }
    }
    expect(violations, violations.join('\n')).toEqual([]);
});

console.log('[exact-signing-lane-authority-boundaries] ok');
