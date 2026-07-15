#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function check(_label, callback) {
  callback();
}

function expect(received, message = '') {
  return {
    toContain(expected) {
      assert.ok(
        received.includes(expected),
        message || `Expected value to contain \`${expected}\``,
      );
    },
    toEqual(expected) {
      assert.deepEqual(received, expected, message);
    },
    toBeGreaterThan(expected) {
      assert.ok(received > expected, message || `Expected ${received} > ${expected}`);
    },
    toBeGreaterThanOrEqual(expected) {
      assert.ok(received >= expected, message || `Expected ${received} >= ${expected}`);
    },
    not: {
      toContain(expected) {
        assert.ok(
          !received.includes(expected),
          message || `Expected value not to contain \`${expected}\``,
        );
      },
    },
  };
}

function readRepoSource(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listTypeScriptFiles(relativePath) {
  const absolutePath = path.join(repoRoot, relativePath);
  const stat = fs.statSync(absolutePath);
  if (stat.isFile()) return /\.tsx?$/.test(relativePath) ? [relativePath] : [];

  const files = [];
  for (const entry of fs.readdirSync(absolutePath, { withFileTypes: true })) {
    if (entry.name === 'dist' || entry.name === 'node_modules') continue;
    const childPath = path.join(relativePath, entry.name);
    if (entry.isDirectory()) files.push(...listTypeScriptFiles(childPath));
    if (entry.isFile() && /\.tsx?$/.test(entry.name)) files.push(childPath);
  }
  return files;
}

function sourceRangeBetween(source, startNeedle, endNeedle) {
  const start = source.indexOf(startNeedle);
  expect(start, `missing source range start: ${startNeedle}`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf(endNeedle, start + startNeedle.length);
  expect(end, `missing source range end: ${endNeedle}`).toBeGreaterThan(start);
  return source.slice(start, end);
}

function allSdkSourceFiles() {
  return listTypeScriptFiles('packages/sdk-web/src').filter(
    (relativePath) => !relativePath.endsWith('.typecheck.ts'),
  );
}

function collectMarkerOffenders(markers) {
  const offenders = [];
  for (const relativePath of allSdkSourceFiles()) {
    const source = readRepoSource(relativePath);
    for (const marker of markers) {
      if (source.includes(marker)) offenders.push(`${relativePath} contains ${marker}`);
    }
  }
  return offenders;
}

check(
  'exact lookup fallback boundary removes legacy fallback helper names from active SDK code',
  () => {
    const forbiddenMarkers = [
      'restorePasskeyEd25519SessionBeforePlanningBestEffort',
      'readRefreshedEd25519CapabilityOrCurrent',
      'knownMissingCacheKey',
      'rememberKnownMissing',
      'hasKnownMissing',
      'cacheSigningSessionPrfFirstBestEffort',
      'attachEd25519SessionToEmailOtpSigningSessionSealBestEffort',
      'selectReconnectWalletSessionJwt',
      'selectSigningSessionStatusForUi',
      'snapshotLaneToSigningSessionStatus',
    ];

    const offenders = collectMarkerOffenders(forbiddenMarkers);
    expect(offenders, offenders.join('\n')).toEqual([]);
  },
);

check(
  'exact lookup fallback boundary rejects committed commented-out legacy fallback blocks',
  () => {
    const forbiddenCommentPatterns = [
      /\/\/.*restorePasskeyEd25519SessionBeforePlanningBestEffort/,
      /\/\/.*readRefreshedEd25519CapabilityOrCurrent/,
      /\/\/.*knownMissingCacheKey/,
      /\/\/.*candidates\[0\] \|\| null/,
      /\/\/.*claimWarmSessionPrfFirst/,
      /\/\/.*WARM_SESSION_MATERIAL_CLAIM/,
      /\/\/.*TODO remove legacy/,
      /\/\/.*LEGACY/,
    ];
    const offenders = [];
    for (const relativePath of allSdkSourceFiles()) {
      const source = readRepoSource(relativePath);
      for (const pattern of forbiddenCommentPatterns) {
        if (pattern.test(source)) offenders.push(`${relativePath} matches ${pattern}`);
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  },
);

check('exact lookup fallback boundary keeps policy-hint fallback display-only', () => {
  const loginSource = readRepoSource('packages/sdk-web/src/SeamsWeb/operations/auth/login.ts');
  const displaySnapshotHelper = sourceRangeBetween(
    loginSource,
    'function snapshotLaneToDisplaySigningSessionStatus(',
    'function snapshotToSigningSessionStatusForUi(',
  );
  const displaySelectionHelper = sourceRangeBetween(
    loginSource,
    'function selectSigningSessionStatusForDisplay(',
    'function snapshotLaneToDisplaySigningSessionStatus(',
  );

  expect(displaySnapshotHelper).toContain('lane.policyHint?.remainingUses');
  expect(displaySnapshotHelper).toContain('lane.policyHint?.expiresAtMs');
  expect(displaySelectionHelper).not.toContain('candidates[0] || null');
  expect(loginSource).not.toContain('function snapshotLaneToSigningSessionStatus(');
  expect(loginSource).not.toContain('function selectSigningSessionStatusForUi(');
});

check(
  'exact lookup fallback boundary models authority-bearing reconnect as exact material or fail-closed',
  () => {
    const ecdsaProvisionPlan = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts',
    );
    const ecdsaProvisionPlanTypecheck = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.typecheck.ts',
    );
    const reconnectBuilder = sourceRangeBetween(
      ecdsaProvisionPlan,
      'export function buildWalletSessionEcdsaReconnect(args: {',
      'export function buildEmailOtpEcdsaSessionProvision(args: {',
    );

    expect(reconnectBuilder).toContain('const recordIdentity = buildEcdsaSessionIdentity(record);');
    expect(reconnectBuilder).toContain('reconnect material has mismatched session identity');
    expect(reconnectBuilder).toContain(
      'thresholdEcdsaChainTargetsEqual(record.chainTarget, args.chainTarget)',
    );
    expect(reconnectBuilder).toContain('reconnect material has mismatched chain target');
    expect(reconnectBuilder).toContain(
      'ecdsaSessionIdentitiesEqual(walletSessionAuth.identity, args.existingSessionIdentity)',
    );
    expect(reconnectBuilder).toContain(
      'reconnect Wallet Session auth does not match planned identity',
    );
    expect(reconnectBuilder).toContain(
      'walletSessionAuth.ecdsaThresholdKeyId !== signingKeyContext.ecdsaThresholdKeyId',
    );
    expect(reconnectBuilder).toContain('walletSessionAuth.relayerKeyId !== relayerKeyId');
    expect(reconnectBuilder).toContain('satisfies WalletSessionEcdsaReconnect');
    expect(reconnectBuilder).not.toContain('candidates[0] || null');
    expect(ecdsaProvisionPlanTypecheck).toContain('reconnect planning requires record material');
    expect(ecdsaProvisionPlanTypecheck).toContain(
      'reconnect material carries verified wallet-session auth from its builder',
    );
  },
);

check(
  'exact lookup fallback boundary removes first-candidate fallback markers from lane selection',
  () => {
    const transactionLaneSelector = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/identity/selectLane.ts',
    );
    const exportLaneSelector = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection.ts',
    );
    const transactionSelection = sourceRangeBetween(
      transactionLaneSelector,
      'function selectOnlyConcreteTransactionCandidate',
      'export function selectTransactionLane',
    );
    const exportSelection = sourceRangeBetween(
      exportLaneSelector,
      'function selectExactExportAvailableLane',
      'function exactEcdsaIdentityForExportLane',
    );

    expect(transactionSelection).toContain('switch (candidates.length)');
    expect(transactionSelection).toContain('case 0:');
    expect(transactionSelection).toContain('case 1:');
    expect(transactionSelection).toContain('default:');
    expect(transactionSelection).not.toContain('selectNewestCandidateWhenUnambiguous');
    expect(transactionSelection).not.toContain('candidateStatePriority');
    expect(transactionSelection).not.toContain('candidateSourcePriority');
    expect(transactionSelection).not.toContain('bestStateCandidates[0] || null');
    expect(transactionSelection).not.toContain('bestSourceCandidates[0] || null');
    expect(transactionSelection).not.toContain('candidates[0] || null');

    expect(exportSelection).toContain('ambiguous_material');
    expect(exportSelection).toContain('no_candidate');
    expect(exportSelection).toContain('args.candidates.length !== 1');
    expect(exportSelection).not.toContain('selectNewestExportLaneWhenUnambiguous');
    expect(exportSelection).not.toContain('candidateStatePriority');
    expect(exportSelection).not.toContain('candidateSourcePriority');
    expect(exportSelection).not.toContain('stateCandidates[0] || null');
    expect(exportSelection).not.toContain('sourceCandidates[0] || null');
    expect(exportSelection).not.toContain('candidates[0] || null');
  },
);

check(
  'exact lookup fallback boundary keeps ECDSA threshold-session lookup exact or fail-closed',
  () => {
    const recordsSource = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/persistence/records.ts',
    );
    const inMemoryLookup = sourceRangeBetween(
      recordsSource,
      'function getInMemoryThresholdEcdsaSessionRecordByThresholdSessionId',
      'function normalizeThresholdEcdsaSessionStoreSource',
    );
    const uniqueSelector = sourceRangeBetween(
      recordsSource,
      'function selectUniqueThresholdEcdsaRecordByThresholdSessionId',
      'export function deriveThresholdEcdsaRuntimeLaneKey',
    );
    const exportedLookup = sourceRangeBetween(
      recordsSource,
      'export function getThresholdEcdsaSessionRecordByThresholdSessionId',
      'export function upsertThresholdEd25519SessionFact',
    );

    expect(inMemoryLookup).toContain('selectUniqueThresholdEcdsaRecordByThresholdSessionId({');
    expect(uniqueSelector).toContain('switch (unique.size)');
    expect(uniqueSelector).toContain('case 0:');
    expect(uniqueSelector).toContain('case 1:');
    expect(uniqueSelector).toContain('default:');
    expect(exportedLookup).toContain('selectUniqueThresholdEcdsaRecordByThresholdSessionId({');
    expect(inMemoryLookup).not.toContain('[0] || null');
    expect(exportedLookup).not.toContain('[0] || null');
  },
);

check(
  'exact lookup fallback boundary keeps budget compatibility fallback at the boundary parser only',
  () => {
    const budgetReader = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts',
    );
    const parser = sourceRangeBetween(
      budgetReader,
      'function parseTrustedBudgetStatusPayload',
      'async function fetchTrustedWalletSigningBudgetStatus',
    );
    expect(parser).toContain('record.committedRemainingUses ?? record.remainingUses');
    expect(parser).toContain('record.availableUses ?? record.remainingUses');

    const nearPlanner = readRepoSource(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts',
    );
    expect(nearPlanner).toContain(
      'type TrustedActiveEd25519SigningBudgetStatus = SigningSessionStatus &',
    );
    expect(nearPlanner).toContain('committedRemainingUses: number;');
    expect(nearPlanner).toContain('inFlightReservedUses: number;');
    expect(nearPlanner).toContain('committedUsesForBudgetAdmission(args.trustedStatus)');
    expect(nearPlanner).not.toContain('record.availableUses ?? record.remainingUses');
    expect(nearPlanner).not.toContain('policyHint');
  },
);

check('exact lookup fallback boundary uses typed ECDSA restore source outcomes', () => {
  const ecdsaRecovery = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.ts',
  );
  const ecdsaRecoveryTypecheck = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.typecheck.ts',
  );
  expect(ecdsaRecovery).toContain('export type EmailOtpEcdsaRestoreSource =');
  expect(ecdsaRecovery).toContain("kind: 'sealed_record_restore';");
  expect(ecdsaRecovery).toContain('ecdsaRecord?: never;');
  expect(ecdsaRecovery).toContain("kind: 'current_record_restore';");
  expect(ecdsaRecovery).not.toContain('args.configs.signing.sessionSeal');
  expect(ecdsaRecovery).not.toContain('ecdsaRecord?.thresholdSessionId || sealedRecord.');
  expect(ecdsaRecovery).not.toContain('ecdsaRecord?.signingGrantId || sealedRecord.');
  expect(ecdsaRecovery).not.toContain('ecdsaRecord?.relayerUrl || sealedRecord.');
  expect(ecdsaRecovery).not.toContain('ecdsaRecord?.chainTarget || sealedRecord.');
  expect(ecdsaRecovery).not.toContain('ecdsaRecord?.keyHandle || sealedRecord.');
  expect(ecdsaRecovery).not.toContain('ecdsaRecord?.relayerKeyId || sealedRecord.');
  expect(ecdsaRecoveryTypecheck).toContain(
    'sealed-source restore cannot carry current-record fallback bags',
  );
  expect(ecdsaRecoveryTypecheck).toContain(
    'current-source restore requires the current ECDSA record',
  );
  expect(ecdsaRecoveryTypecheck).toContain('restore source branches require Wallet Session JWT');

});

console.log('[check-exact-lookup-no-fallback-boundaries] passed');
