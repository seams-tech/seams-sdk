import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

const transactionFlowFiles = [
  'client/src/core/signingEngine/api/nearSigning.ts',
  'client/src/core/signingEngine/orchestration/near/transactionsFlow.ts',
  'client/src/core/signingEngine/orchestration/near/delegateFlow.ts',
  'client/src/core/signingEngine/orchestration/near/nep413Flow.ts',
  'client/src/core/signingEngine/api/evmFamily/authPlanning.ts',
] as const;

const evmFamilySecuritySessionFiles = [
  'client/src/core/signingEngine/api/evmSigning.ts',
  'client/src/core/signingEngine/api/tempoSigning.ts',
  'client/src/core/signingEngine/api/evmFamily/authPlanning.ts',
  'client/src/core/signingEngine/api/evmFamily/budgetSpending.ts',
  'client/src/core/signingEngine/api/evmFamily/ecdsaSelection.ts',
  'client/src/core/signingEngine/api/evmFamily/emailOtpRefresh.ts',
  'client/src/core/signingEngine/api/evmFamily/postSignPolicy.ts',
  'client/src/core/signingEngine/api/evmFamily/transactionExecutor.ts',
  'client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts',
  'client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts',
] as const;

const pureSigningSessionHelperFiles = [
  'client/src/core/signingEngine/session/signingSession/types.ts',
  'client/src/core/signingEngine/session/signingSession/lanes.ts',
  'client/src/core/signingEngine/session/signingSession/budget.ts',
  'client/src/core/signingEngine/session/signingSession/budgetFinalizer.ts',
  'client/src/core/signingEngine/session/signingSession/readiness.ts',
  'client/src/core/signingEngine/session/signingSession/planner.ts',
  'client/src/core/signingEngine/session/signingSession/execution.ts',
  'client/src/core/signingEngine/session/signingSession/trace.ts',
  'client/src/core/signingEngine/session/signingSession/operationFingerprint.ts',
  'client/src/core/signingEngine/session/signingSession/operationIdBinding.ts',
  'client/src/core/signingEngine/session/signingSession/postSignPolicy.ts',
] as const;

const signingSessionQueryFiles = [
  'client/src/core/signingEngine/session/snapshotReader.ts',
  'client/src/core/signingEngine/session/warmSigning/readModel.ts',
  'client/src/core/signingEngine/session/warmSigning/statusReader.ts',
  'client/src/core/signingEngine/session/warmSigning/capabilityReader.ts',
  'client/src/core/signingEngine/session/warmSigning/capabilityReaderCore.ts',
] as const;

const expectedSessionLayoutFiles = [
  'client/src/core/signingEngine/session/SigningSessionCoordinator.ts',
  'client/src/core/signingEngine/session/restoreCoordinator.ts',
  'client/src/core/signingEngine/session/sealedSessionStore.ts',
  'client/src/core/signingEngine/session/snapshotReader.ts',
  ...pureSigningSessionHelperFiles,
  'client/src/core/signingEngine/session/warmSigning/types.ts',
  'client/src/core/signingEngine/session/warmSigning/store.ts',
  'client/src/core/signingEngine/session/warmSigning/readModel.ts',
  'client/src/core/signingEngine/session/warmSigning/runtime.ts',
  'client/src/core/signingEngine/session/warmSigning/persistence.ts',
  'client/src/core/signingEngine/session/warmSigning/transitions.ts',
  'client/src/core/signingEngine/session/warmSigning/statusReader.ts',
  'client/src/core/signingEngine/session/warmSigning/capabilityReader.ts',
  'client/src/core/signingEngine/session/warmSigning/capabilityReaderCore.ts',
  'client/src/core/signingEngine/session/warmSigning/ecdsaBootstrapRequest.ts',
  'client/src/core/signingEngine/session/warmSigning/ecdsaProvisioner.ts',
  'client/src/core/signingEngine/session/warmSigning/ed25519Provisioner.ts',
  'client/src/core/signingEngine/session/warmSigning/postSignPolicyAdapter.ts',
] as const;

const productionFilesThatMayConstructLegacyCoordinatorHelpers = new Set([
  'client/src/core/signingEngine/session/SigningSessionCoordinator.ts',
]);

function listProductionTypeScriptFiles(dir: string): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listProductionTypeScriptFiles(fullPath));
      continue;
    }
    if (entry.isFile() && fullPath.endsWith('.ts')) {
      files.push(path.relative(repoRoot, fullPath));
    }
  }
  return files;
}

function findModuleLevelMutableInitializers(source: string): string[] {
  let depth = 0;
  const matches: string[] = [];
  const lines = source.split('\n');
  for (const [index, line] of lines.entries()) {
    const trimmed = line.trim();
    if (
      depth === 0 &&
      /^(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:new\s+(?:Map|Set|WeakMap|WeakSet)\b|\[\])/.test(
        trimmed,
      )
    ) {
      matches.push(`${index + 1}: ${trimmed}`);
    }
    for (const char of line) {
      if (char === '{') depth += 1;
      if (char === '}') depth = Math.max(0, depth - 1);
    }
  }
  return matches;
}

test.describe('SigningSessionCoordinator architecture guards', () => {
  test('session modules use the grouped signingSession and warmSigning layout', () => {
    const actualFiles = listProductionTypeScriptFiles(
      path.join(repoRoot, 'client/src/core/signingEngine/session'),
    ).sort();

    expect(actualFiles).toEqual([...expectedSessionLayoutFiles].sort());
  });

  test('transaction auth planning goes through SigningSessionCoordinator, not the pure planner', () => {
    for (const relativePath of transactionFlowFiles) {
      const source = readRepoSource(relativePath);

      expect(source, relativePath).toContain('.resolveAuthPlanFromReadiness(');
      expect(source, relativePath).not.toContain('signingSession/planner');
      expect(source, relativePath).not.toContain('planSigningSession(');
    }
  });

  test('transaction auth planning does not import budget helper state directly', () => {
    for (const relativePath of transactionFlowFiles) {
      const source = readRepoSource(relativePath);

      expect(source, relativePath).not.toContain("signingSession/budget'");
      expect(source, relativePath).not.toContain('signingSession/budget"');
      expect(source, relativePath).not.toContain('createSigningSessionBudgetState');
      expect(source, relativePath).not.toContain('createSigningSessionBudget(');
      expect(source, relativePath).not.toContain('reservedUsesByWalletSessionId');
      expect(source, relativePath).not.toContain('reservationsByOperationId');
      expect(source, relativePath).not.toContain('successfulSpendsByOperationId');
      expect(source, relativePath).not.toContain('walletReservationQueues');
    }
  });

  test('runtime construction of legacy coordinator helpers is contained behind SigningSessionCoordinator', () => {
    for (const relativePath of listProductionTypeScriptFiles(
      path.join(repoRoot, 'client/src/core/signingEngine'),
    )) {
      if (productionFilesThatMayConstructLegacyCoordinatorHelpers.has(relativePath)) continue;
      const source = readRepoSource(relativePath);

      expect(source, relativePath).not.toContain('createSigningSessionBudget(');
      expect(source, relativePath).not.toContain('createSigningSessionCoordinator(');
    }
  });

  test('orchestration dependency bundle wires a single SigningSessionCoordinator facade', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts',
    );

    expect(source).toContain('new SigningSessionCoordinator({');
    expect(source).toContain('signingSessionCoordinator: SigningSessionCoordinator;');
    expect(source).toContain('signingSessionCoordinator,');
    expect(source).not.toContain('signingSessionBudget: SigningSessionCoordinator;');
    expect(source).not.toContain('walletSigningSessionCoordinator: SigningSessionCoordinator;');
    expect(source).not.toContain('SigningSessionBudgetPort');
    expect(source).not.toContain('walletSigningSessionCoordinator:');
    expect(source).not.toContain('createSigningSessionBudget(');
    expect(source).not.toContain('createSigningSessionCoordinator(');
  });

  test('EVM-family warm-session services do not use coordinator naming', () => {
    for (const relativePath of listProductionTypeScriptFiles(
      path.join(repoRoot, 'client/src/core/signingEngine/api/evmFamily'),
    )) {
      const source = readRepoSource(relativePath);

      expect(relativePath).not.toBe(
        'client/src/core/signingEngine/api/evmFamily/signingSessionCoordinator.ts',
      );
      expect(source, relativePath).not.toContain('createEvmFamilySigningSessionCoordinator');
      expect(source, relativePath).not.toContain('EvmFamilySigningSessionCoordinator');
      expect(source, relativePath).not.toContain('./signingSessionCoordinator');
    }
  });

  test('EVM-family signing paths use selected-lane scoped session lookups', () => {
    const forbiddenGenericLookups = [
      'getThresholdEcdsaKeyRefForLookup',
      'getThresholdEcdsaSessionRecordForLookup',
      'getThresholdEcdsaSessionRecordByThresholdSessionId',
      'readWarmSessionEcdsaRecordByThresholdSessionId',
    ];

    for (const relativePath of evmFamilySecuritySessionFiles) {
      const source = readRepoSource(relativePath);
      for (const lookup of forbiddenGenericLookups) {
        expect(source, relativePath).not.toContain(lookup);
      }
    }
  });

  test('legacy budget ledger wrapper has been deleted', () => {
    expect(
      fs.existsSync(
        path.join(repoRoot, 'client/src/core/signingEngine/session/WalletSigningBudgetLedger.ts'),
      ),
    ).toBe(false);
  });

  test('legacy wallet session coordinator wrapper has been deleted', () => {
    expect(
      fs.existsSync(
        path.join(
          repoRoot,
          'client/src/core/signingEngine/session/WalletSigningSessionCoordinator.ts',
        ),
      ),
    ).toBe(false);
  });

  test('only SigningSessionCoordinator owns signing-session mutable maps', () => {
    const allowedPath = 'client/src/core/signingEngine/session/SigningSessionCoordinator.ts';
    const forbiddenInitializers = [
      'successfulSpendsByOperationId: new Map',
      'reservationsByOperationId: new Map',
      'reservedUsesByWalletSessionId: new Map',
      'walletReservationQueues: new Map',
      'statusOverrides: new Map',
      'callerProvidedOperationFingerprintsById: new Map',
    ];

    for (const relativePath of listProductionTypeScriptFiles(
      path.join(repoRoot, 'client/src/core/signingEngine'),
    )) {
      const source = readRepoSource(relativePath);
      for (const initializer of forbiddenInitializers) {
        if (relativePath === allowedPath) {
          expect(source, relativePath).toContain(initializer);
        } else {
          expect(source, relativePath).not.toContain(initializer);
        }
      }
    }
  });

  test('pure signing-session helper modules contain no module-level mutable state', () => {
    for (const relativePath of pureSigningSessionHelperFiles) {
      const source = readRepoSource(relativePath);

      expect(findModuleLevelMutableInitializers(source), relativePath).toEqual([]);
    }
  });

  test('pure planner stays independent from storage, workers, auth, and budget state', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/session/signingSession/planner.ts',
    );
    const imports = Array.from(source.matchAll(/from\s+['"]([^'"]+)['"]/g)).map(
      (match) => match[1],
    );

    for (const importPath of imports) {
      expect(importPath).not.toContain('WarmSession');
      expect(importPath).not.toContain('touchConfirm');
      expect(importPath).not.toContain('thresholdLifecycle');
      expect(importPath).not.toContain('emailOtp');
      expect(importPath).not.toContain('passkey');
      expect(importPath).not.toContain('SigningSessionBudget');
      expect(importPath).not.toContain('signingSession/budget');
      expect(importPath).not.toContain('SigningSessionCoordinator');
      expect(importPath).not.toContain('serverSeal');
      expect(importPath).not.toContain('signing-session-seal');
      expect(importPath).not.toContain('restoreCoordinator');
      expect(importPath).not.toContain('snapshotReader');
      expect(importPath).not.toContain('signingSessionSealedStore');
      expect(importPath).not.toContain('sealedSessionStore');
      expect(importPath).not.toContain('warmSigning');
      expect(importPath).not.toContain('provisioner');
    }

    expect(source).not.toContain('restorePersisted');
    expect(source).not.toContain('createSigningSessionBudget');
    expect(source).not.toContain('reservedUsesByWalletSessionId');
    expect(source).not.toContain('readExactSealedSession');
  });

  test('snapshotReader stays read-only and cannot import restore side effects', () => {
    const source = readRepoSource('client/src/core/signingEngine/session/snapshotReader.ts');
    const imports = Array.from(source.matchAll(/from\s+['"]([^'"]+)['"]/g)).map(
      (match) => match[1],
    );

    for (const importPath of imports) {
      expect(importPath).not.toContain('restoreCoordinator');
      expect(importPath).not.toContain('workerManager');
      expect(importPath).not.toContain('touchConfirm');
      expect(importPath).not.toContain('serverSeal');
      expect(importPath).not.toContain('signing-session-seal');
      expect(importPath).not.toContain('EmailOtpThresholdSessionCoordinator');
      expect(importPath).not.toContain('SigningSessionCoordinator');
    }

    expect(source).not.toContain('restorePersisted');
    expect(source).not.toContain('remove-server-seal');
    expect(source).not.toContain('requestWorkerOperation');
    expect(source).not.toContain('deleteExactSealedSession');
    expect(source).not.toContain('writeExactSealedSession');
  });

  test('Email OTP snapshots read runtime identity from the sealed-session owner', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator.ts',
    );
    const snapshotBody = source.slice(
      source.indexOf('async readPersistedSessionSnapshot'),
      source.indexOf('private async restoreEcdsaSealedRecordForAccount'),
    );

    expect(snapshotBody).toContain('listResolvedIdentitiesForAccount');
    expect(snapshotBody).not.toContain('listThresholdEcdsaSessionRecordsForLookup');
    expect(snapshotBody).not.toContain('getStoredThresholdEd25519SessionRecordForAccount');
  });

  test('sealed session store stays storage-only', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/session/sealedSessionStore.ts',
    );
    const imports = Array.from(source.matchAll(/from\s+['"]([^'"]+)['"]/g)).map(
      (match) => match[1],
    );

    for (const importPath of imports) {
      expect(importPath).not.toContain('workerManager');
      expect(importPath).not.toContain('touchConfirm');
      expect(importPath).not.toContain('restoreCoordinator');
      expect(importPath).not.toContain('EmailOtpThresholdSessionCoordinator');
      expect(importPath).not.toContain('serverSeal');
      expect(importPath).not.toContain('signing-session-seal');
      expect(importPath).not.toContain('rpcClients');
    }
    expect(source).not.toContain('requestWorkerOperation');
    expect(source).not.toContain('restorePersisted');
    expect(source).not.toContain('remove-server-seal');
    expect(source).not.toContain('apply-server-seal');
  });

  test('query and snapshot modules do not import server seal clients', () => {
    for (const relativePath of signingSessionQueryFiles) {
      const source = readRepoSource(relativePath);
      const imports = Array.from(source.matchAll(/from\s+['"]([^'"]+)['"]/g)).map(
        (match) => match[1],
      );

      for (const importPath of imports) {
        expect(importPath, relativePath).not.toContain('serverSeal');
        expect(importPath, relativePath).not.toContain('signing-session-seal');
        expect(importPath, relativePath).not.toContain('rpcClients');
      }
      expect(source, relativePath).not.toContain('remove-server-seal');
      expect(source, relativePath).not.toContain('apply-server-seal');
    }
  });

  test('sealed-refresh unseal clients stay behind explicit restore commands', () => {
    const allowed = new Set([
      'client/src/core/signingEngine/session/restoreCoordinator.ts',
      'client/src/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator.ts',
      'client/src/core/signingEngine/touchConfirm/TouchConfirmManager.ts',
      'client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
      'client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts',
    ]);
    const offenders = listProductionTypeScriptFiles(
      path.join(repoRoot, 'client/src/core/signingEngine'),
    ).filter((relativePath) => {
      if (allowed.has(relativePath)) return false;
      const source = readRepoSource(relativePath);
      return (
        source.includes('remove-server-seal') ||
        source.includes('apply-server-seal') ||
        source.includes('tryRestoreEmailOtpEcdsaCapabilityFromSealedRecord')
      );
    });

    expect(offenders).toEqual([]);
  });

  test('transaction signing uses prepared identity boundaries before lane execution', () => {
    const evmSigning = readRepoSource('client/src/core/signingEngine/api/evmSigning.ts');
    const nearSigning = readRepoSource('client/src/core/signingEngine/api/nearSigning.ts');

    expect(evmSigning).toContain('prepareEvmFamilyEcdsaSigningSession({');
    expect(evmSigning).not.toContain('resolveEvmFamilyEcdsaSigningSelection(');
    expect(nearSigning).toContain('prepareNearEd25519TransactionSigningSession(');
    expect(nearSigning).toContain('buildNearTransactionLaneFromPreparedIdentity(');
    expect(nearSigning).not.toContain('buildNearTransactionLaneForRecord');
  });

  test('prepared transaction identities require wallet and threshold session ids', () => {
    const evmPrepared = readRepoSource(
      'client/src/core/signingEngine/api/evmFamily/preparedSigning.ts',
    );
    const nearSigning = readRepoSource('client/src/core/signingEngine/api/nearSigning.ts');
    const signingSessionTypes = readRepoSource(
      'client/src/core/signingEngine/session/signingSession/types.ts',
    );
    const evmPreparedType = evmPrepared.slice(
      evmPrepared.indexOf('export type PreparedEvmFamilyEcdsaSigningSession'),
      evmPrepared.indexOf('export type PrepareEvmFamilyEcdsaSigningDeps'),
    );
    const nearIdentityType = nearSigning.slice(
      nearSigning.indexOf('type NearEd25519PreparedIdentity'),
      nearSigning.indexOf('type PreparedNearEd25519TransactionSigningSession'),
    );
    const nearPreparedType = nearSigning.slice(
      nearSigning.indexOf('type PreparedNearEd25519TransactionSigningSession'),
      nearSigning.indexOf('function createNearTransactionSigningOperationId'),
    );
    const selectedIdentityType = signingSessionTypes.slice(
      signingSessionTypes.indexOf('export type SelectedSigningLaneIdentity'),
      signingSessionTypes.indexOf('export type ResolvedSigningSessionIdentity'),
    );
    const resolvedEd25519IdentityType = signingSessionTypes.slice(
      signingSessionTypes.indexOf('export type ResolvedEd25519SigningSessionIdentity'),
      signingSessionTypes.indexOf('export type ResolvedEcdsaSigningSessionIdentity'),
    );
    const resolvedEcdsaIdentityType = signingSessionTypes.slice(
      signingSessionTypes.indexOf('export type ResolvedEcdsaSigningSessionIdentity'),
      signingSessionTypes.indexOf('export type SigningOperationContext'),
    );

    expect(evmPreparedType).toContain('signingLane: ResolvedEvmFamilyEcdsaSigningLane;');
    expect(evmPreparedType).not.toContain('signingLane?:');
    expect(nearIdentityType).toContain('ResolvedEd25519SigningSessionIdentity');
    expect(selectedIdentityType).toContain('thresholdSessionId: ThresholdSessionId;');
    expect(selectedIdentityType).toContain('walletSigningSessionId: WalletSigningSessionId;');
    expect(selectedIdentityType).not.toContain('thresholdSessionId?:');
    expect(selectedIdentityType).not.toContain('walletSigningSessionId?:');
    expect(resolvedEd25519IdentityType).toContain('thresholdSessionId: ThresholdEd25519SessionId;');
    expect(resolvedEcdsaIdentityType).toContain('thresholdSessionId: ThresholdEcdsaSessionId;');
    expect(nearPreparedType).toContain('identity: NearEd25519PreparedIdentity;');
    expect(nearPreparedType).not.toContain('identity?:');
    expect(nearSigning).toContain('function resolvePreparedSigningRequestSessionId');
    expect(nearSigning).toContain('identity: NearEd25519PreparedIdentity;');
    expect(nearSigning).not.toContain('identity?: NearEd25519PreparedIdentity');
  });

  test('production code does not synthesize wallet signing-session ids from threshold session ids', () => {
    const forbiddenLinePatterns = [
      /walletSigningSessionId\s*:\s*[^,\n]*thresholdSessionId/,
      /walletSigningSessionId\s*=\s*[^;\n]*thresholdSessionId/,
      /walletSigningSessionId\s*:\s*`[^`]*\$\{[^}]*thresholdSessionId[^}]*\}/,
    ];

    for (const relativePath of listProductionTypeScriptFiles(
      path.join(repoRoot, 'client/src/core/signingEngine'),
    )) {
      const source = readRepoSource(relativePath);
      const offendingLines = source
        .split('\n')
        .map((line, index) => ({ line, lineNumber: index + 1 }))
        .filter(({ line }) => forbiddenLinePatterns.some((pattern) => pattern.test(line)));

      expect(
        offendingLines.map(({ line, lineNumber }) => `${lineNumber}: ${line.trim()}`),
        relativePath,
      ).toEqual([]);
    }
  });

  test('Email OTP persistence writes are routed through command-named boundaries', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator.ts',
    );

    expect(source).toContain('cleanupSigningSession(');
    expect(source).toContain('registerSigningSession(');
    expect(source).toContain('recordSessionMaterialClaimed(');
    expect(source).toContain('recordSessionUseConsumed(');
    expect(source).toContain('clearEcdsaRestoreCaches()');
    expect(source).toContain('this.ecdsaSigningRestoreCache.clear();');
    expect(source).toContain('this.ecdsaAccountSealedRestoreCompletedKeys.clear();');
    expect(source).not.toContain('recordWarmSessionPolicyFromStatus');
  });

  test('passkey persistence writes are routed through command-named boundaries', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/touchConfirm/TouchConfirmManager.ts',
    );

    expect(source).toContain('cleanupSigningSession(');
    expect(source).toContain('registerSigningSession(');
    expect(source).toContain('recordSessionMaterialClaimed(');
    expect(source).toContain('recordSessionUseConsumed(');
    expect(source).toContain('recordSessionMaterialRestored(');
  });

  test('wallet-session status polling cannot trigger sealed-session restore', () => {
    const source = readRepoSource('client/src/core/signingEngine/SigningEngine.ts');
    const walletSessionSource = readRepoSource('client/src/core/TatchiPasskey/login.ts');
    const emailOtpCoordinatorSource = readRepoSource(
      'client/src/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator.ts',
    );
    const ecdsaStatusBody = source.slice(
      source.indexOf('getWarmThresholdEcdsaSessionStatus('),
      source.indexOf('listWarmThresholdEcdsaSessionStatuses('),
    );
    const ecdsaStatusListBody = source.slice(
      source.indexOf('listWarmThresholdEcdsaSessionStatuses('),
      source.indexOf('async scheduleThresholdEcdsaLoginPresignPrefill('),
    );
    const walletStatusResolutionBody = walletSessionSource.slice(
      walletSessionSource.indexOf('async function resolveWarmSigningSessionStatusForUi('),
      walletSessionSource.indexOf('async function getLoginStateInternal('),
    );
    const emailOtpStatusBody = emailOtpCoordinatorSource.slice(
      emailOtpCoordinatorSource.indexOf('async readWarmSessionStatusOnly('),
      emailOtpCoordinatorSource.indexOf('async claimWarmSessionMaterial('),
    );
    const statusOnlyTouchConfirmBody = source.slice(
      source.indexOf('private createWarmSessionStatusOnlyTouchConfirm('),
      source.indexOf('private createSigningSessionStatusOnlyCoordinator('),
    );
    const signingEngineStatusReaderBody = source.slice(
      source.indexOf('private createWarmSessionStatusReader()'),
      source.indexOf('private async getWalletSigningBudgetAvailableStatus('),
    );
    const walletBudgetStatusBody = source.slice(
      source.indexOf('private async getWalletSigningBudgetAvailableStatus('),
      source.indexOf('private mergeWalletSigningBudgetStatus'),
    );

    expect(source).not.toContain('restorePersistedEmailOtpSessionsForRead');
    expect(source).not.toContain('restorePersistedEmailOtpSessionForStatusCompatibility');
    expect(source).not.toMatch(
      /getEmailOtpWarmSessionStatus:\s*\(sessionId\)\s*=>\s*this\.emailOtpSessions\.getWarmSessionStatus/,
    );
    expect(source).toContain('this.emailOtpSessions.readWarmSessionStatusOnly(sessionId)');
    expect(statusOnlyTouchConfirmBody).toContain('readWarmSessionStatusOnly');
    expect(statusOnlyTouchConfirmBody).toContain('readWarmSessionStatusesOnly');
    expect(statusOnlyTouchConfirmBody).not.toContain('base.getWarmSessionStatus');
    expect(statusOnlyTouchConfirmBody).not.toContain('base.getWarmSessionStatuses');
    expect(signingEngineStatusReaderBody).toContain('createWarmSessionStatusOnlyTouchConfirm');
    expect(signingEngineStatusReaderBody).toContain('createSigningSessionStatusOnlyCoordinator');
    expect(walletBudgetStatusBody).toContain('createSigningSessionStatusOnlyCoordinator');
    for (const [label, body] of [
      ['getWarmThresholdEcdsaSessionStatus', ecdsaStatusBody],
      ['listWarmThresholdEcdsaSessionStatuses', ecdsaStatusListBody],
      ['resolveWarmSigningSessionStatusForUi', walletStatusResolutionBody],
      ['SigningEngine.createWarmSessionStatusOnlyTouchConfirm', statusOnlyTouchConfirmBody],
      ['SigningEngine.createWarmSessionStatusReader', signingEngineStatusReaderBody],
      ['SigningEngine.getWalletSigningBudgetAvailableStatus', walletBudgetStatusBody],
      ['EmailOtpThresholdSessionCoordinator.readWarmSessionStatusOnly', emailOtpStatusBody],
    ] as const) {
      expect(body, label).not.toContain('restorePersistedSessionForSigning');
      expect(body, label).not.toContain('restorePersistedSessionsForAccount');
      expect(body, label).not.toContain('tryRestoreEcdsaWarmSessionStatusFromSealedRecord');
      expect(body, label).not.toContain('rehydrateEmailOtpEcdsaWarmSessionMaterial');
      expect(body, label).not.toContain('remove-server-seal');
    }
    expect(emailOtpStatusBody).toContain('readWarmSessionStatusOnly');
  });

  test('restore commands enumerate durable exact-purpose sealed records directly', () => {
    const restoreCoordinator = readRepoSource(
      'client/src/core/signingEngine/session/restoreCoordinator.ts',
    );
    const emailOtpCoordinator = readRepoSource(
      'client/src/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator.ts',
    );
    const sealedStore = readRepoSource(
      'client/src/core/signingEngine/session/sealedSessionStore.ts',
    );

    expect(restoreCoordinator).toContain('listExactSealedSessionsForAccount');
    expect(restoreCoordinator).not.toContain('listSealedRecordsForAccount');
    expect(emailOtpCoordinator).toContain('listExactSealedSessionsForAccount');
    expect(sealedStore).toContain('listExactSealedSessionsForAccount');
    const exactListBody = sealedStore.slice(
      sealedStore.indexOf('export async function listExactSealedSessionsForAccount'),
      sealedStore.indexOf('export async function writeExactSealedSession'),
    );
    expect(exactListBody).not.toContain('readRuntimeSessionId');
    expect(exactListBody).not.toContain('runtimeSessionId');
  });

  test('Email OTP restore does not delete sealed records from unauthenticated durable hints', () => {
    const emailOtpCoordinator = readRepoSource(
      'client/src/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator.ts',
    );
    const restoreBody = emailOtpCoordinator.slice(
      emailOtpCoordinator.indexOf('private async tryRestoreEcdsaWarmSessionStatusFromSealedRecord'),
      emailOtpCoordinator.indexOf('private shouldAttemptEcdsaSealedRestoreForSessionId'),
    );

    expect(restoreBody).not.toContain('exact_purpose_metadata_mismatch');
    expect(restoreBody).not.toContain("reason: sealedRecord.remainingUses <= 0 ? 'exhausted' : 'expired'");
    expect(restoreBody).toContain('sealed refresh restore deferred by durable policy hint');
    expect(restoreBody).toContain('sealed refresh restore deferred by store metadata mismatch');
  });

  test('Phase 14 keeps ECDSA signing runtime on resolved lane identity', () => {
    const runtime = readRepoSource(
      'client/src/core/signingEngine/api/evmFamily/signingFlowRuntime.ts',
    );
    const authPlanning = readRepoSource(
      'client/src/core/signingEngine/api/evmFamily/authPlanning.ts',
    );
    const budget = readRepoSource('client/src/core/signingEngine/api/evmFamily/budgetSpending.ts');
    const budgetFinalizer = readRepoSource(
      'client/src/core/signingEngine/session/signingSession/budgetFinalizer.ts',
    );
    const postSign = readRepoSource(
      'client/src/core/signingEngine/api/evmFamily/postSignPolicy.ts',
    );
    const ecdsaLanes = readRepoSource('client/src/core/signingEngine/api/evmFamily/ecdsaLanes.ts');
    const resolvedLaneType = ecdsaLanes.slice(
      ecdsaLanes.indexOf('export type ResolvedEvmFamilyEcdsaSigningLane'),
      ecdsaLanes.indexOf('export function requireResolvedEvmFamilyEcdsaSigningLane'),
    );

    expect(runtime).toContain('getResolvedEcdsaSigningLane');
    expect(runtime).not.toContain('getEcdsaSigningLane');
    expect(runtime).not.toContain('SigningLaneContext | undefined');
    expect(runtime).not.toContain('getResolvedEcdsaSigningLane()!');
    expect(authPlanning).toContain('ecdsaSigningLane: ResolvedEvmFamilyEcdsaSigningLane');
    expect(authPlanning).not.toContain('ecdsaSigningLane?: SigningLaneContext');
    expect(authPlanning).not.toContain('args.ecdsaAuthMethod !== SIGNER_AUTH_METHODS.emailOtp');
    expect(budget).toContain('ecdsaSigningLane: ResolvedEvmFamilyEcdsaSigningLane');
    expect(budget).not.toContain('ecdsaSigningLane?: SigningLaneContext');
    expect(budget).not.toContain('senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm');
    expect(budgetFinalizer).toContain('lane: SelectedSigningLaneContext');
    expect(budgetFinalizer).not.toContain('thresholdSessionId?: ThresholdSessionId');
    expect(postSign).toContain('ecdsaSigningLane: ResolvedEvmFamilyEcdsaSigningLane');
    expect(postSign).toContain('selectedEcdsaSource: ThresholdEcdsaSessionStoreSource');
    expect(postSign).not.toContain('ecdsaSigningLane?: SigningLaneContext');
    expect(postSign).not.toContain('senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm');
    expect(resolvedLaneType).toContain('walletSigningSessionId: WalletSigningSessionId;');
    expect(resolvedLaneType).toContain('thresholdSessionId: ThresholdEcdsaSessionId;');
    expect(resolvedLaneType).not.toContain('walletSigningSessionId?:');
    expect(resolvedLaneType).not.toContain('thresholdSessionId?:');
  });

  test('Phase 14 keeps sealed-session purpose mandatory at write boundaries', () => {
    const sealedStore = readRepoSource(
      'client/src/core/signingEngine/session/sealedSessionStore.ts',
    );
    const touchConfirm = readRepoSource(
      'client/src/core/signingEngine/touchConfirm/TouchConfirmManager.ts',
    );
    const sealedWriteBoundary = sealedStore.slice(
      sealedStore.indexOf('export async function writeExactSealedSession'),
      sealedStore.indexOf('export async function updateExactSealedSessionPolicy'),
    );

    expect(sealedWriteBoundary).toContain("authMethod: 'passkey' | 'email_otp';");
    expect(sealedWriteBoundary).not.toContain("authMethod?: 'passkey' | 'email_otp'");
    expect(sealedWriteBoundary).not.toContain(
      "args.authMethod === 'email_otp' ? 'email_otp' : 'passkey'",
    );
    expect(touchConfirm).toContain("authMethod: 'passkey'");
    expect(touchConfirm).toContain("authMethod?: 'passkey' | 'email_otp'");
    expect(touchConfirm).toContain("curve?: 'ed25519' | 'ecdsa'");
    expect(touchConfirm).toContain('walletSigningSessionId?: string');
    expect(touchConfirm).toContain(
      "authMethod: 'passkey',\n      curve,\n      ...(chain ? { chain } : {}),\n      walletSigningSessionId,",
    );
    expect(touchConfirm).toContain(
      "authMethod: 'passkey',\n        walletSigningSessionId,\n        ...recordMetadata,",
    );
  });

  test('restore-for-signing inputs are exact by curve and chain', () => {
    const restoreCoordinator = readRepoSource(
      'client/src/core/signingEngine/session/restoreCoordinator.ts',
    );
    const inputType = restoreCoordinator.slice(
      restoreCoordinator.indexOf('export type RestorePersistedSessionForSigningInput'),
      restoreCoordinator.indexOf('export type RestorePersistedSessionForSigningResult'),
    );

    expect(inputType).toContain("curve: 'ed25519';");
    expect(inputType).toContain("chain: 'near';");
    expect(inputType).toContain("curve: 'ecdsa';");
    expect(inputType).toContain("chain: 'tempo' | 'evm';");
    expect(inputType).not.toContain("curve: 'ed25519' | 'ecdsa';");
    expect(inputType).not.toContain("chain: 'near' | 'tempo' | 'evm';");
  });

  test('EVM signing cannot bypass restoreCoordinator with direct Email OTP rehydrate deps', () => {
    const evmSigning = readRepoSource('client/src/core/signingEngine/api/evmSigning.ts');
    const orchestrationFactory = readRepoSource(
      'client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts',
    );
    const signingEngine = readRepoSource('client/src/core/signingEngine/SigningEngine.ts');
    const emailOtpCoordinator = readRepoSource(
      'client/src/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator.ts',
    );

    for (const [label, source] of [
      ['evmSigning', evmSigning],
      ['orchestrationFactory', orchestrationFactory],
      ['signingEngine', signingEngine],
      ['emailOtpCoordinator', emailOtpCoordinator],
    ] as const) {
      expect(label).toBeTruthy();
      expect(source).not.toContain('rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord');
    }
  });

  test('Phase 14 keeps Email OTP signing-session lanes fully identified', () => {
    const authLane = readRepoSource('client/src/core/signingEngine/emailOtp/authLane.ts');
    const signingSessionType = authLane.slice(
      authLane.indexOf('export type EmailOtpSigningSessionAuthLane'),
      authLane.indexOf('export type EmailOtpRouteFamily'),
    );
    const capabilityReaderCore = readRepoSource(
      'client/src/core/signingEngine/session/warmSigning/capabilityReaderCore.ts',
    );

    expect(signingSessionType).toContain('export type EmailOtpSigningSessionAuthLane');
    expect(signingSessionType).toContain('walletSigningSessionId: string;');
    expect(signingSessionType).toContain("curve: 'ed25519';");
    expect(signingSessionType).toContain("curve: 'ecdsa';");
    expect(signingSessionType).toContain('chain: ThresholdEcdsaActivationChain;');
    expect(signingSessionType).not.toContain('?:');
    expect(capabilityReaderCore).not.toContain(
      '? { walletSigningSessionId: record.walletSigningSessionId }',
    );
  });

  test('ECDSA selection does not fall back to partial record/keyRef identity after lane resolution', () => {
    const ecdsaSelection = readRepoSource(
      'client/src/core/signingEngine/api/evmFamily/ecdsaSelection.ts',
    );
    const ecdsaLanes = readRepoSource('client/src/core/signingEngine/api/evmFamily/ecdsaLanes.ts');

    expect(ecdsaSelection).toContain('readSelectedEcdsaRecordForLane');
    expect(ecdsaSelection).toContain('readSelectedEcdsaKeyRefForLane');
    expect(ecdsaSelection).not.toContain('|| emailOtpRecord');
    expect(ecdsaSelection).not.toContain('|| emailOtpKeyRef');
    expect(ecdsaSelection).not.toContain('|| passkeyRecord');
    expect(ecdsaSelection).not.toContain('|| passkeyKeyRef');
    expect(ecdsaSelection).not.toContain('fallbackPasskey');
    expect(ecdsaLanes).toContain('recordThresholdSessionId !== keyRefThresholdSessionId');
    expect(ecdsaLanes).toContain('recordWalletSigningSessionId !== keyRefWalletSigningSessionId');
    expect(ecdsaLanes).not.toContain('args.record?.thresholdSessionId || args.keyRef?.thresholdSessionId');
    expect(ecdsaLanes).not.toContain(
      'args.record?.walletSigningSessionId || args.keyRef?.walletSigningSessionId',
    );
  });

  test('transaction and export entrypoints use prepared lane-resolution boundaries', () => {
    const tempoSigning = readRepoSource('client/src/core/signingEngine/api/tempoSigning.ts');
    const evmSigning = readRepoSource('client/src/core/signingEngine/api/evmSigning.ts');
    const preparedSigning = readRepoSource(
      'client/src/core/signingEngine/api/evmFamily/preparedSigning.ts',
    );
    const nearSigning = readRepoSource('client/src/core/signingEngine/api/nearSigning.ts');
    const signingEngine = readRepoSource('client/src/core/signingEngine/SigningEngine.ts');

    expect(tempoSigning).toContain('return await signEvmFamily(deps, args);');
    expect(evmSigning).toContain('prepareEvmFamilyEcdsaSigningSession');
    expect(evmSigning).not.toContain('resolveEvmFamilyEcdsaSigningSelection');
    expect(preparedSigning).toContain('resolveEvmFamilyEcdsaSigningSelection');
    expect(nearSigning).toContain('prepareNearEd25519TransactionSigningSession');
    expect(nearSigning).toContain('PreparedNearEd25519TransactionSigningSession');
    expect(signingEngine.indexOf('restoreEmailOtpEcdsaSessionForExportBestEffort')).toBeLessThan(
      signingEngine.indexOf('resolveEmailOtpEcdsaExportTargetFromLocalMetadata'),
    );
  });
});
