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

const transactionCoordinatorConstructionGuardFiles = [
  'client/src/core/signingEngine/api/nearSigning.ts',
  'client/src/core/signingEngine/api/evmSigning.ts',
  'client/src/core/signingEngine/api/evmFamily/authPlanning.ts',
  'client/src/core/signingEngine/api/evmFamily/budgetSpending.ts',
  'client/src/core/signingEngine/orchestration/near/transactionsFlow.ts',
  'client/src/core/signingEngine/orchestration/near/delegateFlow.ts',
  'client/src/core/signingEngine/orchestration/near/nep413Flow.ts',
  'client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts',
  'client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts',
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
  'client/src/core/signingEngine/session/signingSession/budgetProjection.ts',
  'client/src/core/signingEngine/session/signingSession/budgetFinalizer.ts',
  'client/src/core/signingEngine/session/signingSession/readiness.ts',
  'client/src/core/signingEngine/session/signingSession/planner.ts',
  'client/src/core/signingEngine/session/signingSession/preparedOperation.ts',
  'client/src/core/signingEngine/session/signingSession/execution.ts',
  'client/src/core/signingEngine/session/signingSession/trace.ts',
  'client/src/core/signingEngine/session/signingSession/transactionState.ts',
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

      if (
        relativePath === 'client/src/core/signingEngine/orchestration/near/delegateFlow.ts' ||
        relativePath === 'client/src/core/signingEngine/orchestration/near/nep413Flow.ts'
      ) {
        expect(source, relativePath).toContain('planSigningSession(');
      } else if (
        relativePath === 'client/src/core/signingEngine/api/nearSigning.ts'
      ) {
        expect(source, relativePath).toContain('prepareTransactionSigningOperation');
        expect(source, relativePath).not.toContain('signingSession/planner');
        expect(source, relativePath).not.toContain('planSigningSession(');
      } else if (
        relativePath ===
        'client/src/core/signingEngine/orchestration/near/transactionsFlow.ts'
      ) {
        expect(source, relativePath).toContain(
          'threshold transaction signing requires prepared session identity',
        );
        expect(source, relativePath).not.toContain('.resolveAuthPlanFromReadiness(');
        expect(source, relativePath).not.toContain('signingSession/planner');
        expect(source, relativePath).not.toContain('planSigningSession(');
      } else if (relativePath === 'client/src/core/signingEngine/api/evmFamily/authPlanning.ts') {
        expect(source, relativePath).toContain('preparedOperation: PreparedThresholdSigningOperation');
        expect(source, relativePath).not.toContain('prepareThresholdSigningOperation');
        expect(source, relativePath).not.toContain('signingSession/planner');
        expect(source, relativePath).not.toContain('planSigningSession(');
      } else {
        expect(source, relativePath).toContain('.resolveAuthPlanFromReadiness(');
        expect(source, relativePath).not.toContain('signingSession/planner');
        expect(source, relativePath).not.toContain('planSigningSession(');
      }
    }
  });

  test('transaction code cannot construct SigningSessionCoordinator', () => {
    for (const relativePath of transactionCoordinatorConstructionGuardFiles) {
      const source = readRepoSource(relativePath);

      expect(source, relativePath).not.toContain('new SigningSessionCoordinator(');
      expect(source, relativePath).not.toMatch(
        /import\s+\{\s*SigningSessionCoordinator\b/,
      );
    }
  });

  test('status readers do not import or construct SigningSessionCoordinator', () => {
    for (const relativePath of signingSessionQueryFiles) {
      const source = readRepoSource(relativePath);

      expect(source, relativePath).not.toContain('new SigningSessionCoordinator(');
      expect(source, relativePath).not.toMatch(
        /import\s+(?:type\s+)?\{\s*[^}]*\bSigningSessionCoordinator\b/,
      );
    }
  });

  test('only production assembly constructs SigningSessionCoordinator', () => {
    const allowedPath =
      'client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts';
    for (const relativePath of listProductionTypeScriptFiles(
      path.join(repoRoot, 'client/src/core/signingEngine'),
    )) {
      const source = readRepoSource(relativePath);
      if (relativePath === allowedPath) {
        expect(source, relativePath).toContain('new SigningSessionCoordinator({');
        continue;
      }
      expect(source, relativePath).not.toContain('new SigningSessionCoordinator(');
    }
  });

  test('transaction auth planning does not import budget helper state directly', () => {
    for (const relativePath of transactionFlowFiles) {
      const source = readRepoSource(relativePath);

      // Transaction code may carry prepared budget identity as a type, but it
      // must not reach into budget helper state or projection mutation directly.
      expect(source, relativePath).not.toContain('createSigningSessionBudgetState');
      expect(source, relativePath).not.toContain('createSigningSessionBudget(');
      expect(source, relativePath).not.toContain('applySigningSessionBudgetReservationsToStatus');
      expect(source, relativePath).not.toContain('assertPreparedBudgetProjectionVersion');
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
    const pureProjectionPath =
      'client/src/core/signingEngine/session/signingSession/budgetProjection.ts';
    const forbiddenInitializers = [
      'successfulSpendsByOperationId: new Map',
      'reservationsByOperationId: new Map',
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
        } else if (
          relativePath === pureProjectionPath &&
          initializer === 'reservationsByOperationId: new Map'
        ) {
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

  test('readiness does not use local availability as terminal budget truth', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/session/signingSession/readiness.ts',
    );

    expect(source).not.toContain('walletBudgetStatus.availableUses');
    expect(source).not.toContain('budgetAvailableUses');
  });

  test('budget projection reservations are causally tied to projection versions', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/session/signingSession/budgetProjection.ts',
    );

    expect(source).toContain('reservedAgainstProjectionVersion: string;');
    expect(source).toContain('reservation.reservedAgainstProjectionVersion');
    expect(source).toContain('!== projectionVersion');
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
    expect(source).not.toContain('sessionStorage');
    expect(source).not.toContain('runtimeSessionId');
  });

  test('Phase 13 keeps signing-session identity out of sessionStorage-backed stores', () => {
    const sealedStore = readRepoSource(
      'client/src/core/signingEngine/session/sealedSessionStore.ts',
    );
    const thresholdSessionStore = readRepoSource(
      'client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.ts',
    );
    const sharedSeal = readRepoSource('shared/src/utils/signingSessionSeal.ts');

    for (const [label, source] of [
      ['sealedSessionStore', sealedStore],
      ['thresholdSessionStore', thresholdSessionStore],
      ['signingSessionSeal shared type', sharedSeal],
    ] as const) {
      expect(source, label).not.toContain('sessionStorage');
      expect(source, label).not.toContain('SIGNING_SESSION_RUNTIME_SESSION_ID_KEY');
      expect(source, label).not.toContain('runtimeSessionId');
    }
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
    expect(nearSigning).toContain('provided && provided !== prepared');
    expect(nearSigning).toContain('transaction sessionId must match prepared Ed25519 identity');
    expect(nearSigning).not.toContain('if (provided) return provided');
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
    const walletSessionSource = readRepoSource('client/src/core/SeamsPasskey/login.ts');
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
      source.indexOf('private async ensureSealedRefreshStartupParity('),
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
    expect(signingEngineStatusReaderBody).not.toContain('SigningSessionCoordinator');
    expect(walletBudgetStatusBody).toContain('this.orchestrationDeps.signingSessionCoordinator');
    expect(walletBudgetStatusBody).not.toContain('new SigningSessionCoordinator');
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
    expect(authPlanning).toContain('preparedOperation: PreparedThresholdSigningOperation');
    expect(authPlanning).toContain('const preparedEcdsaLane');
    expect(authPlanning).not.toContain('ecdsaSigningLane: ResolvedEvmFamilyEcdsaSigningLane');
    expect(authPlanning).not.toContain('ecdsaAuthMethod:');
    expect(authPlanning).not.toContain('ecdsaWarmRecord');
    expect(authPlanning).not.toContain('ecdsaWarmKeyRef');
    expect(authPlanning).not.toContain('ecdsaSigningLane?: SigningLaneContext');
    expect(authPlanning).not.toContain('args.ecdsaAuthMethod !== SIGNER_AUTH_METHODS.emailOtp');
    expect(budget).toContain('ecdsaSigningLane: ResolvedEvmFamilyEcdsaSigningLane');
    expect(budget).not.toContain('ecdsaSigningLane?: SigningLaneContext');
    expect(budget).not.toContain('senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm');
    expect(budgetFinalizer).toContain('lane: SigningSessionBudgetFinalizerLane');
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

  test('budget finalizers require prepared budget identity and projection version', () => {
    const budgetFinalizer = readRepoSource(
      'client/src/core/signingEngine/session/signingSession/budgetFinalizer.ts',
    );
    const budget = readRepoSource(
      'client/src/core/signingEngine/session/signingSession/budget.ts',
    );
    const coordinator = readRepoSource(
      'client/src/core/signingEngine/session/SigningSessionCoordinator.ts',
    );
    const evmBudget = readRepoSource(
      'client/src/core/signingEngine/api/evmFamily/budgetSpending.ts',
    );
    const nearTransactions = readRepoSource(
      'client/src/core/signingEngine/orchestration/near/transactionsFlow.ts',
    );
    const evmSigning = readRepoSource('client/src/core/signingEngine/api/evmSigning.ts');
    const nearSigning = readRepoSource('client/src/core/signingEngine/api/nearSigning.ts');
    const budgetFinalizerArgs = budgetFinalizer.slice(
      budgetFinalizer.indexOf('export function createSigningSessionBudgetFinalizer'),
      budgetFinalizer.indexOf('): SigningSessionBudgetFinalizer'),
    );

    expect(budget).toContain('export type SigningSessionPreparedBudgetIdentity');
    expect(budget).toContain('expectedBudgetProjectionVersion?: string;');
    expect(budget).toContain('export type SigningSessionBudgetReserveInput');
    expect(budget).toContain('expectedBudgetProjectionVersion: string;');
    expect(budget).toContain('input: SigningSessionBudgetReserveInput;');
    expect(budget).toContain('assertPreparedBudgetProjectionVersion');
    expect(budget).toContain('prepared budget projection version is required');
    expect(coordinator).toContain('async prepareBudgetIdentity(');
    expect(coordinator).toContain('SIGNING_SESSION_BUDGET_UNKNOWN_ERROR');
    expect(coordinator).toContain('projectionVersion,');
    expect(budgetFinalizerArgs).toContain('budgetIdentity: SigningSessionPreparedBudgetIdentity;');
    expect(budgetFinalizerArgs).not.toContain('budgetIdentity?:');
    expect(budgetFinalizer).toContain(
      'expectedBudgetProjectionVersion: args.budgetIdentity.projectionVersion',
    );
    expect(budgetFinalizer).toContain('reserveWithLocalContentionRetry');
    expect(budgetFinalizer).toContain('isSigningSessionBudgetInFlightError');
    expect(evmBudget).toContain('budgetIdentity: SigningSessionPreparedBudgetIdentity;');
    expect(evmBudget).toContain('budgetIdentity: args.budgetIdentity');
    expect(evmSigning).toContain('ensurePreparedEcdsaBudgetIdentity');
    expect(evmSigning).toContain('budgetIdentity: prepared.budgetIdentity!');
    expect(nearSigning).toContain('prepareTransactionSigningOperation');
    expect(nearSigning).toContain('prepareBudgetIdentity: true');
    expect(nearSigning).toContain('const transactionOperation = preparedTransaction.transactionOperation');
    expect(nearSigning).toContain('admitTransactionBudget(transactionOperation');
    expect(nearTransactions).toContain('budgetAdmittedOperation: providedBudgetAdmittedOperation');
    expect(nearTransactions).toContain('let activeBudgetAdmittedOperation = providedBudgetAdmittedOperation');
    expect(nearTransactions).toContain('budgetAdmission.budgetIdentity');
    expect(nearTransactions).not.toContain('providedBudgetIdentity');
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

  test('EVM signing routes exact restore commands by auth method', () => {
    const signingEngine = readRepoSource('client/src/core/signingEngine/SigningEngine.ts');
    const depsBlock = signingEngine.slice(
      signingEngine.indexOf('restorePersistedSessionForSigning: (args) =>'),
      signingEngine.indexOf('readSigningSessionSnapshotForSigning: (args) =>'),
    );

    expect(depsBlock).toContain("args.authMethod === 'passkey'");
    expect(depsBlock).toContain('this.touchConfirm.restorePersistedSessionForSigning({');
    expect(depsBlock).toContain('this.emailOtpSessions.restorePersistedSessionForSigning(args)');
  });

  test('Email OTP exact-purpose restore execution does not rediscover ECDSA records', () => {
    const emailOtpCoordinator = readRepoSource(
      'client/src/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator.ts',
    );
    const exactEcdsaRestoreBody = emailOtpCoordinator.slice(
      emailOtpCoordinator.indexOf('private async restoreEcdsaSealedRecordForAccount'),
      emailOtpCoordinator.indexOf('private buildEd25519RecordFromSealedRestoreMetadata'),
    );

    expect(exactEcdsaRestoreBody).toContain('args.record');
    expect(exactEcdsaRestoreBody).toContain('args.purpose');
    expect(exactEcdsaRestoreBody).not.toContain(
      'tryRestoreEcdsaWarmSessionStatusFromSealedRecord',
    );
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
    expect(nearSigning).toContain('prepareTransactionSigningOperation');
    expect(nearSigning).toContain('prepareNearEd25519TransactionSigningSession');
    expect(nearSigning).toContain('PreparedNearEd25519TransactionSigningSession');
    expect(signingEngine.indexOf('restoreEmailOtpEcdsaSessionForExportBestEffort')).toBeLessThan(
      signingEngine.indexOf('resolveEmailOtpEcdsaExportTargetFromLocalMetadata'),
    );
  });

  test('NEAR Ed25519 finalization syncs already-consumed threshold session budget', () => {
    const transactionsFlow = readRepoSource(
      'client/src/core/signingEngine/orchestration/near/transactionsFlow.ts',
    );
    const recordSuccessBody = transactionsFlow.slice(
      transactionsFlow.indexOf('const recordSuccessfulWalletSigningSessionSpend'),
      transactionsFlow.indexOf('const recordFailedWalletSigningSessionSpend'),
    );
    const budgetFinalizerBody = transactionsFlow.slice(
      transactionsFlow.indexOf('const createNearBudgetFinalizer'),
      transactionsFlow.indexOf('const recordSuccessfulWalletSigningSessionSpend'),
    );

    expect(recordSuccessBody).toContain(
      'alreadyConsumedThresholdSessionIds: [String(operationState.lane.thresholdSessionId)]',
    );
    expect(recordSuccessBody).toContain('SignedTransactionOperation<NearEd25519TransactionLane>');
    expect(transactionsFlow).toContain('signPreparedTransactionOperation(');
    expect(transactionsFlow).toContain('finalizeSignedTransactionOperation(');
    expect(budgetFinalizerBody).toContain('operationState.budgetAdmission.budgetIdentity');
    expect(budgetFinalizerBody).not.toContain('admitBudgetForSelectedSpendLane');
    expect(recordSuccessBody).not.toContain('ed25519WarmSessionBudgetClaimed');
    expect(transactionsFlow).not.toContain('reserveWalletSigningSessionBudget');
    expect(transactionsFlow).not.toContain('await finalizer.reserve()');
    const reauthAdmissionIndex = transactionsFlow.indexOf('if (refreshedBudgetIdentityRequired) {');
    const signerRequestIndex = transactionsFlow.indexOf(
      'const signedOperation = await signPreparedTransactionOperation(',
    );
    expect(reauthAdmissionIndex).toBeGreaterThan(-1);
    expect(signerRequestIndex).toBeGreaterThan(-1);
    expect(reauthAdmissionIndex).toBeLessThan(signerRequestIndex);
  });

  test('Phase 14 keeps lifecycle decisions in the prepared operation boundary', () => {
    const preparedOperation = readRepoSource(
      'client/src/core/signingEngine/session/signingSession/preparedOperation.ts',
    );
    const nearSigning = readRepoSource('client/src/core/signingEngine/api/nearSigning.ts');
    const evmSigning = readRepoSource('client/src/core/signingEngine/api/evmSigning.ts');
    const evmSigningFlow = readRepoSource(
      'client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts',
    );
    const tempoSigningFlow = readRepoSource(
      'client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts',
    );
    const evmPreparedSigning = readRepoSource(
      'client/src/core/signingEngine/api/evmFamily/preparedSigning.ts',
    );
    const snapshotReader = readRepoSource(
      'client/src/core/signingEngine/session/snapshotReader.ts',
    );
    const restoreCoordinator = readRepoSource(
      'client/src/core/signingEngine/session/restoreCoordinator.ts',
    );
    const evmEcdsaSelection = readRepoSource(
      'client/src/core/signingEngine/api/evmFamily/ecdsaSelection.ts',
    );
    const evmAuthPlanning = readRepoSource(
      'client/src/core/signingEngine/api/evmFamily/authPlanning.ts',
    );
    const transactionsFlow = readRepoSource(
      'client/src/core/signingEngine/orchestration/near/transactionsFlow.ts',
    );
    const transactionState = readRepoSource(
      'client/src/core/signingEngine/session/signingSession/transactionState.ts',
    );
    const nearWalletAuthBody = nearSigning.slice(
      nearSigning.indexOf('async function resolveNearTransactionWalletAuth'),
      nearSigning.indexOf('function resolvePreparedSigningRequestSessionId'),
    );
    const nearEd25519RestoreBody = nearSigning.slice(
      nearSigning.indexOf('async function restoreNearEd25519SelectedSigningSession'),
      nearSigning.indexOf('async function prepareNearEd25519TransactionSigningSession'),
    );
    const evmSigningBody = evmSigning.slice(evmSigning.indexOf('async function signEvmFamilyAttempt'));

    expect(preparedOperation).toContain('prepareThresholdSigningOperation');
    expect(preparedOperation).toContain('lifecycleAdapter: ThresholdSigningLifecycleAdapter');
    expect(preparedOperation).toContain('coordinator: ThresholdSigningOperationCoordinator');
    expect(preparedOperation).not.toContain('planSigningSession');
    expect(preparedOperation).not.toContain('coordinator?:');
    expect(preparedOperation).toContain('executePreparedThresholdSigning');
    expect(preparedOperation).toContain('finalizePreparedThresholdSigning');
    expect(preparedOperation).toContain('prepared signing finalization requires a real finalizer');
    expect(preparedOperation).not.toContain('SigningSessionCoordinator');
    expect(preparedOperation).not.toContain('restoreCoordinator');
    expect(preparedOperation).not.toContain('snapshotReader');
    expect(nearSigning).toContain('prepareTransactionSigningOperation');
    expect(nearSigning).toContain('async function prepareNearEd25519TransactionOperation');
    expect(nearSigning).toContain('await prepareNearEd25519TransactionOperation({');
    expect(nearSigning).toContain('executePreparedThresholdSigning');
    expect(nearSigning).toContain('finalizePreparedThresholdSigning');
    expect(transactionsFlow).toContain(
      'threshold transaction signing requires prepared session identity',
    );
    expect(transactionsFlow).toContain(
      'threshold transaction signing requires prepared transaction operation',
    );
    expect(transactionsFlow).toContain('const budgetAdmittedOperationForWorker');
    expect(transactionsFlow).not.toContain('resolveNearThresholdSigningAuthContext');
    expect(transactionsFlow).not.toContain('buildNearThresholdSigningAuthPlan');
    expect(transactionsFlow).not.toContain('passkeySigningAuthPlan');
    expect(transactionsFlow).not.toContain('?? { signingAuthPlan');
    expect(nearSigning.indexOf('readNearEd25519SigningSnapshot')).toBeLessThan(
      nearSigning.indexOf('restoreNearEd25519SelectedSigningSession({'),
    );
    expect(snapshotReader).toContain('ed25519: {');
    expect(snapshotReader).toContain('near: SigningSessionSnapshotEd25519Lane[];');
    expect(transactionState).toContain('export type TransactionSigningIntent');
    expect(transactionState).toContain('export type TransactionLane');
    expect(transactionState).toContain('export type EvmFamilyEcdsaTransactionLane');
    expect(transactionState).toContain('function isConcreteEvmFamilyEcdsaLane');
    expect(transactionState).toContain('export type PreparedTransactionOperation');
    expect(transactionState).toContain('export type BudgetAdmittedOperation');
    expect(transactionState).toContain('export type TransactionSigningState');
    expect(transactionState).toContain("tag: 'IntentReceived'");
    expect(transactionState).toContain("tag: 'SnapshotRead'");
    expect(transactionState).toContain("tag: 'LaneSelected'");
    expect(transactionState).toContain("tag: 'ExactRestoreAttempted'");
    expect(transactionState).toContain("tag: 'ReadinessClassified'");
    expect(transactionState).toContain('export function selectTransactionLane');
    expect(transactionState).toContain('export function selectTransactionLaneFromSnapshot');
    expect(transactionState).toContain('export function recordExactRestoreAttempt');
    expect(transactionState).toContain('export function classifyTransactionReadiness');
    expect(transactionState).toContain('export function prepareTransactionOperationFromReadiness');
    expect(transactionState).toContain('export function replacePreparedTransactionLane');
    expect(transactionState).toContain('export function admitTransactionBudget');
    expect(transactionState).toContain('export function recordTransactionBudgetAdmission');
    expect(transactionState).toContain('function isConcreteNearEd25519Lane');
    expect(transactionState).toContain("kind: 'current_lane'");
    expect(transactionState).toContain("kind: 'account_class'");
    expect(transactionState).not.toContain('last_used');
    expect(transactionState).not.toContain('require_user_choice');
    expect(nearSigning).toContain('selectNearEd25519TransactionCandidate');
    expect(nearSigning).toContain('discardInvalidNearEd25519RuntimeHint');
    expect(nearSigning).toContain('clearStoredThresholdEd25519SessionRecordForAccount');
    expect(nearSigning).toContain('const transactionOperation = preparedTransaction.transactionOperation');
    expect(nearSigning).toContain('budgetAdmittedOperation');
    expect(transactionsFlow).toContain('activeBudgetAdmittedOperation');
    expect(nearSigning).toContain('replacePreparedTransactionLane(');
    expect(transactionsFlow).toContain('budgetAdmission.budgetIdentity');
    expect(transactionsFlow).toContain(
      'const signedOperation = await signPreparedTransactionOperation(',
    );
    expect(nearSigning).toContain('resolveNearEd25519AuthSelectionPolicy');
    expect(nearSigning).toContain("if (args.record?.source === 'email_otp')");
    expect(nearSigning).toContain("kind: 'account_class'");
    expect(nearSigning).toContain('authMethod: selected');
    expect(nearSigning).toContain('if (args.record) {');
    expect(
      nearSigning.indexOf("if (args.record?.source === 'email_otp')"),
    ).toBeLessThan(nearSigning.indexOf('resolveAccountAuthMethodForSigning?.({'));
    expect(
      nearSigning.indexOf('if (args.record) {'),
    ).toBeGreaterThan(nearSigning.indexOf('resolveAccountAuthMethodForSigning?.({'));
    expect(nearSigning).toContain('receiveTransactionIntent({');
    expect(nearSigning).toContain('recordTransactionSnapshot(intentState');
    expect(nearSigning).toContain('selectTransactionLaneFromSnapshot(snapshotState)');
    expect(nearSigning).not.toContain('selectTransactionLane({');
    expect(nearEd25519RestoreBody).toContain('authMethod: identity.authMethod');
    expect(nearEd25519RestoreBody).toContain('walletSigningSessionId: identity.walletSigningSessionId');
    expect(nearEd25519RestoreBody).toContain('thresholdSessionId: identity.thresholdSessionId');
    expect(nearSigning).not.toContain('resolveNearEd25519PreferredAuthMethod');
    expect(nearSigning).not.toContain('restoreNearEd25519SigningSessionBeforeSelection');
    expect(nearEd25519RestoreBody).not.toContain("['email_otp', 'passkey']");
    expect(nearEd25519RestoreBody).not.toContain('preferredAuthMethod');
    expect(nearWalletAuthBody).not.toContain('prepareThresholdSigningOperation');
    expect(nearWalletAuthBody).not.toContain('resolveNearTransactionPlannerReadiness');
    expect(evmSigning).toContain('executePreparedThresholdSigning');
    expect(evmSigning).toContain('finalizePreparedThresholdSigning');
    expect(evmSigning).toContain('deferSuccessfulSigningSessionFinalization: Boolean');
    expect(evmSigning).toContain('deferFailedSigningSessionFinalization: Boolean');
    expect(evmSigning).toContain('freshAuthRetryHandledFinalization');
    expect(evmSigning).not.toContain('() => {}');
    expect(evmSigningBody).not.toContain('resolveEvmFamilyEcdsaPlannerReadiness');
    expect(evmSigningBody).not.toContain('restorePersistedSessionForSigning(');
    for (const lowerFlow of [evmSigningFlow, tempoSigningFlow]) {
      expect(lowerFlow).toContain("args.request.senderSignatureAlgorithm === 'secp256k1'");
      expect(lowerFlow).toContain('threshold ECDSA transaction signing requires a prepared signing auth plan');
      expect(lowerFlow).toContain('if (hasThresholdEcdsaRequest && !args.signingAuthPlan)');
      expect(lowerFlow).not.toContain('needsWebAuthn: !args.signingAuthPlan && !emailOtpPrompt');
    }
    expect(evmPreparedSigning).toContain('prepareTransactionSigningOperation');
    expect(evmPreparedSigning).toContain('lifecycleAdapter');
    expect(evmPreparedSigning).toContain('selectTransactionLane');
    expect(evmPreparedSigning).toContain('assertSelectionMatchesSnapshotCandidate');
    expect(evmPreparedSigning).toContain('authMethod,');
    expect(evmEcdsaSelection).toContain('authMethod: typeof SIGNER_AUTH_METHODS.emailOtp');
    expect(evmEcdsaSelection).not.toContain('authMethod?:');
    expect(evmPreparedSigning.indexOf('readSigningSessionSnapshotForSigning')).toBeLessThan(
      evmPreparedSigning.indexOf('restorePersistedSessionForSigning({'),
    );
    expect(evmPreparedSigning).toContain(
      'transaction restore requires an exact snapshot lane',
    );
    expect(evmPreparedSigning).toContain("reason: 'selected_snapshot_candidate_ready'");
    expect(evmPreparedSigning).not.toContain("reason: 'no_exact_snapshot_candidate'");
    expect(evmPreparedSigning).not.toContain('let lane selection prove the runtime identity');
    expect(evmPreparedSigning).toContain('walletSigningSessionId,');
    expect(evmPreparedSigning).toContain('thresholdSessionId,');
    expect(evmPreparedSigning).not.toContain("(['email_otp', 'passkey'] as const).map");
    expect(restoreCoordinator).toContain('type RestorePersistedSessionForSigningTransactionInput');
    expect(restoreCoordinator).toContain('walletSigningSessionId: string;');
    expect(restoreCoordinator).toContain('thresholdSessionId: string;');
    expect(restoreCoordinator).toContain("reason: 'transaction';");
    expect(evmAuthPlanning).toContain('preparedOperation: PreparedThresholdSigningOperation');
    expect(evmAuthPlanning).toContain('const preparedEcdsaLane');
    expect(evmAuthPlanning).not.toContain('ecdsaSigningLane: ResolvedEvmFamilyEcdsaSigningLane');
    expect(evmAuthPlanning).not.toContain('ecdsaAuthMethod:');
    expect(evmAuthPlanning).not.toContain('ecdsaWarmRecord');
    expect(evmAuthPlanning).not.toContain('ecdsaWarmKeyRef');
    expect(evmAuthPlanning).not.toContain('.resolveAuthPlanFromReadiness(');
    expect(nearSigning).not.toContain('.resolveAuthPlanFromReadiness(');
  });

  test('transaction step-up sessions mint with operation capacity, not warm-session defaults', () => {
    const nearSigning = readRepoSource('client/src/core/signingEngine/api/nearSigning.ts');
    const signingFlowRuntime = readRepoSource(
      'client/src/core/signingEngine/api/evmFamily/signingFlowRuntime.ts',
    );
    const ecdsaReadiness = readRepoSource(
      'client/src/core/signingEngine/api/evmFamily/ecdsaReadiness.ts',
    );
    const ecdsaProvisioner = readRepoSource(
      'client/src/core/signingEngine/session/warmSigning/ecdsaProvisioner.ts',
    );

    expect(nearSigning).toContain('resolveTransactionStepUpSessionUses');
    expect(nearSigning).toContain('remainingUses: sessionBudgetUses');
    expect(nearSigning).not.toContain('resolveSigningSessionBudgetUses');
    expect(nearSigning).not.toContain('getSigningSessionBudgetUses');
    expect(signingFlowRuntime).toContain('resolveTransactionStepUpSessionUses');
    expect(signingFlowRuntime).not.toContain('resolveConfiguredSigningSessionBudgetUses');
    expect(signingFlowRuntime).toContain('sessionBudgetUses: resolveTransactionStepUpSessionUses');
    const genericEcdsaReconnectStart = signingFlowRuntime.indexOf(
      'ensureThresholdEcdsaKeyRefReady: async () =>',
    );
    const genericEcdsaReconnectBody = signingFlowRuntime.slice(
      genericEcdsaReconnectStart,
      signingFlowRuntime.indexOf(
        'args.setThresholdEcdsaKeyRef(readyKeyRef);',
        genericEcdsaReconnectStart,
      ),
    );
    expect(genericEcdsaReconnectBody).toContain('operationUsesNeeded: 1');
    expect(genericEcdsaReconnectBody).toContain(
      'sessionBudgetUses: resolveTransactionStepUpSessionUses',
    );
    expect(genericEcdsaReconnectBody).not.toContain('resolveConfiguredSigningSessionBudgetUses');
    expect(ecdsaProvisioner).not.toContain('args.sessionBudgetUses ?? args.usesNeeded');
    expect(ecdsaProvisioner).not.toContain('sessionBudgetUses?: number');
    expect(ecdsaReadiness).toContain('operationUsesNeeded?: number');
    expect(ecdsaReadiness).toContain('sessionBudgetUses: number');
    expect(ecdsaReadiness).toContain('usesNeeded: operationUsesNeeded');
    expect(ecdsaReadiness).toContain('sessionBudgetUses,');
    expect(ecdsaProvisioner).toContain('sessionBudgetUses: number');
    expect(ecdsaProvisioner).toContain('remainingUses: reconnectUses');
  });

  test('NEAR Ed25519 reauth carries refreshed budget auth through finalization', () => {
    const transactionsFlow = readRepoSource(
      'client/src/core/signingEngine/orchestration/near/transactionsFlow.ts',
    );
    const signingEngine = readRepoSource('client/src/core/signingEngine/SigningEngine.ts');
    const budgetFinalizer = readRepoSource(
      'client/src/core/signingEngine/session/signingSession/budgetFinalizer.ts',
    );

    expect(transactionsFlow).toContain('budgetStatusAuthFromEd25519SessionState');
    expect(transactionsFlow).toContain('trustedStatusAuth: trustedBudgetStatusAuth');
    expect(budgetFinalizer).toContain('trustedStatusAuth?: SigningSessionBudgetStatusAuth');
    expect(budgetFinalizer).toContain('trustedStatusAuth: args.trustedStatusAuth');
    expect(signingEngine).toContain('trustedStatusAuth: args.trustedStatusAuth');
    expect(signingEngine).toContain('const trustedStatusAuth = args.trustedStatusAuth');
    expect(signingEngine.indexOf('const trustedStatusAuth = args.trustedStatusAuth')).toBeLessThan(
      signingEngine.indexOf('this.resolveWalletSigningBudgetStatusAuth({'),
    );
  });
});
