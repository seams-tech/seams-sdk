import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listSourceFiles(relativeDir: string): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  return fs.readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) return listSourceFiles(relativePath);
    return /\.(ts|tsx)$/.test(entry.name) ? [relativePath] : [];
  });
}

test.describe('nonce coordinator durable architecture guards', () => {
  test('NonceCoordinator does not own a localStorage durable lease mirror', () => {
    const source = readRepoSource('client/src/core/signingEngine/nonce/NonceCoordinator.ts');

    expect(source).not.toContain('localStorage');
    expect(source).not.toContain('seams:nonce-coordinator:v1:evm-leases');
    expect(source).not.toContain('createDefaultSameOriginLeaseStore');
    expect(source).not.toContain('sameOriginLeaseStore');
  });

  test('durable nonce leases live in the canonical seams wallet schema', () => {
    const schemaNames = readRepoSource('client/src/core/indexedDB/schemaNames.ts');
    const repositories = readRepoSource('client/src/core/indexedDB/seamsWalletDB/repositories.ts');
    const managerAssembly = readRepoSource(
      'client/src/core/signingEngine/assembly/createManagers.ts',
    );
    const store = readRepoSource('client/src/core/indexedDB/nonceLaneCoordinationStore.ts');

    expect(schemaNames).toContain("nonceLaneLeases: 'nonce_lane_leases'");
    expect(schemaNames).toContain("nonceLaneLocks: 'nonce_lane_locks'");
    expect(repositories).toContain('SeamsWalletRepositories');
    expect(repositories).toContain('readNonceLaneLeaseRecords');
    expect(schemaNames).not.toContain('nonceLaneLeasesV1');
    expect(schemaNames).not.toContain('nonceLaneLocksV1');
    expect(store).toContain('UnifiedIndexedDBManager');
    expect(store).not.toContain('indexedDB.open');
    expect(store).not.toContain('localStorage');
    expect(managerAssembly).toContain('createIndexedDBNonceLaneCoordinationStore');
    expect(managerAssembly).toContain('nonceLaneCoordinationStore');
  });

  test('transaction signing flows do not import durable nonce storage directly', () => {
    const transactionFiles = [
      'client/src/core/signingEngine/flows/signEvmFamily/transactionExecutor.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/signEvmWithUiConfirm.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/signTempoWithUiConfirm.ts',
      'client/src/core/signingEngine/flows/signNear/signTransactions.ts',
      'client/src/core/signingEngine/flows/signNear/signNear.ts',
    ];

    for (const relativePath of transactionFiles) {
      const source = readRepoSource(relativePath);
      expect(source, relativePath).not.toContain('NonceLaneCoordinationStore');
      expect(source, relativePath).not.toContain('nonceLaneCoordinationStore');
      expect(source, relativePath).not.toContain('nonceLaneLeasesV1');
      expect(source, relativePath).not.toContain('nonceLaneLocksV1');
    }
  });

  test('app and transaction code import nonce helpers only through the coordinator facade', () => {
    const splitImplementationModules = [
      'evmNonceLane',
      'nearNonceLane',
      'nonceDiagnostics',
      'nonceLaneKeys',
      'nonceLeaseState',
      'nonceTypes',
      'nonceUtils',
    ];
    const allowedCallers = new Set(['client/src/core/signingEngine/nonce/NonceCoordinator.ts']);
    const offenders = listSourceFiles('client/src')
      .filter((relativePath) => !relativePath.startsWith('client/src/core/signingEngine/nonce/'))
      .filter((relativePath) => !allowedCallers.has(relativePath))
      .filter((relativePath) => {
        const source = readRepoSource(relativePath);
        return splitImplementationModules.some(
          (moduleName) =>
            source.includes(`/nonce/${moduleName}`) ||
            source.includes(`./${moduleName}`) ||
            source.includes(`../nonce/${moduleName}`),
        );
      });

    expect(offenders).toEqual([]);
  });

  test('nonce internals do not import signing-session restore, lane resolution, or budget mutation', () => {
    const forbiddenImports = [
      'session/restoreCoordinator',
      'session/availableSigningLanes',
      'session/budget/budget',
      'session/budget/BudgetCoordinator',
      'session/identity/laneResolution',
      'sealedSessionStore',
      'restoreCoordinator',
      'availableSigningLanes',
      'WalletSigningBudget',
      'consumeWalletSigningSession',
    ];
    const offenders = listSourceFiles('client/src/core/signingEngine/nonce').filter(
      (relativePath) => {
        const source = readRepoSource(relativePath);
        return forbiddenImports.some((forbiddenImport) => source.includes(forbiddenImport));
      },
    );

    expect(offenders).toEqual([]);
  });

  test('nonce internals use encoded lane keys and keep raw EVM-family chain strings at boundaries', () => {
    const rawLaneKeyOffenders = listSourceFiles('client/src/core/signingEngine/nonce').filter(
      (relativePath) => {
        const source = readRepoSource(relativePath);
        return source.includes(".join(':')") || source.includes('.join(":")');
      },
    );
    expect(rawLaneKeyOffenders).toEqual([]);

    const rawChainBranchOffenders = listSourceFiles('client/src/core/signingEngine/nonce')
      .filter(
        (relativePath) =>
          !relativePath.endsWith('.typecheck.ts') &&
          relativePath !== 'client/src/core/signingEngine/nonce/nonceLaneKeys.ts' &&
          relativePath !== 'client/src/core/signingEngine/nonce/nonceTypes.ts',
      )
      .filter((relativePath) => {
        const source = readRepoSource(relativePath);
        return (
          source.includes("chain === 'evm'") ||
          source.includes("chain === 'tempo'") ||
          source.includes("chain: 'evm'") ||
          source.includes("chain: 'tempo'")
        );
      });

    expect(rawChainBranchOffenders).toEqual([]);
  });

  test('nonce lane-key helpers stay pure and leave durable parsing at boundaries', () => {
    const laneKeys = readRepoSource('client/src/core/signingEngine/nonce/nonceLaneKeys.ts');

    expect(laneKeys).not.toContain('normalizeRequiredString');
    expect(laneKeys).not.toContain('normalizeBigint');
    expect(laneKeys).not.toContain('NonceLaneCoordinationRecord');
    expect(laneKeys).not.toContain('nonceLaneFromCoordinationRecord');
    expect(laneKeys).not.toContain('legacyNonceLaneKeys');
  });

  test('legacy nonce lane-key support is removed from nonce internals', () => {
    const sourceOffenders = listSourceFiles('client/src/core/signingEngine/nonce').filter(
      (relativePath) => readRepoSource(relativePath).includes('legacyNonceLaneKeys'),
    );

    expect(sourceOffenders).toEqual([]);
  });

  test('transaction flows do not import nonce durable boundary parsers', () => {
    const transactionFiles = [
      'client/src/core/signingEngine/flows/signEvmFamily/transactionExecutor.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/signEvmWithUiConfirm.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/signTempoWithUiConfirm.ts',
      'client/src/core/signingEngine/flows/signNear/signTransactions.ts',
      'client/src/core/signingEngine/flows/signNear/signNear.ts',
    ];

    for (const relativePath of transactionFiles) {
      const source = readRepoSource(relativePath);
      expect(source, relativePath).not.toContain('nonceCoordinationRecordBoundary');
      expect(source, relativePath).not.toContain('parseNonceLaneCoordinationRecord');
      expect(source, relativePath).not.toContain('legacyNonceLaneKeys');
    }
  });

  test('raw durable nonce parsing stays at the persistence boundary', () => {
    const allowedParserCallers = new Set([
      'client/src/core/indexedDB/nonceLaneCoordinationStore.ts',
      'client/src/core/signingEngine/nonce/nonceCoordinationRecordBoundary.ts',
    ]);
    const parserCallers = listSourceFiles('client/src')
      .filter((relativePath) => !relativePath.endsWith('.typecheck.ts'))
      .filter((relativePath) => {
        const source = readRepoSource(relativePath);
        return (
          source.includes('nonceCoordinationRecordBoundary') ||
          source.includes('parseNonceLaneCoordinationRecord') ||
          source.includes('RawNonceLaneCoordinationRecord')
        );
      })
      .filter((relativePath) => !allowedParserCallers.has(relativePath));

    expect(parserCallers).toEqual([]);
  });

  test('nonce branch helpers use concrete lease variants instead of lane intersections', () => {
    const nonceModules = [
      'client/src/core/signingEngine/nonce/NonceCoordinator.ts',
      'client/src/core/signingEngine/nonce/evmNonceLane.ts',
      'client/src/core/signingEngine/nonce/nearNonceLane.ts',
    ];

    for (const relativePath of nonceModules) {
      const source = readRepoSource(relativePath);
      expect(source, relativePath).not.toContain('NonceLease & { lane: EvmNonceLane');
      expect(source, relativePath).not.toContain('NonceLease & { lane: NearNonceLane');
      expect(source, relativePath).not.toContain('as NonceLease & { lane');
    }
  });

  test('durable nonce parser accepts persisted decimal strings instead of in-memory bigint values', () => {
    const parser = readRepoSource(
      'client/src/core/signingEngine/nonce/nonceCoordinationRecordBoundary.ts',
    );

    expect(parser).toContain("typeof value !== 'string'");
    expect(parser).not.toContain("typeof value === 'bigint'");
  });

  test('nonce operation and EVM reservation types use prepared concrete identity', () => {
    const nonceTypes = readRepoSource('client/src/core/signingEngine/nonce/nonceTypes.ts');
    const nonceBackend = readRepoSource('client/src/core/rpcClients/evm/nonceBackend.ts');

    const preparedOperationStart = nonceTypes.indexOf('export type PreparedNonceOperationContext');
    const preparedOperationEnd = nonceTypes.indexOf(
      'export type NonceLease',
      preparedOperationStart,
    );
    expect(preparedOperationStart).toBeGreaterThanOrEqual(0);
    expect(preparedOperationEnd).toBeGreaterThan(preparedOperationStart);
    const preparedOperationSource = nonceTypes.slice(preparedOperationStart, preparedOperationEnd);
    expect(preparedOperationSource).not.toContain('walletSigningSessionId');
    expect(preparedOperationSource).not.toContain('chainFamily');
    expect(nonceTypes).not.toContain('export type NonceOperationContext');

    const reserveInputStart = nonceBackend.indexOf('export type ReserveNonceInput');
    const reserveInputEnd = nonceBackend.indexOf('export type ReserveNonceBoundaryInput');
    expect(reserveInputStart).toBeGreaterThanOrEqual(0);
    expect(reserveInputEnd).toBeGreaterThan(reserveInputStart);
    const reserveInputSource = nonceBackend.slice(reserveInputStart, reserveInputEnd);
    expect(reserveInputSource).toContain('chainTarget: ThresholdEcdsaChainTarget');
    expect(reserveInputSource).toContain('subjectId: WalletId');
    expect(reserveInputSource).not.toContain('chain: EvmNonceChain');
    expect(reserveInputSource).not.toContain('walletId');

    const snapshotStart = nonceBackend.indexOf('export type ManagedNonceReservationSnapshot =');
    const snapshotEnd = nonceBackend.indexOf('export type ManagedNonceReservationSnapshotInput');
    expect(snapshotStart).toBeGreaterThanOrEqual(0);
    expect(snapshotEnd).toBeGreaterThan(snapshotStart);
    const snapshotSource = nonceBackend.slice(snapshotStart, snapshotEnd);
    expect(snapshotSource).toContain('chainTarget: ThresholdEcdsaChainTarget');
    expect(snapshotSource).toContain('subjectId: WalletId');
    expect(snapshotSource).not.toContain('chain: EvmNonceChain');
    expect(snapshotSource).not.toContain('walletId');
  });

  test('startup recovery cannot spend budget or rebroadcast raw signed transactions', () => {
    const source = readRepoSource('client/src/core/signingEngine/nonce/NonceCoordinator.ts');
    const recoveryStart = source.indexOf('const recoverDurableLeases = async');
    const recoveryEnd = source.indexOf('const reserveNearNonceBatchUnlocked = async');
    expect(recoveryStart).toBeGreaterThanOrEqual(0);
    expect(recoveryEnd).toBeGreaterThan(recoveryStart);
    const recoverySource = source.slice(recoveryStart, recoveryEnd);

    expect(recoverySource).not.toContain('WalletSigningBudget');
    expect(recoverySource).not.toContain('consumeWalletSigningSession');
    expect(recoverySource).not.toContain('sendRawTransaction');
    expect(recoverySource).not.toContain('broadcastTransaction');
    expect(recoverySource).not.toContain('submitSignedTransaction');
    expect(recoverySource).not.toContain('signedTx');
    expect(recoverySource).not.toContain('rawTransaction');
  });

  test('startup recovery is only invoked from startup or unlock boundaries', () => {
    const allowedCallers = new Set([
      'client/src/core/signingEngine/assembly/createManagers.ts',
      'client/src/core/SeamsPasskey/login.ts',
      'client/src/core/signingEngine/nonce/NonceCoordinator.ts',
      'client/src/core/signingEngine/nonce/nonceTypes.ts',
    ]);
    const callers = listSourceFiles('client/src')
      .filter((relativePath) => readRepoSource(relativePath).includes('recoverDurableLeases('))
      .filter((relativePath) => !allowedCallers.has(relativePath));

    expect(callers).toEqual([]);
  });
});
