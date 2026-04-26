import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function collectRepoFiles(relativeRoot: string): string[] {
  const root = path.join(repoRoot, relativeRoot);
  const files: string[] = [];
  const visit = (absolutePath: string): void => {
    for (const entry of fs.readdirSync(absolutePath, { withFileTypes: true })) {
      const child = path.join(absolutePath, entry.name);
      if (entry.isDirectory()) {
        visit(child);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!/\.(ts|tsx)$/.test(entry.name)) continue;
      files.push(path.relative(repoRoot, child));
    }
  };
  visit(root);
  return files.sort();
}

test.describe('NonceCoordinator boundary guard', () => {
  test('transaction signing paths do not bypass coordinator with direct nonce backend ownership', () => {
    const guardedFiles = [
      'client/src/core/TatchiPasskey/near/actions.ts',
      'client/src/core/signingEngine/orchestration/near/transactionsFlow.ts',
      'client/src/core/signingEngine/orchestration/near/delegateFlow.ts',
      'client/src/core/signingEngine/orchestration/near/nep413Flow.ts',
      'client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts',
      'client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts',
      'client/src/core/signingEngine/touchConfirm/handlers/flows/adapters/adapters.ts',
      'client/src/core/signingEngine/api/evmFamily/evmNonceLifecycle.ts',
      'client/src/core/signingEngine/api/evmFamily/tempoNonceLifecycle.ts',
      'client/src/core/signingEngine/api/evmFamily/nonceLifecycleAdapter.ts',
      'client/src/core/signingEngine/api/evmFamily/transactionExecutor.ts',
    ];
    const forbiddenTokens = [
      '.getNearNonceBackend()',
      ['ctx.near', 'NonceBackend.'].join(''),
      'context.signingEngine.getNearNonceBackend()',
      'createEvmNonceBackend',
      'EvmNonceBackend',
      'reserveNextNonce(',
      'reserveNonces(',
      'releaseNonce(',
      'releaseAllNonces(',
      'updateNonceFromBlockchain(',
      'initializeUser(',
    ];

    const violations: string[] = [];
    for (const relativePath of guardedFiles) {
      const source = readRepoFile(relativePath);
      for (const token of forbiddenTokens) {
        if (source.includes(token)) {
          violations.push(`${relativePath} contains ${token}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('EVM nonce manager surface has been replaced by backend terminology', () => {
    const files = collectRepoFiles('client/src')
      .concat(collectRepoFiles('tests/unit'))
      .filter((relativePath) => relativePath !== 'tests/unit/nonceCoordinator.boundary.guard.unit.test.ts');
    const violations: string[] = [];
    const forbiddenManagerTokens = [
      ['EvmNonce', 'Manager'].join(''),
      ['createEvmNonce', 'Manager'].join(''),
      ['evmNonce', 'Manager'].join(''),
      ['rpcClients/evm/nonce', 'Manager'].join(''),
    ];
    for (const relativePath of files) {
      const source = readRepoFile(relativePath);
      for (const token of forbiddenManagerTokens) {
        if (source.includes(token)) {
          violations.push(`${relativePath} contains ${token}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('NEAR access-key nonce surface has been replaced by backend terminology', () => {
    const files = collectRepoFiles('client/src')
      .concat(collectRepoFiles('tests/unit'))
      .filter(
        (relativePath) =>
          relativePath !== 'tests/unit/nonceCoordinator.boundary.guard.unit.test.ts',
      );
    const violations: string[] = [];
    const forbiddenNearManagerTokens = [
      ['Nonce', 'Manager'].join(''),
      ['nonce', 'Manager'].join(''),
      ['getNonce', 'Manager'].join(''),
      ['rpcClients/near/nonce', 'Manager'].join(''),
    ];
    for (const relativePath of files) {
      const source = readRepoFile(relativePath);
      for (const token of forbiddenNearManagerTokens) {
        if (source.includes(token)) {
          violations.push(`${relativePath} contains ${token}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('only bootstrap and coordinator construct or hold EVM nonce backend ports', () => {
    const allowedFiles = new Set([
      'client/src/core/rpcClients/evm/nonceBackend.ts',
      'client/src/core/signingEngine/bootstrap/managerAssembly.ts',
      'client/src/core/signingEngine/nonce/NonceCoordinator.ts',
    ]);
    const violations: string[] = [];
    for (const relativePath of collectRepoFiles('client/src')) {
      if (allowedFiles.has(relativePath)) continue;
      const source = readRepoFile(relativePath);
      if (source.includes('createEvmNonceBackend') || source.includes('EvmNonceBackend')) {
        violations.push(relativePath);
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('EVM nonce backend is a fetch-only port with no lane state machine', () => {
    const source = readRepoFile('client/src/core/rpcClients/evm/nonceBackend.ts');
    const forbiddenTokens = [
      'reserveNextNonce',
      'markBroadcastAccepted',
      'markBroadcastRejected',
      'markFinalized',
      'markDroppedOrReplaced',
      'reconcileLane',
      'class InMemoryEvmNonceBackend',
    ];
    const violations = forbiddenTokens.filter((token) => source.includes(token));

    expect(source).toContain('fetchChainNonce(input: ReserveNonceInput): Promise<bigint>;');
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('NonceCoordinator owns same-origin EVM lease coordination', () => {
    const source = readRepoFile('client/src/core/signingEngine/nonce/NonceCoordinator.ts');

    expect(source).toContain('createDefaultSameOriginLock');
    expect(source).toContain('createDefaultSameOriginLeaseStore');
    expect(source).toContain('maybeNavigator.navigator?.locks');
    expect(source).toContain('SAME_ORIGIN_EVM_LEASE_STORAGE_KEY');
  });

  test('EVM-family lifecycle transitions are owned by the coordinator adapter boundary', () => {
    const allowedFiles = new Set([
      'client/src/core/signingEngine/api/evmFamily/nonceLifecycleAdapter.ts',
      'client/src/core/signingEngine/nonce/NonceCoordinator.ts',
    ]);
    const guardedRoots = [
      'client/src/core/signingEngine/api/evmFamily',
      'client/src/core/signingEngine/orchestration/evm',
      'client/src/core/signingEngine/orchestration/tempo',
    ];
    const forbiddenTokens = [
      '.markBroadcastAccepted(',
      '.markBroadcastRejected(',
      '.markFinalized(',
      '.markDroppedOrReplaced(',
      '.reconcile({ lane:',
    ];
    const violations: string[] = [];

    for (const relativePath of guardedRoots.flatMap((root) => collectRepoFiles(root))) {
      if (allowedFiles.has(relativePath)) continue;
      const source = readRepoFile(relativePath);
      for (const token of forbiddenTokens) {
        if (source.includes(token)) {
          violations.push(`${relativePath} contains ${token}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('nonce leases and wallet-session budget use the same signing operation context', () => {
    const nonceCoordinatorSource = readRepoFile(
      'client/src/core/signingEngine/nonce/NonceCoordinator.ts',
    );
    expect(nonceCoordinatorSource).toContain(
      'export type NonceOperationContext = SigningOperationContext & {',
    );

    const budgetSpendingSource = readRepoFile(
      'client/src/core/signingEngine/api/evmFamily/budgetSpending.ts',
    );
    expect(budgetSpendingSource).toContain(
      'operation: EvmFamilyTransactionSigningOperationContext;',
    );
    expect(budgetSpendingSource).not.toContain('confirmationOperationId:');
    expect(budgetSpendingSource).not.toContain('operationId: args.confirmationOperationId');
  });

  test('signing-session coordinator and budget modules stay nonce-agnostic', () => {
    const guardedRoots = [
      'client/src/core/signingEngine/session',
      'client/src/core/signingEngine/api/thresholdLifecycle',
      'client/src/core/signingEngine/threshold',
    ];
    const guardedFiles = guardedRoots
      .flatMap((root) => collectRepoFiles(root))
      .concat(['client/src/core/signingEngine/api/evmFamily/signingSessionCoordinator.ts']);
    const forbiddenTokens = [
      'NonceCoordinator',
      'NonceLane',
      'NonceLease',
      'nonceCoordinator',
      'EvmNonceBackend',
      'ReserveNonceInput',
      'ManagedNonceReservation',
      'createEvmNonceBackend',
      'rpcClients/evm/nonceBackend',
      'reserveNearContext(',
      'reserveBatch(',
      'evmNonceLeaseToManagedReservation',
      'evmManagedReservationToLane',
    ];
    const violations: string[] = [];

    for (const relativePath of guardedFiles) {
      const source = readRepoFile(relativePath);
      for (const token of forbiddenTokens) {
        if (source.includes(token)) {
          violations.push(`${relativePath} contains ${token}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('NEAR access-key nonce state is coordinator-owned', () => {
    const forbiddenNearBackendTokens = [
      ['NearAccessKey', 'NonceBackend'].join(''),
      ['near', 'NonceBackend'].join(''),
      ['rpcClients/near/nonce', 'Backend'].join(''),
    ];
    const violations: string[] = [];
    for (const relativePath of collectRepoFiles('client/src')) {
      const source = readRepoFile(relativePath);
      for (const token of forbiddenNearBackendTokens) {
        if (source.includes(token)) {
          violations.push(`${relativePath} contains ${token}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });
});
