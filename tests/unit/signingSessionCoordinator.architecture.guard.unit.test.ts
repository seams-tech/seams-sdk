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

const expectedSessionLayoutFiles = [
  'client/src/core/signingEngine/session/SigningSessionCoordinator.ts',
  ...pureSigningSessionHelperFiles,
  'client/src/core/signingEngine/session/warmSigning/types.ts',
  'client/src/core/signingEngine/session/warmSigning/store.ts',
  'client/src/core/signingEngine/session/warmSigning/readModel.ts',
  'client/src/core/signingEngine/session/warmSigning/runtime.ts',
  'client/src/core/signingEngine/session/warmSigning/persistence.ts',
  'client/src/core/signingEngine/session/warmSigning/transitions.ts',
  'client/src/core/signingEngine/session/warmSigning/statusReader.ts',
  'client/src/core/signingEngine/session/warmSigning/capabilityReader.ts',
  'client/src/core/signingEngine/session/warmSigning/capabilityResolver.ts',
  'client/src/core/signingEngine/session/warmSigning/ecdsaBootstrapRequest.ts',
  'client/src/core/signingEngine/session/warmSigning/ecdsaProvisioner.ts',
  'client/src/core/signingEngine/session/warmSigning/ed25519Provisioner.ts',
  'client/src/core/signingEngine/session/warmSigning/sealedRefreshRestorer.ts',
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
      expect(source, relativePath).not.toContain('createWalletSigningBudgetLedgerState');
      expect(source, relativePath).not.toContain('createWalletSigningBudgetLedger(');
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

      expect(source, relativePath).not.toContain('createWalletSigningBudgetLedger(');
      expect(source, relativePath).not.toContain('createWalletSigningSessionCoordinator(');
    }
  });

  test('orchestration dependency bundle wires a single SigningSessionCoordinator facade', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts',
    );

    expect(source).toContain('new SigningSessionCoordinator({');
    expect(source).toContain('signingSessionCoordinator: SigningSessionCoordinator;');
    expect(source).toContain('signingSessionCoordinator,');
    expect(source).not.toContain('walletSigningBudgetLedger: SigningSessionCoordinator;');
    expect(source).not.toContain('walletSigningSessionCoordinator: SigningSessionCoordinator;');
    expect(source).not.toContain('SigningSessionBudgetPort');
    expect(source).not.toContain('walletSigningSessionCoordinator:');
    expect(source).not.toContain('createWalletSigningBudgetLedger(');
    expect(source).not.toContain('createWalletSigningSessionCoordinator(');
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
        path.join(repoRoot, 'client/src/core/signingEngine/session/WalletSigningSessionCoordinator.ts'),
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
      expect(importPath).not.toContain('WalletSigningBudgetLedger');
      expect(importPath).not.toContain('signingSession/budget');
      expect(importPath).not.toContain('SigningSessionCoordinator');
    }
  });
});
