import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function readConfiguredTransactionExecutor(): string {
  const source = readSource(
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/transactionExecutor.ts',
  );
  const functionStart = source.indexOf(
    'async function executeConfiguredEvmFamilyTransactionSigning',
  );
  const nextFunctionStart = source.indexOf(
    '\nexport async function executeEvmFamilyTransactionSigning',
    functionStart,
  );
  expect(functionStart).toBeGreaterThanOrEqual(0);
  expect(nextFunctionStart).toBeGreaterThan(functionStart);
  return source.slice(functionStart, nextFunctionStart);
}

test.describe('page-refresh EVM-family nonce recovery guard', () => {
  test('awaits wallet-scoped durable recovery before transaction signing can reserve a nonce', () => {
    const source = readConfiguredTransactionExecutor();
    const recoveryIndex = source.indexOf(
      'await args.deps.nonceCoordinator.recoverDurableLeases({ walletId: args.walletId });',
    );
    const signingIndex = source.indexOf('const result = await signWithUiConfirm({');

    expect(recoveryIndex).toBeGreaterThanOrEqual(0);
    expect(signingIndex).toBeGreaterThan(recoveryIndex);
  });

  test('keeps the fire-and-forget startup path deleted', () => {
    const source = readSource('packages/sdk-web/src/core/signingEngine/assembly/createManagers.ts');
    expect(source).not.toContain('void nonceCoordinator.recoverDurableLeases()');
  });

  test('preserves accepted broadcasts during generic IndexedDB expiry pruning', () => {
    const source = readSource('packages/sdk-web/src/core/indexedDB/seamsWalletDB/repositories.ts');
    const pruneStart = source.indexOf('async pruneExpiredNonceLaneLeaseRecords(');
    const pruneEnd = source.indexOf('\n  async withNonceLaneCoordinationLock', pruneStart);
    expect(pruneStart).toBeGreaterThanOrEqual(0);
    expect(pruneEnd).toBeGreaterThan(pruneStart);

    const pruneSource = source.slice(pruneStart, pruneEnd);
    expect(pruneSource).toContain("parsed.state !== 'broadcast_accepted'");
  });
});
