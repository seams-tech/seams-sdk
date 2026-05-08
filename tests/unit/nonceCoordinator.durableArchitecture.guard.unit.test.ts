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

  test('durable nonce leases live in the existing PasskeyClientDB schema', () => {
    const schema = readRepoSource('client/src/core/indexedDB/passkeyClientDB/schema.ts');
    const managerAssembly = readRepoSource(
      'client/src/core/signingEngine/assembly/createManagers.ts',
    );
    const store = readRepoSource('client/src/core/indexedDB/nonceLaneCoordinationStore.ts');

    expect(schema).toContain("nonceLaneLeasesStore: 'nonceLaneLeasesV1'");
    expect(schema).toContain("nonceLaneLocksStore: 'nonceLaneLocksV1'");
    const versionMatch = schema.match(/dbVersion:\s*(\d+)/);
    expect(versionMatch?.[1]).toBeDefined();
    expect(Number(versionMatch?.[1])).toBeGreaterThanOrEqual(32);
    expect(schema).not.toContain("dbName: 'Nonce");
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
    ]);
    const callers = listSourceFiles('client/src')
      .filter((relativePath) => readRepoSource(relativePath).includes('recoverDurableLeases('))
      .filter((relativePath) => !allowedCallers.has(relativePath));

    expect(callers).toEqual([]);
  });
});
