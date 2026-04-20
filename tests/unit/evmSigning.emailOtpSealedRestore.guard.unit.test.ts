import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

function repoRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
}

test.describe('EVM family Email OTP sealed restore guard', () => {
  test('tries sealed restore before falling back to Email OTP transaction reauth', () => {
    const sourcePath = path.join(repoRoot(), 'client/src/core/signingEngine/api/evmSigning.ts');
    const source = fs.readFileSync(sourcePath, 'utf8');
    const resolverStart = source.indexOf('async function resolveEvmFamilyTransactionWalletAuth');
    const challengeStart = source.indexOf('const challenge = await walletAuthPlan.challenge()');
    const restoreAttempt = source.indexOf(
      'await warmSessionManager.getWarmSession(args.nearAccountId)',
      resolverStart,
    );

    expect(resolverStart).toBeGreaterThanOrEqual(0);
    expect(challengeStart).toBeGreaterThan(resolverStart);
    expect(restoreAttempt).toBeGreaterThan(resolverStart);
    expect(restoreAttempt).toBeLessThan(challengeStart);
  });

  test('surfaces sealed restore as a restoring transaction confirmation state', () => {
    const sourcePath = path.join(repoRoot(), 'client/src/core/signingEngine/api/evmSigning.ts');
    const source = fs.readFileSync(sourcePath, 'utf8');
    const warmManagerStart = source.indexOf('function createEvmFamilyWarmSessionManager');
    const restoreMessage = source.indexOf('Restoring signing session...', warmManagerStart);
    const overlayIntent = source.indexOf(
      "interaction: { kind: 'transaction_confirmation', overlay: 'show' }",
      warmManagerStart,
    );

    expect(warmManagerStart).toBeGreaterThanOrEqual(0);
    expect(source).toContain('onSealedRestore: (event) =>');
    expect(source).toContain("if (event.status === 'started')");
    expect(restoreMessage).toBeGreaterThan(warmManagerStart);
    expect(overlayIntent).toBeGreaterThan(warmManagerStart);
  });
});
