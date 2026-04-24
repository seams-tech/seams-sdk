import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

function repoRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
}

test.describe('EVM family Email OTP sealed restore guard', () => {
  test('checks planner readiness before preparing an Email OTP challenge', () => {
    const sourcePath = path.join(
      repoRoot(),
      'client/src/core/signingEngine/api/evmFamily/authPlanning.ts',
    );
    const source = fs.readFileSync(sourcePath, 'utf8');
    const readinessStart = source.indexOf('async function resolveEvmFamilyEcdsaPlannerReadiness');
    const resolverStart = source.indexOf('async function resolveEvmFamilyTransactionWalletAuth');
    const readinessCall = source.indexOf(
      'const readiness = await resolveEvmFamilyEcdsaPlannerReadiness',
      resolverStart,
    );
    const challengeStart = source.indexOf(
      'activeChallenge = await walletAuthPlan.challenge()',
      resolverStart,
    );

    expect(readinessStart).toBeGreaterThanOrEqual(0);
    expect(resolverStart).toBeGreaterThanOrEqual(0);
    expect(readinessCall).toBeGreaterThan(resolverStart);
    expect(challengeStart).toBeGreaterThan(resolverStart);
    expect(readinessCall).toBeLessThan(challengeStart);
  });

  test('surfaces sealed restore as a restoring transaction confirmation state', () => {
    const sourcePath = path.join(
      repoRoot(),
      'client/src/core/signingEngine/api/evmFamily/signingSessionCoordinator.ts',
    );
    const source = fs.readFileSync(sourcePath, 'utf8');
    const coordinatorStart = source.indexOf('function createEvmFamilySigningSessionCoordinator');
    const restoreMessage = source.indexOf('Restoring signing session...', coordinatorStart);
    const overlayIntent = source.indexOf(
      "interaction: { kind: 'transaction_confirmation', overlay: 'show' }",
      coordinatorStart,
    );

    expect(coordinatorStart).toBeGreaterThanOrEqual(0);
    expect(source).toContain('const onSealedRestore = (event: WarmSessionSealedRestoreEvent)');
    expect(source).toContain("if (event.status === 'started')");
    expect(restoreMessage).toBeGreaterThan(coordinatorStart);
    expect(overlayIntent).toBeGreaterThan(coordinatorStart);
  });
});
