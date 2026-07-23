import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test('passkey Yao registration owners persist local material before activation', () => {
  const source = readSource(
    'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
  );
  const ownerNames = [
    'async commitPasskey(',
    'async function commitPendingPasskeyEd25519YaoRegistration(',
  ];

  for (const ownerName of ownerNames) {
    const ownerIndex = source.indexOf(ownerName);
    const persistenceIndex = source.indexOf(
      'await persistPasskeyEd25519YaoLocalMaterialV1({',
      ownerIndex,
    );
    const activationIndex = source.indexOf('await pending.commit({', ownerIndex);
    const alternateActivationIndex = source.indexOf('await args.pending.commit({', ownerIndex);
    const resolvedActivationIndex =
      activationIndex >= 0 &&
      (alternateActivationIndex < 0 || activationIndex < alternateActivationIndex)
        ? activationIndex
        : alternateActivationIndex;

    expect(ownerIndex).toBeGreaterThanOrEqual(0);
    expect(persistenceIndex).toBeGreaterThan(ownerIndex);
    expect(resolvedActivationIndex).toBeGreaterThan(persistenceIndex);
  }
});

test('passkey Yao recovery persists refresh state before publishing the active capability', () => {
  const source = readSource('packages/sdk-web/src/SeamsWeb/operations/recovery/syncAccount.ts');
  const persistenceIndex = source.indexOf('await persistPasskeyEd25519YaoSessionForRefresh({');
  const activationIndex = source.indexOf('await input.activateCapability({');

  expect(persistenceIndex).toBeGreaterThanOrEqual(0);
  expect(activationIndex).toBeGreaterThan(persistenceIndex);
});

test('Email OTP registration seals the worker-owned Yao factor after activation', () => {
  const source = readSource(
    'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
  );
  const activationIndex = source.indexOf('await args.yaoWork.commit({');
  const persistenceIndex = source.indexOf(
    'await args.context.signingEngine.persistEmailOtpEd25519YaoSessionForRefreshInternal(record);',
    activationIndex,
  );

  expect(activationIndex).toBeGreaterThanOrEqual(0);
  expect(persistenceIndex).toBeGreaterThan(activationIndex);
});

test('Email OTP login recovery replaces its durable Yao seal before returning', () => {
  const source = readSource(
    'packages/sdk-web/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts',
  );
  const methodIndex = source.indexOf('async loginWithEmailOtpEd25519YaoCapabilityInternal(');
  const recoveryIndex = source.indexOf(
    'const recovered = await recoverColdEmailOtpEd25519CapabilityForLoginV1({',
    methodIndex,
  );
  const persistenceIndex = source.indexOf(
    'await this.persistEmailOtpEd25519YaoSessionForRefreshInternal(recovered.record);',
    recoveryIndex,
  );
  const returnIndex = source.indexOf('return recovered.record;', persistenceIndex);

  expect(methodIndex).toBeGreaterThanOrEqual(0);
  expect(recoveryIndex).toBeGreaterThan(methodIndex);
  expect(persistenceIndex).toBeGreaterThan(recoveryIndex);
  expect(returnIndex).toBeGreaterThan(persistenceIndex);
});

test('Email OTP page refresh rehydrates the exact sealed Yao factor without an OTP challenge', () => {
  const source = readSource(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519YaoSealedRecovery.ts',
  );
  const methodIndex = source.indexOf(
    'export async function recoverEmailOtpEd25519YaoFromSealedSessionV1(',
  );
  const methodEndIndex = source.indexOf(
    'export async function resolveEmailOtpEd25519YaoExportContextV1(',
    methodIndex,
  );
  const methodSource = source.slice(methodIndex, methodEndIndex);
  const recordIndex = methodSource.indexOf('const sealedRecord = await resolveSealedRecord({');
  const sessionIndex = methodSource.indexOf('const session = exactLocalSessionFromSealedRecord({');
  const rehydrateIndex = methodSource.indexOf(
    'const rehydrated = await requestRehydrateEmailOtpEd25519YaoLocalMaterial({',
  );
  const activationIndex = methodSource.indexOf(
    'const recovery = await activateColdEmailOtpEd25519YaoLocalSessionV1({',
  );

  expect(methodIndex).toBeGreaterThanOrEqual(0);
  expect(methodEndIndex).toBeGreaterThan(methodIndex);
  expect(recordIndex).toBeGreaterThanOrEqual(0);
  expect(sessionIndex).toBeGreaterThan(recordIndex);
  expect(rehydrateIndex).toBeGreaterThan(sessionIndex);
  expect(activationIndex).toBeGreaterThan(rehydrateIndex);
  expect(methodSource).not.toContain('fetchWarmBootstrap');
  expect(methodSource).not.toContain('activateColdEmailOtpEd25519YaoUnlockedRecoveryV1');
  expect(methodSource).not.toContain('challengeId');
  expect(methodSource).not.toContain('otpCode');
});
