import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function occurrenceIndexes(source: string, pattern: RegExp): number[] {
  const indexes: number[] = [];
  for (const match of source.matchAll(pattern)) {
    if (match.index !== undefined) indexes.push(match.index);
  }
  return indexes;
}

test('all passkey Yao registration branches persist refresh state before activation', () => {
  const source = readSource(
    'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
  );

  const persistenceIndexes = occurrenceIndexes(
    source,
    /await persistPasskeyEd25519YaoSessionForRefresh\(\{/g,
  );
  const activationIndexes = occurrenceIndexes(
    source,
    /await (?:args\.yaoWork|pending)\.commit\(\{ activation:/g,
  );

  expect(persistenceIndexes).toHaveLength(3);
  expect(activationIndexes).toHaveLength(3);
  for (let index = 0; index < persistenceIndexes.length; index += 1) {
    expect(persistenceIndexes[index]).toBeLessThan(activationIndexes[index]);
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
  const activationIndex = source.indexOf(
    'await args.yaoWork.commit({ activation: args.context.signingEngine, walletSessionState });',
  );
  const persistenceIndex = source.indexOf(
    'await args.context.signingEngine.persistEmailOtpEd25519YaoSessionForRefreshInternal(record);',
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
  const recordIndex = source.indexOf('const sealedRecord = await resolveSealedRecord({');
  const bootstrapIndex = source.indexOf('const bootstrapResponse = await fetchWarmBootstrap({');
  const rehydrateIndex = source.indexOf(
    'const rehydrated = await requestRehydrateEmailOtpEd25519YaoFactor({',
  );
  const activationIndex = source.indexOf(
    'const recovery = await activateColdEmailOtpEd25519YaoUnlockedRecoveryV1({',
  );

  expect(recordIndex).toBeGreaterThanOrEqual(0);
  expect(bootstrapIndex).toBeGreaterThan(recordIndex);
  expect(rehydrateIndex).toBeGreaterThan(bootstrapIndex);
  expect(activationIndex).toBeGreaterThan(rehydrateIndex);
  expect(source).not.toContain('challengeId');
  expect(source).not.toContain('otpCode');
});
