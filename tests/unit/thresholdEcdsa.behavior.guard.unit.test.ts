import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

test.describe('threshold ECDSA behavior guard', () => {
  test('presign refill scheduler remains wired to secp256k1 signing path', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const secp256k1Path = path.join(
      repoRoot,
      'client/src/core/signingEngine/flows/signEvmFamily/signers/secp256k1.ts',
    );
    const secp256k1Content = fs.readFileSync(secp256k1Path, 'utf8');
    const schedulerCallCount =
      secp256k1Content.match(/scheduleThresholdEcdsaClientPresignaturePoolRefill\(/g)?.length || 0;

    expect(schedulerCallCount).toBeGreaterThanOrEqual(2);
    expect(secp256k1Content.includes("trigger: 'commit_start'")).toBe(true);
    expect(secp256k1Content.includes("trigger: 'post_sign_success'")).toBe(true);
  });

  test('ECDSA signing authorization uses role-local records only', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const servicePath = path.join(
      repoRoot,
      'server/src/core/ThresholdService/ThresholdSigningService.ts',
    );
    const source = fs.readFileSync(servicePath, 'utf8');

    expect(source).not.toContain('deriveEcdsaKeyMaterialFromPersistedBackend');
    expect(source).not.toContain('bootstrapEcdsaFromRegistrationMaterial');
    expect(source).not.toContain('getEcdsaIntegratedKeyRecordByKeyHandle');
    expect(source).toContain('getRoleLocalByKeyHandle');
    expect(source).toContain('roleLocalKey.signingRootId');
    expect(source).toContain('roleLocalKey.signingRootVersion');
    expect(source).toContain(
      'ECDSA key selector signing root does not match threshold session scope',
    );
  });
});
