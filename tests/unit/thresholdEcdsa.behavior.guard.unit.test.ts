import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

test.describe('threshold ECDSA behavior guard', () => {
  test('presign refill scheduler remains wired to secp256k1 signing path', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const secp256k1Path = path.join(
      repoRoot,
      'client/src/core/signingEngine/signers/algorithms/secp256k1.ts',
    );
    const secp256k1Content = fs.readFileSync(secp256k1Path, 'utf8');
    const schedulerCallCount =
      secp256k1Content.match(/scheduleThresholdEcdsaClientPresignaturePoolRefill\(/g)?.length || 0;

    expect(schedulerCallCount).toBeGreaterThanOrEqual(2);
    expect(secp256k1Content.includes("trigger: 'commit_start'")).toBe(true);
    expect(secp256k1Content.includes("trigger: 'post_sign_success'")).toBe(true);
  });

  test('persisted ECDSA replay validates signing-root metadata before session release', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const servicePath = path.join(
      repoRoot,
      'server/src/core/ThresholdService/ThresholdSigningService.ts',
    );
    const source = fs.readFileSync(servicePath, 'utf8');

    expect(source).toContain('private async deriveEcdsaKeyMaterialFromPersistedBackend');
    expect(source).toContain('signingRootMetadata: {');
    expect(source).toContain('signingRootId: input.integratedKey.signingRootId');
    expect(source).toContain('const expectedSigningRootMetadata = createEcdsaSigningRootMetadata(');
    expect(source).toContain('derived.value.signingRootMetadata');
    expect(source).toContain(
      "message: 'threshold_ecdsa.session_policy signing root does not match integrated key'",
    );
    expect(source).toContain(
      'ecdsaThresholdKeyId signing root does not match threshold session scope',
    );
  });
});
