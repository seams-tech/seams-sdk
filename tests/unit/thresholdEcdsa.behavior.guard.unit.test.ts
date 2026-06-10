import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

function listFiles(root: string, extensions: readonly string[]): string[] {
  const entries = fs.readdirSync(root, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'target' || entry.name === 'dist') return [];
      return listFiles(fullPath, extensions);
    }
    return extensions.some((extension) => entry.name.endsWith(extension)) ? [fullPath] : [];
  });
}

test.describe('threshold ECDSA behavior guard', () => {
  test('presign refill scheduler remains wired to secp256k1 signing path', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const secp256k1Path = path.join(
      repoRoot,
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signers/secp256k1.ts',
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
      'packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts',
    );
    const source = fs.readFileSync(servicePath, 'utf8');

    expect(source).not.toContain('deriveEcdsaKeyMaterialFromPersistedBackend');
    expect(source).not.toContain('bootstrapEcdsaFromRegistrationMaterial');
    expect(source).not.toContain('getEcdsaIntegratedKeyRecordByKeyHandle');
  });

  test('runtime ECDSA HSS code does not call v1 derivation surfaces', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const roots = [
      'packages/sdk-web/src',
      'packages/sdk-server-ts/src',
      'packages/shared-ts/src',
      'wasm/eth_signer/src',
      'wasm/hss_client_signer/src',
      'wasm/threshold_prf/src',
    ];
    const forbiddenTokens = [
      'EcdsaHssStableKeyContextV1',
      'encode_context_v1',
      'derive_client_share_v1',
      'derive_relayer_share_v1',
      'derive_relayer_share_for_client_public_v1',
      'public_transcript_digest_v1',
      'export_authorization_digest_v1',
      'reconstruct_export_key_v1',
    ];
    const offenders: string[] = [];

    for (const relativeRoot of roots) {
      for (const filePath of listFiles(path.join(repoRoot, relativeRoot), ['.ts', '.tsx', '.rs'])) {
        const source = fs.readFileSync(filePath, 'utf8');
        for (const token of forbiddenTokens) {
          if (source.includes(token)) {
            offenders.push(`${path.relative(repoRoot, filePath)} contains ${token}`);
          }
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('ECDSA HSS crate source has no retained old context-version API', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const crateSourceRoot = path.join(repoRoot, 'crates/ecdsa-hss/src');
    const forbiddenTokens = [
      'reference_v1',
      'ClientOutputV1',
      'EcdsaHssStableKeyContextV1',
      'PrepareEnvelopeV1',
      'derive_client_share_v1',
      'wallet_session_user_id',
      'subject_id',
      'ecdsa-hss-v1',
    ];
    const offenders: string[] = [];

    for (const filePath of listFiles(crateSourceRoot, ['.rs'])) {
      const source = fs.readFileSync(filePath, 'utf8');
      for (const token of forbiddenTokens) {
        if (source.includes(token)) {
          offenders.push(`${path.relative(repoRoot, filePath)} contains ${token}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });
});
