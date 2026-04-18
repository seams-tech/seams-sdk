import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

const removedSlotNamePattern = new RegExp(
  ['device' + 'Number', 'Device' + 'Number', 'device_' + 'number'].join('|'),
);

test.describe('signerSlot no-legacy-surface guard', () => {
  test('generic signing and worker payload surfaces do not expose legacy slot names', () => {
    const guardedFiles = [
      'client/src/core/signingEngine/api/nearSigning.ts',
      'client/src/core/signingEngine/interfaces/near.ts',
      'client/src/core/signingEngine/orchestration/near/shared/signingMaterials.ts',
      'client/src/core/signingEngine/orchestration/near/transactionsFlow.ts',
      'client/src/core/signingEngine/orchestration/near/delegateFlow.ts',
      'client/src/core/signingEngine/orchestration/near/nep413Flow.ts',
      'client/src/core/types/secure-confirm-worker.ts',
      'client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts',
      'client/src/core/signingEngine/touchConfirm/shared/confirmTypes.ts',
      'client/src/core/signingEngine/touchConfirm/handlers/flows/registration.ts',
      'client/src/core/signingEngine/touchConfirm/handlers/flows/requestRegistrationCredentialConfirmation.ts',
      'client/src/core/signingEngine/signers/webauthn/prompt/touchIdPrompt.ts',
    ];

    const violations: string[] = [];
    for (const relativePath of guardedFiles) {
      const source = readRepoFile(relativePath);
      if (removedSlotNamePattern.test(source)) {
        violations.push(`removed-slot-name: ${relativePath}`);
      }
      if (/\bkeyMaterialSlot\b|\bKeyMaterialSlot\b/.test(source)) {
        violations.push(`keyMaterialSlot: ${relativePath}`);
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('persisted key material and profile-state schemas do not expose legacy slot names', () => {
    const guardedFiles = [
      'client/src/core/indexedDB/accountKeyMaterialDB.types.ts',
      'client/src/core/indexedDB/accountKeyMaterialDB/schema.ts',
      'client/src/core/indexedDB/accountKeyMaterialDB/manager.ts',
      'client/src/core/indexedDB/accountKeyMaterialDB/envelope.ts',
      'client/src/core/indexedDB/lastProfileState.ts',
      'client/src/core/indexedDB/passkeyClientDB.types.ts',
      'client/src/core/indexedDB/passkeyClientDB/schema.ts',
    ];

    const violations: string[] = [];
    for (const relativePath of guardedFiles) {
      const source = readRepoFile(relativePath);
      if (/\bkeyMaterialSlot\b|\bKeyMaterialSlot\b/.test(source)) {
        violations.push(`keyMaterialSlot: ${relativePath}`);
      }
      if (removedSlotNamePattern.test(source)) {
        violations.push(`removed-slot-name: ${relativePath}`);
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('wallet auth and signer metadata domains are imported from shared domain constants', () => {
    const guardedFiles = [
      'client/src/core/types/tatchi.ts',
      'client/src/core/signingEngine/auth/walletAuthModeResolver.ts',
      'client/src/core/indexedDB/passkeyClientDB.types.ts',
      'client/src/core/indexedDB/accountSignerLifecycle.ts',
    ];
    const forbidden = [
      /export type WalletAuthMethod\s*=\s*['"]passkey['"]/,
      /export type SigningSessionRetention\s*=\s*['"]session['"]/,
      /export type SignerKind\s*=\s*['"]threshold-ed25519['"]/,
      /export type SignerAuthMethod\s*=\s*['"]passkey['"]/,
      /export type SignerSource\s*=\s*['"]passkey_registration['"]/,
      /method:\s*['"]passkey['"];/,
      /method:\s*['"]email_otp['"];/,
      /primaryAuthMethod\s*===\s*['"]passkey['"]/,
      /primaryAuthMethod\s*===\s*['"]email_otp['"]/,
    ];

    const violations: string[] = [];
    for (const relativePath of guardedFiles) {
      const source = readRepoFile(relativePath);
      if (!source.includes('@shared/utils')) {
        violations.push(`missing shared domain import: ${relativePath}`);
      }
      for (const pattern of forbidden) {
        if (pattern.test(source)) {
          violations.push(`local wallet/signer domain literal: ${relativePath}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });
});
