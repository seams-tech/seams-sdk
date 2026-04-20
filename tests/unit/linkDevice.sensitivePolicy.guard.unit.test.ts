import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

test.describe('link-device sensitive-operation policy guard', () => {
  test('Device1 add-key authorization requires fresh same-method auth', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const rpcCallsPath = path.join(repoRoot, 'client/src/core/rpcClients/near/rpcCalls.ts');
    const content = fs.readFileSync(rpcCallsPath, 'utf8');

    expect(content).toContain('SENSITIVE_OPERATION_POLICIES.requireFreshSameMethod');
    expect(content).toContain('sensitivePolicy: SENSITIVE_OPERATION_POLICIES.requireFreshSameMethod');
  });

  test('link-device and add-signer code does not touch transaction sealed-refresh storage', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const guardedFiles = [
      'client/src/core/TatchiPasskey/near/linkDevice.ts',
      'client/src/core/TatchiPasskey/scanDevice.ts',
      'client/src/core/TatchiPasskey/near/linkDevicePreparedEcdsa.ts',
      'client/src/core/TatchiPasskey/near/linkDeviceOwnerManagement.ts',
      'client/src/core/TatchiPasskey/evm/linkDeviceThresholdEcdsa.ts',
      'client/src/core/indexedDB/passkeyClientDB/manager.ts',
      'client/src/core/indexedDB/unifiedIndexedDBManager.ts',
    ];
    const forbidden = [
      'signingSessionSealedStore',
      'writeSigningSessionSealedRecord',
      'updateSigningSessionSealedRecordPolicy',
      'deleteSigningSessionSealedRecord',
      'apply-server-seal',
      'remove-server-seal',
      'sealEmailOtpWarmSessionMaterial',
      'rehydrateEmailOtpEcdsaWarmSessionMaterial',
    ];

    const violations: string[] = [];
    for (const relativePath of guardedFiles) {
      const content = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
      for (const needle of forbidden) {
        if (content.includes(needle)) {
          violations.push(`${relativePath} contains ${needle}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });
});
