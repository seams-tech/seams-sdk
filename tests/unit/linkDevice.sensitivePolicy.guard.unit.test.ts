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
});
