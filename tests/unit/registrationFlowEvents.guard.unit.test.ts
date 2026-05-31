import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

test.describe('registration flow event guards', () => {
  test('unified registration events use the resolved auth method', () => {
    const source = fs.readFileSync(
      path.join(repoRoot, 'client/src/core/SeamsPasskey/registration.ts'),
      'utf8',
    );
    expect(source).toContain('flowId: `registration:${authMethod}:${nearAccountId}`');
    expect(source).toContain('authMethod: args.authMethod.kind');
    expect(source).not.toContain('flowId: `registration:passkey:${nearAccountId}`');
  });
});
