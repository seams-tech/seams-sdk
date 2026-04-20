import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

function readRepoFile(relativePath: string): string {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test.describe('PasskeyAuthMenu Google SSO copy guard', () => {
  test('does not render login-mode Google SSO helper copy', () => {
    const content = readRepoFile('client/src/react/components/PasskeyAuthMenu/client.tsx');
    const socialCopy = readRepoFile('client/src/react/components/PasskeyAuthMenu/socialCopy.ts');

    expect(content.includes('googleAccountNameNote')).toBe(false);
    expect(socialCopy).toContain("return '';");
  });
});
