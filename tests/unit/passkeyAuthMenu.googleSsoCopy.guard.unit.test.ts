import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

function readRepoFile(relativePath: string): string {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test.describe('PasskeyAuthMenu Google SSO copy guard', () => {
  test('distinguishes passkey username input from Google SSO account mapping', () => {
    const content = readRepoFile('client/src/react/components/PasskeyAuthMenu/client.tsx');

    expect(content.includes('googleAccountNameNote')).toBe(true);
    expect(content.includes('The username above is only for Passkey.')).toBe(true);
    expect(content.includes('Google SSO creates the wallet from your Google email.')).toBe(true);
    expect(content.includes('Google SSO finds your Email OTP wallet from your Google account.')).toBe(
      true,
    );
  });
});
