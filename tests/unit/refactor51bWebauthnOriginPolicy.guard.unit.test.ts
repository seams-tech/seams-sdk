import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const verifierCallFiles = [
  'packages/sdk-server-ts/src/router/cloudflare/routes/auth.ts',
  'packages/sdk-server-ts/src/router/cloudflare/routes/sessions.ts',
  'packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts',
  'packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519.ts',
  'packages/sdk-server-ts/src/router/express/routes/auth.ts',
  'packages/sdk-server-ts/src/router/express/routes/sessions.ts',
  'packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts',
  'packages/sdk-server-ts/src/router/express/routes/thresholdEd25519.ts',
  'packages/sdk-server-ts/src/router/relayWalletRegistration.ts',
  'packages/sdk-server-ts/src/router/walletUnlockRouteHandlers.ts',
  'packages/sdk-server-ts/src/core/AuthService.ts',
  'packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts',
] as const;

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function findMatchingBrace(source: string, openBraceIndex: number): number {
  let depth = 0;
  let quote: '"' | "'" | '`' | null = null;
  let escaped = false;
  for (let i = openBraceIndex; i < source.length; i += 1) {
    const ch = source[i];
    if (quote) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (ch === '\\') {
        escaped = true;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      continue;
    }
    if (ch === '{') depth += 1;
    if (ch === '}') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  throw new Error(`No matching brace found at index ${openBraceIndex}`);
}

function extractVerifierCallObjects(source: string): string[] {
  const calls: string[] = [];
  const pattern = /\bverifyWebAuthn(?:AuthenticationLite|Login)\s*!?\s*\(\s*\{/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(source))) {
    const openBraceIndex = source.indexOf('{', match.index);
    const closeBraceIndex = findMatchingBrace(source, openBraceIndex);
    calls.push(source.slice(openBraceIndex, closeBraceIndex + 1));
    pattern.lastIndex = closeBraceIndex + 1;
  }
  return calls;
}

test('WebAuthn verification calls carry an expected origin policy', () => {
  const violations: string[] = [];
  for (const file of verifierCallFiles) {
    const source = readRepoFile(file);
    for (const callObject of extractVerifierCallObjects(source)) {
      if (/\bexpected_origin\b|\bexpectedOrigin\b/.test(callObject)) continue;
      violations.push(file);
    }
  }

  expect(violations, violations.join('\n')).toEqual([]);
});

test('WebAuthn verifier boundary does not infer expected origin from clientDataJSON', () => {
  const source = readRepoFile('packages/sdk-server-ts/src/core/AuthService.ts');
  expect(source).not.toMatch(/\bexpectedOrigin\s*:\s*[^,\n]*\|\|\s*clientData\.origin/);
  expect(source).not.toMatch(/\bconst\s+expectedOriginStrict\s*=\s*[^;\n]*\|\|\s*clientData\.origin/);
});
