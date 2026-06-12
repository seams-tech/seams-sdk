import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const AUTH_NEUTRAL_DOCS = [
  'apps/docs/src/concepts/security-model.md',
  'apps/docs/src/concepts/threshold-signing.md',
  'docs/otp/email-otp.md',
  'docs/signing-session-architecture/sealed-refresh.md',
  'docs/hss-threshold-ed25519.md',
  'docs/hss-export-key.md',
  'docs/cloudflare-signing-worker-self-host.md',
  'docs/refactor-62-hss-prepare-preauth.md',
] as const;

const FORBIDDEN_AUTH_NEUTRAL_TERMS = [
  { label: 'passkey PRF', pattern: /passkey PRF/i },
  { label: 'passkey-derived', pattern: /passkey-derived/i },
  { label: 'PRF-specific', pattern: /PRF-specific/i },
  { label: 'PRF-only', pattern: /PRF-only/i },
  { label: 'raw passkey', pattern: /raw passkey/i },
  { label: 'passkey signing-session secret', pattern: /passkey signing-session secret/i },
] as const;

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test.describe('auth secret terminology guards', () => {
  test('auth-neutral docs use factor-derived terminology', () => {
    const offenders = AUTH_NEUTRAL_DOCS.flatMap((relativePath) => {
      const source = readRepoFile(relativePath);
      return FORBIDDEN_AUTH_NEUTRAL_TERMS.filter(({ pattern }) => pattern.test(source)).map(
        ({ label }) => `${relativePath}: ${label}`,
      );
    });

    expect(offenders).toEqual([]);
  });
});
