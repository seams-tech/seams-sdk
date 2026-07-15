import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const authNeutralDocs = Object.freeze([
  'apps/docs/src/concepts/architecture.md',
  'apps/docs/src/concepts/auth-planes.md',
  'apps/docs/src/concepts/threshold-signing/index.md',
  'apps/docs/src/concepts/threshold-signing/router-ab.md',
  'apps/docs/src/concepts/threshold-signing/evm-ecdsa.md',
  'apps/docs/src/concepts/threshold-signing/blind-deterministic-derivation.md',
  'apps/docs/src/concepts/auth-methods/email-otp.md',
  'apps/docs/src/concepts/sessions/sealed-refresh.md',
  'docs/otp/email-otp.md',
  'docs/signing-session-architecture/sealed-refresh.md',
  'docs/refactor-62-hss-prepare-preauth.md',
]);

const forbiddenAuthNeutralTerms = Object.freeze([
  { label: 'passkey PRF', pattern: /passkey PRF/i },
  { label: 'passkey-derived', pattern: /passkey-derived/i },
  { label: 'PRF-specific', pattern: /PRF-specific/i },
  { label: 'PRF-only', pattern: /PRF-only/i },
  { label: 'raw passkey', pattern: /raw passkey/i },
  { label: 'passkey signing-session secret', pattern: /passkey signing-session secret/i },
]);

function readRepoFile(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function findAuthSecretTerminologyOffenders() {
  const offenders = [];
  for (const relativePath of authNeutralDocs) {
    const source = readRepoFile(relativePath);
    for (const { label, pattern } of forbiddenAuthNeutralTerms) {
      if (pattern.test(source)) offenders.push(`${relativePath}: ${label}`);
    }
  }
  return offenders;
}

const offenders = findAuthSecretTerminologyOffenders();
if (offenders.length > 0) {
  console.error('[check-auth-secret-terminology] forbidden auth-specific docs terminology:');
  for (const offender of offenders) console.error(`- ${offender}`);
  process.exitCode = 1;
} else {
  console.log('[check-auth-secret-terminology] passed');
}
