import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const verifierCallFiles = Object.freeze([
  'packages/sdk-server-ts/src/router/cloudflare/routes/auth.ts',
  'packages/sdk-server-ts/src/router/cloudflare/routes/sessions.ts',
  'packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts',
  'packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519.ts',
  'packages/sdk-server-ts/src/router/walletRegistrationRoutes.ts',
  'packages/sdk-server-ts/src/router/walletUnlockRouteHandlers.ts',
  'packages/sdk-server-ts/src/core/AuthService.ts',
  'packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts',
]);

function readRepoFile(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function findMatchingBrace(source, openBraceIndex) {
  let depth = 0;
  let quote = null;
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

function extractVerifierCallObjects(source) {
  const calls = [];
  const pattern = /\bverifyWebAuthn(?:AuthenticationLite|Login)\s*!?\s*\(\s*\{/g;
  let match = null;
  while ((match = pattern.exec(source))) {
    const openBraceIndex = source.indexOf('{', match.index);
    const closeBraceIndex = findMatchingBrace(source, openBraceIndex);
    calls.push(source.slice(openBraceIndex, closeBraceIndex + 1));
    pattern.lastIndex = closeBraceIndex + 1;
  }
  return calls;
}

function findVerifierCallOriginViolations() {
  const violations = [];
  for (const file of verifierCallFiles) {
    const source = readRepoFile(file);
    for (const callObject of extractVerifierCallObjects(source)) {
      if (/\bexpected_origin\b|\bexpectedOrigin\b/.test(callObject)) continue;
      violations.push(file);
    }
  }
  return violations;
}

function findClientDataOriginFallbackViolations() {
  const source = readRepoFile('packages/sdk-server-ts/src/core/AuthService.ts');
  const patterns = [
    /\bexpectedOrigin\s*:\s*[^,\n]*\|\|\s*clientData\.origin/,
    /\bconst\s+expectedOriginStrict\s*=\s*[^;\n]*\|\|\s*clientData\.origin/,
  ];
  return patterns
    .filter((pattern) => pattern.test(source))
    .map((pattern) => `packages/sdk-server-ts/src/core/AuthService.ts matches ${pattern}`);
}

const violations = [
  ...findVerifierCallOriginViolations(),
  ...findClientDataOriginFallbackViolations(),
];

if (violations.length > 0) {
  console.error('[check-webauthn-origin-policy] WebAuthn origin policy violations found:');
  for (const violation of violations) console.error(`- ${violation}`);
  process.exitCode = 1;
} else {
  console.log('[check-webauthn-origin-policy] passed');
}
