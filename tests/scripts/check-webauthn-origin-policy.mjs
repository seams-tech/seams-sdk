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

function findWalletRegistrationOriginViolations() {
  const violations = [];
  const touchPromptPath =
    'packages/sdk-web/src/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt.ts';
  const touchPrompt = readRepoFile(touchPromptPath);
  if (/\b(?:webAuthnPromptQueue|enqueueWebAuthnPrompt)\b/.test(touchPrompt)) {
    violations.push(`${touchPromptPath} retains a promise-tail WebAuthn queue`);
  }
  if (!/registrationOriginPolicy:\s*'wallet_origin_only'/.test(touchPrompt)) {
    violations.push(`${touchPromptPath} does not require wallet-origin registration`);
  }

  const fallbackPath =
    'packages/sdk-web/src/core/signingEngine/webauthnAuth/fallbacks/safari-fallbacks.ts';
  const fallback = readRepoFile(fallbackPath);
  if (!/class\s+WalletOriginWebAuthnUnavailableError/.test(fallback)) {
    violations.push(`${fallbackPath} lacks the typed wallet-origin registration error`);
  }
  if (!/if \(kind === 'create'\)[\s\S]{0,500}WalletOriginWebAuthnUnavailableError/.test(fallback)) {
    violations.push(`${fallbackPath} does not stop CREATE before parent fallback handling`);
  }

  const hostPath = 'packages/sdk-web/src/SeamsWeb/walletIframe/host/handlers/near.ts';
  const host = readRepoFile(hostPath);
  if (!/continuePreparedIframePasskeyRegistration\(activated\)/.test(host)) {
    violations.push(`${hostPath} does not use the prepared registration continuation`);
  }
  if (/registerPasskey\s*\(/.test(host)) {
    violations.push(`${hostPath} invokes the broad registerPasskey path after activation`);
  }
  const continuationCall = host.indexOf('continuePreparedIframePasskeyRegistration(activated)');
  const continuationThen = host.indexOf('registration.then', continuationCall);
  if (continuationCall < 0 || continuationThen < continuationCall) {
    violations.push(`${hostPath} does not start the prepared continuation before promise dispatch`);
  }

  const seamsWebPath = 'packages/sdk-web/src/SeamsWeb/SeamsWeb.ts';
  const seamsWeb = readRepoFile(seamsWebPath);
  const continuationStart = seamsWeb.indexOf('continuePreparedIframePasskeyRegistration(');
  const credentialStart = seamsWeb.indexOf(
    'startPreparedPasskeyRegistrationCredential',
    continuationStart,
  );
  const registrationStart = seamsWeb.indexOf(
    'registerWalletWithPreparedPasskeyAuthority',
    credentialStart,
  );
  if (
    continuationStart < 0 ||
    credentialStart < continuationStart ||
    registrationStart < credentialStart
  ) {
    violations.push(
      `${seamsWebPath} does not start WebAuthn before registration continuation work`,
    );
  }
  return violations;
}

const violations = [
  ...findVerifierCallOriginViolations(),
  ...findClientDataOriginFallbackViolations(),
  ...findWalletRegistrationOriginViolations(),
];

if (violations.length > 0) {
  console.error('[check-webauthn-origin-policy] WebAuthn origin policy violations found:');
  for (const violation of violations) console.error(`- ${violation}`);
  process.exitCode = 1;
} else {
  console.log('[check-webauthn-origin-policy] passed');
}
