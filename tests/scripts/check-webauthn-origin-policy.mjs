import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const verifierCallFiles = Object.freeze([
  'packages/wallet-server/src/router/transport/fetch/routes/auth.ts',
  'packages/wallet-server/src/router/transport/fetch/routes/sessions.ts',
  'packages/wallet-server/src/router/transport/fetch/routes/thresholdEcdsa.ts',
  'packages/wallet-server/src/router/transport/fetch/routes/thresholdEd25519.ts',
  'packages/wallet-server/src/router/domains/walletRegistration/walletRegistrationRoutes.ts',
  'packages/wallet-server/src/router/domains/walletUnlock/walletUnlockRouteHandlers.ts',
  'packages/wallet-server/src/core/AuthService.ts',
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
  const source = readRepoFile('packages/wallet-server/src/core/AuthService.ts');
  const patterns = [
    /\bexpectedOrigin\s*:\s*[^,\n]*\|\|\s*clientData\.origin/,
    /\bconst\s+expectedOriginStrict\s*=\s*[^;\n]*\|\|\s*clientData\.origin/,
  ];
  return patterns
    .filter((pattern) => pattern.test(source))
    .map((pattern) => `packages/wallet-server/src/core/AuthService.ts matches ${pattern}`);
}

function findWalletRegistrationOriginViolations() {
  const violations = [];
  const touchPromptPath =
    'packages/wallet/src/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt.ts';
  const touchPrompt = readRepoFile(touchPromptPath);
  if (/\b(?:webAuthnPromptQueue|enqueueWebAuthnPrompt)\b/.test(touchPrompt)) {
    violations.push(`${touchPromptPath} retains a promise-tail WebAuthn queue`);
  }
  if (!/registrationOriginPolicy:\s*'wallet_origin_only'/.test(touchPrompt)) {
    violations.push(`${touchPromptPath} does not require wallet-origin registration`);
  }

  const fallbackPath =
    'packages/wallet/src/core/signingEngine/webauthnAuth/fallbacks/safari-fallbacks.ts';
  const fallback = readRepoFile(fallbackPath);
  if (!/class\s+WalletOriginWebAuthnUnavailableError/.test(fallback)) {
    violations.push(`${fallbackPath} lacks the typed wallet-origin registration error`);
  }
  if (!/if \(kind === 'create'\)[\s\S]{0,500}WalletOriginWebAuthnUnavailableError/.test(fallback)) {
    violations.push(`${fallbackPath} does not stop CREATE before parent fallback handling`);
  }

  const hostPath = 'packages/wallet/src/SeamsWeb/walletIframe/host/handlers/near.ts';
  const host = readRepoFile(hostPath);
  if (!/PM_REGISTER_WALLET:[\s\S]{0,1000}pm\.registration\.registerWallet\(\{/.test(host)) {
    violations.push(`${hostPath} does not route iframe registration through registerWallet`);
  }
  if (/registrationActivation|continuePreparedIframePasskeyRegistration/.test(host)) {
    violations.push(`${hostPath} retains the obsolete registration activation path`);
  }

  const hostEntryPath = 'packages/wallet/src/SeamsWeb/walletIframe/host/index.ts';
  const hostEntry = readRepoFile(hostEntryPath);
  const configPreload = hostEntry.indexOf('await preloadWalletHostRegistrationSurface()');
  const configReady = hostEntry.indexOf("post({ type: 'PONG', requestId })", configPreload);
  if (configPreload < 0 || configReady < configPreload) {
    violations.push(`${hostEntryPath} does not preload registration UI before config readiness`);
  }
  if (
    /openRegistrationPreparationIfNeeded|openWalletHostRegistrationPreparation|preparationHandle/.test(
      hostEntry,
    )
  ) {
    violations.push(`${hostEntryPath} mounts an obsolete duplicate registration shell`);
  }

  const preloadPath =
    'packages/wallet/src/SeamsWeb/walletIframe/host/registrationPreparationPreload.ts';
  const preload = readRepoFile(preloadPath);
  if (
    !/preloadWalletHostRegistrationPreparation\([\s\S]{0,600}prewarmTxConfirmerUi\(\)/.test(
      preload,
    )
  ) {
    violations.push(`${preloadPath} does not preload the registration modal element`);
  }

  const uiConfirmPath = 'packages/wallet/src/core/signingEngine/uiConfirm/UiConfirmManager.ts';
  const uiConfirm = readRepoFile(uiConfirmPath);
  if (
    !/openRegistrationPreparationModal\([\s\S]{0,1800}loading:\s*true[\s\S]{0,500}uiMode:\s*'modal'/.test(
      uiConfirm,
    )
  ) {
    violations.push(`${uiConfirmPath} does not mount an immediate loading registration modal`);
  }
  if (
    !/takeRegistrationConfirmationSurface\(\)[\s\S]{0,700}kind:\s*'reuse_mounted'/.test(
      uiConfirm,
    )
  ) {
    violations.push(`${uiConfirmPath} does not reuse the preparation modal for confirmation`);
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
