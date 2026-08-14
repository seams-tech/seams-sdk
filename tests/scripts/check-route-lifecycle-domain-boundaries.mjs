#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function check(_label, callback) {
  callback();
}

function expect(received, message = '') {
  return {
    toContain(expected) {
      assert.ok(
        received.includes(expected),
        message || `Expected value to contain \`${expected}\``,
      );
    },
    toEqual(expected) {
      assert.deepEqual(received, expected, message);
    },
    toBeGreaterThan(expected) {
      assert.ok(received > expected, message || `Expected ${received} > ${expected}`);
    },
    toBeGreaterThanOrEqual(expected) {
      assert.ok(received >= expected, message || `Expected ${received} >= ${expected}`);
    },
    toMatch(expected) {
      assert.ok(expected.test(received), message || `Expected value to match ${expected}`);
    },
    not: {
      toContain(expected) {
        assert.ok(
          !received.includes(expected),
          message || `Expected value not to contain \`${expected}\``,
        );
      },
      toMatch(expected) {
        assert.ok(!expected.test(received), message || `Expected value not to match ${expected}`);
      },
    },
  };
}

function readRepoSource(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listTypeScriptFiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const absolutePath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listTypeScriptFiles(absolutePath));
      continue;
    }
    if (entry.isFile() && /\.(ts|tsx)$/.test(entry.name) && !entry.name.endsWith('.d.ts')) {
      files.push(path.relative(repoRoot, absolutePath).replaceAll(path.sep, '/'));
    }
  }
  return files.sort();
}

function sourceRange(source, startNeedle, endNeedle) {
  const start = source.indexOf(startNeedle);
  expect(start, `missing source range start: ${startNeedle}`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf(endNeedle, start + startNeedle.length);
  expect(end, `missing source range end: ${endNeedle}`).toBeGreaterThan(start);
  return source.slice(start, end);
}

function sourceFrom(source, startNeedle) {
  const start = source.indexOf(startNeedle);
  expect(start, `missing source start: ${startNeedle}`).toBeGreaterThanOrEqual(0);
  return source.slice(start);
}

function routeLifecycleAuthorityFiles() {
  const roots = [
    'packages/sdk-web/src/core/signingEngine',
    'packages/sdk-web/src/core/types',
    'packages/sdk-web/src/SeamsWeb/operations',
    'packages/sdk-web/src/SeamsWeb/publicApi',
    'packages/sdk-web/src/SeamsWeb/walletIframe',
    'packages/sdk-web/src/react',
    'packages/sdk-server-ts/src/router',
    'packages/sdk-server-ts/src/core/ThresholdService',
  ];
  return roots.flatMap((root) => listTypeScriptFiles(path.join(repoRoot, root)));
}

function signingSessionLifecycleFiles() {
  const roots = [
    'packages/sdk-web/src/core/signingEngine',
    'packages/sdk-server-ts/src/core/ThresholdService',
  ];
  return roots.flatMap((root) => listTypeScriptFiles(path.join(repoRoot, root)));
}

check('route/lifecycle boundary code avoids unsafe any casts', () => {
  const violations = [];
  for (const relativePath of signingSessionLifecycleFiles()) {
    const source = readRepoSource(relativePath);
    const lines = source.split('\n');
    lines.forEach((line, index) => {
      if (/\bas\s+any\b/.test(line)) {
        violations.push(`${relativePath}:${index + 1}: ${line.trim()}`);
      }
    });
  }

  expect(violations, violations.join('\n')).toEqual([]);
});

check('route/lifecycle boundary normalized confirmation config keeps silent mode branch-specific', () => {
  const runtimeSource = readRepoSource('packages/sdk-web/src/core/types/confirmationConfig.ts');
  const silentBranch = sourceRange(
    runtimeSource,
    'export type SilentConfirmationConfig = {',
    'export type InteractiveConfirmationConfig = {',
  );

  expect(silentBranch).toContain("kind: 'silent';");
  expect(silentBranch).toContain("uiMode: 'none';");
  expect(silentBranch).toContain('behavior?: never;');
  expect(silentBranch).toContain('autoProceedDelay?: never;');
  expect(runtimeSource).toContain("if (input?.uiMode === 'none')");
});

check('route/lifecycle boundary confirmation core consumes normalized config after boundary parsing', () => {
  const violations = [];
  const guardedFiles = [
    'packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/handlePromptFromWorker.ts',
    'packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/adapters/adapters.ts',
    'packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/signing.ts',
    'packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/registration.ts',
    'packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/localOnly.ts',
  ];

  for (const relativePath of guardedFiles) {
    const source = readRepoSource(relativePath);
    if (source.includes('confirmationConfig: ConfirmationConfig')) {
      violations.push(`${relativePath}: core confirmation flow accepts raw ConfirmationConfig`);
    }
    if (/(^|[^.\w])confirmationConfig\.behavior/.test(source)) {
      violations.push(`${relativePath}: reads raw confirmation behavior directly`);
    }
    if (/(^|[^.\w])confirmationConfig\.autoProceedDelay/.test(source)) {
      violations.push(`${relativePath}: reads raw confirmation delay directly`);
    }
  }

  expect(violations, violations.join('\n')).toEqual([]);
});

check('route/lifecycle boundary type-only modules are imported with import type', () => {
  const violations = [];
  for (const relativePath of routeLifecycleAuthorityFiles()) {
    const source = readRepoSource(relativePath);
    const lines = source.split('\n');
    for (const line of lines) {
      if (!line.includes('.types')) continue;
      if (/^\s*import\s+(?!type\b)/.test(line)) {
        violations.push(`${relativePath}: ${line.trim()}`);
      }
    }
  }

  expect(violations, violations.join('\n')).toEqual([]);
});

check('route/lifecycle boundary nonce lifecycle uses branch-specific lane and transition state', () => {
  const nearLaneSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/nonce/nearNonceLane.ts',
  );
  const leaseStateSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/nonce/nonceLeaseState.ts',
  );
  const nonceTypeSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/nonce/nonceTypes.ts',
  );
  const nearStateRange = sourceRange(
    nearLaneSource,
    'export type NearNonceLaneState = {',
    'export type NearInFlightNonceRecord = {',
  );

  expect(nearLaneSource).toContain('export type NearNonceLaneLifecycle =');
  expect(nearLaneSource).toContain("kind: 'implicit_unfunded';");
  expect(nearLaneSource).toContain("kind: 'access_key_lookup_pending';");
  expect(nearStateRange).not.toMatch(/walletId:\s*string\s*\|\s*null/);
  expect(nearStateRange).not.toMatch(/accountId:\s*string\s*\|\s*null/);
  expect(nearStateRange).not.toMatch(/publicKey:\s*string\s*\|\s*null/);
  expect(nearStateRange).not.toMatch(/transactionContext:\s*TransactionContext\s*\|\s*null/);

  expect(nonceTypeSource).toContain('export type NonceLeaseLifecycleState =');
  expect(leaseStateSource).toContain('export function tryReduceNonceLeaseState');
  expect(leaseStateSource).toContain('function assertNeverNonceLeaseTransition');
  expect(leaseStateSource).not.toContain("if (transition === '");
});

check('route/lifecycle boundary React SDK flow display state is a discriminated union', () => {
  const reactTypesSource = readRepoSource('packages/sdk-web/src/react/types.ts');
  const sdkFlowRange = sourceRange(
    reactTypesSource,
    'export type SDKFlowState =',
    'export type SDKFlowRuntime =',
  );

  expect(reactTypesSource).not.toContain('export type SDKFlowStatus =');
  expect(sdkFlowRange).toContain("status: 'idle';");
  expect(sdkFlowRange).toContain("status: 'in-progress';");
  expect(sdkFlowRange).toContain("status: 'success';");
  expect(sdkFlowRange).toContain("status: 'error';");
  expect(sdkFlowRange).toContain('error: string;');
  expect(sdkFlowRange).toContain('accountId?: never;');
});

check('route/lifecycle boundary public result types use success-specific branches', () => {
  const seamsTypesSource = readRepoSource('packages/sdk-web/src/core/types/seams.ts');
  const sdkPublicResultsSource = readRepoSource(
    'packages/sdk-web/src/core/types/sdkPublicResults.ts',
  );
  const signNearSource = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts',
  );
  const loginRange = sourceRange(
    seamsTypesSource,
    'export type LoginResult =',
    'export interface SigningSessionStatus',
  );
  const actionRange = sourceRange(
    seamsTypesSource,
    'export type ActionResult =',
    'export interface SignTransactionResult',
  );
  const registrationRange = sourceRange(
    seamsTypesSource,
    'export type RegistrationResult =',
    'export type RouterApiSecretKeyAuthErrorCode',
  );
  const nep413Range = sourceRange(
    sdkPublicResultsSource,
    'export type SignNEP413MessageResult =',
    'export type SyncAccountResult =',
  );
  const syncAccountRange = sourceFrom(sdkPublicResultsSource, 'export type SyncAccountResult =');
  const coreNep413Range = sourceRange(
    signNearSource,
    'export type SignNep413MessageResult =',
    'export type SignTransactionWithActionsInput =',
  );

  for (const [name, source] of [
    ['LoginResult', loginRange],
    ['ActionResult', actionRange],
    ['RegistrationResult', registrationRange],
    ['SignNEP413MessageResult', nep413Range],
    ['SyncAccountResult', syncAccountRange],
    ['Core SignNep413MessageResult', coreNep413Range],
  ]) {
    expect(source, `${name} must not use flat boolean success`).not.toContain('success: boolean');
    expect(source, `${name} must have a success branch`).toContain('success: true;');
    expect(source, `${name} must have a failure branch`).toContain('success: false;');
    expect(source, `${name} failure must reject at least one success-only field`).toContain(
      '?: never;',
    );
  }
});

check('route/lifecycle boundary sync-account routes parse request bodies at the boundary', () => {
  const parserSource = readRepoSource(
    'packages/sdk-server-ts/src/router/domains/syncAccount/syncAccountRequestValidation.ts',
  );
  const guardedFiles = [
    'packages/sdk-server-ts/src/router/transport/fetch/routes/syncAccount.ts',
  ];

  expect(parserSource).toContain('export function parseSyncAccountOptionsRequest');
  expect(parserSource).toContain('export function parseSyncAccountVerifyRequest');
  expect(parserSource).toContain('Unsupported sync-account options field');
  expect(parserSource).toContain('Unsupported sync-account verify field');

  for (const relativePath of guardedFiles) {
    const source = readRepoSource(relativePath);
    expect(source).toContain('parseSyncAccountOptionsRequest');
    expect(source).toContain('parseSyncAccountVerifyRequest');
  }
});

check('route/lifecycle boundary email-recovery prepare parses request bodies at the boundary', () => {
  const parserSource = readRepoSource(
    'packages/sdk-server-ts/src/router/domains/emailRecovery/emailRecoveryRequestValidation.ts',
  );
  const guardedFiles = [
    'packages/sdk-server-ts/src/router/transport/fetch/routes/emailRecovery.ts',
  ];

  expect(parserSource).toContain('export function parsePrepareEmailRecoveryRequest');
  expect(parserSource).toContain('Unsupported ${context} field');
  expect(parserSource).toContain("'email-recovery prepare'");
  expect(parserSource).toContain('threshold_ecdsa_prepare: Record<string, unknown>;');

  for (const relativePath of guardedFiles) {
    const source = readRepoSource(relativePath);
    expect(source).toContain('parsePrepareEmailRecoveryRequest');
  }
});

check('route/lifecycle boundary auth provider routes parse request bodies at the boundary', () => {
  const parserSource = readRepoSource(
    'packages/sdk-server-ts/src/router/auth/authRequestValidation.ts',
  );
  const cloudflareSource = readRepoSource(
    'packages/sdk-server-ts/src/router/transport/fetch/routes/auth.ts',
  );
  const cloudflareProviderRoute = sourceRange(
    cloudflareSource,
    "const parsedRoute = parseAuthProviderActionPath(ctx.pathname);",
    '    default:',
  );

  expect(parserSource).toContain('export function parseAuthProviderAction');
  expect(parserSource).toContain('export function parseAuthProviderActionPath');
  expect(parserSource).toContain('export function parsePasskeyLoginOptionsRequest');
  expect(parserSource).toContain('export function parsePasskeyLoginVerifyRequest');
  expect(parserSource).toContain('export function parseGoogleLoginVerifyRequest');
  expect(parserSource).toContain('export function parseAuthLinkIdentityRequest');
  expect(parserSource).toContain('export function parseAuthUnlinkIdentityRequest');
  expect(parserSource).toContain('export function parseAuthIdentityMutationRequest');
  expect(parserSource).toContain("kind: 'passkey_options'");
  expect(parserSource).toContain("kind: 'passkey_verify'");
  expect(parserSource).toContain("kind: 'google_options'");
  expect(parserSource).toContain("kind: 'google_verify'");
  expect(parserSource).toContain("kind: 'link'");
  expect(parserSource).toContain("kind: 'unlink'");
  expect(cloudflareSource).toContain('assertNeverAuthProviderAction');
  expect(cloudflareSource).toContain('assertNeverAuthIdentityMutation');

  expect(cloudflareProviderRoute).toContain('switch');
  expect(cloudflareProviderRoute).toContain('parsePasskeyLoginOptionsRequest');
  expect(cloudflareProviderRoute).toContain('parsePasskeyLoginVerifyRequest');
  expect(cloudflareProviderRoute).toContain('parseGoogleLoginVerifyRequest');
});

check('route/lifecycle boundary auth identity mutation routes parse request bodies at the boundary', () => {
  const cloudflareSource = readRepoSource(
    'packages/sdk-server-ts/src/router/transport/fetch/routes/auth.ts',
  );
  const cloudflareMutationRoute = sourceRange(
    cloudflareSource,
    "if (ctx.method === 'POST' && (ctx.pathname === '/auth/link' || ctx.pathname === '/auth/unlink'))",
    "  const parsedRoute = parseAuthProviderActionPath(ctx.pathname);",
  );

  expect(cloudflareMutationRoute).toContain('parseAuthIdentityMutationRequest');
  expect(cloudflareMutationRoute).toContain('switch (command.kind)');
  expect(cloudflareMutationRoute).toContain('assertNeverAuthIdentityMutation');
});

check('route/lifecycle boundary threshold ECDSA key-identity inventory has one wallet boundary', () => {
  const walletRegistrationSource = readRepoSource(
    'packages/sdk-server-ts/src/router/domains/walletRegistration/walletRegistrationRoutes.ts',
  );

  expect(walletRegistrationSource).toContain('handleRouterApiWalletEcdsaKeyFactsInventory');
});

check('route/lifecycle boundary threshold routes parse commands before services', () => {
  const ed25519Parser = readRepoSource(
    'packages/sdk-server-ts/src/router/domains/ed25519Yao/session/thresholdEd25519RequestValidation.ts',
  );
  const ecdsaParser = readRepoSource(
    'packages/sdk-server-ts/src/router/domains/ecdsa/thresholdEcdsaRequestValidation.ts',
  );
  const routeValidation = readRepoSource(
    'packages/sdk-server-ts/src/router/framework/routeRequestValidation.ts',
  );
  const coreTypes = readRepoSource('packages/sdk-server-ts/src/core/types.ts');
  const normalSigningRuntime = readRepoSource(
    'packages/sdk-server-ts/src/core/routerAbSigning/RouterAbNormalSigningRuntime.ts',
  );
  const cloudflareEd25519 = readRepoSource(
    'packages/sdk-server-ts/src/router/transport/fetch/routes/thresholdEd25519.ts',
  );
  const cloudflareEcdsa = readRepoSource(
    'packages/sdk-server-ts/src/router/transport/fetch/routes/thresholdEcdsa.ts',
  );

  expect(ed25519Parser).toContain('parseThresholdEd25519SessionRouteRequest');
  expect(ecdsaParser).toContain('parseRouterAbEcdsaDerivationPoolFillInitRouteRequest');
  expect(ecdsaParser).toContain('parseRouterAbEcdsaDerivationPoolFillStepRouteRequest');
  expect(routeValidation).toContain('export function parseWebAuthnAuthenticationCredential');

  expect(ed25519Parser).not.toContain('appSessionClaims');
  expect(ed25519Parser).not.toContain('ecdsaSessionClaims');
  expect(coreTypes).toContain('export type ThresholdEd25519SessionAuth');
  expect(coreTypes).toContain('auth: ThresholdEd25519SessionAuth');
  const ed25519SessionRequestType = sourceRange(
    coreTypes,
    'export interface ThresholdEd25519SessionRequest',
    'export interface ThresholdEd25519SessionResponse',
  );
  expect(ed25519SessionRequestType).not.toContain('appSessionClaims');
  expect(ed25519SessionRequestType).not.toContain('ecdsaSessionClaims');
  expect(ed25519SessionRequestType).not.toContain('verifiedWalletAuth?');
  expect(ed25519SessionRequestType).not.toContain('webauthn_authentication?');
  expect(ed25519SessionRequestType).not.toContain('expected_origin: string');
  expect(normalSigningRuntime).not.toContain('request.appSessionClaims');
  expect(normalSigningRuntime).not.toContain('request.ecdsaSessionClaims');
  expect(normalSigningRuntime).not.toContain('request.verifiedWalletAuth');
  expect(normalSigningRuntime).not.toContain('request.webauthn_authentication');
  expect(normalSigningRuntime).not.toContain('parseAppSessionClaims(request');
  expect(normalSigningRuntime).not.toContain('parseRouterAbEcdsaDerivationWalletSessionClaims(request');
  expect(normalSigningRuntime).not.toContain('ThresholdEd25519SessionWalletAuthProof');
  expect(normalSigningRuntime).not.toContain('resolveThresholdEd25519SessionWalletAuthProof');
  expect(normalSigningRuntime).not.toContain('walletAuthProof');

  expect(cloudflareEd25519).toContain('parseThresholdEd25519SessionRouteRequest');
  expect(cloudflareEd25519).toContain('verifyWebAuthnAuthenticationLite({');
  expect(cloudflareEd25519).not.toContain('buildThresholdEd25519VerifiedWalletAuth');
  expect(cloudflareEd25519).not.toContain('validated.body as unknown as ThresholdEd25519');
  expect(cloudflareEd25519).not.toContain('request: validated.body as');
  expect(cloudflareEd25519).not.toContain('request: validated.body');
  expect(cloudflareEd25519).not.toContain('as unknown as ThresholdEd25519SessionRequest');

  const cloudflarePoolFill = sourceRange(
    cloudflareEcdsa,
    'if (pathname === ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH)',
    '  return null;',
  );
  expect(cloudflarePoolFill).toContain('parseRouterAbEcdsaDerivationPoolFillInitRouteRequest');
  expect(cloudflarePoolFill).toContain('parseRouterAbEcdsaDerivationPoolFillStepRouteRequest');
  expect(cloudflarePoolFill).not.toContain('as RouterAbEcdsaDerivationPoolFill');
  expect(cloudflarePoolFill).not.toContain('const reqBody =');
  expect(cloudflarePoolFill).not.toContain('request: reqBody');
  expect(cloudflarePoolFill).not.toContain('body: req.body');

});

console.log('[check-route-lifecycle-domain-boundaries] passed');
