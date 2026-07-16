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
  expect(registrationRange).toContain("kind: 'near_wallet_registered';");
  expect(registrationRange).toContain("kind: 'ecdsa_wallet_registered';");
  expect(registrationRange).toContain("kind: 'near_ed25519_signer_added';");
  expect(registrationRange).toContain("kind: 'ecdsa_signer_added';");
});

check('route/lifecycle boundary sync-account routes parse request bodies at the boundary', () => {
  const parserSource = readRepoSource(
    'packages/sdk-server-ts/src/router/syncAccountRequestValidation.ts',
  );
  const guardedFiles = [
    'packages/sdk-server-ts/src/router/cloudflare/routes/syncAccount.ts',
  ];

  expect(parserSource).toContain('export function parseSyncAccountOptionsRequest');
  expect(parserSource).toContain('export function parseSyncAccountVerifyRequest');
  expect(parserSource).toContain('Unsupported sync-account options field');
  expect(parserSource).toContain('Unsupported sync-account verify field');
  expect(parserSource).not.toContain('challenge_id');
  expect(parserSource).not.toContain('ttlMs');

  for (const relativePath of guardedFiles) {
    const source = readRepoSource(relativePath);
    expect(source).toContain('parseSyncAccountOptionsRequest');
    expect(source).toContain('parseSyncAccountVerifyRequest');
    expect(source).not.toContain('createWebAuthnSyncAccountOptions(req.body)');
    expect(source).not.toContain('createWebAuthnSyncAccountOptions(body as any)');
    expect(source).not.toContain('verifyWebAuthnSyncAccount({');
    expect(source).not.toContain('challenge_id');
    expect(source).not.toContain('threshold_ed25519 ?');
  }
});

check('route/lifecycle boundary link-device server routes are absent until the feature returns', () => {
  const serverRouteSurface = [
    readRepoSource('packages/sdk-server-ts/src/router/routeDefinitions.ts'),
    readRepoSource('packages/sdk-server-ts/src/router/express-adaptor.ts'),
    readRepoSource('packages/sdk-server-ts/src/router/cloudflare/createCloudflareRouter.ts'),
  ].join('\n');

  expect(serverRouteSurface).not.toContain('/link-device/');
  expect(serverRouteSurface).not.toContain('link_device_session');
  expect(serverRouteSurface).not.toContain('link_device_prepare');
  expect(serverRouteSurface).not.toContain('registerLinkDeviceRoutes');
  expect(serverRouteSurface).not.toContain('handleLinkDevice');
});

check('route/lifecycle boundary email-recovery routes parse request bodies at the boundary', () => {
  const parserSource = readRepoSource(
    'packages/sdk-server-ts/src/router/emailRecoveryRequestValidation.ts',
  );
  const guardedFiles = [
    'packages/sdk-server-ts/src/router/cloudflare/routes/emailRecovery.ts',
  ];

  expect(parserSource).toContain('export function parsePrepareEmailRecoveryRequest');
  expect(parserSource).toContain('export function parseRespondEmailRecoveryEcdsaRequest');
  expect(parserSource).toContain('Unsupported ${context} field');
  expect(parserSource).toContain("'email-recovery prepare'");
  expect(parserSource).toContain("'email-recovery ECDSA respond'");
  expect(parserSource).toContain('threshold_ecdsa_prepare: Record<string, unknown>;');
  expect(parserSource).not.toMatch(/['"]requestId['"]/);
  expect(parserSource).not.toMatch(/['"]accountId['"]/);
  expect(parserSource).not.toMatch(/['"]clientBootstrap['"]/);
  expect(parserSource).not.toContain('threshold_ecdsa email-recovery bootstrap has been removed');

  for (const relativePath of guardedFiles) {
    const source = readRepoSource(relativePath);
    expect(source).toContain('parsePrepareEmailRecoveryRequest');
    expect(source).toContain('parseRespondEmailRecoveryEcdsaRequest');
    expect(source).not.toContain('prepareEmailRecovery({');
    expect(source).not.toContain('respondEmailRecoveryEcdsa({ ...(req.body || {}) })');
    expect(source).not.toContain('respondEmailRecoveryEcdsa(body as any)');
    expect(source).not.toContain('body as any');
    expect(source).not.toContain('(req.body || {}).rp_id');
    expect(source).not.toContain('(body as Record<string, unknown>).rp_id');
  }
});

check('route/lifecycle boundary auth provider routes parse request bodies at the boundary', () => {
  const parserSource = readRepoSource('packages/sdk-server-ts/src/router/authRequestValidation.ts');
  const cloudflareSource = readRepoSource(
    'packages/sdk-server-ts/src/router/cloudflare/routes/auth.ts',
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
  expect(parserSource).not.toMatch(/['"]userId['"]/);
  expect(parserSource).not.toMatch(/['"]rpId['"]/);
  expect(parserSource).not.toMatch(/['"]ttlMs['"]/);
  expect(parserSource).not.toMatch(/['"]idToken['"]/);
  expect(parserSource).not.toMatch(/['"]challenge_id['"]/);
  expect(parserSource).not.toMatch(/['"]stepUpChallengeId['"]/);
  expect(parserSource).not.toMatch(/['"]step_up_webauthn_authentication['"]/);
  expect(parserSource).not.toMatch(/['"]sessionKind['"]/);
  expect(cloudflareSource).toContain('assertNeverAuthProviderAction');
  expect(cloudflareSource).toContain('assertNeverAuthIdentityMutation');

  expect(cloudflareProviderRoute).toContain('switch');
  expect(cloudflareProviderRoute).toContain('parsePasskeyLoginOptionsRequest');
  expect(cloudflareProviderRoute).toContain('parsePasskeyLoginVerifyRequest');
  expect(cloudflareProviderRoute).toContain('parseGoogleLoginVerifyRequest');
  expect(cloudflareProviderRoute).not.toContain('createWebAuthnLoginOptions(req.body)');
  expect(cloudflareProviderRoute).not.toContain('createWebAuthnLoginOptions(body as any)');
  expect(cloudflareProviderRoute).not.toContain('verifyWebAuthnLogin({');
  expect(cloudflareProviderRoute).not.toContain('verifyGoogleLogin({ idToken');
  expect(cloudflareProviderRoute).not.toContain('body as any');
  expect(cloudflareProviderRoute).not.toContain('sessionKind');
  expect(cloudflareProviderRoute).not.toContain('idToken');
  expect(cloudflareProviderRoute).not.toContain('challenge_id');
});

check('route/lifecycle boundary auth identity mutation routes parse request bodies at the boundary', () => {
  const cloudflareSource = readRepoSource(
    'packages/sdk-server-ts/src/router/cloudflare/routes/auth.ts',
  );
  const cloudflareMutationRoute = sourceRange(
    cloudflareSource,
    "if (ctx.method === 'POST' && (ctx.pathname === '/auth/link' || ctx.pathname === '/auth/unlink'))",
    "  const parsedRoute = parseAuthProviderActionPath(ctx.pathname);",
  );

  expect(cloudflareMutationRoute).toContain('parseAuthIdentityMutationRequest');
  expect(cloudflareMutationRoute).toContain('switch (command.kind)');
  expect(cloudflareMutationRoute).toContain('assertNeverAuthIdentityMutation');
  expect(cloudflareMutationRoute).not.toContain('linkParsed!');
  expect(cloudflareMutationRoute).not.toContain('unlinkParsed!');

  expect(cloudflareMutationRoute).not.toContain('body as any');
  expect(cloudflareMutationRoute).not.toContain('(req.body || {})');
  expect(cloudflareMutationRoute).not.toContain('(body as Record<string, unknown>)');
  expect(cloudflareMutationRoute).not.toContain('stepUpChallengeId');
  expect(cloudflareMutationRoute).not.toContain('step_up_webauthn_authentication');
  expect(cloudflareMutationRoute).not.toContain('sessionKind');
  expect(cloudflareMutationRoute).not.toContain('id_token');
  expect(cloudflareMutationRoute).not.toContain('step_up_challenge_id');
});

check('route/lifecycle boundary threshold ECDSA key-identity inventory has one wallet boundary', () => {
  const parserSource = readRepoSource(
    'packages/sdk-server-ts/src/router/thresholdEcdsaRequestValidation.ts',
  );
  const cloudflareSource = readRepoSource(
    'packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts',
  );
  const routeDefinitionSource = readRepoSource('packages/sdk-server-ts/src/router/routeDefinitions.ts');
  const walletRegistrationSource = readRepoSource(
    'packages/sdk-server-ts/src/router/walletRegistrationRoutes.ts',
  );

  for (const source of [parserSource, cloudflareSource, routeDefinitionSource]) {
    expect(source).not.toContain('ROUTER_AB_ECDSA_HSS_KEY_IDENTITIES_PATH');
    expect(source).not.toContain('parseRouterAbEcdsaDerivationKeyIdentitiesRequest');
    expect(source).not.toContain('RouterAbEcdsaDerivationKeyIdentitiesRequest');
    expect(source).not.toContain('Unsupported threshold-ecdsa key-identities field');
    expect(source).not.toContain('router_ab_ecdsa_derivation_key_identities');
  }

  expect(walletRegistrationSource).toContain('handleRouterApiWalletEcdsaKeyFactsInventory');
  expect(walletRegistrationSource).toContain("permission: 'ecdsa_key_facts_inventory'");
  expect(cloudflareSource).not.toContain("typeof (body as { walletId?: unknown }).walletId");
  expect(cloudflareSource).not.toContain("typeof (body as { clientDeviceId?: unknown }).clientDeviceId");
});

check('route/lifecycle boundary threshold and session exchange routes parse commands before services', () => {
  const ed25519Parser = readRepoSource(
    'packages/sdk-server-ts/src/router/thresholdEd25519RequestValidation.ts',
  );
  const ecdsaParser = readRepoSource(
    'packages/sdk-server-ts/src/router/thresholdEcdsaRequestValidation.ts',
  );
  const sessionExchangeParser = readRepoSource(
    'packages/sdk-server-ts/src/router/sessionExchangeRequestValidation.ts',
  );
  const routeValidation = readRepoSource(
    'packages/sdk-server-ts/src/router/routeRequestValidation.ts',
  );
  const coreTypes = readRepoSource('packages/sdk-server-ts/src/core/types.ts');
  const normalSigningRuntime = readRepoSource(
    'packages/sdk-server-ts/src/core/routerAbSigning/RouterAbNormalSigningRuntime.ts',
  );
  const cloudflareEd25519 = readRepoSource(
    'packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519.ts',
  );
  const cloudflareEcdsa = readRepoSource(
    'packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts',
  );
  const cloudflareSessions = readRepoSource(
    'packages/sdk-server-ts/src/router/cloudflare/routes/sessions.ts',
  );

  expect(ed25519Parser).toContain('parseThresholdEd25519SessionRouteRequest');
  expect(ecdsaParser).toContain('parseRouterAbEcdsaDerivationPoolFillInitRouteRequest');
  expect(ecdsaParser).toContain('parseRouterAbEcdsaDerivationPoolFillStepRouteRequest');
  expect(sessionExchangeParser).toContain('export function parseSessionExchangeRouteCommand');
  expect(sessionExchangeParser).toContain("import { parseSessionKind } from './routerApi'");
  expect(sessionExchangeParser).toContain(
    "import { parseOidcAccountMode } from './emailOtpSessionRouteHelpers'",
  );
  expect(sessionExchangeParser).not.toContain('function unexpectedKey');
  expect(sessionExchangeParser).not.toContain('function normalizedString');
  expect(sessionExchangeParser).not.toContain('function parseSessionKind');
  expect(sessionExchangeParser).not.toContain('function parseAccountMode');
  expect(sessionExchangeParser).not.toContain('function parseWebAuthnAuthenticationCredential');
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

  const cloudflareExchange = sourceRange(
    cloudflareSessions,
    'export async function handleSessionExchange',
    'export async function handleSessionRevoke',
  );
  expect(cloudflareExchange).toContain('parseSessionExchangeRouteCommand');
  expect(cloudflareExchange).toContain('const command = parsedExchange.command;');
  expect(cloudflareExchange).toContain("if (command.kind === 'oidc_jwt')");
  expect(cloudflareExchange).not.toContain('const exchange =');
  expect(cloudflareExchange).not.toContain('exchange as any');
  expect(cloudflareExchange).not.toContain('exchange.token');
  expect(cloudflareExchange).not.toContain('exchange.webauthn_authentication');
  expect(cloudflareExchange).not.toContain('verifyGoogleLogin({ idToken: (exchange');
  expect(cloudflareExchange).not.toContain('verifyOidcJwtExchange({ token: (exchange');
});

console.log('[check-route-lifecycle-domain-boundaries] passed');
