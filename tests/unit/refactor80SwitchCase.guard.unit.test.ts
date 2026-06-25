import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listTypeScriptFiles(dir: string): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];
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

function sourceRange(source: string, startNeedle: string, endNeedle: string): string {
  const start = source.indexOf(startNeedle);
  expect(start, `missing source range start: ${startNeedle}`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf(endNeedle, start + startNeedle.length);
  expect(end, `missing source range end: ${endNeedle}`).toBeGreaterThan(start);
  return source.slice(start, end);
}

function sourceFrom(source: string, startNeedle: string): string {
  const start = source.indexOf(startNeedle);
  expect(start, `missing source start: ${startNeedle}`).toBeGreaterThanOrEqual(0);
  return source.slice(start);
}

function refactor80AuthorityFiles(): string[] {
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

function refactor80SigningSessionLifecycleFiles(): string[] {
  const roots = [
    'packages/sdk-web/src/core/signingEngine',
    'packages/sdk-server-ts/src/core/ThresholdService',
  ];
  return roots.flatMap((root) => listTypeScriptFiles(path.join(repoRoot, root)));
}

test('Refactor 80 guard uses the current plan number', () => {
  const plan = readRepoSource('docs/refactor-80-switch-case.md');
  expect(plan).toContain('tests/unit/refactor80SwitchCase.guard.unit.test.ts');
  expect(plan).not.toContain('refactor77SwitchCase.guard.unit.test.ts');
});

test('Refactor 80 signing/session lifecycle code avoids unsafe any casts', () => {
  const violations: string[] = [];
  for (const relativePath of refactor80SigningSessionLifecycleFiles()) {
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

test('Refactor 80 normalized confirmation config keeps silent mode branch-specific', () => {
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

test('Refactor 80 confirmation core consumes normalized config after boundary parsing', () => {
  const violations: string[] = [];
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

test('Refactor 80 type-only modules are imported with import type', () => {
  const violations: string[] = [];
  for (const relativePath of refactor80AuthorityFiles()) {
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

test('Refactor 80 nonce lifecycle uses branch-specific lane and transition state', () => {
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

test('Refactor 80 React SDK flow display state is a discriminated union', () => {
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

test('Refactor 80 public result types use success-specific branches', () => {
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
    'export type RelaySecretKeyAuthErrorCode',
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
  ] as const) {
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

test('Refactor 80 sync-account routes parse request bodies at the boundary', () => {
  const parserSource = readRepoSource(
    'packages/sdk-server-ts/src/router/syncAccountRequestValidation.ts',
  );
  const guardedFiles = [
    'packages/sdk-server-ts/src/router/express/routes/syncAccount.ts',
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

test('Refactor 80 link-device routes parse request bodies at the boundary', () => {
  const parserSource = readRepoSource(
    'packages/sdk-server-ts/src/router/linkDeviceRequestValidation.ts',
  );
  const guardedFiles = [
    'packages/sdk-server-ts/src/router/express/routes/linkDevice.ts',
    'packages/sdk-server-ts/src/router/cloudflare/routes/linkDevice.ts',
  ];

  expect(parserSource).toContain('export function parseRegisterLinkDeviceSessionRequest');
  expect(parserSource).toContain('export function parseClaimLinkDeviceSessionRequest');
  expect(parserSource).toContain('export function parsePrepareLinkDeviceRequest');
  expect(parserSource).toContain('export function parseRespondLinkDeviceEcdsaRequest');
  expect(parserSource).toContain('Unsupported ${context} field');
  expect(parserSource).toContain("'link-device session'");
  expect(parserSource).toContain("'link-device claim'");
  expect(parserSource).toContain("'link-device prepare'");
  expect(parserSource).toContain("'link-device ECDSA respond'");
  expect(parserSource).not.toMatch(/['"]sessionId['"]/);
  expect(parserSource).not.toMatch(/['"]accountId['"]/);
  expect(parserSource).not.toMatch(/['"]walletId['"]/);
  expect(parserSource).not.toContain('threshold_ecdsa link-device bootstrap has been removed');

  for (const relativePath of guardedFiles) {
    const source = readRepoSource(relativePath);
    expect(source).toContain('parseRegisterLinkDeviceSessionRequest');
    expect(source).toContain('parseClaimLinkDeviceSessionRequest');
    expect(source).toContain('parsePrepareLinkDeviceRequest');
    expect(source).toContain('parseRespondLinkDeviceEcdsaRequest');
    expect(source).not.toContain('registerLinkDeviceSession({ ...(req.body || {}) })');
    expect(source).not.toContain('claimLinkDeviceSession({ ...(req.body || {}) })');
    expect(source).not.toContain('respondLinkDeviceEcdsa({ ...(req.body || {}) })');
    expect(source).not.toContain('registerLinkDeviceSession(body as any)');
    expect(source).not.toContain('claimLinkDeviceSession(body as any)');
    expect(source).not.toContain('respondLinkDeviceEcdsa(body as any)');
    expect(source).not.toContain('prepareLinkDevice({');
    expect(source).not.toContain('body as any');
    expect(source).not.toContain('(body as Record<string, unknown>).rp_id');
  }
});

test('Refactor 80 email-recovery routes parse request bodies at the boundary', () => {
  const parserSource = readRepoSource(
    'packages/sdk-server-ts/src/router/emailRecoveryRequestValidation.ts',
  );
  const guardedFiles = [
    'packages/sdk-server-ts/src/router/express/routes/emailRecovery.ts',
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

test('Refactor 80 auth provider routes parse request bodies at the boundary', () => {
  const parserSource = readRepoSource('packages/sdk-server-ts/src/router/authRequestValidation.ts');
  const expressSource = readRepoSource('packages/sdk-server-ts/src/router/express/routes/auth.ts');
  const cloudflareSource = readRepoSource(
    'packages/sdk-server-ts/src/router/cloudflare/routes/auth.ts',
  );
  const expressProviderRoute = sourceRange(
    expressSource,
    "router.post('/auth/:provider/:action'",
    '    } catch (e: any) {',
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
  expect(expressSource).toContain('assertNeverAuthProviderAction');
  expect(cloudflareSource).toContain('assertNeverAuthProviderAction');
  expect(cloudflareSource).toContain('assertNeverAuthIdentityMutation');

  for (const source of [expressProviderRoute, cloudflareProviderRoute]) {
    expect(source).toContain('switch');
    expect(source).toContain('parsePasskeyLoginOptionsRequest');
    expect(source).toContain('parsePasskeyLoginVerifyRequest');
    expect(source).toContain('parseGoogleLoginVerifyRequest');
    expect(source).not.toContain('createWebAuthnLoginOptions(req.body)');
    expect(source).not.toContain('createWebAuthnLoginOptions(body as any)');
    expect(source).not.toContain('verifyWebAuthnLogin({');
    expect(source).not.toContain('verifyGoogleLogin({ idToken');
    expect(source).not.toContain('body as any');
    expect(source).not.toContain('sessionKind');
    expect(source).not.toContain('idToken');
    expect(source).not.toContain('challenge_id');
  }
});

test('Refactor 80 auth identity mutation routes parse request bodies at the boundary', () => {
  const expressSource = readRepoSource('packages/sdk-server-ts/src/router/express/routes/auth.ts');
  const cloudflareSource = readRepoSource(
    'packages/sdk-server-ts/src/router/cloudflare/routes/auth.ts',
  );
  const expressLinkRoute = sourceRange(
    expressSource,
    "router.post('/auth/link'",
    "  router.post('/auth/unlink'",
  );
  const expressUnlinkRoute = sourceRange(
    expressSource,
    "router.post('/auth/unlink'",
    "  router.post('/auth/:provider/:action'",
  );
  const cloudflareMutationRoute = sourceRange(
    cloudflareSource,
    "if (ctx.method === 'POST' && (ctx.pathname === '/auth/link' || ctx.pathname === '/auth/unlink'))",
    "  const parsedRoute = parseAuthProviderActionPath(ctx.pathname);",
  );

  expect(expressLinkRoute).toContain('parseAuthLinkIdentityRequest');
  expect(expressUnlinkRoute).toContain('parseAuthUnlinkIdentityRequest');
  expect(cloudflareMutationRoute).toContain('parseAuthIdentityMutationRequest');
  expect(cloudflareMutationRoute).toContain('switch (command.kind)');
  expect(cloudflareMutationRoute).toContain('assertNeverAuthIdentityMutation');
  expect(cloudflareMutationRoute).not.toContain('linkParsed!');
  expect(cloudflareMutationRoute).not.toContain('unlinkParsed!');

  for (const source of [expressLinkRoute, expressUnlinkRoute, cloudflareMutationRoute]) {
    expect(source).not.toContain('body as any');
    expect(source).not.toContain('(req.body || {})');
    expect(source).not.toContain('(body as Record<string, unknown>)');
    expect(source).not.toContain('stepUpChallengeId');
    expect(source).not.toContain('step_up_webauthn_authentication');
    expect(source).not.toContain('sessionKind');
    expect(source).not.toContain('id_token');
    expect(source).not.toContain('step_up_challenge_id');
  }
});

test('Refactor 80 threshold ECDSA key-identity route parses body at the boundary', () => {
  const parserSource = readRepoSource(
    'packages/sdk-server-ts/src/router/thresholdEcdsaRequestValidation.ts',
  );
  const expressSource = readRepoSource(
    'packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts',
  );
  const cloudflareSource = readRepoSource(
    'packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts',
  );
  const expressRoute = sourceRange(
    expressSource,
    'router.post(ROUTER_AB_ECDSA_HSS_KEY_IDENTITIES_PATH_V1',
    '  router.post(ROUTER_AB_ECDSA_HSS_BOOTSTRAP_PATH_V1',
  );
  const cloudflareRoute = sourceRange(
    cloudflareSource,
    'if (pathname === ROUTER_AB_ECDSA_HSS_KEY_IDENTITIES_PATH_V1)',
    '  if (pathname === ROUTER_AB_ECDSA_HSS_BOOTSTRAP_PATH_V1)',
  );

  expect(parserSource).toContain('export function parseRouterAbEcdsaHssKeyIdentitiesRequest');
  expect(parserSource).toContain('Unsupported threshold-ecdsa key-identities field');
  expect(parserSource).toContain("const KEY_IDENTITIES_KEYS = ['sessionKind', 'keyTargets']");
  expect(parserSource).not.toContain('targets');

  for (const source of [expressRoute, cloudflareRoute]) {
    expect(source).toContain('parseRouterAbEcdsaHssKeyIdentitiesRequest');
    expect(source).toContain('parsed.request.keyTargets');
    expect(source).not.toContain('bodyRecord');
    expect(source).not.toContain('Array.isArray(bodyRecord.keyTargets)');
    expect(source).not.toContain('body as Record<string, unknown>');
  }

  expect(expressSource).toContain('thresholdEcdsaRouteDiagnosticMetadata');
  expect(expressSource).not.toContain("typeof (body as { walletId?: unknown }).walletId");
  expect(expressSource).not.toContain("typeof (body as { clientDeviceId?: unknown }).clientDeviceId");
});

test('Refactor 80 threshold Ed25519 HSS rejects legacy email OTP command by discriminant', () => {
  const guardedFiles = [
    'packages/sdk-server-ts/src/router/express/routes/thresholdEd25519.ts',
    'packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519.ts',
  ];

  for (const relativePath of guardedFiles) {
    const source = readRepoSource(relativePath);
    const helper = sourceRange(
      source,
      'function isEmailOtpRegistrationHssRequest',
      'function rejectLegacyEmailOtpRegistrationHssRequest',
    );
    expect(helper).toContain("return body.kind === 'email_otp_registration';");
    expect(helper).not.toContain('registrationAttemptId');
    expect(helper).not.toContain('new_account_id');
    expect(helper).not.toContain('rp_id');
  }
});
